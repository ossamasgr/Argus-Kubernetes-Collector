import json
from urllib.error import HTTPError
import pytest
import yaml
from collector import agent


def test_inventory_filters_sensitive_spec_and_reports_partial_coverage():
    calls = []
    def get(path):
        calls.append(path)
        if '/services?' in path:
            raise HTTPError(path, 403, 'private-provider-message', {}, None)
        if '/pods?' in path:
            return {'items': [{'metadata': {'name': 'api', 'uid': 'uid-1', 'labels': {'private': 'excluded'}},
                'spec': {'containers': [{'env': 'excluded'}]},
                'status': {'phase': 'Running', 'containerStatuses': [{'ready': True, 'restartCount': 3}]}}]}
        return {'items': []}
    result = agent.collect(['production'], get)
    assert result['version'] == 1 and len(result['coverage']) == 9
    assert result['items'] == [{'namespace': 'production', 'kind': 'pods', 'name': 'api', 'uid': 'uid-1',
        'phase': 'Running', 'ready': 1, 'desired': 1, 'restarts': 3}]
    assert 'excluded' not in json.dumps(result) and 'private-provider-message' not in json.dumps(result)
    assert next(c for c in result['coverage'] if c['kind'] == 'services')['error'] == 'forbidden'
    assert all('/namespaces/production/' in c for c in calls)


def test_pagination_and_resource_limit_are_explicit():
    pages = []
    def get(path):
        pages.append(path)
        return {'items': [{'metadata': {'name': 'item-' + str(i), 'uid': f'{len(pages)}-{i}'}} for i in range(50)],
            'metadata': {'continue': 'next'}}
    result = agent.collect(['production', 'monitoring'], get)
    assert len(result['items']) == 500 and len(pages) == 10
    assert 'continue=next' in pages[1]
    assert all(not c['complete'] and c['error'] == 'limit' for c in result['coverage'])


def test_collection_deadline_bounds_requests(monkeypatch):
    clock = iter([0] + [100] * 100)
    monkeypatch.setattr(agent.time, 'monotonic', lambda: next(clock))
    result = agent.collect(['production'], lambda _: pytest.fail('Request after deadline'))
    assert not result['items'] and all(c['error'] == 'unavailable' for c in result['coverage'])


def test_tls_preserves_system_roots_and_adds_custom_ca(monkeypatch):
    class Context:
        def load_verify_locations(self, *, cafile):
            assert cafile == '/fixture/ca.pem'
    context = Context()
    monkeypatch.setattr(agent.ssl, 'create_default_context', lambda: context)
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            assert limit == 2_000_001
            return b'{"status":"ok"}'
    class Opener:
        def open(self, request, *, timeout):
            assert timeout == 15 and request.get_method() == 'POST'
            assert request.headers['Authorization'] == 'Bearer fixture'
            return Response()
    monkeypatch.setattr(agent, 'HTTPSHandler', lambda **kwargs: kwargs)
    monkeypatch.setattr(agent, 'build_opener', lambda *args: Opener())
    assert agent.transfer('https://argus.example.com', 'fixture', {}, ca='/fixture/ca.pem') == {'status': 'ok'}
    with pytest.raises(ValueError, match='HTTPS'):
        agent.transfer('http://argus.example.com', 'fixture')
    assert agent.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.example.com') is None


def test_chart_is_namespaced_read_only_and_uses_external_credentials():
    with open('artifacts/rendered.yaml') as stream:
        objects = list(yaml.safe_load_all(stream))
    assert not any(o['kind'] in ('Secret', 'Namespace', 'ClusterRole', 'ClusterRoleBinding', 'Service') for o in objects)
    roles = [o for o in objects if o['kind'] == 'Role']
    assert {o['metadata']['namespace'] for o in roles} == {'production', 'monitoring'}
    for role in roles:
        assert all(rule['verbs'] == ['get', 'list'] for rule in role['rules'])
        assert not {'secrets', 'configmaps', 'nodes', 'pods/log', 'pods/exec'} & {r for rule in role['rules'] for r in rule['resources']}
    pod = next(o for o in objects if o['kind'] == 'Deployment')['spec']['template']['spec']
    assert pod['securityContext']['runAsNonRoot'] is True
    container = pod['containers'][0]
    assert container['securityContext']['readOnlyRootFilesystem'] is True
    assert container['securityContext']['capabilities']['drop'] == ['ALL']
    assert '@sha256:' in container['image']
    assert next(e['value'] for e in container['env'] if e['name'] == 'ARGUS_CA_FILE') == '/etc/argus-ca/ca.crt'
    assert not any('KEY' in e['name'] or 'TOKEN' in e['name'] for e in container['env'])
    assert next(v['secret']['secretName'] for v in pod['volumes'] if 'secret' in v) == 'fixture-credentials'
    policy = next(o for o in objects if o['kind'] == 'NetworkPolicy')['spec']
    assert policy['ingress'] == []
    assert set(policy['policyTypes']) == {'Ingress', 'Egress'}
