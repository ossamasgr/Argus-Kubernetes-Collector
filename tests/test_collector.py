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


def test_tls_uses_explicit_ca_or_system_roots_without_silent_fallback(monkeypatch):
    trust = []
    def context(*, cafile):
        trust.append(cafile)
        return object()
    monkeypatch.setattr(agent.ssl, 'create_default_context', context)
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
    assert trust == ['/fixture/ca.pem']
    assert agent.transfer('https://argus.example.com', 'fixture', {}) == {'status': 'ok'}
    assert trust == ['/fixture/ca.pem', None]
    with pytest.raises(ValueError, match='HTTPS'):
        agent.transfer('http://argus.example.com', 'fixture')
    assert agent.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.example.com') is None


def test_chart_is_namespaced_read_only_and_uses_external_credentials():
    with open('artifacts/rendered.yaml') as stream:
        objects = list(yaml.safe_load_all(stream))
    assert not any(o['kind'] in ('Secret', 'Namespace', 'Service') for o in objects)
    roles = [o for o in objects if o['kind'] == 'Role']
    assert {o['metadata']['namespace'] for o in roles} == {'production', 'monitoring'}
    for role in roles:
        assert all(rule['verbs'] == ['get', 'list'] for rule in role['rules'])
        assert not {'secrets', 'configmaps', 'nodes', 'pods/log', 'pods/exec'} & {r for rule in role['rules'] for r in rule['resources']}
    pod = next(o for o in objects if o['kind'] == 'Deployment')['spec']['template']['spec']
    assert pod['hostAliases'] == [{'ip': '192.0.2.10', 'hostnames': ['argus.example.com']}]
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


@pytest.mark.parametrize('status', [404, 410])
def test_legacy_cronjob_api_fallback(status):
    calls = []
    def get(path):
        calls.append(path)
        if path.startswith('/apis/batch/v1/namespaces/') and '/cronjobs?' in path:
            raise HTTPError(path, status, 'private', {}, None)
        return {'items': []}
    result = agent.collect(['production'], get)
    assert all(c['complete'] for c in result['coverage'])
    assert any(path.startswith('/apis/batch/v1beta1/') for path in calls)


@pytest.mark.parametrize('status', [401, 403, 500])
def test_api_errors_do_not_downgrade(status):
    calls = []
    def get(path):
        calls.append(path)
        raise HTTPError(path, status, 'private', {}, None)
    result = agent.collect(['production'], get)
    assert all(not c['complete'] for c in result['coverage'])
    assert not any('/v1beta1/' in path for path in calls)


def test_failure_logs_are_actionable_and_never_include_exception_details(capsys):
    from urllib.error import URLError
    agent.failure('collection_or_delivery_failed', 'snapshot', URLError(TimeoutError('secret url and token')))
    agent.failure('collection_or_delivery_failed', 'enrollment', HTTPError('https://private', 401, 'secret', {}, None))
    lines = capsys.readouterr().out.splitlines()
    assert json.loads(lines[0])['error'] == 'timeout'
    assert json.loads(lines[1]) == {'event': 'collection_or_delivery_failed', 'stage': 'enrollment', 'error': 'unauthorized', 'http_status': 401}
    assert 'secret' not in ''.join(lines) and 'private' not in ''.join(lines)


@pytest.mark.parametrize('version', ['1.16.15', '1.18.20', '1.19.16', '1.21.14', '1.25.16', '1.28.10', '1.33.0', '1.36.0'])
def test_chart_uses_version_appropriate_security_fields(version):
    with open(f'artifacts/compatibility-{version}.yaml') as stream:
        objects = list(yaml.safe_load_all(stream))
    pod = next(o for o in objects if o['kind'] == 'Deployment')['spec']['template']
    assert pod['spec']['securityContext']['runAsNonRoot'] is True
    if int(version.split('.')[1]) < 19:
        assert 'seccompProfile' not in pod['spec']['securityContext']
        assert pod['metadata']['annotations']['seccomp.security.alpha.kubernetes.io/pod'] == 'runtime/default'
    else:
        assert pod['spec']['securityContext']['seccompProfile'] == {'type': 'RuntimeDefault'}
