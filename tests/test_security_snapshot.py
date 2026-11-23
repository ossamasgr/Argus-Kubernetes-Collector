import json
from urllib.error import HTTPError
import yaml
from collector import security_snapshot as snapshot

POD = {'metadata': {'name': 'api-1', 'namespace': 'production', 'uid': 'u1', 'labels': {'app': 'api'},
                    'annotations': {'kubectl.kubernetes.io/last-applied-configuration': '{"secret":"leak-annotation"}', 'nginx.ingress.kubernetes.io/ssl-redirect': 'true'},
                    'managedFields': [{'manager': 'leak-manager'}]},
       'spec': {'serviceAccountName': 'api', 'automountServiceAccountToken': False,
                'containers': [{'name': 'api', 'image': 'shop/api:1', 'command': ['sh', '-c', 'echo leak-command'], 'args': ['--password=leak-arg'],
                                'env': [{'name': 'DB_PASSWORD', 'value': 'leak-env-value'}, {'name': 'TOKEN', 'valueFrom': {'secretKeyRef': {'name': 'db', 'key': 'token'}}}],
                                'envFrom': [{'secretRef': {'name': 'shop-env'}}],
                                'livenessProbe': {'exec': {'command': ['leak-probe']}},
                                'securityContext': {'runAsNonRoot': True, 'readOnlyRootFilesystem': True}}],
                'volumes': [{'name': 'creds', 'secret': {'secretName': 'db', 'items': [{'key': 'leak-item', 'path': 'p'}]}},
                            {'name': 'data', 'persistentVolumeClaim': {'claimName': 'data'}}]},
       'status': {'phase': 'Running', 'containerStatuses': [{'name': 'api', 'image': 'shop/api:1', 'imageID': 'registry/shop/api@sha256:abc', 'ready': True, 'restartCount': 0,
                                                             'lastState': {'terminated': {'message': 'leak-status'}}}]}}


def fake(pages):
    calls = []
    def get(path):
        calls.append(path)
        for key, value in pages.items():
            if key in path:
                if isinstance(value, Exception):
                    raise value
                return value
        return {'items': []}
    return get, calls


def test_snapshot_keeps_security_settings_and_drops_every_value():
    deployment = {'metadata': {'name': 'api', 'uid': 'd1'}, 'spec': {'replicas': 2, 'template': {'metadata': {'labels': {'app': 'api'}}, 'spec': POD['spec']}}, 'status': {'readyReplicas': 2}}
    get, calls = fake({'/namespaces/production/pods?': {'items': [POD]}, '/namespaces/production/deployments?': {'items': [deployment]},
                       '/version': {'gitVersion': 'v1.28.2', 'platform': 'linux/amd64'}})
    result = snapshot.collect(['production'], get, cluster=False, now=lambda: 100.0)
    text = json.dumps(result)
    for leak in ('leak-env-value', 'leak-command', 'leak-arg', 'leak-annotation', 'leak-manager', 'leak-probe', 'leak-item', 'leak-status'):
        assert leak not in text
    pod = next(i['object'] for i in result['items'] if i['kind'] == 'pods')
    api = pod['spec']['containers'][0]
    assert api['env'] == [{'name': 'DB_PASSWORD', 'value': '(set)'}, {'name': 'TOKEN', 'valueFrom': {'secretKeyRef': {'name': 'db', 'key': 'token'}}}]
    assert api['has_command'] is True and api['probes'] == ['livenessProbe'] and api['securityContext']['runAsNonRoot'] is True
    assert pod['spec']['volumes'] == [{'name': 'creds', 'type': 'secret', 'secretName': 'db'}, {'name': 'data', 'type': 'persistentVolumeClaim', 'claimName': 'data'}]
    assert pod['status']['containerStatuses'][0]['imageID'] == 'registry/shop/api@sha256:abc'
    assert pod['metadata']['annotations'] == {'nginx.ingress.kubernetes.io/ssl-redirect': 'true'}
    template = next(i['object'] for i in result['items'] if i['kind'] == 'deployments')['spec']['template']['spec']
    assert template['containers'][0]['env'][0]['value'] == '(set)'
    assert result['cluster']['gitVersion'] == 'v1.28.2' and result['collected_at'] == 100.0
    assert not any('secrets' in c or 'configmaps' in c for c in calls)
    assert {c['kind'] for c in result['coverage']} == set(snapshot.NAMESPACED)


def test_cluster_read_keeps_only_bindings_that_reach_the_watched_namespaces():
    bindings = {'items': [
        {'metadata': {'name': 'shop-admin'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'api', 'namespace': 'production'}], 'roleRef': {'kind': 'ClusterRole', 'name': 'cluster-admin'}},
        {'metadata': {'name': 'everyone'}, 'subjects': [{'kind': 'Group', 'name': 'system:authenticated'}], 'roleRef': {'kind': 'ClusterRole', 'name': 'viewer'}},
        {'metadata': {'name': 'other-team'}, 'subjects': [{'kind': 'ServiceAccount', 'name': 'x', 'namespace': 'other'}], 'roleRef': {'kind': 'ClusterRole', 'name': 'other-role'}}]}
    roles = {'items': [{'metadata': {'name': n}, 'rules': [{'verbs': ['*']}]} for n in ('cluster-admin', 'viewer', 'other-role', 'unused')]}
    get, _ = fake({'/clusterrolebindings?': bindings, '/clusterroles?': roles, '/api/v1/namespaces/production': {'metadata': {'labels': {'pod-security.kubernetes.io/enforce': 'restricted'}}}})
    result = snapshot.collect(['production'], get, cluster=True)
    names = {(i['kind'], i['object']['metadata']['name']) for i in result['items']}
    assert names == {('clusterrolebindings', 'shop-admin'), ('clusterrolebindings', 'everyone'), ('clusterroles', 'cluster-admin'), ('clusterroles', 'viewer')}
    assert result['namespace_labels'] == {'production': {'pod-security.kubernetes.io/enforce': 'restricted'}}


def test_forbidden_kinds_are_reported_not_hidden():
    get, _ = fake({'/networkpolicies?': HTTPError('u', 403, 'private-message', {}, None), '/version': HTTPError('u', 403, 'x', {}, None)})
    result = snapshot.collect(['production'], get, cluster=False)
    assert next(c for c in result['coverage'] if c['kind'] == 'networkpolicies') == {'namespace': 'production', 'kind': 'networkpolicies', 'complete': False, 'error': 'forbidden'}
    assert result['cluster'] == {'complete': False, 'error': 'forbidden'} and 'private-message' not in json.dumps(result)


def test_oversized_snapshot_drops_pods_first_and_says_so(monkeypatch):
    monkeypatch.setattr(snapshot, 'MAX_BYTES', 6_000)
    pods = {'items': [{**POD, 'metadata': {**POD['metadata'], 'name': f'api-{i}', 'uid': str(i)}} for i in range(40)]}
    services = {'items': [{'metadata': {'name': 'api', 'uid': 's'}, 'spec': {'type': 'ClusterIP', 'ports': [{'port': 80}]}}]}
    get, _ = fake({'/pods?': pods, '/services?': services})
    result = snapshot.collect(['production'], get, cluster=False)
    assert len(json.dumps(result, separators=(',', ':')).encode()) <= 6_000
    assert not any(i['kind'] == 'pods' for i in result['items']) and any(i['kind'] == 'services' for i in result['items'])
    assert next(c for c in result['coverage'] if c['kind'] == 'pods')['error'] == 'limit'


def load(name):
    with open(f'artifacts/{name}.yaml') as stream:
        return [o for o in yaml.safe_load_all(stream) if o]


def test_chart_security_read_is_read_only_and_switchable():
    objects = load('rendered')
    cluster = next(o for o in objects if o['kind'] == 'ClusterRole')
    assert all(rule['verbs'] in (['get', 'list'], ['get']) for rule in cluster['rules'])
    resources = {r for rule in cluster['rules'] for r in rule['resources']}
    assert resources == {'clusterroles', 'clusterrolebindings', 'ingressclasses', 'namespaces'}
    namespaces = next(rule for rule in cluster['rules'] if rule['resources'] == ['namespaces'])
    assert namespaces['verbs'] == ['get'] and namespaces['resourceNames'] == ['production', 'monitoring']
    role = next(o for o in objects if o['kind'] == 'Role')
    granted = {r for rule in role['rules'] for r in rule['resources']}
    assert {'ingresses', 'networkpolicies', 'roles', 'rolebindings', 'serviceaccounts', 'poddisruptionbudgets'} <= granted
    assert not {'secrets', 'configmaps', 'nodes', 'pods/log', 'pods/exec'} & granted
    env = {e['name']: e['value'] for e in next(o for o in objects if o['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]['env'] if 'value' in e}
    assert env['ARGUS_SECURITY_READ'] == 'cluster'
    namespaced = load('security-namespaced')
    assert not any(o['kind'] in ('ClusterRole', 'ClusterRoleBinding') for o in namespaced)
    off = load('security-off')
    assert not any(o['kind'] in ('ClusterRole', 'ClusterRoleBinding') for o in off)
    assert 'ingresses' not in {r for o in off if o['kind'] == 'Role' for rule in o['rules'] for r in rule['resources']}
    assert {e['name']: e.get('value') for e in next(o for o in off if o['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]['env']}['ARGUS_SECURITY_READ'] == 'off'
