"""Read-only security view of the watched namespaces (security snapshot protocol version 1).

Argus security reviews need the settings that decide exposure, privileges and hardening: who can do what,
what is reachable, and how each workload runs. Only those settings leave the cluster. Secret and ConfigMap
objects are never requested. Environment values, commands, arguments, probes' contents, annotations outside a
short allowlist and server bookkeeping are removed here, before anything is sent.
"""
import json
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode

VERSION = 1
INTERVAL = 600
MAX_BYTES = 2_000_000
PAGE = 100
NAMESPACED = {
    'deployments': 'apis/apps/v1', 'statefulsets': 'apis/apps/v1', 'daemonsets': 'apis/apps/v1',
    'cronjobs': 'apis/batch/v1', 'jobs': 'apis/batch/v1', 'pods': 'api/v1', 'services': 'api/v1',
    'serviceaccounts': 'api/v1', 'persistentvolumeclaims': 'api/v1', 'resourcequotas': 'api/v1', 'limitranges': 'api/v1',
    'ingresses': 'apis/networking.k8s.io/v1', 'networkpolicies': 'apis/networking.k8s.io/v1',
    'roles': 'apis/rbac.authorization.k8s.io/v1', 'rolebindings': 'apis/rbac.authorization.k8s.io/v1',
    'poddisruptionbudgets': 'apis/policy/v1',
}
CLUSTER = {'clusterroles': 'apis/rbac.authorization.k8s.io/v1', 'clusterrolebindings': 'apis/rbac.authorization.k8s.io/v1',
           'ingressclasses': 'apis/networking.k8s.io/v1'}
# Pods repeat their controller's template, so they are the first to go when a snapshot is too large.
DROP_ORDER = ('pods', 'jobs', 'persistentvolumeclaims', 'poddisruptionbudgets', 'limitranges', 'resourcequotas')
ANNOTATIONS = ('kubernetes.io/ingress.class', 'nginx.ingress.kubernetes.io/', 'traefik.ingress.kubernetes.io/', 'cert-manager.io/',
               'seccomp.security.alpha.kubernetes.io/', 'container.apparmor.security.beta.kubernetes.io/', 'pod-security.kubernetes.io/',
               'ingress.kubernetes.io/', 'alb.ingress.kubernetes.io/')
BROAD_GROUPS = {'system:authenticated', 'system:unauthenticated', 'system:serviceaccounts'}


def pick(value, keys):
    return {key: value[key] for key in keys if isinstance(value, dict) and key in value}


def metadata(item):
    meta = item.get('metadata') or {}
    result = pick(meta, ('name', 'namespace', 'uid', 'labels', 'creationTimestamp', 'generation'))
    notes = {k: str(v)[:500] for k, v in (meta.get('annotations') or {}).items() if k.startswith(ANNOTATIONS)}
    if notes:
        result['annotations'] = notes
    owners = [pick(o, ('kind', 'name')) for o in meta.get('ownerReferences') or []]
    if owners:
        result['ownerReferences'] = owners
    return result


def reference(value):
    """Keep which Secret or ConfigMap a setting points at, never what it contains."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in ('secretKeyRef', 'configMapKeyRef'):
        if key in value:
            result[key] = pick(value[key], ('name', 'key', 'optional'))
    for key in ('fieldRef', 'resourceFieldRef'):
        if key in value:
            result[key] = pick(value[key], ('fieldPath', 'resource'))
    return result


def container(value):
    result = pick(value, ('name', 'image', 'imagePullPolicy', 'ports', 'securityContext', 'resources'))
    env = []
    for item in value.get('env') or []:
        entry = {'name': item.get('name', '')}
        if 'value' in item:
            entry['value'] = '(set)'
        if 'valueFrom' in item:
            entry['valueFrom'] = reference(item['valueFrom'])
        env.append(entry)
    if env:
        result['env'] = env
    sources = [{key: pick(item[key], ('name', 'optional')) for key in ('secretRef', 'configMapRef') if key in item} for item in value.get('envFrom') or []]
    if sources:
        result['envFrom'] = sources
    mounts = [pick(m, ('name', 'mountPath', 'readOnly', 'subPath')) for m in value.get('volumeMounts') or []]
    if mounts:
        result['volumeMounts'] = mounts
    result['probes'] = sorted(key for key in ('livenessProbe', 'readinessProbe', 'startupProbe') if value.get(key))
    result['has_command'] = bool(value.get('command') or value.get('args'))
    return result


def volume(value):
    kinds = [key for key in value if key != 'name']
    result = {'name': value.get('name', ''), 'type': kinds[0] if kinds else ''}
    source = value.get(result['type']) or {}
    detail = {'secret': ('secretName', 'optional'), 'configMap': ('name', 'optional'), 'persistentVolumeClaim': ('claimName', 'readOnly'),
              'hostPath': ('path', 'type'), 'emptyDir': ('medium', 'sizeLimit')}.get(result['type'])
    if detail:
        result.update(pick(source, detail))
    if result['type'] == 'projected':
        result['sources'] = sorted({key for s in source.get('sources') or [] for key in s})
    return result


def pod_spec(spec):
    result = pick(spec, ('serviceAccountName', 'automountServiceAccountToken', 'hostNetwork', 'hostPID', 'hostIPC', 'securityContext',
                         'shareProcessNamespace', 'enableServiceLinks', 'runtimeClassName', 'priorityClassName', 'nodeSelector', 'restartPolicy'))
    for key in ('containers', 'initContainers', 'ephemeralContainers'):
        if spec.get(key):
            result[key] = [container(c) for c in spec[key]]
    if spec.get('volumes'):
        result['volumes'] = [volume(v) for v in spec['volumes']]
    if spec.get('imagePullSecrets'):
        result['imagePullSecrets'] = [pick(s, ('name',)) for s in spec['imagePullSecrets']]
    return result


def template(value):
    return {'metadata': pick(metadata(value), ('labels', 'annotations')), 'spec': pod_spec((value or {}).get('spec') or {})}


def clean(kind, item):
    spec, status = item.get('spec') or {}, item.get('status') or {}
    result = {'metadata': metadata(item)}
    if kind in ('deployments', 'statefulsets', 'daemonsets'):
        result['spec'] = {**pick(spec, ('replicas', 'selector', 'strategy', 'updateStrategy', 'serviceName')), 'template': template(spec.get('template'))}
        result['status'] = pick(status, ('replicas', 'readyReplicas', 'availableReplicas', 'updatedReplicas', 'numberReady', 'desiredNumberScheduled'))
    elif kind == 'cronjobs':
        job = (spec.get('jobTemplate') or {}).get('spec') or {}
        result['spec'] = {**pick(spec, ('schedule', 'suspend', 'concurrencyPolicy')), 'jobTemplate': {'spec': {'template': template(job.get('template'))}}}
    elif kind == 'jobs':
        result['spec'] = {'template': template(spec.get('template'))}
        result['status'] = pick(status, ('succeeded', 'failed', 'active'))
    elif kind == 'pods':
        result['spec'] = pod_spec(spec)
        result['status'] = {**pick(status, ('phase', 'qosClass')), 'containerStatuses': [pick(c, ('name', 'image', 'imageID', 'ready', 'restartCount')) for c in status.get('containerStatuses') or []]}
    elif kind == 'services':
        result['spec'] = pick(spec, ('type', 'ports', 'selector', 'clusterIP', 'externalIPs', 'externalName', 'loadBalancerSourceRanges', 'externalTrafficPolicy', 'sessionAffinity'))
        result['status'] = pick(status, ('loadBalancer',))
    elif kind == 'ingresses':
        result['spec'] = pick(spec, ('ingressClassName', 'rules', 'tls', 'defaultBackend'))
        result['status'] = pick(status, ('loadBalancer',))
    elif kind in ('networkpolicies', 'limitranges', 'ingressclasses'):
        result['spec'] = spec
    elif kind == 'serviceaccounts':
        result.update(pick(item, ('automountServiceAccountToken',)))
        result['secrets'] = len(item.get('secrets') or [])
        result['imagePullSecrets'] = [pick(s, ('name',)) for s in item.get('imagePullSecrets') or []]
    elif kind in ('roles', 'clusterroles'):
        result.update(pick(item, ('rules', 'aggregationRule')))
    elif kind in ('rolebindings', 'clusterrolebindings'):
        result.update(pick(item, ('subjects', 'roleRef')))
    elif kind == 'persistentvolumeclaims':
        result['spec'] = pick(spec, ('storageClassName', 'accessModes', 'resources', 'volumeMode'))
        result['status'] = pick(status, ('phase',))
    elif kind == 'poddisruptionbudgets':
        result['spec'] = pick(spec, ('minAvailable', 'maxUnavailable', 'selector'))
        result['status'] = pick(status, ('currentHealthy', 'desiredHealthy', 'disruptionsAllowed'))
    elif kind == 'resourcequotas':
        result['spec'] = pick(spec, ('hard', 'scopes'))
        result['status'] = pick(status, ('used',))
    return result


def listing(get, path, deadline):
    items, cursor = [], ''
    for _ in range(20):
        if time.monotonic() >= deadline:
            return items, 'unavailable'
        query = {'limit': PAGE, **({'continue': cursor} if cursor else {})}
        data = get(path + '?' + urlencode(query))
        batch = data['items']
        if not isinstance(batch, list) or len(batch) > PAGE:
            raise ValueError('invalid_response')
        items.extend(batch)
        cursor = (data.get('metadata') or {}).get('continue', '')
        if not cursor:
            return items, ''
    return items, 'limit'


def read(get, path, deadline):
    try:
        return listing(get, path, deadline)
    except HTTPError as exc:
        return [], 'forbidden' if exc.code in (401, 403) else 'unavailable'
    except (OSError, ValueError, KeyError, TypeError):
        return [], 'unavailable'


def concerns(binding, namespaces):
    """A cluster-wide binding matters when it gives powers to the watched namespaces' identities or to everyone."""
    for subject in binding.get('subjects') or []:
        if subject.get('kind') == 'ServiceAccount' and subject.get('namespace') in namespaces:
            return True
        if subject.get('kind') == 'Group' and (subject.get('name') in BROAD_GROUPS or subject.get('name', '').removeprefix('system:serviceaccounts:') in namespaces):
            return True
    return False


def collect(namespaces, get, cluster=True, now=time.time):
    deadline = time.monotonic() + 90
    items, coverage, labels = [], [], {}
    for namespace in namespaces:
        for kind, prefix in NAMESPACED.items():
            found, error = read(get, '/' + prefix + '/namespaces/' + quote(namespace, safe='') + '/' + kind, deadline)
            items.extend({'kind': kind, 'namespace': namespace, 'object': clean(kind, item)} for item in found)
            coverage.append({'namespace': namespace, 'kind': kind, 'complete': not error, 'error': error})
    info = {'complete': False, 'error': 'not_enabled'}
    if cluster:
        for namespace in namespaces:
            try:
                labels[namespace] = (get('/api/v1/namespaces/' + quote(namespace, safe='')).get('metadata') or {}).get('labels') or {}
                coverage.append({'namespace': namespace, 'kind': 'namespaces', 'complete': True, 'error': ''})
            except HTTPError as exc:
                coverage.append({'namespace': namespace, 'kind': 'namespaces', 'complete': False, 'error': 'forbidden' if exc.code in (401, 403) else 'unavailable'})
            except (OSError, ValueError, KeyError, TypeError):
                coverage.append({'namespace': namespace, 'kind': 'namespaces', 'complete': False, 'error': 'unavailable'})
        bindings, error = read(get, '/' + CLUSTER['clusterrolebindings'] + '/clusterrolebindings', deadline)
        bindings = [b for b in bindings if concerns(b, namespaces)]
        coverage.append({'namespace': '', 'kind': 'clusterrolebindings', 'complete': not error, 'error': error})
        wanted = {b.get('roleRef', {}).get('name') for b in bindings} | {i['object'].get('roleRef', {}).get('name') for i in items
                  if i['kind'] == 'rolebindings' and i['object'].get('roleRef', {}).get('kind') == 'ClusterRole'}
        roles, role_error = read(get, '/' + CLUSTER['clusterroles'] + '/clusterroles', deadline)
        coverage.append({'namespace': '', 'kind': 'clusterroles', 'complete': not role_error, 'error': role_error})
        classes, class_error = read(get, '/' + CLUSTER['ingressclasses'] + '/ingressclasses', deadline)
        coverage.append({'namespace': '', 'kind': 'ingressclasses', 'complete': not class_error, 'error': class_error})
        items.extend({'kind': 'clusterrolebindings', 'namespace': '', 'object': clean('clusterrolebindings', b)} for b in bindings)
        items.extend({'kind': 'clusterroles', 'namespace': '', 'object': clean('clusterroles', r)} for r in roles if (r.get('metadata') or {}).get('name') in wanted)
        items.extend({'kind': 'ingressclasses', 'namespace': '', 'object': clean('ingressclasses', c)} for c in classes)
    try:
        version = get('/version')
        info = {**pick(version, ('gitVersion', 'major', 'minor', 'platform')), 'complete': True, 'error': ''}
    except HTTPError as exc:
        info = {'complete': False, 'error': 'forbidden' if exc.code in (401, 403) else 'unavailable'}
    except (OSError, ValueError, KeyError, TypeError):
        info = {'complete': False, 'error': 'unavailable'}
    result = {'version': VERSION, 'collected_at': now(), 'cluster': info, 'namespace_labels': labels, 'items': items, 'coverage': coverage}
    return bounded(result)


def bounded(result):
    """Stay under the platform's size limit by dropping whole kinds, least useful first, and saying so."""
    def size():
        return len(json.dumps(result, separators=(',', ':')).encode())
    for kind in DROP_ORDER:
        if size() <= MAX_BYTES:
            break
        result['items'] = [i for i in result['items'] if i['kind'] != kind]
        for entry in result['coverage']:
            if entry['kind'] == kind:
                entry.update(complete=False, error='limit')
    while size() > MAX_BYTES and result['items']:
        removed = result['items'].pop()
        for entry in result['coverage']:
            if entry['kind'] == removed['kind'] and entry['namespace'] == removed['namespace']:
                entry.update(complete=False, error='limit')
    return result
