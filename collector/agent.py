"""Argus read-only Kubernetes inventory collector (protocol version 1)."""
import json
import os
import ssl
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, quote, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler

RESOURCES = {
    'pods': ('api/v1', 'pods'), 'services': ('api/v1', 'services'),
    'persistentvolumeclaims': ('api/v1', 'persistentvolumeclaims'), 'events': ('api/v1', 'events'),
    'deployments': ('apis/apps/v1', 'deployments'), 'statefulsets': ('apis/apps/v1', 'statefulsets'),
    'daemonsets': ('apis/apps/v1', 'daemonsets'), 'jobs': ('apis/batch/v1', 'jobs'),
    'cronjobs': ('apis/batch/v1', 'cronjobs'),
}
SA = Path('/var/run/secrets/kubernetes.io/serviceaccount')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def transfer(url, token, body=None, ca=None):
    if urlsplit(url).scheme != 'https':
        raise ValueError('HTTPS is required')
    # An explicitly configured CA defines platform trust; do not accept an unrelated public-site certificate.
    context = ssl.create_default_context(cafile=ca)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    request = Request(url, data=json.dumps(body).encode() if body is not None else None,  # noqa: S310 -- HTTPS scheme validated above
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'})
    # Fixed trusted origins come from the installer or in-cluster API endpoint; redirects are refused.
    with opener.open(request, timeout=15) as response:  # noqa: S310
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('response_limit')
        return json.loads(raw)


def summarize(item, namespace, kind):
    metadata, status = item.get('metadata', {}), item.get('status', {})
    result = {'namespace': namespace, 'kind': kind, 'name': metadata['name'], 'uid': metadata['uid']}
    # Never forward pod specs, environment values, annotations, labels, event messages or volume details.
    if kind == 'pods':
        containers = status.get('containerStatuses', [])
        result.update(phase=status.get('phase', 'Unknown'), ready=sum(c.get('ready') is True for c in containers),
            desired=len(item.get('spec', {}).get('containers', [])), restarts=sum(c.get('restartCount', 0) for c in containers))
    elif kind in ('deployments', 'statefulsets'):
        result.update(ready=status.get('readyReplicas', 0), desired=item.get('spec', {}).get('replicas', 1))
    elif kind == 'daemonsets':
        result.update(ready=status.get('numberReady', 0), desired=status.get('desiredNumberScheduled', 0))
    elif kind == 'jobs':
        result.update(ready=status.get('succeeded', 0), failed=status.get('failed', 0), desired=item.get('spec', {}).get('completions', 1) or 1)
    elif kind == 'persistentvolumeclaims':
        result['phase'] = status.get('phase', 'Unknown')
    elif kind == 'events':
        result['phase'] = 'Warning' if item.get('type') == 'Warning' else 'Normal'
    return result


def collect(namespaces, get):
    items, coverage = [], []
    deadline = time.monotonic() + 45
    for namespace in namespaces:
        for kind, (prefix, resource) in RESOURCES.items():
            cursor, complete, error = '', False, ''
            try:
                for _ in range(20):
                    if time.monotonic() >= deadline:
                        error = 'unavailable'
                        break
                    if len(items) >= 500:
                        error = 'limit'
                        break
                    params = {'limit': min(50, 500 - len(items))}
                    if cursor:
                        params['continue'] = cursor
                    data = get('/' + prefix + '/namespaces/' + quote(namespace, safe='') + '/' + resource + '?' + urlencode(params))
                    batch = data['items']
                    if not isinstance(batch, list) or len(batch) > params['limit']:
                        raise ValueError('invalid_response')
                    items.extend(summarize(item, namespace, kind) for item in batch)
                    cursor = data.get('metadata', {}).get('continue', '')
                    if not cursor:
                        complete = True
                        break
                if not complete and not error:
                    error = 'limit'
            except HTTPError as exc:
                error = 'forbidden' if exc.code in (401, 403) else 'unavailable'
            except (OSError, ValueError, KeyError, TypeError):
                error = 'unavailable'
            coverage.append({'namespace': namespace, 'kind': kind, 'complete': complete, 'error': error})
    result = {'version': 1, 'collected_at': time.time(), 'items': items, 'coverage': coverage}
    while len(json.dumps(result).encode()) > 220_000 and items:
        removed = items.pop()
        for entry in coverage:
            if entry['namespace'] == removed['namespace'] and entry['kind'] == removed['kind']:
                entry.update(complete=False, error='limit')
    return result


def main():
    endpoint = os.environ['ARGUS_ENDPOINT'].rstrip('/')
    namespaces = json.loads(os.environ['ARGUS_NAMESPACES'])
    platform_ca = os.environ.get('ARGUS_CA_FILE')
    api = 'https://kubernetes.default.svc'
    while True:
        started = time.monotonic()
        try:
            body = collect(namespaces, lambda path: transfer(api + path, (SA / 'token').read_text().strip(), ca=str(SA / 'ca.crt')))
            agent_key = Path('/credentials/agent-key').read_text().strip()
            try:
                transfer(endpoint + '/snapshot', agent_key, body, ca=platform_ca)
            except HTTPError as exc:
                if exc.code != 401:
                    raise
                transfer(endpoint + '/enroll', Path('/credentials/enrollment-key').read_text().strip(), {}, ca=platform_ca)
                transfer(endpoint + '/snapshot', agent_key, body, ca=platform_ca)
            print(json.dumps({'event': 'snapshot_sent', 'items': len(body['items']), 'complete': all(c['complete'] for c in body['coverage'])}), flush=True)
        except Exception:
            # Provider responses and bearer credentials never enter logs.
            print('{"event":"collection_or_delivery_failed"}', flush=True)
        targets = os.environ.get('ARGUS_MONITORING_TARGETS_FILE')
        if targets:
            try:
                try:
                    from .monitoring_runtime import run_once
                except ImportError:
                    from monitoring_runtime import run_once
                result = run_once(endpoint, Path('/credentials/agent-key').read_text().strip(), platform_ca,
                    targets, os.environ['ARGUS_MONITORING_STATE_DIR'], transfer)
                print(json.dumps({'event': 'private_monitoring', 'result': result}), flush=True)
            except Exception:
                print('{"event":"private_monitoring_failed"}', flush=True)
        time.sleep(max(5, 60 - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
