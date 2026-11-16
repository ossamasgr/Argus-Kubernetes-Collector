"""Argus read-only Kubernetes inventory collector (protocol version 1)."""
import json
import os
import ssl
import socket
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
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


def failure(event, stage, exc):
    """Log allowlisted diagnostics without URLs, credentials or provider response bodies."""
    reason = exc.reason if isinstance(exc, URLError) else exc
    if isinstance(exc, HTTPError):
        error = {401: 'unauthorized', 403: 'forbidden'}.get(exc.code, 'http_error')
    elif isinstance(reason, (TimeoutError, socket.timeout)):
        error = 'timeout'
    elif isinstance(reason, ssl.SSLError):
        error = 'tls_error'
    elif isinstance(reason, socket.gaierror):
        error = 'dns_error'
    elif isinstance(exc, (URLError, OSError)):
        error = 'network_error'
    elif isinstance(exc, (ValueError, KeyError, TypeError)):
        error = 'invalid_response'
    else:
        error = 'unexpected_error'
    record = {'event': event, 'stage': stage, 'error': error}
    if isinstance(exc, HTTPError):
        record['http_status'] = exc.code
    print(json.dumps(record), flush=True)


def resource_page(get, prefix, namespace, resource, query):
    suffix = '/namespaces/' + quote(namespace, safe='') + '/' + resource + '?' + query
    try:
        return get('/' + prefix + suffix)
    except HTTPError as exc:
        # Retry only an absent/removed API. Authorization/network failures stay visible.
        if resource != 'cronjobs' or exc.code not in (404, 410):
            raise
        return get('/apis/batch/v1beta1' + suffix)


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
                    data = resource_page(get, prefix, namespace, resource, urlencode(params))
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
        stage = 'collection'
        try:
            body = collect(namespaces, lambda path: transfer(api + path, (SA / 'token').read_text().strip(), ca=str(SA / 'ca.crt')))
            agent_key = Path('/credentials/agent-key').read_text().strip()
            stage = 'snapshot'
            try:
                transfer(endpoint + '/snapshot', agent_key, body, ca=platform_ca)
            except HTTPError as exc:
                if exc.code != 401:
                    raise
                stage = 'enrollment'
                transfer(endpoint + '/enroll', Path('/credentials/enrollment-key').read_text().strip(), {}, ca=platform_ca)
                stage = 'snapshot'
                transfer(endpoint + '/snapshot', agent_key, body, ca=platform_ca)
            print(json.dumps({'event': 'snapshot_sent', 'items': len(body['items']), 'complete': all(c['complete'] for c in body['coverage'])}), flush=True)
        except Exception as exc:
            failure('collection_or_delivery_failed', stage, exc)
        targets = os.environ.get('ARGUS_MONITORING_TARGETS_FILE')
        if targets:
            try:
                try:
                    from .monitoring_runtime import run_batch
                except ImportError:
                    from monitoring_runtime import run_batch
                results = run_batch(endpoint, Path('/credentials/agent-key').read_text().strip(), platform_ca,
                    targets, os.environ['ARGUS_MONITORING_STATE_DIR'], transfer)
                for result in results:
                    print(json.dumps({'event': 'private_monitoring', 'result': result}), flush=True)
            except Exception as exc:
                failure('private_monitoring_failed', 'private_monitoring', exc)
        time.sleep(max(5, 60 - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
