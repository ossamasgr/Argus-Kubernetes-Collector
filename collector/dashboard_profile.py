"""Bounded namespace-only dashboard compiler, shared with the outbound collector.

The wire carries metric identifiers, never PromQL or endpoints. Keep this file
identical to collector/dashboard_profile.py in Argus-Kubernetes-Collector.
"""
import math
import re
from urllib.parse import urlencode

OPERATION = 'prometheus.dashboard'


def validate(namespace, mode, metrics):
    if not isinstance(namespace, str) or not re.fullmatch(r'[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?', namespace):
        raise ValueError('invalid_namespace')
    if mode not in ('discover', 'query') or not isinstance(metrics, list) or len(metrics) > 8:
        raise ValueError('invalid_dashboard')
    if mode == 'discover' and metrics or mode == 'query' and not metrics:
        raise ValueError('invalid_dashboard')
    for item in metrics:
        if (not isinstance(item, dict) or set(item) != {'name', 'kind'} or
                not isinstance(item['name'], str) or not re.fullmatch(r'[a-zA-Z_:][a-zA-Z0-9_:]{0,127}', item['name']) or
                item['kind'] not in ('counter', 'gauge', 'histogram', 'error_ratio')):
            raise ValueError('invalid_metric')
    if len({(m['name'], m['kind']) for m in metrics}) != len(metrics):
        raise ValueError('duplicate_metric')


def selector(name, namespace, label):
    extra = ',container!="",container!="POD"' if name.startswith('container_') else ',route!~"/healthz|/readyz|/metrics"' if 'http_request' in name else ''
    return f'{name}{{{label}="{namespace}"{extra}}}'


def expression(item, namespace):
    name, kind = item['name'], item['kind']
    selectors = [selector(name, namespace, label) for label in ('namespace', 'kubernetes_namespace')]
    if kind == 'error_ratio':
        if name != 'minishop_http_requests_total':
            raise ValueError('unsupported_error_labels')
        total = expression({'name': name, 'kind': 'counter'}, namespace)
        errors = '(' + ' or '.join(f'rate({s[:-1]},status=~"5.."}}[5m])' for s in selectors) + ')'
        return f'100 * (sum({errors}) or ({total} * 0)) / ({total} > 0)' 
    if kind in ('counter', 'histogram'):
        scoped = '(' + ' or '.join(f'rate({s}[5m])' for s in selectors) + ')'
    else:
        scoped = '(' + ' or '.join(selectors) + ')'
    if kind == 'histogram':
        return f'histogram_quantile(0.95, sum by (le) ({scoped}))'
    if name.startswith('container_'):
        return f'sum(max by (namespace,pod,container) ({scoped}))'
    return f'sum(max by (namespace,deployment) ({scoped}))' if name == 'kube_deployment_status_replicas_available' else f'sum({scoped})'


def query_path(namespace, mode, metrics, end):
    validate(namespace, mode, metrics)
    if mode == 'discover':
        return '/api/v1/query?' + urlencode({'query': f'count by (__name__) ({{namespace="{namespace}"}} or {{kubernetes_namespace="{namespace}"}})', 'timeout': '10s'})
    parts = []
    for index, metric in enumerate(metrics):
        parts.append(f'label_replace(({expression(metric, namespace)}), "argus_metric", "{index}", "", "")')
        raw = '(' + ' or '.join(selector(metric['name'], namespace, label) for label in ('namespace', 'kubernetes_namespace')) + ')'
        parts.append(f'label_replace(max(timestamp({raw})), "argus_metric", "source_{index}", "", "")')
    return '/api/v1/query_range?' + urlencode({'query': ' or '.join(parts), 'start': end - 3600, 'end': end, 'step': 60, 'timeout': '10s'})


def normalize(value, mode, count=8):
    if not isinstance(value, dict) or value.get('status') != 'success' or value.get('warnings'):
        raise ValueError('invalid_response')
    data = value.get('data', {})
    rows = data.get('result')
    if not isinstance(rows, list) or len(rows) > (1000 if mode == 'discover' else count * 2):
        raise ValueError('limit')
    if mode == 'discover':
        if data.get('resultType') != 'vector':
            raise ValueError('invalid_response')
        names = sorted({r.get('metric', {}).get('__name__', '') for r in rows})
        if any(not isinstance(n, str) or not re.fullmatch(r'[a-zA-Z_:][a-zA-Z0-9_:]{0,127}', n) for n in names):
            raise ValueError('invalid_response')
        return {'names': names}
    if data.get('resultType') != 'matrix':
        raise ValueError('invalid_response')
    result, seen = [], set()
    for row in rows:
        key = row.get('metric', {}).get('argus_metric')
        if key not in {str(i) for i in range(count)} | {f'source_{i}' for i in range(count)} or key in seen:
            raise ValueError('invalid_response')
        seen.add(key)
        samples = row.get('values')
        if not isinstance(samples, list) or len(samples) > 61:
            raise ValueError('limit')
        values, previous = [], -1
        for point in samples:
            if (not isinstance(point, list) or len(point) != 2 or type(point[0]) not in (int, float) or
                    not math.isfinite(point[0]) or point[0] <= previous or
                    not isinstance(point[1], (str, int, float)) or isinstance(point[1], bool) or len(str(point[1])) > 40):
                raise ValueError('invalid_response')
            number = float(point[1])
            values.append([point[0], number if math.isfinite(number) else None])
            previous = point[0]
        result.append({'metric': {'argus_metric': key}, 'values': values})
    return {'series': result}
