"""Fixed namespace-scoped one-hour Prometheus dashboard profile (no arbitrary PromQL)."""
import math
import re
from urllib.parse import urlencode

KEYS = ('requests', 'errors', 'latency', 'orders', 'cpu', 'memory', 'replicas', 'targets')


def expressions(namespace):
    if not isinstance(namespace, str) or not re.fullmatch(r'[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?', namespace):
        raise ValueError('invalid_namespace')
    def app(metric, labels=''):
        return '(' + ' or '.join(f'{metric}{{{key}="{namespace}"{labels}}}' for key in ('namespace', 'kubernetes_namespace')) + ')'
    def rate(metric, labels=''):
        # Counter functions apply to each original series before aggregation.
        selectors = [f'rate({metric}{{{key}="{namespace}"{labels}}}[5m])' for key in ('namespace', 'kubernetes_namespace')]
        return '(' + ' or '.join(selectors) + ')'
    routes = ',route!~"/healthz|/readyz|/metrics"'
    requests = f'sum({rate("minishop_http_requests_total", routes)})'
    errors = f'sum({rate("minishop_http_requests_total", routes + ",status=~\"5..\"")})'
    # A zero error numerator is valid only where a request counter exists.
    errors = f'100 * ({errors} or ({requests} * 0)) / ({requests} > 0)'
    ns = f'namespace="{namespace}"'
    return {
        'requests': requests,
        'errors': errors,
        'latency': f'histogram_quantile(0.95, sum by (le) ({rate("minishop_http_request_duration_seconds_bucket", routes)})) * 1000',
        'orders': f'sum({rate("minishop_orders_total")}) * 60',
        'cpu': f'sum(max by (namespace,pod,container) (rate(container_cpu_usage_seconds_total{{{ns},container="app",pod=~"minishop-app-.*"}}[5m])))',
        'memory': f'sum(max by (namespace,pod,container) (container_memory_working_set_bytes{{{ns},container="app",pod=~"minishop-app-.*"}})) / 1048576',
        'replicas': f'max(kube_deployment_status_replicas_available{{{ns},deployment="minishop-app"}})',
        'targets': f'sum({app("up", ",job=~\".*minishop.*\"")})',
    }


def query_path(namespace, end):
    query = ' or '.join(f'label_replace(({expr}), "argus_metric", "{key}", "", "")' for key, expr in expressions(namespace).items())
    return '/api/v1/query_range?' + urlencode({'query': query, 'start': end - 3600, 'end': end, 'step': 60, 'timeout': '10s'})


def normalize(response):
    if not isinstance(response, dict) or response.get('status') != 'success' or response.get('warnings'):
        raise ValueError('invalid_response')
    data = response.get('data', {})
    if data.get('resultType') != 'matrix' or not isinstance(data.get('result'), list) or len(data['result']) > len(KEYS):
        raise ValueError('invalid_response')
    result, seen = [], set()
    for series in data['result']:
        key = series.get('metric', {}).get('argus_metric')
        samples = series.get('values')
        if key not in KEYS or key in seen or not isinstance(samples, list) or len(samples) > 61:
            raise ValueError('invalid_response')
        seen.add(key)
        values, previous = [], -1
        for sample in samples:
            if not isinstance(sample, list) or len(sample) != 2 or type(sample[0]) not in (int, float):
                raise ValueError('invalid_response')
            timestamp = sample[0]
            if not math.isfinite(timestamp) or timestamp <= previous:
                raise ValueError('invalid_response')
            if sample[1] is not None and (type(sample[1]) not in (int, float, str) or isinstance(sample[1], str) and len(sample[1]) > 40):
                raise ValueError('invalid_response')
            number = float(sample[1]) if sample[1] is not None else float('nan')
            values.append([timestamp, number if math.isfinite(number) else None])
            previous = timestamp
        result.append({'metric': {'argus_metric': key}, 'values': values})
    return {'status': 'success', 'data': {'resultType': 'matrix', 'result': result}}
