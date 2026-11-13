import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from collector import metric_profile, monitoring, monitoring_runtime


def test_fixed_queries_and_time_limits():
    path = metric_profile.query_path('minishop-prod', 6000)
    values = parse_qs(urlsplit(path).query)
    assert values['start'] == ['2400'] and values['end'] == ['6000'] and values['step'] == ['60']
    assert values['timeout'] == ['10s'] and 'minishop_http_requests_total' in values['query'][0]
    assert 'kubernetes_namespace="minishop-prod"' in values['query'][0]
    assert 'namespace="minishop-prod"' in values['query'][0]
    for invalid in ('foo"} or up', '*', '', 'production/other'):
        with pytest.raises(ValueError):
            metric_profile.query_path(invalid, 6000)


def test_normalization_preserves_gaps_and_rejects_unbounded_results():
    value = {'status': 'success', 'data': {'resultType': 'matrix', 'result': [
        {'metric': {'argus_metric': 'latency', 'secret': 'omit'}, 'values': [[1, 'NaN'], [2, '10.5']]}]}}
    result = metric_profile.normalize(value)
    assert result['data']['result'][0] == {'metric': {'argus_metric': 'latency'}, 'values': [[1, None], [2, 10.5]]}
    assert metric_profile.normalize(result) == result
    for mutation in ({**value, 'warnings': ['partial']}, {'status': 'success', 'data': {'resultType': 'vector', 'result': []}}):
        with pytest.raises(ValueError):
            metric_profile.normalize(mutation)
    value['data']['result'][0]['values'] = [[i, '1'] for i in range(62)]
    with pytest.raises(ValueError):
        metric_profile.normalize(value)


def test_metrics_lease_is_locally_namespace_scoped(monkeypatch):
    now = datetime.now(timezone.utc)
    lease = dict(schema_version=1, capability=monitoring_runtime.CAPABILITY, workspace_id=str(uuid4()),
                 collector_id='kubernetes:one', connection_id='monitoring:one', connection_revision='a'*64,
                 target_revision='b'*64, operation_id=str(uuid4()), lease_id=str(uuid4()), operation='prometheus.metrics',
                 metrics_namespace='minishop-prod', issued_at=now.isoformat(), expires_at=(now + timedelta(minutes=2)).isoformat())
    registration = monitoring.Registration('a'*64, 'b'*64, monitoring.Target('prometheus.internal', 443))
    args = dict(workspace_id=lease['workspace_id'], collector_id=lease['collector_id'], registrations={'monitoring:one': registration}, claim=lambda _: True)
    with pytest.raises(ValueError, match='namespace_denied'):
        monitoring.execute_lease(lease, **args, allowed_namespaces=['other'])
    called = []
    def read(target, operation, *, metrics_path):
        called.append(metrics_path)
        return {'status': 'success', 'data': {'resultType': 'matrix', 'result': []}}
    monkeypatch.setattr(monitoring, 'read', read)
    assert monitoring.execute_lease(lease, **args, allowed_namespaces=['minishop-prod'])['status'] == 'success'
    assert '/api/v1/query_range?' in called[0]


def test_rules_keep_details_without_arbitrary_labels():
    response = {'status': 'success', 'data': {'groups': [{'name': 'app', 'rules': [
        {'type': 'alerting', 'name': 'MiniShopHighLatency', 'query': 'histogram_quantile(0.95, latency)',
         'duration': 120, 'state': 'inactive', 'labels': {'severity': 'warning', 'secret': 'no'},
         'annotations': {'summary': 'Latency high', 'password': 'no'}}]}]}}
    result = monitoring_runtime.minimize(response, 'prometheus.rules')
    rule = result['data']['groups'][0]['rules'][0]
    assert rule['state'] == 'inactive' and rule['labels'] == {'severity': 'warning'}
    assert rule['query'].startswith('histogram_quantile') and rule['annotations'] == {'summary': 'Latency high'}
    assert 'password' not in json.dumps(result) and 'secret' not in json.dumps(result)
