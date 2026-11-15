from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from collector import dashboard_profile as profile, monitoring


def test_catalog_is_namespace_scoped_and_queries_are_bounded():
    path = profile.query_path('shop-prod', 'discover', [], 1800000000)
    assert 'count by (__name__)' in parse_qs(urlsplit(path).query)['query'][0]
    path = profile.query_path('shop-prod', 'query', [{'name': 'orders_total', 'kind': 'counter'}], 1800000000)
    params = parse_qs(urlsplit(path).query)
    assert params['step'] == ['60'] and params['start'] == ['1799996400']
    for name in ('orders_total{} or up', 'up{namespace="other"}', 'up&query=up'):
        with pytest.raises(ValueError):
            profile.query_path('shop-prod', 'query', [{'name': name, 'kind': 'gauge'}], 1800000000)


def test_dashboard_lease_keeps_local_namespace_and_replay_boundary(monkeypatch):
    at = datetime.now(timezone.utc)
    lease = dict(schema_version=1, capability='monitoring.prometheus.read.v1', workspace_id=str(uuid4()),
        collector_id='kubernetes:one', connection_id='monitoring:one', connection_revision='a'*64, target_revision='b'*64,
        operation_id=str(uuid4()), lease_id=str(uuid4()), operation='prometheus.dashboard', metrics_namespace='shop-prod',
        dashboard_mode='query', dashboard_metrics=[{'name': 'orders_total', 'kind': 'counter'}],
        issued_at=at.isoformat(), expires_at=(at+timedelta(minutes=2)).isoformat())
    target = monitoring.Registration('a'*64, 'b'*64, monitoring.Target('prometheus.internal', 443))
    args = dict(workspace_id=lease['workspace_id'], collector_id=lease['collector_id'], registrations={'monitoring:one': target})
    calls = []
    monkeypatch.setattr(monitoring, 'read', lambda *a, **kw: calls.append(kw['metrics_path']) or {'status': 'success'})
    with pytest.raises(ValueError, match='namespace_denied'):
        monitoring.execute_lease(lease, **args, claim=lambda _: True, allowed_namespaces=['other'])
    with pytest.raises(ValueError, match='replayed_lease'):
        monitoring.execute_lease(lease, **args, claim=lambda _: False, allowed_namespaces=['shop-prod'])
    assert not calls
    assert monitoring.execute_lease(lease, **args, claim=lambda _: True, allowed_namespaces=['shop-prod']) == {'status': 'success'}
    assert 'query_range' in calls[0]
