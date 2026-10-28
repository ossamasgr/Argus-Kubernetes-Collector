import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from collector import monitoring, monitoring_runtime


def test_private_monitoring_runs_only_fixed_approved_target(tmp_path, monkeypatch):
    workspace, collector, operation, lease_id = map(str, (uuid4(), uuid4(), uuid4(), uuid4()))
    collector = collector.replace('-', '')
    endpoint = 'https://argus.example/api/kubernetes-agent/' + workspace + '/' + collector
    config = [{'connection_id':'monitoring:one', 'connection_revision':'a'*64, 'target_revision':'b'*64,
               'host':'prometheus.internal', 'port':443}]
    path = tmp_path / 'targets.json'
    path.write_text(json.dumps(config))
    now = datetime.now(timezone.utc)
    lease = {'schema_version':1, 'capability':monitoring_runtime.CAPABILITY, 'workspace_id':workspace,
             'collector_id':'kubernetes:' + collector, 'connection_id':'monitoring:one',
             'connection_revision':'a'*64, 'target_revision':'b'*64, 'operation_id':operation,
             'lease_id':lease_id, 'operation':'prometheus.rules', 'issued_at':now.isoformat(),
             'expires_at':(now + timedelta(minutes=2)).isoformat()}
    sent = []
    def transfer(url, _token, body, ca=None):
        sent.append((url, body))
        if url.endswith('/monitoring-next'):
            return {'lease':lease}
        return {'status':'accepted'}
    monkeypatch.setattr(monitoring, 'read', lambda target, operation: {'status':'success', 'host':target.host, 'operation':operation})
    assert monitoring_runtime.run_once(endpoint, 'token', None, str(path), str(tmp_path), transfer) == 'complete'
    assert sent[0][1]['targets'] == [{'connection_id':'monitoring:one', 'target_revision':'b'*64}]
    assert sent[-1][1]['data']['host'] == 'prometheus.internal'
    assert (tmp_path / lease_id).exists()
    assert monitoring_runtime.run_once(endpoint, 'token', None, str(path), str(tmp_path), transfer) == 'failed'
    assert sent[-1][1]['data'] == {}


def test_local_configuration_rejects_paths_and_unknown_fields(tmp_path):
    path = tmp_path / 'targets.json'
    target = {'connection_id':'monitoring:one', 'connection_revision':'a'*64, 'target_revision':'b'*64,
              'host':'prometheus.internal', 'port':443}
    path.write_text(json.dumps([{**target, 'url':'http://169.254.169.254'}]))
    with pytest.raises(ValueError, match='invalid_configuration'):
        monitoring_runtime.configuration(path)
    outside = tmp_path / 'outside'
    outside.write_text('not a secret to be read')
    path.write_text(json.dumps([{**target, 'token_file':str(outside)}]))
    with pytest.raises(ValueError, match='invalid_configuration'):
        monitoring_runtime.configuration(path, mount_root=tmp_path / 'secrets')
    path.write_text(json.dumps([target, target]))
    with pytest.raises(ValueError, match='invalid_configuration'):
        monitoring_runtime.configuration(path)
