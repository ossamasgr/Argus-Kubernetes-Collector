import json
import os
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
    target_revision = monitoring_runtime.configuration(path)['monitoring:one'].target_revision
    now = datetime.now(timezone.utc)
    lease = {'schema_version':1, 'capability':monitoring_runtime.CAPABILITY, 'workspace_id':workspace,
             'collector_id':'kubernetes:' + collector, 'connection_id':'monitoring:one',
             'connection_revision':'a'*64, 'target_revision':target_revision, 'operation_id':operation,
             'lease_id':lease_id, 'operation':'prometheus.rules', 'issued_at':now.isoformat(),
             'expires_at':(now + timedelta(minutes=2)).isoformat()}
    sent = []
    def transfer(url, _token, body, ca=None):
        sent.append((url, body))
        if url.endswith('/monitoring-next'):
            return {'lease':lease}
        return {'status':'accepted'}
    def read(target, operation):
        assert target.host == 'prometheus.internal' and operation == 'prometheus.rules'
        return {'status':'success', 'data':{'groups':[{'rules':[{'type':'alerting', 'name':'PrivateAlert', 'annotations':{'secret':'omit'}}]}]}}
    monkeypatch.setattr(monitoring, 'read', read)
    assert monitoring_runtime.run_once(endpoint, 'token', None, str(path), str(tmp_path), transfer) == 'complete'
    assert sent[0][1]['targets'] == [{'connection_id':'monitoring:one', 'target_revision':target_revision}]
    assert sent[-1][1]['data']['data']['groups'][0]['rules'] == [{'type':'alerting', 'name':'PrivateAlert'}]
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
    path.write_text(json.dumps([target]))
    first = monitoring_runtime.configuration(path)['monitoring:one'].target_revision
    path.write_text(json.dumps([{**target, 'host':'other.internal'}]))
    assert monitoring_runtime.configuration(path)['monitoring:one'].target_revision != first


def test_claim_cleanup_retains_recent_and_nonclaim_files(tmp_path):
    old, recent = tmp_path / str(uuid4()), tmp_path / str(uuid4())
    unrelated = tmp_path / 'operator-file'
    for path in (old, recent, unrelated):
        path.touch()
    os.utime(old, (1, 1))
    os.utime(unrelated, (1, 1))
    monitoring_runtime.clean_old_claims(tmp_path, now=100000)
    assert not old.exists() and recent.exists() and unrelated.exists()
