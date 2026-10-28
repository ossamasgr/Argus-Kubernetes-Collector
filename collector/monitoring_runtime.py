"""Private Prometheus collector runtime, configured only by the cluster operator."""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

try:
    from . import monitoring
except ImportError:  # The release image runs agent.py as a standalone script.
    import monitoring

CAPABILITY = 'monitoring.prometheus.read.v1'


def configuration(path, *, secret_root='/monitoring'):
    """Load operator-owned targets; the platform cannot supply paths or endpoints."""
    value = json.loads(Path(path).read_text())
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError('invalid_configuration')
    registrations = {}
    allowed = {'connection_id', 'connection_revision', 'target_revision', 'host', 'port', 'ca_file', 'token_file'}
    required = {'connection_id', 'connection_revision', 'target_revision', 'host', 'port'}
    root = Path(secret_root).resolve()
    for item in value:
        if not isinstance(item, dict) or not required <= set(item) <= allowed:
            raise ValueError('invalid_configuration')
        connection = item['connection_id']
        if (not isinstance(connection, str) or not re.fullmatch(r'monitoring:[A-Za-z0-9._-]{1,100}', connection) or
                connection in registrations or any(not isinstance(item[key], str) or
                not re.fullmatch(r'[a-f0-9]{64}', item[key]) for key in ('connection_revision', 'target_revision'))):
            raise ValueError('invalid_configuration')
        for key in ('ca_file', 'token_file'):
            if item.get(key):
                try:
                    Path(item[key]).resolve(strict=True).relative_to(root)
                except (ValueError, TypeError, OSError):
                    raise ValueError('invalid_configuration') from None
        target = monitoring.Target(host=item['host'], port=item['port'], ca_file=item.get('ca_file', ''),
                                   token_file=item.get('token_file', ''))
        registrations[connection] = monitoring.Registration(item['connection_revision'], item['target_revision'], target)
    return registrations


def claim_once(directory, lease_id):
    """A persistent cluster-admin-provisioned volume survives process and pod restarts."""
    if str(UUID(lease_id)) != lease_id:
        raise ValueError('invalid_lease')
    path = Path(directory) / lease_id
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    os.close(descriptor)
    return True


def run_once(endpoint, agent_key, platform_ca, targets_file, state_dir, transfer):
    registrations = configuration(targets_file)
    targets = [{'connection_id': key, 'target_revision': value.target_revision} for key, value in registrations.items()]
    transfer(endpoint + '/monitoring-capabilities', agent_key,
             {'version': 1, 'capability': CAPABILITY, 'targets': targets}, ca=platform_ca)
    lease = transfer(endpoint + '/monitoring-next', agent_key, {}, ca=platform_ca).get('lease')
    if lease is None:
        return 'idle'
    # Workspace and collector are bound to the enrolled endpoint, not to the lease body.
    from urllib.parse import urlsplit
    parts = urlsplit(endpoint).path.rstrip('/').split('/')
    if len(parts) < 4 or parts[-3] != 'kubernetes-agent' or not re.fullmatch(r'[a-f0-9]{32}', parts[-1]):
        raise ValueError('invalid_endpoint')
    workspace, collector = parts[-2], 'kubernetes:' + parts[-1]
    try:
        data = monitoring.execute_lease(lease, workspace_id=workspace, collector_id=collector,
            registrations=registrations, claim=lambda key: claim_once(state_dir, key))
        if len(json.dumps(data, allow_nan=False).encode()) > 65_536:
            raise ValueError('limit')
        outcome, error = 'complete', ''
    except (OSError, ValueError, KeyError, TypeError):
        # Never include provider response bodies, local paths or credentials in errors.
        data, outcome, error = {}, 'failed', 'unreachable'
    result = {k:v for k, v in lease.items() if k not in ('issued_at', 'expires_at')}
    result.update(outcome=outcome, error_code=error, data=data, observed_at=datetime.now(timezone.utc).isoformat())
    transfer(endpoint + '/monitoring-result', agent_key, result, ca=platform_ca)
    return outcome
