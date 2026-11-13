"""Private Prometheus collector runtime, configured only by the cluster operator."""
import hashlib
import json
import os
import re
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

try:
    from . import monitoring
except ImportError:  # The release image runs agent.py as a standalone script.
    import monitoring

CAPABILITY = 'monitoring.prometheus.read.v1'


def configuration(path, *, mount_root='/monitoring'):
    """Load operator-owned targets; the platform cannot supply paths or endpoints."""
    value = json.loads(Path(path).read_text())
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError('invalid_configuration')
    registrations = {}
    allowed = {'connection_id', 'connection_revision', 'target_revision', 'host', 'port', 'ca_file', 'token_file', 'base_path'}
    required = {'connection_id', 'connection_revision', 'target_revision', 'host', 'port'}
    root = Path(mount_root).resolve()
    for item in value:
        if not isinstance(item, dict) or not required <= set(item) <= allowed:
            raise ValueError('invalid_configuration')
        connection = item['connection_id']
        if (not isinstance(connection, str) or not re.fullmatch(r'monitoring:[A-Za-z0-9._-]{1,100}', connection) or
                connection in registrations or any(not isinstance(item[key], str) or
                not re.fullmatch(r'[a-f0-9]{64}', item[key]) for key in ('connection_revision', 'target_revision'))):
            raise ValueError('invalid_configuration')
        if (not isinstance(item['host'], str) or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', item['host']) or
                type(item['port']) is not int or not 1 <= item['port'] <= 65535 or
                not isinstance(item.get('base_path', ''), str) or
                len(item.get('base_path', '')) > 512 or
                not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)*', item.get('base_path', ''))):
            raise ValueError('invalid_configuration')
        for key in ('ca_file', 'token_file'):
            if item.get(key):
                try:
                    Path(item[key]).resolve(strict=True).relative_to(root)
                except (ValueError, TypeError, OSError):
                    raise ValueError('invalid_configuration') from None
        ca_bytes = Path(item['ca_file']).read_bytes() if item.get('ca_file') else b''
        if len(ca_bytes) > 64_000:
            raise ValueError('invalid_configuration')
        if ca_bytes:
            if b'PRIVATE KEY' in ca_bytes:
                raise ValueError('invalid_configuration')
            try:
                ssl.create_default_context(cadata=ca_bytes.decode('ascii'))
            except (UnicodeDecodeError, ssl.SSLError):
                raise ValueError('invalid_configuration') from None
        # Target identity changes with local configuration and the public CA.
        # The operator-provided target_revision is a nonce to rotate on token changes;
        # bearer contents are deliberately not hashed or sent to the platform.
        derived = hashlib.sha256(json.dumps({'target': item, 'ca_sha256': hashlib.sha256(ca_bytes).hexdigest()},
            sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        target = monitoring.Target(host=item['host'], port=item['port'], ca_file=item.get('ca_file', ''),
                                   token_file=item.get('token_file', ''), base_path=item.get('base_path', ''))
        registrations[connection] = monitoring.Registration(item['connection_revision'], derived, target)
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


def clean_old_claims(directory, *, now=None):
    """Remove only old UUID claim files, long after the maximum lease lifetime."""
    now = time.time() if now is None else now
    removed = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            try:
                if (str(UUID(entry.name)) == entry.name and entry.is_file(follow_symlinks=False) and
                        now - entry.stat(follow_symlinks=False).st_mtime > 86400):
                    os.unlink(entry.path)
                    removed += 1
                    if removed == 100:
                        break
            except (ValueError, FileNotFoundError):
                continue


def bounded_result(value):
    if len(json.dumps(value, allow_nan=False).encode()) > 65_536:
        raise ValueError('limit')
    def visit(item, depth=0):
        if depth > 16:
            raise ValueError('limit')
        for child in item.values() if isinstance(item, dict) else item if isinstance(item, list) else ():
            visit(child, depth + 1)
    visit(value)


def minimize(value, operation):
    """Send only fields needed by the fixed platform adapters, without annotations."""
    if not isinstance(value, dict) or value.get('status') != 'success' or value.get('warnings'):
        raise ValueError('invalid_response')
    data = value.get('data')
    if not isinstance(data, dict):
        raise ValueError('invalid_response')
    if operation == 'prometheus.rules':
        groups = data.get('groups')
        if not isinstance(groups, list):
            raise ValueError('invalid_response')
        rules = []
        result_groups = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('rules'), list):
                raise ValueError('invalid_response')
            for rule in group['rules']:
                if not isinstance(rule, dict) or rule.get('type') != 'alerting' or not isinstance(rule.get('name'), str):
                    raise ValueError('invalid_response')
                labels = rule.get('labels') if isinstance(rule.get('labels'), dict) else {}
                annotations = rule.get('annotations') if isinstance(rule.get('annotations'), dict) else {}
                # Keep only bounded alerting fields consumed by Argus; drop arbitrary labels/annotations.
                detail = {'type': 'alerting', 'name': rule['name']}
                for key, size in (('query', 500), ('state', 20)):
                    if isinstance(rule.get(key), str):
                        detail[key] = rule[key][:size]
                if type(rule.get('duration')) in (int, float) and 0 <= rule['duration'] <= 31536000:
                    detail['duration'] = rule['duration']
                if isinstance(labels.get('severity'), str):
                    detail['labels'] = {'severity': labels['severity'][:40]}
                summary = annotations.get('summary')
                if isinstance(summary, str):
                    detail['annotations'] = {'summary': summary[:300]}
                rules.append(detail)
                if len(rules) > 500:
                    raise ValueError('limit')
            result_groups.append({'name': str(group.get('name', ''))[:120], 'rules': rules[:]})
            rules = []
        # Detailed cluster listings are larger than a lease; bound them explicitly.
        if sum(len(g['rules']) for g in result_groups) > 500:
            raise ValueError('limit')
        result = {'status': 'success', 'data': {'groups': result_groups}}
        # Preserve every name/state/severity. Trim the largest narrative fields if needed
        # to remain inside the existing 64 KiB wire budget.
        candidates = [r for g in result_groups for r in g['rules']]
        candidates.sort(key=lambda r: len(json.dumps(r)), reverse=True)
        for field in ('annotations', 'query'):
            for rule in candidates:
                if len(json.dumps(result, allow_nan=False).encode()) <= 64_000:
                    return result
                rule.pop(field, None)
        return result
    if operation == 'prometheus.metrics':
        try:
            from .metric_profile import normalize
        except ImportError:
            from metric_profile import normalize
        return normalize(value)
    if operation == 'prometheus.alerts':
        alerts = data.get('alerts')
        if not isinstance(alerts, list) or len(alerts) > 500:
            raise ValueError('limit')
        result = []
        for alert in alerts:
            if (not isinstance(alert, dict) or not isinstance(alert.get('labels'), dict) or
                    alert.get('state') not in ('pending', 'firing') or not isinstance(alert.get('activeAt'), str)):
                raise ValueError('invalid_response')
            result.append({'state': alert['state'], 'activeAt': alert['activeAt'], 'labels': alert['labels']})
        return {'status': 'success', 'data': {'alerts': result}}
    raise ValueError('unsupported_operation')


def run_once(endpoint, agent_key, platform_ca, targets_file, state_dir, transfer, *, advertise=True):
    registrations = configuration(targets_file)
    clean_old_claims(state_dir)
    targets = [{'connection_id': key, 'target_revision': value.target_revision, 'host': value.target.host,
                'port': value.target.port, 'base_path': value.target.base_path} for key, value in registrations.items()]
    if advertise:
        transfer(endpoint + '/monitoring-capabilities', agent_key,
                 {'version': 1, 'capability': CAPABILITY, 'targets': targets,
                  'operations': ['prometheus.rules', 'prometheus.alerts', 'prometheus.metrics']}, ca=platform_ca)
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
            registrations=registrations, claim=lambda key: claim_once(state_dir, key),
            allowed_namespaces=json.loads(os.environ.get('ARGUS_NAMESPACES', '[]')))
        data = minimize(data, lease['operation'])
        bounded_result(data)
        outcome, error = 'complete', ''
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Never include provider response bodies, local paths or credentials in errors.
        data, outcome, error = {}, 'failed', 'limit' if str(exc) == 'limit' else 'unreachable'
    result = {k:v for k, v in lease.items() if k not in ('issued_at', 'expires_at')}
    result.update(outcome=outcome, error_code=error, data=data, observed_at=datetime.now(timezone.utc).isoformat())
    transfer(endpoint + '/monitoring-result', agent_key, result, ca=platform_ca)
    return outcome


def run_batch(endpoint, agent_key, platform_ca, targets_file, state_dir, transfer):
    """Drain bounded work without starving metrics behind existing alert watches.

    Advertise once per inventory cycle; repeated advertisements would hit the
    platform's 15-second rate limit. Each read keeps its own lease and replay claim.
    """
    deadline = time.monotonic() + 45
    results = []
    for index in range(10):
        if index and time.monotonic() >= deadline:
            break
        result = run_once(endpoint, agent_key, platform_ca, targets_file, state_dir, transfer, advertise=index == 0)
        results.append(result)
        if result == 'idle':
            break
    return results
