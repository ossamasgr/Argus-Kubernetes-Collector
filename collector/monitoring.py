"""Collector-side fixed Prometheus reads; not wired into the inventory collector yet.

Targets are provisioned locally by the cluster administrator. Leases never carry
URLs, headers, credentials or arbitrary queries. This module does no authorization
or lease validation; callers must verify those boundaries before invoking it.
"""
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

PATHS = {'prometheus.rules': '/api/v1/rules?type=alert', 'prometheus.alerts': '/api/v1/alerts'}
MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    ca_file: str = ''
    token_file: str = ''


@dataclass(frozen=True)
class Registration:
    """A local, administrator-provisioned target bound to a connection revision."""
    connection_revision: str
    target_revision: str
    target: Target


def execute_lease(lease, *, workspace_id, collector_id, registrations, claim, now=None):
    """Execute a single bound lease after the caller authenticates its issuer.

    The caller must implement an atomic, durable `claim(lease_id)` returning
    false on replay, and manage registrations locally. This is not a transport,
    enrollment protocol, authorization check or persistent lease store.
    """
    required = {'schema_version', 'capability', 'workspace_id', 'collector_id', 'connection_id', 'connection_revision',
                'target_revision', 'operation_id', 'lease_id', 'operation', 'issued_at', 'expires_at'}
    if not isinstance(lease, dict) or set(lease) != required:
        raise ValueError('invalid_lease')
    if (type(lease['schema_version']) is not int or lease['schema_version'] != 1 or
            lease['capability'] != 'monitoring.prometheus.read.v1' or
            not isinstance(lease['operation'], str) or lease['operation'] not in PATHS):
        raise ValueError('invalid_lease')
    if lease['workspace_id'] != workspace_id or lease['collector_id'] != collector_id:
        raise ValueError('invalid_lease')
    try:
        for key in ('workspace_id', 'operation_id', 'lease_id'):
            if str(UUID(lease[key])) != lease[key]:
                raise ValueError
        issued = datetime.fromisoformat(lease['issued_at'].replace('Z', '+00:00'))
        expires = datetime.fromisoformat(lease['expires_at'].replace('Z', '+00:00'))
        current = now or datetime.now(timezone.utc)
        if issued.tzinfo is None or expires.tzinfo is None or current.tzinfo is None:
            raise ValueError
        if not (issued <= current <= expires and timedelta(0) < expires - issued <= timedelta(minutes=5)):
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ValueError('invalid_lease') from None
    if (not isinstance(lease['connection_id'], str) or not 1 <= len(lease['connection_id']) <= 200 or
            any(not isinstance(lease[key], str) or not re.fullmatch(r'[0-9a-f]{64}', lease[key])
                for key in ('connection_revision', 'target_revision'))):
        raise ValueError('invalid_lease')
    registration = registrations.get(lease['connection_id'])
    if (not isinstance(registration, Registration) or
            registration.connection_revision != lease['connection_revision'] or
            registration.target_revision != lease['target_revision']):
        raise ValueError('unregistered_target')
    if not claim(lease['lease_id']):
        raise ValueError('replayed_lease')
    return read(registration.target, lease['operation'])


def addresses(host, port):
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid_target')
    result = []
    for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(row[4][0])
        address = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
        if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or
                address.is_reserved or str(address) in ('100.100.100.200', 'fd00:ec2::254')):
            raise ValueError('forbidden_target')
        if str(address) not in result:
            result.append(str(address))
    if not result:
        raise ValueError('unresolved_target')
    return result


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, context, timeout):
        super().__init__(host, port, timeout=timeout, context=context)
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def read(target: Target, operation: str):
    path = PATHS.get(operation)
    if path is None:
        raise ValueError('unsupported_operation')
    resolved = addresses(target.host, target.port)
    context = ssl.create_default_context(cafile=target.ca_file or None)
    token = Path(target.token_file).read_text().strip() if target.token_file else ''
    if token and (len(token) > 4096 or any(ord(c) < 32 or ord(c) > 126 for c in token)):
        raise ValueError('invalid_credential')
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    conn = PinnedHTTPSConnection(target.host, target.port, resolved[0], context, timeout=10)
    started = time.monotonic()
    try:
        conn.request('GET', path, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError('provider_rejected')
        body = bytearray()
        while True:
            chunk = response.read(min(65536, MAX_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_BYTES or time.monotonic() - started > 15:
                raise ValueError('response_limit')
        def reject_nonfinite(_value):
            raise ValueError('invalid_response')
        result = json.loads(body, parse_constant=reject_nonfinite)
        if not isinstance(result, dict):
            raise ValueError('invalid_response')
        return result
    finally:
        conn.close()
