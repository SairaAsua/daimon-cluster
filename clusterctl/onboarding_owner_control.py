"""Short owner-local controls after a qualified all-reader observation round.

This maintenance client does not select or relabel the loaded runtime. The
coordinator still owns current all-required adoption, admission and roster proof.
Its absolute deadline bounds this invocation; the native service owns the CAS.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import being_seed
from .onboarding import OnboardingError, digest
from .onboarding_receiving_update import OwnerGroupClient
from .owner_process import ParentProcessPresence

PUBLIC_ERRORS = frozenset({
    'receiving_owner_deadline_expired', 'receiving_owner_deadline_binding_required',
    'receiving_control_process_changed', 'receiving_control_parent_changed',
    'receiving_control_binding_conflict', 'receiving_control_fresh_request_expired',
    'receiving_owner_scope_required', 'receiving_control_not_accepted',
    'receiving_control_completion_uncertain', 'receiving_group_socket_changed',
    'invalid_receiving_control_request', 'daemon_response_truncated',
    'daemon_deadline_expired', 'daemon_timeout',
})


def _accept(deadline_ns: int) -> None:
    if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
        raise OnboardingError('receiving_owner_deadline_expired')


def _selection(observed: dict[str, Any]) -> dict[str, Any]:
    runtime = observed['runtime_status']['loaded_runtime']
    application = observed['runtime_status']['loaded_application']
    return dict(receiving_code=runtime['qualified_startup']['code_digest'],
        matrix_sdk=runtime['qualified_startup']['matrix_wheel_sha256'],
        runtime_bundle_sha256=runtime['runtime_bundle_sha256'],
        application_sha256=application['application_sha256'],
        publication_sha256=application['publication_sha256'],
        visibility_installation_sha256=application['visibility']['installation_sha256'])


def observe(owner: OwnerGroupClient, *, expected: dict[str, Any],
            deadline_ns: int) -> dict[str, Any]:
    """Read a known loaded owner; full adoption remains the coordinator's job."""
    _accept(deadline_ns)
    if owner.deadline_ns != deadline_ns:
        raise OnboardingError('receiving_owner_deadline_binding_required')
    with ExitStack() as stack:
        current = owner.status()
        if (current['process'] != expected['process'] or current['server'] != expected['server']
                or _selection(current) != expected['selection']):
            raise OnboardingError('receiving_control_process_changed')
        if expected.get('admission_parent') is not None:
            parent = stack.enter_context(ParentProcessPresence(current['process']))
            if parent.process != expected['admission_parent']:
                raise OnboardingError('receiving_control_parent_changed')
            parent.verify()
        if owner._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        owner._observer.verify()
        _accept(deadline_ns)
        return current


def execute(owner: OwnerGroupClient, command: dict[str, Any], path: Path, *,
            expected: dict[str, Any], deadline_ns: int) -> dict[str, Any]:
    """One authenticated status, durable exact request and reconciled native ACK.

    The caller keeps this owner's observer open. Do not use a previous invocation's
    observation or make another request after an uncertain submission.
    """
    from daimon_matrix.local_api import MAX_CLOCK_SKEW_MS, request_hash

    _accept(deadline_ns)
    if owner.deadline_ns != deadline_ns:
        raise OnboardingError('receiving_owner_deadline_binding_required')
    with being_seed._locked(owner._control_directory(path)), ExitStack() as stack:
        current = owner.status()
        _accept(deadline_ns)
        if (current['process'] != expected['process'] or current['server'] != expected['server']
                or _selection(current) != expected['selection']):
            raise OnboardingError('receiving_control_process_changed')
        parent = None
        if expected.get('admission_parent') is not None:
            parent = stack.enter_context(ParentProcessPresence(current['process']))
            if parent.process != expected['admission_parent']:
                raise OnboardingError('receiving_control_parent_changed')
        socket_before = owner.socket.lstat()
        client = owner._client('receiving-controller')
        fresh = not path.exists()
        if fresh:
            if (current['gate']['process_instance_id'] != command.get('process_instance_id')
                    or current['gate']['head'] != command.get('expected_head')):
                raise OnboardingError('receiving_control_binding_conflict')
            request = client.prepare('runtime.reader-selection', command)
            retained = dict(schema='cluster-receiving-owner-control/v1', command=command,
                request=request, process=current['process'], server=current['server'])
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        else:
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if (set(retained) != {'schema', 'command', 'request', 'process', 'server'}
                    or retained['schema'] != 'cluster-receiving-owner-control/v1'
                    or retained['command'] != command or retained['process'] != current['process']
                    or retained['server'] != current['server']):
                raise OnboardingError('receiving_control_binding_conflict')
            request = retained['request']
        if request.get('method') != 'runtime.reader-selection' or request.get('params') != command:
            raise OnboardingError('receiving_control_binding_conflict')
        owner._durable_control(path)
        _accept(deadline_ns)
        if fresh and time.time_ns() // 1_000_000 - request['issued_at_ms'] > MAX_CLOCK_SKEW_MS:
            raise OnboardingError('receiving_control_fresh_request_expired')
        if parent is not None:
            parent.verify()
        if owner._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        owner._observer.verify()
        # LocalClient verifies the response MAC, request hash, runtime and server.
        # SDK0dc reconciles this method against its live CAS/physical fence even
        # on a cached request. A second status is not that stronger proof.
        response = client.send(request)
        _accept(deadline_ns)
        if response.get('ok') is not True:
            raise OnboardingError('receiving_control_not_accepted')
        gate = response.get('result')
        fingerprint = request_hash(request)
        if (not isinstance(gate, dict)
                or gate.get('schema') != current['gate']['schema']
                or gate.get('controlled') is not True
                or gate.get('context_sha256') != current['gate']['context_sha256']
                or gate.get('process_id') != current['process']['pid']
                or any(gate.get(key) != command.get(key) for key in (
                    'channel_id', 'process_instance_id', 'phase', 'operation_id', 'release_digest', 'readers'))
                or gate.get('request_sha256') != fingerprint
                or not isinstance(gate.get('head'), str)
                or re.fullmatch('[0-9a-f]{64}', gate['head']) is None):
            raise OnboardingError('receiving_control_completion_uncertain')
        after = owner.socket.lstat()
        if (socket_before.st_dev, socket_before.st_ino, socket_before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_ctime_ns):
            raise OnboardingError('receiving_group_socket_changed')
        if parent is not None:
            parent.verify()
        owner._observer.verify()
        _accept(deadline_ns)
        return dict(schema='cluster-receiving-owner-control-observation/v1',
            process=current['process'], server=current['server'], gate=gate,
            request_id=request['request_id'], request_sha256=fingerprint,
            command_sha256=digest(command))


def main() -> int:
    """Invoke as the receiving owner with the already selected closed SDK."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--path', type=Path)
    parser.add_argument('--observe-only', action='store_true')
    parser.add_argument('--deadline-ns', type=int, required=True)
    parser.add_argument('--time-namespace', required=True)
    args = parser.parse_args()
    try:
        _accept(args.deadline_ns)
        if (args.deadline_ns - time.monotonic_ns() > 60_000_000_000
                or os.readlink('/proc/self/ns/time') != args.time_namespace):
            raise OnboardingError('receiving_owner_deadline_binding_required')
        value = json.loads(sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1))
        fields = {'expected'} if args.observe_only else {'command', 'expected'}
        if (not isinstance(value, dict) or set(value) != fields
                or args.observe_only != (args.path is None)):
            raise OnboardingError('invalid_receiving_control_request')
        with OwnerGroupClient(args.root, args.socket, deadline_ns=args.deadline_ns) as owner:
            if args.observe_only:
                result = observe(owner, expected=value['expected'], deadline_ns=args.deadline_ns)
            else:
                assert args.path is not None
                result = execute(owner, value['command'], args.path,
                    expected=value['expected'], deadline_ns=args.deadline_ns)
        print(json.dumps(result))
        return 0
    except Exception as error:
        # Neither private paths, capability material nor arbitrary exception text.
        from daimon_matrix.client import ClientError
        code = (str(error) if isinstance(error, (OnboardingError, ClientError))
            and str(error) in PUBLIC_ERRORS else 'receiving_owner_control_refused')
        print(json.dumps(dict(error=code)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
