"""Owner-local native relationship requests for shared group admission.

Only authenticated relationship frames/results are retained here. No transport,
membership shortcut, background attention or running-admission claim is added.
Offline callers must hold the native runtime writer for the entire invocation.
"""
from __future__ import annotations

import copy
import os
import re
import time
import uuid
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory

METHODS = frozenset({'tribe.invite', 'tribe.membership.accept', 'relationship.event.ingest'})


def command(value: dict) -> dict:
    try:
        if (not isinstance(value, dict) or set(value) != {'operation_id', 'step', 'method', 'params'}
                or str(uuid.UUID(value['operation_id'])) != value['operation_id']
                or not isinstance(value['step'], str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', value['step']) is None
                or value['method'] not in METHODS or not isinstance(value['params'], dict)):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_relationship_command_required') from None
    return copy.deepcopy(value)


def request_packet(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {'command', 'offline', 'authority_closure'}
            or type(value['offline']) is not bool or not isinstance(value['authority_closure'], dict)):
        raise OnboardingError('onboarding_group_relationship_command_required')
    return dict(command=command(value['command']), offline=value['offline'],
                authority_closure=copy.deepcopy(value['authority_closure']))


def public_authorities(bundle: dict, closure: dict) -> dict:
    """Validate the public closure already approved by this owner CLI's caller.

    Self-consistent signatures alone are not approval. The protected operation
    and existing Source/Target owner routes supply that separate authorization.
    """
    from daimon_matrix import operator_messaging
    reader = getattr(operator_messaging, 'public_authority_history', None)
    if not callable(reader):
        raise OnboardingError('onboarding_group_history_sdk_required')
    if not isinstance(closure, dict) or len(closure) > 256:
        raise OnboardingError('approved_onboarding_group_history_required')
    result = {}
    for ref, row in closure.items():
        if (ref == bundle['manifest']['being_ref'] or not isinstance(row, dict)
                or set(row) != {'authority', 'history'}):
            raise OnboardingError('approved_onboarding_group_history_required')
        authority = reader(row['authority'], row['history'])
        if authority.active.manifest.being_ref != ref:
            raise OnboardingError('approved_onboarding_group_history_required')
        result[ref] = authority
    return result


def merge_authorities(current: dict, supplied: dict) -> dict:
    result = dict(current)
    for ref, authority in supplied.items():
        previous = result.get(ref)
        if previous is not None and (getattr(previous, 'active', previous) != authority.active
                or hasattr(previous, 'historical') and previous != authority):
            raise OnboardingError('approved_onboarding_group_history_conflict')
        result[ref] = authority
    return result


def _sync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def check_retained_ledger(runtime_root: Path, journal: Path, value: dict) -> dict:
    """Check the original ledger before a loader could initialize missing state."""
    from daimon_matrix.service import LoadedStoreBinding
    selected = command(value)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    name = bundle['ledger']
    if not isinstance(name, str) or Path(name).name != name or name in {'', '.', '..'}:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    identity = dict(filename=name, file_identity=list(LoadedStoreBinding.file_identity(runtime_root / name)))
    path = journal / selected['operation_id'] / (selected['step'] + '.json')
    if path.exists() and being_seed._read(path, limit=being_seed.MAX_SELECTION).get('identity', {}).get('ledger') != identity:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    return identity


def relationship_request(runtime_root: Path, journal: Path, value: dict, *,
                         offline=None, deadline_ns: int | None = None) -> dict:
    """Record or retry one native request; never return local capability material."""
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.local_api import MAX_CLOCK_SKEW_MS, authenticate_request, verify_response
    from daimon_matrix.messaging_config import protected_read
    from daimon_matrix.operator_capabilities import operator_capability_profile

    selected = command(value)
    private_directory(runtime_root)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    profile = operator_capability_profile('relationships')
    directory = runtime_root / profile['client_directory']
    config = ClientConfig.load(directory / profile['client_config_filename'],
        bytearray(protected_read(directory / profile['client_key_filename'])))
    identity = dict(runtime_id=bundle['runtime_id'], runtime_label=bundle['runtime_label'],
                    server=bundle['local_origin'], capability_id=config.capability.capability_id,
                    ledger=check_retained_ledger(runtime_root, journal, selected))
    if (config.runtime_id != identity['runtime_id'] or config.runtime_label != identity['runtime_label']
            or config.expected_server != identity['server']
            or config.capability.client_id != 'client:operator:' + config.runtime_label + ':relationships'
            or selected['method'] not in config.capability.methods):
        raise OnboardingError('onboarding_group_relationship_client_conflict')
    clock = (lambda: time.time_ns() // 1_000_000) if offline is None else offline.service.clock
    if offline is not None and (offline.state_root != runtime_root
            or offline.service.runtime_identity != {key: identity[key] for key in ('runtime_id', 'runtime_label')}
            or offline.service.origin != identity['server']):
        raise OnboardingError('onboarding_group_relationship_client_conflict')
    client = LocalClient(runtime_root / bundle['socket'], config, clock=clock,
                         timeout_seconds=40, deadline_ns=deadline_ns)

    def check_deadline():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')

    def authenticate(frame: dict) -> str:
        normalized, request_hash = authenticate_request(frame, config.capability,
            now_ms=frame['issued_at_ms'])
        if normalized['method'] != selected['method'] or normalized['params'] != selected['params']:
            raise OnboardingError('onboarding_group_relationship_request_conflict')
        return request_hash

    def verify_loaded_stores():
        binding = offline.service.loaded_stores.get('ledger')
        if (binding is None or binding.path != offline.service.ledger.path
                or list(binding.identity) != identity['ledger']['file_identity']):
            raise OnboardingError('onboarding_group_relationship_ledger_changed')
        for item in offline.service.loaded_stores.values():
            item.verify()

    check_deadline()
    private_directory(journal, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / selected['operation_id'], create=True)
        path = operation / (selected['step'] + '.json')
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if (set(retained) != {'schema', 'command', 'identity', 'request', 'retired_requests', 'response'}
                    or retained['schema'] != 'cluster-group-relationship-operation/v1'
                    or retained['command'] != selected or retained['identity'] != identity
                    or not isinstance(retained['retired_requests'], list)):
                raise OnboardingError('onboarding_group_relationship_request_conflict')
        else:
            retained = dict(schema='cluster-group-relationship-operation/v1', command=selected,
                identity=identity, request=client.prepare(selected['method'], selected['params']),
                retired_requests=[], response=None)
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        request_hash = authenticate(retained['request'])
        for earlier in retained['retired_requests']:
            authenticate(earlier)
            if earlier['request_id'] != retained['request']['request_id']:
                raise OnboardingError('onboarding_group_relationship_request_conflict')
        for parent in (operation, journal, journal.parent):
            _sync(parent)
        request = retained['request']
        if retained['response'] is None:
            check_deadline()
            if offline is not None and clock() - request['issued_at_ms'] > MAX_CLOCK_SKEW_MS:
                # Current capability validity is still required. Actual exclusive
                # writer ownership makes native RPC absence a stable fact.
                authenticate_request(request, config.capability, now_ms=clock(), allow_stale=True)
                verify_loaded_stores()
                rows = [row for row in offline.service.ledger.rpc_requests()
                    if row['client_id'] == request['client_id'] and row['request_id'] == request['request_id']]
                verify_loaded_stores()
                if rows and (rows[0]['request_hash'] != request_hash or rows[0]['method'] != request['method']):
                    raise OnboardingError('onboarding_group_relationship_request_conflict')
                if not rows:
                    retained['retired_requests'].append(request)
                    request = client.prepare(selected['method'], selected['params'], request_id=request['request_id'])
                    retained['request'] = request
                    being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
                    request_hash = authenticate(request)
            check_deadline()
            response = client.send(request) if offline is None else offline.service.handle(request)
        else:
            response = retained['response']
        verified = verify_response(response, config.capability,
            expected_request_id=request['request_id'], expected_request_hash=request_hash,
            expected_server=config.expected_server,
            expected_runtime=dict(runtime_id=config.runtime_id, runtime_label=config.runtime_label))
        if retained['response'] is None:
            retained['response'] = verified
            # A failed local result write remains recoverable through native RPC.
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        check_deadline()
        return dict(schema='cluster-group-relationship-result/v1',
            status='recorded' if verified['ok'] else 'rejected',
            request_id=request['request_id'], request_sha256=request_hash,
            response_sha256=digest(verified), result=verified['result'], native_error=verified['error'])
