"""Owner-local native relationship requests for shared group admission.

Authenticated relationship frames/results and their approved public authority
context are retained here. No transport, membership shortcut, background
attention or running-admission claim is added.
Offline callers must hold the native runtime writer for the entire invocation.
"""
from __future__ import annotations

import copy
import json
import os
import re
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory

METHODS = frozenset({'tribe.invite', 'tribe.membership.accept', 'relationship.event.ingest',
                     'relationship.snapshot'})
PUBLICATIONS = {
    'context-preview': set(),
    'application': {'expected_application_sha256', 'specification', 'additions',
                    'admitted_being_refs', 'secret_sources'},
    'visibility-disclosure': {'approved_destination', 'issued_at_ms'},
    'visibility-accept': {'approved_destination', 'disclosures'},
    'visibility-publish': {'disclosure', 'bindings', 'expected_installation_sha256', 'initial_configuration'},
    'selection': {'expected_selection_sha256'},
    'snapshot': {'application_step', 'visibility_step', 'selection_step', 'owner_context_sha256'},
}


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
    fields = {'command', 'offline', 'authority_closure'}
    if (not isinstance(value, dict) or set(value) not in (fields, fields | {'expected_context_sha256'})
            or type(value['offline']) is not bool or not isinstance(value['authority_closure'], dict)
            or 'expected_context_sha256' in value and (not value['offline']
                or not isinstance(value['expected_context_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', value['expected_context_sha256']) is None)):
        raise OnboardingError('onboarding_group_relationship_command_required')
    publication = isinstance(value['command'], dict) and 'action' in value['command']
    if publication and not value['offline']:
        raise OnboardingError('onboarding_group_relationship_writer_required')
    return dict(command=(publication_command if publication else command)(value['command']), offline=value['offline'],
                authority_closure=copy.deepcopy(value['authority_closure']),
                **({'expected_context_sha256': value['expected_context_sha256']}
                   if 'expected_context_sha256' in value else {}))


def publication_command(value: dict) -> dict:
    try:
        if (not isinstance(value, dict) or set(value) != {'operation_id', 'step', 'action', 'params'}
                or str(uuid.UUID(value['operation_id'])) != value['operation_id']
                or not isinstance(value['step'], str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', value['step']) is None
                or not isinstance(value['action'], str) or value['action'] not in PUBLICATIONS
                or not isinstance(value['params'], dict)
                or set(value['params']) != PUBLICATIONS[value['action']] and not (
                    value['action'] == 'snapshot'
                    and PUBLICATIONS['snapshot'] <= set(value['params'])
                    and set(value['params']) - PUBLICATIONS['snapshot'] <= {'expected_stores', 'expected_preservation'})):
            raise ValueError
        params = value['params']
        if value['action'] == 'application':
            from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3
            first = params['expected_application_sha256'] is None
            if (not isinstance(params['secret_sources'], dict)
                    or not isinstance(params['admitted_being_refs'], list)
                    or first and (not isinstance(params['specification'], dict) or params['additions'] is not None
                        or params['admitted_being_refs'] != []
                        or params['specification'].get('schema') != APPLICATION_SCHEMA_V3)
                    or not first and (params['specification'] is not None or not isinstance(params['additions'], dict)
                        or set(params['additions']) != {'authorities', 'relationship_events', 'roster'}
                        or any(not isinstance(rows, list) for rows in params['additions'].values()))):
                raise ValueError
        if value['action'] == 'visibility-accept' and (not isinstance(params['disclosures'], list)
                or not 1 <= len(params['disclosures']) <= 256):
            raise ValueError
        if value['action'] == 'snapshot' and (any(not isinstance(step, str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,79}', step) is None
                for key, step in params.items() if key not in {
                    'owner_context_sha256', 'expected_stores', 'expected_preservation'})
                or not isinstance(params['owner_context_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', params['owner_context_sha256']) is None):
            raise ValueError
        if 'expected_stores' in params and (not isinstance(params['expected_stores'], dict)
                or 'ledger' not in params['expected_stores']):
            raise ValueError
        if 'expected_preservation' in params and (not isinstance(params['expected_preservation'], dict)
                or 'expected_stores' not in params):
            raise ValueError
        digest(value)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_publication_command_required') from None
    return copy.deepcopy(value)


def check_snapshot_context(journal: Path, value: dict) -> None:
    """A snapshot never creates/reconstructs its approved owner context."""
    if value['action'] == 'snapshot':
        context = being_seed._read(journal / value['operation_id'] / 'owner/context.json',
                                  limit=being_seed.MAX_SELECTION)
        if digest(context) != value['params']['owner_context_sha256']:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        if 'expected_stores' in value['params']:
            from .onboarding_receiving_update import admission_store_bindings, preserved_admission_stores
            identity = context['identity']
            root = Path(identity['runtime_root'])
            bundle = being_seed._read(root / 'runtime.json', limit=being_seed.MAX_SELECTION)
            if digest(bundle) != identity['runtime_bundle_sha256']:
                raise OnboardingError('onboarding_group_owner_context_conflict')
            if 'expected_preservation' in value['params']:
                preserved_admission_stores(root, bundle, value['params']['expected_preservation'],
                                          value['params']['expected_stores'])
            else:
                admission_store_bindings(root, bundle, value['params']['expected_stores'])


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


def _owner_context(runtime_root: Path, group_root: Path, operation_id: str, closure: dict) -> tuple[dict, dict]:
    """Construct the same public pins for preparation and writer retention."""
    from . import onboarding_peer
    try:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_owner_context_conflict') from None
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    identity = dict(runtime_root=str(runtime_root), group_root=str(group_root),
        runtime_bundle_sha256=digest(bundle),
        ledger=_ledger_identity(runtime_root, bundle))
    approved = dict(schema='cluster-group-owner-context/v1',
        operation_id=operation_id, identity=identity,
        authority_closure=copy.deepcopy(closure))
    authorities = public_authorities(bundle, closure)
    # A self-consistent replacement chain cannot erase native known history.
    onboarding_peer._group_authorities_with_history(bundle, authorities,
        {ref: authority.active for ref, authority in authorities.items()})
    return approved, authorities


def _first_owner_context(runtime_root: Path, group_root: Path, approved: dict, authorities: dict) -> dict:
    from . import onboarding_peer
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    if digest(bundle) != approved['identity']['runtime_bundle_sha256']:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    current = onboarding_peer.approved_group_authorities(runtime_root, group_root, bundle)
    if not set(current) <= set(authorities):
        raise OnboardingError('onboarding_group_owner_context_incomplete')
    merge_authorities(current, authorities)
    selection = group_root / 'selection.json'
    predecessor = digest(being_seed._read(selection, limit=being_seed.MAX_SELECTION)) if selection.exists() else None
    return {**approved, 'predecessor_selection_sha256': predecessor}


def preview_owner_context(runtime_root: Path, group_root: Path, operation_id: str, closure: dict,
                          *, deadline_ns: int | None = None) -> dict:
    """Read public context pins before interruption, without custody or writes.

    This is a prospective digest, not writer ownership or receiving acceptance.
    The later writer compares these exact pins before retaining any context.
    """
    def budget():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')
    budget()
    approved, authorities = _owner_context(runtime_root, group_root, operation_id, closure)
    context = _first_owner_context(runtime_root, group_root, approved, authorities)
    # Read-only observation must not certify a mixture across a concurrent
    # bundle/ledger/selector change. The writer remains the final CAS boundary.
    fresh, _ = _owner_context(runtime_root, group_root, operation_id, closure)
    if fresh != approved or _first_owner_context(runtime_root, group_root, fresh, authorities) != context:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    budget()
    return dict(schema='cluster-group-owner-context-preview/v1', operation_id=operation_id,
        owner_context_sha256=digest(context), runtime_bundle_sha256=approved['identity']['runtime_bundle_sha256'],
        predecessor_selection_sha256=context['predecessor_selection_sha256'], receiving_readiness='unobserved')


def owner_authorities(runtime_root: Path, group_root: Path, journal: Path,
                      operation_id: str, closure: dict, *, expected_context_sha256: str | None = None) -> dict:
    """Freeze the complete owner-approved closure before partial publication.

    The caller holds the native writer. First use validates the actual serving
    selector and preserves all its Roots. An exact retained operation can then
    load a closed maintenance context even while that selector lags publication.
    Normal serving and observation keep their strict application pins.
    """
    if expected_context_sha256 is not None and (not isinstance(expected_context_sha256, str)
            or re.fullmatch('[0-9a-f]{64}', expected_context_sha256) is None):
        raise OnboardingError('onboarding_group_owner_context_conflict')
    approved, authorities = _owner_context(runtime_root, group_root, operation_id, closure)
    private_directory(journal, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / operation_id, create=True)
        context = private_directory(operation / 'owner', create=True)
        path = context / 'context.json'
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            predecessor = retained.get('predecessor_selection_sha256')
            if (retained != {**approved, 'predecessor_selection_sha256': predecessor}
                    or predecessor is not None
                    and (not isinstance(predecessor, str) or re.fullmatch('[0-9a-f]{64}', predecessor) is None)):
                raise OnboardingError('onboarding_group_owner_context_conflict')
        else:
            retained = _first_owner_context(runtime_root, group_root, approved, authorities)
        if expected_context_sha256 is not None and digest(retained) != expected_context_sha256:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        if not path.exists():
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        # Retry the durability boundary even after a lost write/fsync reply.
        # No native load or relationship dispatch precedes this boundary.
        for parent in (context, operation, journal, journal.parent):
            _sync(parent)
    return authorities


def load_owner_runtime(runtime_root: Path, reader, *, authorities: dict,
                       qualified_startup: dict | None = None):
    """Load only a closed owner context, never a serving selector or egress."""
    from daimon_matrix import native_egress, runtime
    def clock():
        return time.time_ns() // 1_000_000
    return runtime.load_runtime(runtime_root, 'runtime.json', reader, clock=clock,
        relationship_authorities=authorities,
        egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'),
        **({} if qualified_startup is None else {'qualified_startup': qualified_startup}))


def _sync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def check_retained_ledger(runtime_root: Path, journal: Path, value: dict) -> dict:
    """Check the original ledger before a loader could initialize missing state."""
    selected = command(value)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    identity = _ledger_identity(runtime_root, bundle)
    path = journal / selected['operation_id'] / (selected['step'] + '.json')
    if path.exists() and being_seed._read(path, limit=being_seed.MAX_SELECTION).get('identity', {}).get('ledger') != identity:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    return identity


def _ledger_identity(runtime_root: Path, bundle: dict) -> dict:
    from daimon_matrix.service import LoadedStoreBinding
    name = bundle['ledger']
    if not isinstance(name, str) or Path(name).name != name or name in {'', '.', '..'}:
        raise OnboardingError('onboarding_group_relationship_ledger_changed')
    return dict(filename=name, file_identity=list(LoadedStoreBinding.file_identity(runtime_root / name)))


def _publish_application(hosted, directory: Path, params: dict) -> dict:
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import (
        config_digest, load_application, read_document, read_publication, read_verified_publication, verify_binding,
    )
    expected = params['expected_application_sha256']
    if expected is None:
        published = directory.exists()
        if not published:
            operator_messaging.prepare(hosted, directory, params['specification'],
                secret_sources=params['secret_sources'])
        snapshot = read_verified_publication(hosted, directory)
        publication = json.loads(snapshot.publication)
        if (snapshot.metadata != directory or publication['body']['generation'] != '.'
                or publication['body']['predecessor_sha256'] is not None):
            raise OnboardingError('onboarding_group_publication_changed')
        application = json.loads(snapshot.application)
        specification = {key: value for key, value in application.items() if key != 'client'}
        if specification != params['specification']:
            raise OnboardingError('onboarding_group_publication_changed')
        # prepare can publish before its reply/load-validation is lost. Reuse
        # that exact client and finish native validation, never prepare over it.
        if published:
            load_application(hosted, directory)
        _sync(directory.parent)
    else:
        previous, metadata = read_publication(hosted, directory)
        if config_digest(previous) != expected:
            # The SDK retains its authenticated predecessor with the selected
            # successor. Derive the same additions from it on an exact retry.
            previous = read_document(metadata / 'predecessor.json')
            verify_binding(hosted, previous, read_document(metadata / 'predecessor-binding.json'))
        if config_digest(previous) != expected:
            raise OnboardingError('onboarding_group_publication_changed')
        specification = copy.deepcopy(previous)
        for key, rows in params['additions'].items():
            specification[key].extend(rows)
        operator_messaging.admit_group_application(hosted, directory, specification,
            expected_application_sha256=expected, admitted_being_refs=params['admitted_being_refs'],
            secret_sources=params['secret_sources'])
        application, _ = read_publication(hosted, directory)
    return dict(application_sha256=config_digest(application),
                publication_sha256=config_digest(read_document(directory / 'publication.json')))


def _publication_snapshot(hosted, group_root: Path, operation: Path, value: dict,
                          context: dict, snapshot: Callable[[], dict] | None) -> dict:
    """Correlate a fresh signed group view with this owner's actual effects.

    The owner supplies the profile-specific authenticated group reader while
    retaining its native writer. Step references identify existing records;
    they never supply hashes, paths or a substitute candidate group.
    """
    if snapshot is None:
        raise OnboardingError('onboarding_group_snapshot_reader_required')
    if digest(context) != value['params']['owner_context_sha256']:
        raise OnboardingError('onboarding_group_owner_context_conflict')
    receipts: dict[str, dict] = {}
    for action, key in (('application', 'application_step'), ('visibility-publish', 'visibility_step'),
                        ('selection', 'selection_step')):
        step = value['params'][key]
        retained = being_seed._read(operation / 'publications' / (step + '.json'),
                                   limit=being_seed.MAX_SELECTION)
        command = retained.get('command')
        result = retained.get('result')
        if (retained.get('schema') != 'cluster-group-publication-operation/v1'
                or retained.get('owner_context_sha256') != digest(context)
                or not isinstance(command, dict) or command.get('operation_id') != value['operation_id']
                or command.get('step') != step or command.get('action') != action
                or not isinstance(result, dict) or result.get('schema') != 'cluster-group-publication-result/v1'
                or result.get('operation_id') != value['operation_id'] or result.get('step') != step
                or result.get('action') != action or result.get('status') != 'recorded'
                or result.get('receiving_readiness') != 'unobserved'):
            raise OnboardingError('onboarding_group_snapshot_publication_required')
        publication_command(command)
        receipts[action] = dict(command_sha256=digest(command), result=result)
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest
    application_value, _members = operator_messaging._group_visibility_context(hosted, group_root / 'application')
    authorities = operator_messaging._application_authorities(application_value)
    controller = operator_messaging._owner_visibility_controller(authorities=authorities,
        application_sha256=config_digest(application_value),
        installation_path=group_root / 'visibility/installation.json',
        authority=operator_messaging._runtime_authority(hosted), origin=hosted.service.origin,
        runtime_id=hosted.service.runtime_id, runtime_label=hosted.service.runtime_label,
        signer_public_key=hosted.service.signer.public_key, clock=hosted.service.clock,
        catalog_mode='validate')
    group = snapshot()
    selected = being_seed._read(group_root / 'selection.json', limit=being_seed.MAX_SELECTION)
    application = receipts['application']['result']
    visibility = receipts['visibility-publish']['result']
    selection = receipts['selection']['result']
    if (any(group.get(key) != application.get(key) for key in ('application_sha256', 'publication_sha256'))
            or group.get('installation_sha256') != visibility.get('installation_sha256')
            or group.get('installation_sha256') != controller.installation_digest
            or group.get('application_sha256') != config_digest(application_value)
            # The receiving selector retains Cluster's document codec. Native
            # application/visibility receipts use Matrix's canonical codec.
            or digest(application_value) != selection.get('application_sha256')
            or digest(selected) != selection.get('selection_sha256')):
        raise OnboardingError('onboarding_group_snapshot_publication_changed')
    return dict(group=group, selection_sha256=digest(selected), publications=receipts,
                owner_context_sha256=digest(context),
                stores={role: json.loads(binding.observation)
                        for role, binding in hosted.service.loaded_stores.items()})


def _publication_effect(hosted, group_root: Path, value: dict, closure: dict, *,
                        operation: Path, context: dict,
                        snapshot: Callable[[], dict] | None) -> dict:
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest
    params = value['params']
    directory = group_root / 'application'
    action = value['action']
    if action == 'snapshot':
        return _publication_snapshot(hosted, group_root, operation, value, context, snapshot)
    if action == 'application':
        return _publish_application(hosted, directory, params)
    if action == 'visibility-disclosure':
        disclosure = operator_messaging.group_visibility_disclosure(hosted, directory, **params)
        return dict(disclosure=disclosure, disclosure_sha256=config_digest(disclosure))
    if action == 'visibility-accept':
        return dict(bindings=[dict(disclosure_sha256=config_digest(disclosure),
            binding=operator_messaging.accept_group_visibility(hosted, directory, disclosure,
                approved_destination=params['approved_destination'])) for disclosure in params['disclosures']])
    if action == 'visibility-publish':
        installation = private_directory(group_root / 'visibility', create=True) / 'installation.json'
        result = operator_messaging.publish_group_visibility(hosted, directory, installation, **params)
        return dict(installation_sha256=result['installation_sha256'])
    from .onboarding_peer import publish_group_selection
    result = publish_group_selection(hosted, group_root, operation_id=value['operation_id'],
        expected_selection_sha256=params['expected_selection_sha256'],
        authority_history={ref: row['history'] for ref, row in closure.items()})
    return {key: result[key] for key in ('selection_sha256', 'application_sha256')}


def publication_request(hosted, group_root: Path, journal: Path, value: dict, *,
                        deadline_ns: int | None = None,
                        snapshot: Callable[[], dict] | None = None) -> dict:
    """Resume one exact owner publication through supported Matrix operations.

    The caller holds the runtime writer and has retained owner_authorities.
    SDK publication preimages and CAS remain authoritative; cached results do
    not bypass current publication checks or prove receiving readiness.
    """
    selected = publication_command(value)
    if selected['action'] == 'context-preview':
        raise OnboardingError('onboarding_group_context_preview_is_read_only')
    def check_deadline():
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_group_relationship_deadline_expired')
    check_deadline()
    private_directory(group_root, create=True)
    with being_seed._locked(journal):
        operation = private_directory(journal / selected['operation_id'])
        context = being_seed._read(operation / 'owner/context.json', limit=being_seed.MAX_SELECTION)
        bundle = being_seed._read(hosted.state_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        expected = dict(runtime_root=str(hosted.state_root), group_root=str(group_root),
            runtime_bundle_sha256=digest(bundle), ledger=_ledger_identity(hosted.state_root, bundle))
        if (context['identity'] != expected or hosted.service.origin != bundle['local_origin']
                or hosted.service.runtime_identity != {key: bundle[key] for key in ('runtime_id', 'runtime_label')}):
            raise OnboardingError('onboarding_group_owner_context_conflict')
        for binding in hosted.service.loaded_stores.values():
            binding.verify()
        directory = private_directory(operation / 'publications', create=True)
        path = directory / (selected['step'] + '.json')
        intent = dict(schema='cluster-group-publication-operation/v1', command=selected,
                      owner_context_sha256=digest(context))
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if retained != {**intent, 'result': retained.get('result')}:
                raise OnboardingError('onboarding_group_publication_intent_conflict')
        else:
            if (selected['action'] == 'application' and selected['params']['expected_application_sha256'] is None
                    and (group_root / 'application').exists()):
                raise OnboardingError('onboarding_group_publication_changed')
            retained = {**intent, 'result': None}
            being_seed._write(path, retained, limit=being_seed.MAX_SELECTION)
        for parent in (directory, operation, journal, journal.parent):
            _sync(parent)
        check_deadline()
        observed = _publication_effect(hosted, group_root, selected, context['authority_closure'],
            operation=operation, context=context, snapshot=snapshot)
        if (selected['action'] == 'snapshot' and retained['result'] is not None
                and 'stores' not in retained['result'] and 'expected_stores' not in selected['params']):
            # Preserve an older completed observation's exact result shape.
            # It remains fresh-validated but cannot become admission store proof.
            observed.pop('stores', None)
        result = dict(schema='cluster-group-publication-result/v1', operation_id=selected['operation_id'],
            step=selected['step'], action=selected['action'], status='recorded',
            receiving_readiness='unobserved', **observed)
        if retained['result'] is not None and retained['result'] != result:
            raise OnboardingError('onboarding_group_publication_changed')
        if retained['result'] is None:
            being_seed._write(path, {**retained, 'result': result}, limit=being_seed.MAX_SELECTION)
        check_deadline()
        return result


def relationship_request(runtime_root: Path, journal: Path, value: dict, *,
                         offline=None, deadline_ns: int | None = None) -> dict:
    """Record or retry one native request; never return local capability material.

    A relationship snapshot is the native reducer's observation at its retained
    verified_at_ms. Exact retry returns that observation, not fresh membership
    or receiving readiness. A later phase needs its own approved step.
    """
    from daimon_matrix.client import ClientConfig, LocalClient
    from daimon_matrix.local_api import MAX_CLOCK_SKEW_MS, authenticate_request, verify_response
    from daimon_matrix.messaging_config import protected_read
    from daimon_matrix.operator_capabilities import operator_capability_profile

    selected = command(value)
    private_directory(runtime_root)
    bundle = being_seed._read(runtime_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    role = 'observe' if selected['method'] == 'relationship.snapshot' else 'relationships'
    profile = operator_capability_profile(role)
    directory = runtime_root / profile['client_directory']
    config = ClientConfig.load(directory / profile['client_config_filename'],
        bytearray(protected_read(directory / profile['client_key_filename'])))
    identity = dict(runtime_id=bundle['runtime_id'], runtime_label=bundle['runtime_label'],
                    server=bundle['local_origin'], capability_id=config.capability.capability_id,
                    ledger=check_retained_ledger(runtime_root, journal, selected))
    if (config.runtime_id != identity['runtime_id'] or config.runtime_label != identity['runtime_label']
            or config.expected_server != identity['server']
            or config.capability.client_id != 'client:operator:' + config.runtime_label + ':' + role
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
