"""Signed group selection and retained directed-enrollment verification.

Group trust comes from the owner-signed shared selection, without pair grants.
Historical directed repair retains its exact qualified native tool. Body custody
and private route material remain in the receiver in both cases.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import time
import types
from contextlib import closing
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory

TOOL_SHA256 = 'd1f67e40bbc8c08eff0e0f96354e107d2f8219b258c661b81b9e98a60565c03c'
TOOL_MODULE = 'onboarding_peer_native.py'
TOOL_COMMIT = '63968130294c4db6eac51a94800a837f2c10bad5'


def native(code: Path, *, uid: int = 0):
    import importlib.metadata
    import sys
    from .onboarding_code_successor import sdk_parameters
    from .onboarding_sdk import MATRIX_COMMIT, verify
    # Entry points verify every installed wheel byte before importing Matrix.
    # The offline body has a pinned installation receipt, not VCS direct_url.
    # Host/source invocation instead retains the exact installed VCS guard.
    manifest = code / 'sdk/sdk.json'
    if manifest.exists():
        # The selected code was verified before this helper. Its explicit
        # successor pins the replacement wheel as well as the commit; legacy
        # code retains the fixed pin. Validating historical peer publication
        # must not reject an otherwise qualified SDK solely for being newer.
        parameters = sdk_parameters(code, uid=uid)
        sdk = verify(code, uid=uid, **parameters)
        prefix = Path(sys.prefix)
        receipt = json.loads(onboarding_release.regular(prefix.parent / 'installation.json', uid=os.geteuid()))
        expected = dict(schema='cluster-onboarding-sdk-installation/v1', sdk_digest=digest(sdk),
            matrix_commit=sdk['matrix_commit'], wheel_count=len(sdk['wheels']))
        if (prefix.name != 'venv'
                or prefix.parent.name != digest(sdk) or receipt != expected):
            raise OnboardingError('qualified_native_peer_sdk_required')
    else:
        if sdk_parameters(code, uid=uid):
            raise OnboardingError('qualified_native_peer_sdk_required')
        installed = json.loads(importlib.metadata.distribution('daimon-matrix').read_text('direct_url.json') or '{}')
        if installed.get('vcs_info', {}).get('commit_id') != MATRIX_COMMIT:
            raise OnboardingError('qualified_native_peer_sdk_required')
    path = code / 'clusterctl' / TOOL_MODULE
    raw = onboarding_release.regular(path, uid=uid)
    if hashlib.sha256(raw).hexdigest() != TOOL_SHA256:
        raise OnboardingError('qualified_native_peer_tool_required')
    module = types.ModuleType('qualified_onboarding_peer_native')
    module.__file__ = str(path)
    # Execute the verified bytes, never reopen a mutable path for importing.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def root(target) -> Path:
    return target.root / 'peer'


def loaded(target):
    from daimon_matrix import runtime, native_egress
    def clock():
        return time.time_ns() // 1_000_000
    return runtime.load_runtime(target.package / 'runtime', 'runtime.json', target._reader,
        clock=clock, egress=native_egress.closed_visibility(clock=clock, catalog_mode='migrate'))


def identity(target) -> dict:
    tool = native(target.code, uid=target.code_uid)
    with target._runtime_writer():
        if target.observe()['phase'] != 'v8':
            raise OnboardingError('current_onboarding_target_required')
        return tool.public_identity(loaded(target), target.document_bundle())


def accept(target, packet: dict, *, expected_being: str) -> dict:
    tool = native(target.code, uid=target.code_uid)
    sender = tool.verify_identity(packet['sender_identity'])
    if sender.state.being_ref != expected_being or expected_being == target.document_bundle()['manifest']['being_ref']:
        raise OnboardingError('approved_onboarding_peer_required')
    directory = private_directory(root(target), create=True)
    with target._runtime_writer():
        if target.observe()['phase'] not in {'v8', 'peer-published'}:
            raise OnboardingError('current_onboarding_target_required')
        # The native receiver verifies both Body signatures and the shared graph
        # before publishing. Its persisted proposals recover every lost ACK.
        response = tool.accept(loaded(target), target.package / 'runtime',
                               bytes(target._reader()), packet, directory, additional_link=True)
        observed = target.observe()
        if observed['phase'] != 'v8':
            raise OnboardingError('native_onboarding_peer_incomplete')
        return json.loads(onboarding_release.regular(response, uid=os.geteuid()))


def _authority_selections(target, tool, identity, known):
    """Verify the bounded owner-signed selection chain from the original peer."""
    from daimon_matrix.operator_messaging import known_peer_successor
    path = root(target) / 'authority-successor.json'
    packets = []
    seen = set()
    while path.exists():
        packet = json.loads(onboarding_release.regular(path, uid=os.geteuid()))
        tool.verify_document(identity, packet['document'], packet['binding'])
        packet_hash = digest(packet)
        if packet_hash in seen or len(packets) >= 256:
            raise OnboardingError('onboarding_peer_successor_conflict')
        seen.add(packet_hash)
        packets.append(packet)
        previous = packet['document'].get('previous_selection_sha256')
        if previous is None:
            break
        import re
        if not isinstance(previous, str) or re.fullmatch('[0-9a-f]{64}', previous) is None:
            raise OnboardingError('onboarding_peer_successor_conflict')
        path = root(target) / ('authority-successor-' + previous + '.json')
        if not path.exists() or digest(json.loads(onboarding_release.regular(path, uid=os.geteuid()))) != previous:
            raise OnboardingError('onboarding_peer_successor_conflict')
    prior = copy.deepcopy(known)
    authority = None
    for packet in reversed(packets):
        prior = copy.deepcopy(known)
        document = packet['document']
        known, authority = known_peer_successor(known, document['authority'], document['authority_history'])
    return known, prior, authority, packets[0] if packets else None


def additional_bundle(target, expected: dict, local_identity: dict) -> dict:
    """Accept only exact owner-signed additional peers; preserve the base body."""
    path = root(target) / 'additional-links.json'
    if not path.exists():
        return expected
    tool = native(target.code, uid=target.code_uid)
    packet = json.loads(onboarding_release.regular(path, uid=os.geteuid()))
    document = packet['document']
    tool.verify_document(local_identity, document, packet['binding'])
    if (set(document) != {'schema', 'before_sha256', 'peers'}
            or document['schema'] != 'cluster-onboarding-additional-peers/v1'
            or document['before_sha256'] != digest(expected)
            or not isinstance(document['peers'], list) or not 1 <= len(document['peers']) <= 16):
        raise OnboardingError('approved_onboarding_peer_required')
    selected = copy.deepcopy(expected)
    import re
    import uuid
    from daimon_matrix.messaging_config import _read_publication
    used_sockets = {'matrix.sock', 'peer.sock'}
    for row in document['peers']:
        if set(row) != {'identity', 'link_id', 'directory', 'visibility', 'socket', 'application_sha256'}:
            raise OnboardingError('approved_onboarding_peer_required')
        link = str(uuid.UUID(row['link_id']))
        directory = target.root / 'additional-peers' / link
        if (row['directory'] != str(directory / 'application')
                or row['visibility'] != str(directory / 'visibility/installation.json')
                or not isinstance(row['socket'], str)
                or re.fullmatch(r'[a-z0-9_-]{1,19}\.sock', row['socket']) is None
                or row['socket'] in used_sockets):
            raise OnboardingError('approved_onboarding_peer_required')
        used_sockets.add(row['socket'])
        authority = tool.verify_identity(row['identity'])
        if authority.state.being_ref == expected['manifest']['being_ref']:
            raise OnboardingError('approved_onboarding_peer_required')
        peers = selected['sources']['known_beings']
        if any(peer['manifest']['being_ref'] == authority.state.being_ref for peer in peers):
            raise OnboardingError('approved_onboarding_peer_required')
        peers.append(tool.known_peer(row['identity']['document'], authority, [], link))
        refs = selected['relationships']['known_being_refs']
        refs.append(authority.state.being_ref)
        refs.sort()
        application, _ = _read_publication(Path(row['directory']),
            lambda value, binding: tool.verify_document(local_identity, value, binding))
        if digest(application) != row['application_sha256']:
            raise OnboardingError('approved_onboarding_peer_required')
    return selected


def additional_applications(target) -> list[dict]:
    """Called only after Target.observe authenticates the exact selection."""
    path = root(target) / 'additional-links.json'
    if not path.exists():
        return []
    packet = json.loads(onboarding_release.regular(path, uid=os.geteuid()))
    return packet['document']['peers']


def group_application(target, hosted):
    return approved_group_application(hosted, target.root / 'tribe')


def approved_group_application(hosted, group_root: Path):
    """Select one owner-approved group, retaining pair enrollment as history.

    This is a default application selection, not new identity or membership.
    Native Matrix validates the publication, membership and transport after this
    selector; old bootstrap apps are not started when their grants have ended.
    """
    from daimon_matrix.messaging_config import verify_binding
    return _approved_group(group_root, lambda value, binding:
        verify_binding(hosted, value, binding))


def _approved_group(group_root: Path, verify):
    packet = _approved_group_packet(group_root, verify)
    return None if packet is None else packet[0]


def _approved_group_packet(group_root: Path, verify):
    path = group_root / 'selection.json'
    if not path.exists():
        return None
    packet = json.loads(onboarding_release.regular(path, uid=os.geteuid()))
    return _validate_group_packet(group_root, packet, verify)


def _validate_group_packet(group_root: Path, packet: dict, verify):
    from daimon_matrix.messaging_config import APPLICATION_SCHEMA_V3, _read_publication
    if set(packet) != {'document', 'binding'}:
        raise OnboardingError('approved_onboarding_group_required')
    document = packet['document']
    verify(document, packet['binding'])
    directory = group_root / 'application'
    visibility = group_root / 'visibility' / 'installation.json'
    fields = {'schema', 'tribe_ref', 'directory', 'visibility', 'socket', 'application_sha256'}
    schema = document.get('schema')
    if schema == 'cluster-onboarding-group-selection/v2':
        fields.add('authority_history')
    if (set(document) != fields
            or schema not in {'cluster-onboarding-group-selection/v1', 'cluster-onboarding-group-selection/v2'}
            or document['directory'] != str(directory)
            or document['visibility'] != str(visibility)
            or document['socket'] != 'tribe.sock'):
        raise OnboardingError('approved_onboarding_group_required')
    application, _ = _read_publication(directory, verify)
    if (application['schema'] != APPLICATION_SCHEMA_V3
            or application['tribe']['policy']['tribe_ref'] != document['tribe_ref']
            or digest(application) != document['application_sha256']):
        raise OnboardingError('approved_onboarding_group_required')
    histories = None
    if schema == 'cluster-onboarding-group-selection/v2':
        histories = _group_public_history(document, packet['binding'], application)
    return document, histories


def publish_group_selection(hosted, group_root: Path, *, operation_id: str,
                            expected_selection_sha256: str | None,
                            authority_history: dict) -> dict:
    """Owner-local CAS after application publication, under the runtime writer.

    This selects public authority/application pins only. It neither loads a
    visibility controller nor claims startup, receiving admission or delivery.
    The caller must keep senders fenced until the complete admission succeeds.
    """
    import re
    import uuid
    from daimon_matrix.messaging_config import (
        create_binding, read_application_authorities, read_publication, verify_binding,
    )
    try:
        if (str(uuid.UUID(operation_id)) != operation_id
                or expected_selection_sha256 is not None
                and re.fullmatch(r'[0-9a-f]{64}', expected_selection_sha256) is None):
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise OnboardingError('onboarding_group_selection_operation_required') from None
    private_directory(group_root)
    def verify(document, binding):
        return verify_binding(hosted, document, binding)
    with being_seed._locked(group_root):
        application, _ = read_publication(hosted, group_root / 'application')
        document = dict(schema='cluster-onboarding-group-selection/v2',
            tribe_ref=application['tribe']['policy']['tribe_ref'],
            directory=str(group_root / 'application'),
            visibility=str(group_root / 'visibility/installation.json'), socket='tribe.sock',
            application_sha256=digest(application), authority_history=copy.deepcopy(authority_history))
        candidate = dict(document=document, binding=create_binding(hosted, document))
        if len(json.dumps(candidate, sort_keys=True).encode()) > being_seed.MAX_SELECTION:
            raise OnboardingError('onboarding_group_selection_too_large')
        # Validate before retaining anything, including the exact foreign Root
        # history map. The predecessor can legitimately pin the earlier app.
        _, histories = _validate_group_packet(group_root, candidate, verify)
        bundle = being_seed._read(hosted.state_root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        current = read_application_authorities(hosted.state_root, 'runtime.json',
            group_root / 'application', at_ms=hosted.service.clock())
        _group_authorities_with_history(bundle, histories, current)
        path = group_root / 'selection.json'
        before = being_seed._read(path, limit=being_seed.MAX_SELECTION) if path.exists() else None
        command = dict(operation_id=operation_id, expected_selection_sha256=expected_selection_sha256,
                       candidate_sha256=digest(candidate))
        operations = group_root / 'selection-operations'
        private_directory(operations, create=True)
        operation = operations / (operation_id + '.json')
        if operation.exists():
            retained = being_seed._read(operation, limit=2 * being_seed.MAX_SELECTION + being_seed.MAX_RECORD)
            if (set(retained) != {'schema', 'command', 'before', 'candidate'}
                    or retained['schema'] != 'cluster-onboarding-group-selection-operation/v1'
                    or retained['command'] != command or retained['candidate'] != candidate):
                raise OnboardingError('onboarding_group_selection_operation_conflict')
            predecessor = retained['before']
        else:
            predecessor = before
        if (None if predecessor is None else digest(predecessor)) != expected_selection_sha256:
            raise OnboardingError('onboarding_group_selection_changed')
        if predecessor is not None:
            if set(predecessor) != {'document', 'binding'}:
                raise OnboardingError('approved_onboarding_group_required')
            verify(predecessor['document'], predecessor['binding'])
            if predecessor['document']['tribe_ref'] != document['tribe_ref']:
                raise OnboardingError('onboarding_group_selection_changed')
        if not operation.exists():
            being_seed._write(operation, dict(schema='cluster-onboarding-group-selection-operation/v1',
                command=command, before=predecessor, candidate=candidate),
                limit=2 * being_seed.MAX_SELECTION + being_seed.MAX_RECORD)
        if before != predecessor and before != candidate:
            raise OnboardingError('onboarding_group_selection_changed')
        # A retry after a failed directory fsync must finish durability before
        # replacing the selector, even when the retained operation is readable.
        for directory in (operations, group_root):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        current_application, _ = read_publication(hosted, group_root / 'application')
        if digest(current_application) != document['application_sha256']:
            raise OnboardingError('onboarding_group_selection_changed')
        before = being_seed._read(path, limit=being_seed.MAX_SELECTION) if path.exists() else None
        if before != predecessor and before != candidate:
            raise OnboardingError('onboarding_group_selection_changed')
        if before != candidate:
            being_seed._write(path, candidate, limit=being_seed.MAX_SELECTION)
        else:
            descriptor = os.open(group_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return dict(schema='cluster-onboarding-group-selection-result/v1',
            status='selected', operation_id=operation_id, selection_sha256=digest(candidate),
            application_sha256=document['application_sha256'], receiving_readiness='unobserved')


def _group_public_history(selection: dict, binding: dict, application: dict) -> dict:
    from daimon_matrix import operator_messaging
    reader = getattr(operator_messaging, 'public_authority_history', None)
    if not callable(reader):
        raise OnboardingError('onboarding_group_history_sdk_required')
    owner = binding['body']['being_ref']
    snapshots = {row['manifest']['being_ref']: row for row in application['authorities']
                 if row['manifest']['being_ref'] != owner}
    history = selection['authority_history']
    if not isinstance(history, dict) or set(history) != set(snapshots):
        raise OnboardingError('approved_onboarding_group_history_required')
    try:
        return {ref: reader(snapshot, history[ref]) for ref, snapshot in snapshots.items()}
    except (ValueError, KeyError, TypeError):
        raise OnboardingError('approved_onboarding_group_history_required') from None


def observed_group(target, bundle: dict, *, socket_root: Path | None = None) -> dict | None:
    """Read the body's signed group selection without opening another runtime.

    Called after ordinary receiving identity validation. It proves selection,
    not a model read or delivery, and never reconstructs archived pair routes.
    """
    selected = _group_selection_from_bundle(target.root / 'tribe', bundle)
    if selected is None:
        return None
    return dict(tribe_ref=selected['tribe_ref'], application=selected['directory'],
        visibility=selected['visibility'], socket=str((target.package / 'runtime'
            if socket_root is None else socket_root) / selected['socket']),
        channel_id='tribe')


def _group_selection_from_bundle(directory: Path, bundle: dict) -> dict | None:
    packet = _group_selection_packet_from_bundle(directory, bundle)
    return None if packet is None else packet[0]


def _group_selection_packet_from_bundle(directory: Path, bundle: dict):
    """Verify the fixed receiving selector before opening private runtime state."""
    import time
    from daimon_matrix.canonical import unb64url
    from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
    from daimon_matrix.messaging_config import _public_identity, verify_public_binding
    if not (directory / 'selection.json').exists():
        return None
    authority = authority_from_runtime_bundle(bundle)
    identity = _public_identity(authority, bundle['local_origin'], bundle['runtime_id'],
        bundle['runtime_label'], time.time_ns() // 1000000)
    key = unb64url(authority.credentials[identity['credential_id']]['body']['signing_key']['public'])
    return _approved_group_packet(directory, lambda value, binding:
        verify_public_binding(identity, key, value, binding))


def approved_group_authorities(runtime_root: Path, group_root: Path, bundle: dict) -> dict:
    """Recover the owner-approved group's Root closure without pair enrollment.

    Matrix verifies the selected signed publication against the current local
    bundle and preserves any already-known authority history. No peer discovery,
    native bundle mutation or private custody access is performed here.
    """
    packet = _group_selection_packet_from_bundle(group_root, bundle)
    if packet is None:
        return {}
    selected, histories = packet
    import time
    from daimon_matrix.messaging_config import read_application_authorities
    current = read_application_authorities(runtime_root, 'runtime.json',
        Path(selected['directory']), at_ms=time.time_ns() // 1000000)
    return _group_authorities_with_history(bundle, histories, current)


def _group_authorities_with_history(bundle: dict, histories: dict | None, current: dict) -> dict:
    if histories is None:
        return current
    from daimon_matrix.operator_messaging import public_authority_history
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA
    # Known histories stay in their native bundle. Do not silently truncate or
    # replace an already accepted chain with another valid self-consistent one.
    known = bundle['sources']['known_beings'] if bundle['sources'] else []
    for row in known:
        ref = row['manifest']['being_ref']
        if ref not in histories:
            continue
        native = public_authority_history(dict(schema=AUTHORITY_SCHEMA, **{
            key: row[key] for key in ('manifest', 'control_artifacts', 'control_head',
                                     'credentials', 'incarnations')}), row['authority_history'])
        if histories[ref] != native:
            raise OnboardingError('approved_onboarding_group_history_conflict')
    if any(histories[ref].active != authority for ref, authority in current.items()):
        raise OnboardingError('approved_onboarding_group_history_conflict')
    return {ref: histories[ref] for ref in current}


def augmented(target, original: dict, bundle: dict) -> tuple[dict, bool]:
    """Verify only the exact native additive peer change, not a new identity.

    Current identity observation is separate from historical credential receipt.
    Read relationship evidence through SQLite's read-only URI. Observation does
    not acquire the runtime writer lock, initialize stores, or read an inbox.
    """
    tool = native(target.code, uid=target.code_uid)
    payload = json.loads(onboarding_release.regular(root(target) / 'accepted-private.json', uid=os.geteuid()))
    plan = payload['plan']
    identities = plan['identities']
    authorities = [tool.verify_identity(value) for value in identities]
    own, peer = identities[1]['document'], identities[0]['document']
    if (own['runtime_id'] != original['runtime_id'] or own['origin'] != original['local_origin']
            or own['authority']['manifest'] != original['manifest']
            or own['authority']['credentials'] != original['credentials']
            or own['authority']['incarnations'] != original['incarnations']
            or own['authority']['control_artifacts'] != original['control_artifacts']
            or own['authority']['control_head'] != original['control_head']
            or own['authority_history'] != original['authority_history']
            or authorities[0].state.being_ref == authorities[1].state.being_ref):
        raise OnboardingError('existing_onboarding_target_preserved')
    expected = copy.deepcopy(original)
    known = {key: value for key, value in peer['authority'].items() if key != 'schema'}
    # uuid validation prevents a peer plan from choosing a private path.
    import uuid
    uuid.UUID(plan['link_id'])
    known.update(authority_history=peer['authority_history'], ledger_filename='peer-' + plan['link_id'] + '.sqlite')
    if expected['sources'] is None:
        expected['sources'] = dict(cas_filename='sources.sqlite3', known_beings=[])
    peers = expected['sources']['known_beings']
    successor_path = root(target) / 'authority-successor.json'
    successor_authority = None
    prior_known = copy.deepcopy(known)
    pending = False
    if successor_path.exists():
        known, prior_known, successor_authority, selected = _authority_selections(
            target, tool, identities[1], known)
        succession = selected['document']
    matching = [row for row in peers if row['manifest']['being_ref'] == authorities[0].state.being_ref]
    if matching and matching != [known]:
        raise OnboardingError('existing_onboarding_target_preserved')
    if not matching:
        peers.append(known)
    if expected['relationships'] is None:
        expected['relationships'] = dict(store_filename='relationships.sqlite3', known_being_refs=[])
    refs = expected['relationships']['known_being_refs']
    if authorities[0].state.being_ref not in refs:
        refs.append(authorities[0].state.being_ref)
        refs.sort()
    expected = additional_bundle(target, expected, identities[1])
    if bundle != expected:
        prior = copy.deepcopy(expected)
        prior['sources']['known_beings'] = [prior_known if row['manifest']['being_ref'] == authorities[0].state.being_ref else row
            for row in prior['sources']['known_beings']]
        if successor_authority is None or bundle != prior:
            raise OnboardingError('existing_onboarding_target_preserved')
        pending = True
    from daimon_matrix.weave import verify_event
    from daimon_matrix.relationship_store import RelationshipView
    from daimon_matrix.runtime import verify_relationship_card_authority
    by_being = {authority.state.being_ref: authority for authority in authorities}
    events = payload['signed_events']
    if (len(events) != len(plan['events']) or any(
            {k: v for k, v in event.items() if k != 'signature'} !=
            {k: v for k, v in draft.items() if k != 'signature'}
            for event, draft in zip(events, plan['events'], strict=True))):
        raise OnboardingError('native_onboarding_peer_plan_conflict')
    signed = [*plan['prior_cards'], *events]
    for event in signed:
        verify_event(event, by_being[event['being_ref']])
    historical = RelationshipView(signed, at_ms=payload['signed_at_ms'],
        card_verifier=lambda card, at: verify_relationship_card_authority(card,
            by_being[card['being_ref']], at_ms=at))
    snapshot = historical.snapshot(plan['tribe_ref'])
    if len(snapshot.value['members']) != 2 or len(snapshot.value['grants']) != 2:
        raise OnboardingError('native_onboarding_peer_plan_conflict')
    complete = False
    store = target.package / 'runtime' / expected['relationships']['store_filename']
    if store.exists() and (root(target) / 'ready.json').exists():
        onboarding_release.regular(store, uid=os.geteuid())
        with closing(sqlite3.connect(store.as_uri() + '?mode=ro', uri=True)) as database:
            retained = [json.loads(row[0]) for row in database.execute('SELECT event_json FROM events')]
        complete = all(event in retained for event in signed)
        ready = json.loads(onboarding_release.regular(root(target) / 'ready.json', uid=os.geteuid()))
        application = root(target) / 'application'
        visibility = root(target) / 'visibility/installation.json'
        if (ready['link_id'] != plan['link_id'] or ready['app_directory'] != str(application)
                or ready['runtime_root'] != str(target.package / 'runtime')
                or ready['visibility_installation'] != str(visibility)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        from daimon_matrix.messaging_config import _read_publication, verify_visibility_participant
        try:
            app, metadata = _read_publication(application,
                lambda value, binding: tool.verify_document(identities[1], value, binding))
        except ValueError:
            raise OnboardingError('native_onboarding_peer_plan_conflict') from None
        approved_authorities = [value['document']['authority'] for value in identities]
        if successor_authority is not None:
            approved_authorities[0] = succession['authority']
        if digest(app) != ready['application_sha256']:
            publication = json.loads(onboarding_release.regular(application / 'publication.json', uid=os.geteuid()))
            if successor_authority is None or publication['body']['predecessor_sha256'] != ready['application_sha256']:
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            pending = True
        if app['authorities'] != approved_authorities:
            prior_authorities = [dict(schema='dm.operator.authority/v1', **{
                key: value for key, value in prior_known.items()
                if key not in {'authority_history', 'ledger_filename'}}), identities[1]['document']['authority']]
            if successor_authority is None or app['authorities'] != prior_authorities:
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            approved_authorities = app['authorities']
            pending = True
        from urllib.parse import urlsplit
        endpoint = urlsplit(plan['endpoints'][1])
        rules = tool.policies(plan)
        if (app['listen'] != dict(host=endpoint.hostname, port=endpoint.port)
                or app['authorities'] != approved_authorities
                or app['relationship_events'] != signed
                or app['relationship_mode'] != dict(mode='shared', runtime_id=original['runtime_id'],
                    state_root=str(target.package / 'runtime'), store_filename=store.name)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        for direction, actor, recipient in (('incoming', 0, 1), ('outgoing', 1, 0)):
            channel = app[direction]
            if (channel['channel_id'] != ('peer-in' if direction == 'incoming' else 'peer-out')
                    or channel['recipient_being_ref'] != authorities[recipient].state.being_ref
                    or channel['recipient_credential_id'] != rules[recipient]['peer_credential_id']
                    or channel['policy'] != rules[actor]):
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            for phase in ('evidence', 'message'):
                route = channel['routes'][phase]
                name = f'{recipient}-{phase}.key'
                secret = tool.unb64url(payload['route_keys'][name], length=32)
                if route != dict(provider_ref=f"provider:link:{plan['link_id']}:{recipient}:{phase}",
                        route_ref=f"route:link:{plan['link_id']}:{recipient}:{phase}",
                        key_ref=f"key:link:{plan['link_id']}:{recipient}:{phase}", secret_file=name,
                        secret_sha256=hashlib.sha256(secret).hexdigest(),
                        endpoint=plan['endpoints'][recipient] + '/dm-messaging/v1/' + phase):
                    raise OnboardingError('native_onboarding_peer_plan_conflict')
        installed = json.loads(onboarding_release.regular(visibility, uid=os.geteuid()))
        document = installed['document']
        tool.verify_document(identities[1], document, installed['binding'])
        disclosure = tool.disclosures(plan)[1]
        beings = [authority.state.being_ref for authority in authorities]
        # The preserved ceremony pins audience and scope, while every participant
        # may sign a maintained presentation successor for that same disclosure.
        # Requiring its original bytes would prevent an admitted body restarting
        # after the SDK's two-party presentation update.
        from daimon_matrix.telegram_mirror import REPRESENTATIONS
        current = document['disclosure']
        expected_disclosure = copy.deepcopy(disclosure)
        expected_disclosure['destination']['representation'] = current['destination']['representation']
        expected_disclosure['issued_at_ms'] = current['issued_at_ms']
        acceptance = document['acceptance_set']
        bindings = acceptance['bindings']
        if document['application_sha256'] != digest(app):
            if successor_authority is None or document['application_sha256'] != ready['application_sha256']:
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            pending = True
        if (document['runtime_id'] != original['runtime_id']
                or current != expected_disclosure
                or current['destination']['representation'] not in REPRESENTATIONS
                or type(current['issued_at_ms']) is not int
                or not disclosure['issued_at_ms'] <= current['issued_at_ms'] <= tool.now()
                or not isinstance(bindings, list) or len(bindings) != len(beings)
                or acceptance != dict(schema='dm.messaging.visibility-acceptance-set/v1',
                    disclosure_sha256=digest(current), bindings=bindings)
                or document['telegram_qualification'] != payload['telegram_qualification']
                or any(document['policy'][key] != current['destination'][key] for key in plan['destination'])
                or document['policy']['acceptance_digest'] != digest(acceptance)):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        for being, binding in zip(sorted(beings), bindings, strict=True):
            if binding['body']['being_ref'] != being:
                raise OnboardingError('native_onboarding_peer_plan_conflict')
            authority = successor_authority if being == beings[0] and successor_authority is not None else authorities[beings.index(being)]
            verify_visibility_participant(authority, being, current, binding, at_ms=tool.now())
        for actor in (0, 1):
            tool.verify_document(identities[actor], disclosure, payload['visibility_bindings'][actor][1])
        secrets = document['secrets']
        if secrets['telegram_token_file'] != 'telegram.token' or secrets['proof_key_file'] != 'proof.key':
            raise OnboardingError('native_onboarding_peer_plan_conflict')
        token = onboarding_release.regular(visibility.parent / 'telegram.token', uid=os.geteuid())
        proof = onboarding_release.regular(visibility.parent / 'proof.key', uid=os.geteuid())
        if (token != tool.unb64url(payload['telegram_token'])
                or hashlib.sha256(token).hexdigest() != secrets['telegram_token_sha256']
                or len(proof) != 32 or document['policy']['proof_key_id'] != 'sha256:' + hashlib.sha256(proof).hexdigest()):
            raise OnboardingError('native_onboarding_peer_plan_conflict')
    receipt = dict(schema='cluster-onboarding-peer-runtime-observation/v1', plan_digest=digest(target.plan),
        origin=bundle['local_origin'], runtime_sha256=digest(bundle),
        credential_runtime_sha256=digest(original), link_id=plan['link_id'],
        peer_being_ref=authorities[0].state.being_ref)
    return receipt, complete and not pending


def adopt_authority(target, authority: dict, history: list, *, native_visibility: Path | None = None) -> dict:
    """Resume an existing signed link's successor, with no second ceremony."""
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.messaging_config import create_binding, config_digest, read_document
    from daimon_matrix.operator_messaging import (
        _reissue_installation, adopt_peer_authority, known_peer_successor, republish,
    )
    from daimon_matrix.keystore import _atomic_write

    tool = native(target.code, uid=target.code_uid)
    directory = private_directory(root(target))
    selected = directory / 'authority-successor.json'
    proposal = dict(authority=authority, authority_history=history)
    with target._runtime_writer():
        # Original receiving/custody checks remain in Target.observe, including
        # partial successor states that the same observer now reports unready.
        if target.observe()['phase'] not in {'v8', 'peer-published'}:
            raise OnboardingError('current_onboarding_target_required')
        runtime = loaded(target)
        being = authority['manifest']['being_ref']
        rows = target.document_bundle()['sources']['known_beings']
        previous = [row for row in rows if row['manifest']['being_ref'] == being]
        if len(previous) != 1:
            raise OnboardingError('approved_onboarding_peer_required')
        try:
            known_peer_successor(previous[0], authority, history)
        except Exception:
            raise OnboardingError('onboarding_peer_successor_conflict') from None
        if selected.exists():
            packet = read_document(selected)
            payload = packet['document']
            if {key: payload[key] for key in ('authority', 'authority_history')} != proposal:
                # A next selection may replace only a fully accepted generation.
                if target.observe()['phase'] != 'v8':
                    raise OnboardingError('onboarding_peer_successor_conflict')
                accepted = tool.authority_from_document(payload['authority'])
                if previous[0]['manifest'] != accepted.manifest.value:
                    raise OnboardingError('onboarding_peer_successor_conflict')
                packet_hash = config_digest(packet)
                archive = directory / ('authority-successor-' + packet_hash + '.json')
                if archive.exists() and read_document(archive) != packet:
                    raise OnboardingError('onboarding_peer_successor_conflict')
                _atomic_write(archive, canonical_bytes(packet))
                proposal['previous_selection_sha256'] = packet_hash
                _atomic_write(selected, canonical_bytes(dict(document=proposal,
                    binding=create_binding(runtime, proposal))))
        else:
            _atomic_write(selected, canonical_bytes(dict(document=proposal,
                binding=create_binding(runtime, proposal))))
        adopt_peer_authority(runtime, authority, history)
        current = loaded(target)
        if native_visibility is not None:
            _reissue_installation(current, native_visibility,
                application_sha256=config_digest(target.document_bundle()))
        result = republish(current, directory / 'application',
            installation=directory / 'visibility/installation.json', peer_being_refs=[being])
        ready_path = directory / 'ready.json'
        ready = read_document(ready_path)
        ready['application_sha256'] = result['application_sha256']
        _atomic_write(ready_path, canonical_bytes(ready))
        observed = target.observe()
        if observed['phase'] != 'v8':
            raise OnboardingError('native_onboarding_peer_incomplete')
        receipt = dict(schema='cluster-onboarding-peer-authority-adoption/v1',
            plan_digest=digest(target.plan), peer_being_ref=being,
            manifest_hash=config_digest(authority['manifest']),
            manifest_revision=authority['manifest']['revision'],
            runtime_sha256=config_digest(target.document_bundle()),
            application_sha256=result['application_sha256'], status='current')
        _atomic_write(directory / 'authority-adoption.json', canonical_bytes(dict(
            document=receipt, binding=create_binding(current, receipt))))
        return receipt
