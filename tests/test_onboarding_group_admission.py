"""Native owner requests retain real relationship effects across interrupted ACKs."""
import copy
import os
import time
import uuid
from dataclasses import replace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_group_admission import command, public_authorities, relationship_request, request_packet
from clusterctl.onboarding_target import Target, document
from tests import test_onboarding_group_authorities as group_fixtures

group_source = group_fixtures.group_source


def closure(bundle):
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA
    return {bundle['manifest']['being_ref']: dict(authority=dict(schema=AUTHORITY_SCHEMA,
        **{key: bundle[key] for key in ('manifest', 'control_artifacts', 'control_head',
                                      'credentials', 'incarnations')}), history=bundle['authority_history'])}


def invitation(source, peer_bundle):
    from daimon_matrix.canonical import b64url
    from daimon_matrix.relationships import INVITATION_SCHEMA, invitation_id
    selected = being_seed._read(source.outputs / 'tribe/selection.json')['document']
    bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    nonce = b64url(os.urandom(32))
    invitee = peer_bundle['manifest']['being_ref']
    now = time.time_ns() // 1_000_000
    payload = dict(schema=INVITATION_SCHEMA, tribe_ref=selected['tribe_ref'], founder_epoch=0,
        founder_being_ref=bundle['manifest']['being_ref'], invitee_being_ref=invitee, nonce=nonce,
        invitation_id=invitation_id(tribe=selected['tribe_ref'], founder_epoch=0,
            invitee_being_ref=invitee, nonce=nonce), issued_at_ms=now, expires_at_ms=now + 86_400_000)
    return dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params=dict(payload=payload))


def test_source_and_offline_newcomer_record_real_membership_without_running_group(group_source, tmp_path):
    from daimon_matrix.relationships import MEMBERSHIP_ACCEPTANCE_SCHEMA
    source, first, _peer_authority, peer_bundle, _old = group_source
    target = Target(tmp_path / 'candidate/guest', first.plan,
        document(tmp_path / 'candidate/custody' / digest(first.plan) / 'genesis.json'))
    before = {root: {name: (root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
              for root in (source.root, target.package / 'runtime')}
    request = invitation(source, peer_bundle)
    # The actual founder uses the Target/guest profile here: hosting role does
    # not choose who may invite. Native social authority chooses that role.
    invited = first.group_relationship(request, authority_closure=closure(peer_bundle))
    assert invited['status'] == 'recorded' and invited['native_error'] is None
    event = invited['result']['event']
    assert first.group_relationship(request, authority_closure=closure(peer_bundle)) == invited
    base = source._load(signed=False)
    declaration = next(row for row in base.service.relationships.store.events() if row['kind'] == 'matrix/tribe-declaration')
    authorities = closure(first.document_bundle())
    for step, value in (('declaration', declaration), ('invitation', event)):
        ingested = target.group_relationship(dict(operation_id=request['operation_id'], step=step,
            method='relationship.event.ingest', params=dict(event=value)), authority_closure=authorities)
        assert ingested['status'] == 'recorded'
    acceptance = dict(operation_id=request['operation_id'], step='accept', method='tribe.membership.accept',
        params=dict(payload=dict(schema=MEMBERSHIP_ACCEPTANCE_SCHEMA,
            tribe_ref=request['params']['payload']['tribe_ref'], founder_epoch=0,
            invitation_ref=dict(event_id=event['event_id'], event_hash=event['content_hash']),
            invitee_being_ref=peer_bundle['manifest']['being_ref'], membership_sequence=0,
            previous_membership_terminal_ref=None, accepted_at_ms=time.time_ns() // 1_000_000)))
    accepted = target.group_relationship(acceptance, authority_closure=authorities)
    assert accepted['status'] == 'recorded' and accepted['result']['event']['origin'] == peer_bundle['local_origin']
    assert target.group_relationship(acceptance, authority_closure=authorities) == accepted
    source.group_relationship(dict(operation_id=request['operation_id'], step='acceptance',
        method='relationship.event.ingest', params=dict(event=accepted['result']['event'])),
        offline=True, authority_closure=closure(peer_bundle))
    hosted = source._load(signed=False, relationship_authorities=public_authorities(
        first.document_bundle(), closure(peer_bundle)))
    view = hosted.service.relationships.store.view(at_ms=time.time_ns() // 1_000_000,
        card_verifier=hosted.service.relationships.card_verifier)
    tribe = view.tribes[request['params']['payload']['tribe_ref']]
    assert tribe['memberships'][peer_bundle['manifest']['being_ref']]['state'] == 'active'
    assert not (target.package / 'runtime/matrix.sock').exists()
    assert not (target.root / 'tribe/selection.json').exists()
    for root, original in before.items():
        assert {name: (root / name).read_bytes() for name in original} == original
    with target._runtime_writer(), pytest.raises(BlockingIOError):
        target.group_relationship(acceptance, authority_closure=authorities)


def test_lost_native_reply_retries_original_stale_frame_without_another_event(group_source, monkeypatch):
    from daimon_matrix.service import HostedWeave
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'
    original = HostedWeave.handle

    def lost(self, value):
        original(self, value)
        raise OSError('synthetic lost native response')

    monkeypatch.setattr(HostedWeave, 'handle', lost)
    with source.writer(), pytest.raises(OSError, match='synthetic lost'):
        relationship_request(source.root, journal, request, offline=base)
    frame = being_seed._read(path)['request']
    events = base.service.ledger.events()
    assert any(row['request_id'] == frame['request_id'] and row['state'] == 'completed'
               for row in base.service.ledger.rpc_requests())
    monkeypatch.setattr(HostedWeave, 'handle', original)
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    with source.writer():
        result = relationship_request(source.root, journal, request, offline=late)
    assert result['status'] == 'recorded'
    retained = being_seed._read(path)
    assert retained['request'] == frame and retained['retired_requests'] == []
    assert base.service.ledger.events() == events
    changed = copy.deepcopy(request)
    changed['params']['payload']['expires_at_ms'] += 1
    with source.writer(), pytest.raises(OnboardingError, match='request_conflict'):
        relationship_request(source.root, journal, changed, offline=late)
    retained['response']['auth']['value'] = 'A' * 43
    being_seed._write(path, retained)
    with source.writer(), pytest.raises(ValueError, match='invalid_local_response'):
        relationship_request(source.root, journal, request, offline=late)


def test_expired_unsubmitted_frame_renews_only_after_exclusive_native_absence(group_source, monkeypatch):
    from daimon_matrix.service import HostedWeave
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'
    original = HostedWeave.handle

    def not_submitted(self, value):
        raise OSError('synthetic stop before native dispatch')

    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, request, offline=base)
    frame = being_seed._read(path)['request']
    assert not any(row['request_id'] == frame['request_id'] for row in base.service.ledger.rpc_requests())
    monkeypatch.setattr(HostedWeave, 'handle', original)
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    with source.writer():
        result = relationship_request(source.root, journal, request, offline=late)
    retained = being_seed._read(path)
    assert result['status'] == 'recorded' and retained['retired_requests'] == [frame]
    assert retained['request']['request_id'] == frame['request_id']
    assert retained['request']['issued_at_ms'] == frame['issued_at_ms'] + 61_000
    assert retained['request'] != frame
    assert len([row for row in base.service.ledger.rpc_requests() if row['request_id'] == frame['request_id']]) == 1
    # A different native row is not absence and must never refresh the frame.
    conflicting = invitation(source, peer_bundle)
    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, conflicting, offline=base)
    path = journal / conflicting['operation_id'] / 'invite.json'
    saved = being_seed._read(path)
    frame = saved['request']
    with source.writer():
        base.service.ledger.begin_rpc(client_id=frame['client_id'], request_id=frame['request_id'],
            request_hash='0' * 64, method=frame['method'])
    late = replace(base, service=replace(base.service, clock=lambda: frame['issued_at_ms'] + 61_000))
    monkeypatch.setattr(HostedWeave, 'handle', original)
    with source.writer(), pytest.raises(OnboardingError, match='request_conflict'):
        relationship_request(source.root, journal, conflicting, offline=late)
    assert being_seed._read(path) == saved


def test_closed_commands_and_packets_reject_unrelated_methods_and_paths():
    value = dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params={})
    assert command(value) == value
    for invalid in ({**value, 'step': '../escape'}, {**value, 'method': 'messaging.send'},
                    {**value, 'operation_id': True}, {**value, 'extra': True}):
        with pytest.raises(OnboardingError, match='command_required'):
            command(invalid)
    for invalid in ({'command': value}, dict(command=value, offline=1, authority_closure={}),
                    dict(command=value, offline=True, authority_closure={}, extra=True)):
        with pytest.raises(OnboardingError, match='command_required'):
            request_packet(invalid)
    assert request_packet(dict(command=value, offline=True, authority_closure={}))['command'] == value


def test_missing_or_replaced_ledger_cannot_turn_uncertainty_into_absence(group_source, monkeypatch):
    from daimon_matrix.ledger import Ledger
    from daimon_matrix.service import HostedWeave, ServiceError
    source, _target, _peer, peer_bundle, _old = group_source
    base = source._load(signed=False)
    request = invitation(source, peer_bundle)
    journal = source.outputs / 'group-admission'
    path = journal / request['operation_id'] / 'invite.json'

    def not_submitted(self, value):
        raise OSError('synthetic stop before dispatch')

    monkeypatch.setattr(HostedWeave, 'handle', not_submitted)
    with source.writer(), pytest.raises(OSError, match='synthetic stop'):
        relationship_request(source.root, journal, request, offline=base)
    retained = being_seed._read(path)
    ledger = base.service.ledger.path
    saved = ledger.with_name(ledger.name + '.saved')
    reader = source._reader
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('missing/replaced ledger reached private runtime load'))
    ledger.rename(saved)
    try:
        with pytest.raises(FileNotFoundError):
            source.group_relationship(request, offline=True)
        assert not ledger.exists() and being_seed._read(path) == retained
        ledger.write_bytes(b'foreign replacement must not initialize')
        ledger.chmod(0o600)
        with pytest.raises(OnboardingError, match='ledger_changed'):
            source.group_relationship(request, offline=True)
        assert ledger.read_bytes() == b'foreign replacement must not initialize'
        assert being_seed._read(path) == retained
    finally:
        ledger.unlink(missing_ok=True)
        saved.rename(ledger)
    monkeypatch.setattr(source, '_reader', reader)
    original = Ledger.rpc_requests

    def removed_after_inventory(self):
        rows = original(self)
        self.path.rename(saved)
        return rows

    monkeypatch.setattr(Ledger, 'rpc_requests', removed_after_inventory)
    late = replace(base, service=replace(base.service,
        clock=lambda: retained['request']['issued_at_ms'] + 61_000))
    try:
        with source.writer(), pytest.raises(ServiceError, match='loaded_store_replaced'):
            relationship_request(source.root, journal, request, offline=late)
        assert not ledger.exists() and being_seed._read(path) == retained
    finally:
        saved.rename(ledger)
