"""Owner publication routes use native SDK effects, preserving exact retries."""
import copy
import hashlib
import json
import os
import time
import uuid

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_group_admission import publication_command, request_packet
from clusterctl.onboarding_source import Source
from clusterctl.onboarding_target import Target, document
from tests import test_onboarding_group_authorities as group_fixtures
from tests.test_onboarding_group_admission import closure, invitation

group_source = group_fixtures.group_source


@pytest.fixture
def unicode_group_source(tmp_path):
    root = tmp_path / 'mémoire'
    root.mkdir(mode=0o700)
    return group_source.__wrapped__(root)


def initial_publication(group_source, profile):
    from daimon_matrix.messaging_config import read_publication
    source, target, _peer, _peer_bundle, _old = group_source
    base = source._load(signed=False)
    specification, _ = read_publication(base, source.outputs / 'tribe/application')
    specification.pop('client')
    # This first-publication boundary uses the already genuine synthetic Root
    # and its one active founder. Full new-member admission remains a separate
    # integrated scenario; no new being or acceptance is fabricated here.
    specification['authorities'] = [row for row in specification['authorities']
        if row['manifest']['being_ref'] == target.document_bundle()['manifest']['being_ref']]
    if profile == 'source':
        owner = Source({**source.settings, 'outputs': str(source.outputs / 'new-group-owner')})
        group = owner.outputs / 'tribe'
        journal = owner.outputs / 'group-admission'
    else:
        owner = target
        group = target.root / 'tribe'
        journal = target.root / 'group-admission'
    identifier = str(uuid.uuid4())
    request = dict(operation_id=identifier, step='application', action='application',
        params=dict(expected_application_sha256=None, specification=specification, additions=None,
            admitted_being_refs=[], secret_sources={'route.key': str(source.outputs / 'route.key')}))
    return owner, group, journal, request, base


@pytest.mark.parametrize('profile', ['source', 'target'])
def test_context_preview_is_read_only_and_pins_the_later_native_writer(group_source, monkeypatch, profile):
    source, target, _peer, peer_bundle, _old = group_source
    owner = source if profile == 'source' else target
    group = source.outputs / 'tribe' if profile == 'source' else target.root / 'tribe'
    journal = source.outputs / 'group-admission' if profile == 'source' else target.root / 'group-admission'
    runtime = source.root if profile == 'source' else target.package / 'runtime'
    request = invitation(source, peer_bundle)
    preview = dict(operation_id=request['operation_id'], step='context', action='context-preview', params={})
    approved = closure(peer_bundle)
    before = {path: path.read_bytes() for path in runtime.rglob('*') if path.is_file()}
    with monkeypatch.context() as read_only:
        def forbidden(*_args, **_kwargs):
            pytest.fail('context preparation must not acquire a writer, open custody or create an event')
        read_only.setattr(owner, 'writer' if profile == 'source' else '_runtime_writer', forbidden)
        read_only.setattr(owner, '_reader', forbidden)
        result = owner.group_publication(preview, authority_closure=approved)
        assert owner.group_publication(preview, authority_closure=approved) == result
    assert result['schema'] == 'cluster-group-owner-context-preview/v1'
    assert result['receiving_readiness'] == 'unobserved'
    assert not (journal / request['operation_id']).exists()
    assert {path: path.read_bytes() for path in before} == before
    assert result['predecessor_selection_sha256'] == (
        digest(being_seed._read(group / 'selection.json')) if (group / 'selection.json').exists() else None)
    options = dict(authority_closure=approved, **({'offline': True} if profile == 'source' else {}))
    with monkeypatch.context() as mismatch:
        mismatch.setattr(owner, '_reader', lambda: pytest.fail('changed preparation reached custody'))
        with pytest.raises(OnboardingError, match='owner_context_conflict'):
            owner.group_relationship(request, expected_context_sha256='0'*64, **options)
    assert not (journal / request['operation_id'] / 'owner/context.json').exists()
    accepted = owner.group_relationship(request, expected_context_sha256=result['owner_context_sha256'], **options)
    assert accepted['status'] == 'recorded' and accepted['native_error'] is None
    context = being_seed._read(journal / request['operation_id'] / 'owner/context.json')
    assert digest(context) == result['owner_context_sha256']
    assert owner.group_relationship(request, expected_context_sha256=result['owner_context_sha256'], **options) == accepted


@pytest.mark.parametrize('failure', ['deadline', 'ledger-drift'])
def test_context_preview_refuses_expiry_or_concurrent_identity_drift(group_source, monkeypatch, failure):
    from types import SimpleNamespace
    from clusterctl import onboarding_group_admission as admission
    source, _target, _peer, peer_bundle, _old = group_source
    identifier = str(uuid.uuid4())
    original = admission._ledger_identity
    calls, clock = [], [1]
    def identity(root, bundle):
        result = original(root, bundle)
        calls.append(True)
        if failure == 'ledger-drift' and len(calls) == 2:
            result['file_identity'][-1] += 1
        if failure == 'deadline':
            clock[0] = 11
        return result
    monkeypatch.setattr(admission, '_ledger_identity', identity)
    monkeypatch.setattr(admission, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0]))
    with pytest.raises(OnboardingError, match='deadline_expired' if failure == 'deadline' else 'context_conflict'):
        admission.preview_owner_context(source.root, source.outputs / 'tribe', identifier,
            closure(peer_bundle), deadline_ns=10)
    assert not (source.outputs / 'group-admission' / identifier).exists()


@pytest.mark.parametrize('profile', ['source', 'target'])
def test_native_first_publication_signatures_and_selector_recover_exact_lost_replies(unicode_group_source, monkeypatch, profile):
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import read_publication, verify_binding
    group_source = unicode_group_source
    source, target, *_ = group_source
    owner, group, journal, request, base = initial_publication(group_source, profile)
    identifier = request['operation_id']
    native = {name: (source.root / name).read_bytes() for name in ('runtime.json', 'custody.json')}
    prepare = operator_messaging.prepare

    def lost_prepare(*args, **kwargs):
        prepare(*args, **kwargs)
        raise OSError('synthetic lost native prepare reply')

    monkeypatch.setattr(operator_messaging, 'prepare', lost_prepare)
    with pytest.raises(OSError, match='lost native prepare'):
        owner.group_publication(request, authority_closure={})
    path = journal / identifier / 'publications/application.json'
    assert being_seed._read(path)['result'] is None
    _document, metadata = read_publication(base, group / 'application')
    client = {name: (metadata / name).read_bytes() for name in ('client.json', 'client.key')}
    monkeypatch.setattr(operator_messaging, 'prepare',
        lambda *args, **kwargs: pytest.fail('retry reminted an already published client'))
    prepared = owner.group_publication(request, authority_closure={})
    assert prepared['receiving_readiness'] == 'unobserved'
    assert not {'capability_id', 'client', 'client_key', 'client_config'} & set(prepared)
    assert owner.group_publication(request, authority_closure={}) == prepared
    assert {name: (metadata / name).read_bytes() for name in client} == client
    changed = copy.deepcopy(request)
    changed['params']['specification']['tribe']['policy']['max_ttl_ms'] -= 1
    with pytest.raises(OnboardingError, match='publication_intent_conflict'):
        owner.group_publication(changed, authority_closure={})

    destination = dict(bot_id=1, chat_id=-123, topic_id=None, representation='compact-text/v1')
    disclosure = owner.group_publication(dict(operation_id=identifier, step='disclosure',
        action='visibility-disclosure', params=dict(approved_destination=destination,
            issued_at_ms=time.time_ns() // 1_000_000)), authority_closure={})['disclosure']
    signing = dict(operation_id=identifier, step='accept-visibility', action='visibility-accept',
                   params=dict(approved_destination=destination, disclosures=[disclosure]))
    accepted = owner.group_publication(signing, authority_closure={})
    binding = accepted['bindings'][0]['binding']
    verify_binding(base, disclosure, binding)
    assert binding['body']['being_ref'] == target.document_bundle()['manifest']['being_ref']
    assert owner.group_publication(signing, authority_closure={}) == accepted

    visibility = group / 'visibility'
    visibility.mkdir(mode=0o700)
    token, proof = b'1:SYNTHETIC_NOT_A_TOKEN', os.urandom(32)
    for name, raw in (('telegram.token', token), ('proof.key', proof)):
        path = visibility / name
        path.write_bytes(raw)
        path.chmod(0o600)
    # Explicit synthetic qualification data exercises native publication only;
    # it is not an observed Telegram probe or a real communication receipt.
    configuration = dict(destination=destination,
        secrets=dict(telegram_token_file='telegram.token', telegram_token_sha256=hashlib.sha256(token).hexdigest(),
            proof_key_file='proof.key'),
        telegram_qualification=dict(schema='dm.messaging.telegram-qualification/v1',
            qualified_at_ms=disclosure['issued_at_ms'], token_sha256=hashlib.sha256(token).hexdigest(),
            get_me_bot_id=1, probe_chat_id=-123, probe_topic_id=None, probe_message_id=1,
            probe_text_sha256='b' * 64))
    published_visibility = owner.group_publication(dict(operation_id=identifier, step='visibility',
        action='visibility-publish', params=dict(disclosure=disclosure, bindings=[binding],
            expected_installation_sha256=None, initial_configuration=configuration)), authority_closure={})

    selection = dict(operation_id=identifier, step='select', action='selection',
                     params=dict(expected_selection_sha256=None))
    write = being_seed._write
    def lost_selection(path, *args, **kwargs):
        write(path, *args, **kwargs)
        if path == group / 'selection.json':
            raise OSError('synthetic lost selection reply')
    monkeypatch.setattr(being_seed, '_write', lost_selection)
    with pytest.raises(OSError, match='lost selection'):
        owner.group_publication(selection, authority_closure={})
    selected = (group / 'selection.json').read_bytes()
    monkeypatch.setattr(being_seed, '_write', write)
    result = owner.group_publication(selection, authority_closure={})
    assert result['selection_sha256'] == digest(being_seed._read(group / 'selection.json'))
    assert result['receiving_readiness'] == 'unobserved'
    assert (group / 'selection.json').read_bytes() == selected
    snapshot_request = dict(operation_id=identifier, step='snapshot', action='snapshot', params=dict(
        application_step='application', visibility_step='visibility', selection_step='select',
        owner_context_sha256=digest(being_seed._read(journal / identifier / 'owner/context.json')),
        expected_stores={role: json.loads(item.observation) for role, item in base.service.loaded_stores.items()}))
    snapshot_path = journal / identifier / 'publications/snapshot.json'
    def lost_snapshot(path, value, **kwargs):
        write(path, value, **kwargs)
        if path == snapshot_path and value.get('result') is not None:
            raise OSError('synthetic lost snapshot result reply')
    monkeypatch.setattr(being_seed, '_write', lost_snapshot)
    with pytest.raises(OSError, match='lost snapshot'):
        owner.group_publication(snapshot_request, authority_closure={})
    retained_snapshot = snapshot_path.read_bytes()
    monkeypatch.setattr(being_seed, '_write', write)
    snapshot = owner.group_publication(snapshot_request, authority_closure={})
    assert snapshot_path.read_bytes() == retained_snapshot
    assert snapshot['group']['application_sha256'] == prepared['application_sha256']
    assert snapshot['group']['publication_sha256'] == prepared['publication_sha256']
    assert snapshot['group']['installation_sha256'] == published_visibility['installation_sha256']
    assert snapshot['selection_sha256'] == result['selection_sha256']
    assert set(snapshot['publications']) == {'application', 'visibility-publish', 'selection'}
    from daimon_matrix.messaging_config import config_digest
    application = read_publication(base, group / 'application')[0]
    assert config_digest(application) != digest(application)
    assert owner.group_publication(snapshot_request, authority_closure={}) == snapshot
    wrong_context = copy.deepcopy(snapshot_request)
    wrong_context['params']['owner_context_sha256'] = '0' * 64
    with monkeypatch.context() as checks:
        checks.setattr(owner, '_reader', lambda: pytest.fail('wrong snapshot context reached custody'))
        with pytest.raises(OnboardingError, match='owner_context_conflict'):
            owner.group_publication(wrong_context, authority_closure={})
        missing_context = {**snapshot_request, 'operation_id': str(uuid.uuid4())}
        with pytest.raises(FileNotFoundError):
            owner.group_publication(missing_context, authority_closure={})
        assert not (journal / missing_context['operation_id']).exists()
    installation = visibility / 'installation.json'
    previous_visibility = installation.read_bytes()
    tampered = being_seed._read(installation)
    tampered['document']['generation'] += 1
    being_seed._write(installation, tampered)
    try:
        with pytest.raises(ValueError):
            owner.group_publication(snapshot_request, authority_closure={})
    finally:
        installation.write_bytes(previous_visibility)
    ledger = base.state_root / target.document_bundle()['ledger']
    saved_ledger = ledger.with_name('retained-snapshot-test-ledger')
    ledger.rename(saved_ledger)
    try:
        with monkeypatch.context() as checks:
            checks.setattr(owner, '_reader', lambda: pytest.fail('missing/replaced store reached custody'))
            with pytest.raises(OnboardingError, match='store_binding_changed'):
                owner.group_publication(snapshot_request, authority_closure={})
            assert not ledger.exists()
            ledger.write_bytes(saved_ledger.read_bytes())
            ledger.chmod(0o600)
            with pytest.raises(OnboardingError, match='store_binding_changed'):
                owner.group_publication(snapshot_request, authority_closure={})
    finally:
        ledger.unlink(missing_ok=True)
        saved_ledger.rename(ledger)
    legacy_request = copy.deepcopy(snapshot_request)
    legacy_request['step'] = 'legacy-snapshot'
    del legacy_request['params']['expected_stores']
    owner.group_publication(legacy_request, authority_closure={})
    legacy_path = journal / identifier / 'publications/legacy-snapshot.json'
    legacy = being_seed._read(legacy_path)
    del legacy['result']['stores']
    being_seed._write(legacy_path, legacy)
    assert owner.group_publication(legacy_request, authority_closure={}) == legacy['result']
    wrong_steps = copy.deepcopy(snapshot_request)
    wrong_steps.update(step='wrong-snapshot')
    wrong_steps['params']['visibility_step'] = 'disclosure'
    with pytest.raises(OnboardingError, match='snapshot_publication_required'):
        owner.group_publication(wrong_steps, authority_closure={})
    assert {name: (source.root / name).read_bytes() for name in native} == native
    assert not (source.root / 'tribe.sock').exists()
    with owner.writer() if profile == 'source' else owner._runtime_writer():
        operator_messaging.renew(base, group / 'application', expected_application_sha256=config_digest(application))
    winner = (group / 'application/publication.json').read_bytes()
    with pytest.raises(ValueError):
        owner.group_publication(snapshot_request, authority_closure={})
    assert (group / 'application/publication.json').read_bytes() == winner


def test_pending_initial_publication_preserves_a_later_native_client_renewal(group_source, monkeypatch):
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import config_digest, read_publication
    owner, group, journal, request, base = initial_publication(group_source, 'source')
    prepare = operator_messaging.prepare
    def lost(*args, **kwargs):
        prepare(*args, **kwargs)
        raise OSError('synthetic lost first prepare reply')
    monkeypatch.setattr(operator_messaging, 'prepare', lost)
    with pytest.raises(OSError, match='first prepare'):
        owner.group_publication(request, authority_closure={})
    before, _ = read_publication(base, group / 'application')
    with owner.writer():
        operator_messaging.renew(base, group / 'application', expected_application_sha256=config_digest(before))
    current, metadata = read_publication(base, group / 'application')
    winner = (group / 'application/publication.json').read_bytes()
    assert current['client'] != before['client'] and metadata != group / 'application'
    assert {key: row for key, row in current.items() if key != 'client'} == request['params']['specification']
    with pytest.raises(OnboardingError, match='publication_changed'):
        owner.group_publication(request, authority_closure={})
    assert (group / 'application/publication.json').read_bytes() == winner
    path = journal / request['operation_id'] / 'publications/application.json'
    assert being_seed._read(path)['result'] is None


def test_native_additive_publication_recovers_its_sdk_predecessor_without_another_client(group_source, tmp_path, monkeypatch):
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import read_publication
    from daimon_matrix.relationships import MEMBERSHIP_ACCEPTANCE_SCHEMA
    source, founder, _peer, peer_bundle, _old = group_source
    owner, group, journal, first, base = initial_publication(group_source, 'source')
    approved = closure(peer_bundle)
    original = owner.group_publication(first, authority_closure=approved)
    identifier = first['operation_id']
    request = {**invitation(source, peer_bundle), 'operation_id': identifier}
    invited = owner.group_relationship(request, offline=True, authority_closure=approved)['result']['event']
    target = Target(tmp_path / 'candidate/guest', founder.plan,
        document(tmp_path / 'candidate/custody' / digest(founder.plan) / 'genesis.json'))
    foreign = closure(founder.document_bundle())
    declaration = next(row for row in base.service.relationships.store.events()
                       if row['kind'] == 'matrix/tribe-declaration')
    for step, event in (('declaration', declaration), ('invitation', invited)):
        assert target.group_relationship(dict(operation_id=identifier, step=step,
            method='relationship.event.ingest', params=dict(event=event)),
            authority_closure=foreign)['status'] == 'recorded'
    acceptance = target.group_relationship(dict(operation_id=identifier, step='accept',
        method='tribe.membership.accept', params=dict(payload=dict(schema=MEMBERSHIP_ACCEPTANCE_SCHEMA,
            tribe_ref=request['params']['payload']['tribe_ref'], founder_epoch=0,
            invitation_ref=dict(event_id=invited['event_id'], event_hash=invited['content_hash']),
            invitee_being_ref=peer_bundle['manifest']['being_ref'], membership_sequence=0,
            previous_membership_terminal_ref=None, accepted_at_ms=time.time_ns() // 1_000_000))),
        authority_closure=foreign)['result']['event']
    assert owner.group_relationship(dict(operation_id=identifier, step='accepted',
        method='relationship.event.ingest', params=dict(event=acceptance)),
        offline=True, authority_closure=approved)['status'] == 'recorded'
    key = source.outputs / 'peer-route.key'
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    route = dict(provider_ref='peer', route_ref='peer', key_ref='peer',
        endpoint='http://127.0.0.1:48676/dm-messaging/v1/message',
        secret_file=key.name, secret_sha256=hashlib.sha256(key.read_bytes()).hexdigest())
    peer = peer_bundle['manifest']['being_ref']
    addition = dict(operation_id=identifier, step='add-member', action='application', params=dict(
        expected_application_sha256=original['application_sha256'], specification=None,
        admitted_being_refs=[peer], secret_sources={key.name: str(key)},
        additions=dict(authorities=[approved[peer]['authority']], relationship_events=[invited, acceptance],
            roster=[dict(being_ref=peer, embodiment_id=peer_bundle['local_origin']['embodiment_id'],
                body_ref=peer_bundle['local_origin']['body_ref'], route=route)])))
    _, previous_metadata = read_publication(base, group / 'application')
    client = {name: (previous_metadata / name).read_bytes() for name in ('client.json', 'client.key')}
    events = base.service.ledger.events()
    admit = operator_messaging.admit_group_application
    def lost(*args, **kwargs):
        admit(*args, **kwargs)
        raise OSError('synthetic lost additive publication reply')
    monkeypatch.setattr(operator_messaging, 'admit_group_application', lost)
    with pytest.raises(OSError, match='lost additive'):
        owner.group_publication(addition, authority_closure=approved)
    current, metadata = read_publication(base, group / 'application')
    assert metadata != previous_metadata
    publication = (group / 'application/publication.json').read_bytes()
    assert being_seed._read(journal / identifier / 'publications/add-member.json')['result'] is None
    monkeypatch.setattr(operator_messaging, 'admit_group_application', admit)
    result = owner.group_publication(addition, authority_closure=approved)
    assert result['application_sha256'] != original['application_sha256']
    assert owner.group_publication(addition, authority_closure=approved) == result
    assert (group / 'application/publication.json').read_bytes() == publication
    assert (metadata / 'client.json').read_bytes() == client['client.json']
    assert (group / 'application/client.key').read_bytes() == client['client.key']
    assert base.service.ledger.events() == events
    assert {row['manifest']['being_ref'] for row in current['authorities']} == {peer, founder.document_bundle()['manifest']['being_ref']}
    disclosure = owner.group_publication(dict(operation_id=identifier, step='expanded-disclosure',
        action='visibility-disclosure', params=dict(approved_destination=dict(bot_id=1,
            chat_id=-123, topic_id=None, representation='compact-text/v1'),
            issued_at_ms=time.time_ns() // 1_000_000)), authority_closure=approved)['disclosure']
    assert set(disclosure['scope']['channels'][0]['participants']) == {peer, founder.document_bundle()['manifest']['being_ref']}


def test_publication_packets_are_closed_and_cannot_use_online_relationship_route():
    value = dict(operation_id=str(uuid.uuid4()), step='select', action='selection',
                 params=dict(expected_selection_sha256=None))
    assert publication_command(value) == value
    assert request_packet(dict(command=value, offline=True, authority_closure={}))['command'] == value
    preview = {**value, 'action': 'context-preview', 'params': {}}
    assert publication_command(preview) == preview
    from clusterctl.onboarding_group_admission import publication_request
    with pytest.raises(OnboardingError, match='preview_is_read_only'):
        publication_request(None, None, None, preview)
    with pytest.raises(OnboardingError, match='writer_required'):
        request_packet(dict(command=value, offline=False, authority_closure={}))
    for changed in ({**value, 'method': 'tribe.invite'},
                    {**value, 'action': 'serve'},
                    {**value, 'params': {**value['params'], 'directory': '/unapproved'}}):
        with pytest.raises(OnboardingError, match='publication_command_required'):
            publication_command(changed)
    initial = {**value, 'action': 'application', 'params': dict(expected_application_sha256=None,
        specification={'schema': 'dm.messaging.application/v1'}, additions=None,
        admitted_being_refs=[], secret_sources={})}
    with pytest.raises(OnboardingError, match='publication_command_required'):
        publication_command(initial)
    snapshot = dict(operation_id=value['operation_id'], step='snapshot', action='snapshot', params=dict(
        application_step='application', visibility_step='visibility', selection_step='selection',
        owner_context_sha256='1' * 64))
    assert publication_command(snapshot) == snapshot
    for step in ('../outside', '/other-owner', '', 1):
        changed = copy.deepcopy(snapshot)
        changed['params']['application_step'] = step
        with pytest.raises(OnboardingError, match='publication_command_required'):
            publication_command(changed)
    with pytest.raises(OnboardingError, match='publication_command_required'):
        publication_command({**snapshot, 'params': {**snapshot['params'], 'expected_stores': {}}})
    with pytest.raises(OnboardingError, match='publication_command_required'):
        publication_command({**snapshot, 'params': {**snapshot['params'], 'expected_preservation': {}}})
