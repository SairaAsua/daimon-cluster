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


@pytest.fixture
def schema_owner(tmp_path):
    from tests.test_onboarding_target import receiving
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
    return target


@pytest.mark.parametrize('boundary', ['prepared', 'intermediate', 'reply'])
def test_initial_schema_owner_phase_resumes_original_plan_and_physical_store(schema_owner, monkeypatch, boundary):
    from daimon_matrix import operator_communication_migration as migration
    from daimon_matrix.communication import CommunicationStore
    from clusterctl.onboarding_group_admission import load_owner_runtime
    owner = schema_owner
    group, journal = owner.root/'tribe', owner.root/'group-admission'
    operation = str(uuid.uuid4())
    runtime = owner.package / 'runtime'
    ledger = runtime / owner.document_bundle()['ledger']
    original = migration.plan(ledger)
    assert original['source_version'] == 1
    identity = (ledger.stat().st_dev, ledger.stat().st_ino)
    original_ledger = load_owner_runtime(runtime, owner._reader, authorities={}).service.ledger
    events = original_ledger.events()
    native = {name:(runtime/name).read_bytes() for name in ('runtime.json', 'custody.json')}
    preview = owner.group_publication(dict(operation_id=operation,
        step='context', action='context-preview', params={}), authority_closure={})
    assert preview['communication_plan'] == original
    request = dict(operation_id=operation, step='communication-prepare',
        action='communication-prepare', params=dict(expected_plan_sha256=original['plan_sha256'],
            expires_at_ms=time.time_ns()//1_000_000+60_000))
    options = dict(authority_closure={}, expected_context_sha256=preview['owner_context_sha256'],
        deadline_ns=time.monotonic_ns()+30_000_000_000)
    write, apply, upgrade = migration._write, migration.apply, CommunicationStore.upgrade_legs_v3
    def interrupted_write(path, value):
        write(path, value)
        if boundary == 'prepared' and path.name == 'prepared.json':
            raise OSError('synthetic schema interruption')
    def interrupted_apply(*args, **kwargs):
        result = apply(*args, **kwargs)
        if boundary == 'reply':
            raise OSError('synthetic schema interruption')
        return result
    def interrupted_upgrade(store):
        if boundary == 'intermediate' and store.ledger.path == ledger:
            raise OSError('synthetic schema interruption')
        return upgrade(store)
    with monkeypatch.context() as fault:
        fault.setattr(migration, '_write', interrupted_write)
        fault.setattr(migration, 'apply', interrupted_apply)
        fault.setattr(CommunicationStore, 'upgrade_legs_v3', interrupted_upgrade)
        with pytest.raises(OSError, match='schema interruption'):
            owner.group_publication(request, **options)
    options['deadline_ns'] = time.monotonic_ns()+30_000_000_000
    if boundary == 'reply':
        # Explicit later-publication path seam; completed history must be
        # recognized before fresh no-application guards, not republished.
        (group/'application').mkdir()
    result = owner.group_publication(request, **options)
    assert owner.group_publication(request, **options) == result
    assert result['migration']['source_plan_sha256'] == original['plan_sha256']
    assert result['migration']['target_version'] == migration.plan(ledger)['source_version'] == 4
    assert (ledger.stat().st_dev, ledger.stat().st_ino) == identity
    assert original_ledger.events() == events
    assert all((runtime/name).read_bytes() == raw for name,raw in native.items())
    assert (group/'application').exists() == (boundary == 'reply')
    assert not (group/'selection.json').exists()
    assert (journal/request['operation_id']/'communication-preparation/migration/completed.json').exists()


@pytest.mark.parametrize('rejection', ['expired', 'plan'])
def test_schema_preparation_refuses_unapproved_effects(schema_owner, rejection):
    from daimon_matrix import operator_communication_migration as migration
    owner = schema_owner
    runtime = owner.package/'runtime'
    ledger = runtime / being_seed._read(runtime/'runtime.json')['ledger']
    before = migration.plan(ledger)
    request = dict(operation_id=str(uuid.uuid4()), step='communication-prepare', action='communication-prepare',
        params=dict(expected_plan_sha256='0'*64 if rejection == 'plan' else before['plan_sha256'],
            expires_at_ms=time.time_ns()//1_000_000+(-1 if rejection == 'expired' else 60_000)))
    expected = 'authorization_expired' if rejection == 'expired' else 'migration_plan_changed'
    with pytest.raises((OnboardingError, migration.MigrationError), match=expected):
        owner.group_publication(request, authority_closure={})
    assert migration.plan(ledger) == before


def test_schema_preparation_refuses_an_existing_group(group_source):
    from daimon_matrix import operator_communication_migration as migration
    source, _target, _peer, peer_bundle, _old = group_source
    ledger = source.root / being_seed._read(source.root/'runtime.json')['ledger']
    before = migration.plan(ledger)
    request = dict(operation_id=str(uuid.uuid4()), step='communication-prepare', action='communication-prepare',
        params=dict(expected_plan_sha256=before['plan_sha256'], expires_at_ms=time.time_ns()//1_000_000+60_000))
    with pytest.raises(OnboardingError, match='initial_schema_required'):
        source.group_publication(request, authority_closure=closure(peer_bundle))
    assert migration.plan(ledger) == before


def test_schema_expiry_during_plan_durability_cannot_begin_ddl(schema_owner, monkeypatch):
    from types import SimpleNamespace
    from daimon_matrix import operator_communication_migration as migration
    from clusterctl import onboarding_group_admission as admission
    from clusterctl.onboarding_service import GuestServiceBootstrap
    owner = schema_owner
    ledger = owner.package/'runtime'/owner.document_bundle()['ledger']
    original = migration.plan(ledger)
    expiry = time.time_ns()//1_000_000+60_000
    clock = [time.time_ns()]
    record = GuestServiceBootstrap._record
    def expire(path, value):
        result = record(path, value)
        if path.name == 'plan.json' and path.parent.name == 'communication-preparation':
            clock[0] = expiry*1_000_000
        return result
    request = dict(operation_id=str(uuid.uuid4()), step='communication-prepare', action='communication-prepare',
        params=dict(expected_plan_sha256=original['plan_sha256'], expires_at_ms=expiry))
    with monkeypatch.context() as fault:
        fault.setattr(admission, 'time', SimpleNamespace(monotonic_ns=time.monotonic_ns, time_ns=lambda: clock[0]))
        fault.setattr(GuestServiceBootstrap, '_record', staticmethod(expire))
        with pytest.raises(OnboardingError, match='authorization_expired'):
            owner.group_publication(request, authority_closure={})
    assert migration.plan(ledger) == original
    assert not (owner.root/'group-admission'/request['operation_id']/'communication-preparation/migration').exists()
    assert owner.group_publication(request, authority_closure={})['migration']['target_version'] == 4


@pytest.mark.parametrize('version', [3, 4])
def test_noop_schema_history_survives_lost_owner_result_later_history_and_publication(schema_owner, monkeypatch, version):
    import sqlite3
    from contextlib import closing
    from daimon_matrix import operator_communication_migration as migration
    from clusterctl.onboarding_group_admission import load_owner_runtime
    owner = schema_owner
    runtime = owner.package/'runtime'
    hosted = load_owner_runtime(runtime, owner._reader, authorities={})
    store = hosted.service.communication
    store.upgrade_receipts_v2()
    store.upgrade_legs_v3()
    if version == 3:
        # Native migration's original healthy-v3 fixture, on an empty store.
        with closing(sqlite3.connect(store.ledger.path)) as database:
            database.execute('DROP TABLE communication_leg_aliases')
            database.execute('DROP TABLE communication_leg_migration')
            database.execute("UPDATE communication_meta SET value='3' WHERE key='schema_version'")
            database.commit()
    original = migration.plan(store.ledger.path)
    assert original['source_version'] == original['target_version'] == version
    identifier = str(uuid.uuid4())
    request = dict(operation_id=identifier, step='communication-prepare', action='communication-prepare',
        params=dict(expected_plan_sha256=original['plan_sha256'], expires_at_ms=time.time_ns()//1_000_000+60_000))
    write = being_seed._write
    result_path = owner.root/'group-admission'/identifier/'publications/communication-prepare.json'
    def lost(path, value, **kwargs):
        if path == result_path and value.get('result') is not None:
            raise OSError('synthetic lost noop result')
        write(path, value, **kwargs)
    with monkeypatch.context() as fault:
        fault.setattr(being_seed, '_write', lost)
        with pytest.raises(OSError, match='lost noop result'):
            owner.group_publication(request, authority_closure={})
    with owner._runtime_writer():
        later = load_owner_runtime(runtime, owner._reader, authorities={})
        event = later.service.ledger.append_local(kind='experience.observed', subject='later schema history',
            payload={'summary':'A genuine later event remains intact.'}, signer=later.service.signer,
            sensitivity='shareable', occurred_at_ms=time.time_ns()//1_000_000)
    (owner.root/'tribe/application').mkdir()  # Later-publication path seam, not a signed group proof.
    result = owner.group_publication(request, authority_closure={})
    assert result['migration'] == original
    assert owner.group_publication(request, authority_closure={}) == result
    assert migration.plan(store.ledger.path)['state_sha256'] != original['state_sha256']
    assert later.service.ledger.events()[-1]['event_id'] == event['event_id']
    assert not (owner.root/'group-admission'/identifier/'communication-preparation/migration').exists()


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


@pytest.mark.parametrize('outcome', ['recover', 'later-winner', 'dispatch-winner', 'visibility-winner'])
def test_cohort_publication_derives_native_acceptance_and_recovers_lost_results(group_source, tmp_path, monkeypatch, outcome):
    """Actual native publications and signed reducers; physical stop is a seam."""
    from clusterctl import onboarding_group_admission as social
    from clusterctl.onboarding_code_successor import plan_update
    from clusterctl.onboarding_receiving_update import CohortController
    from clusterctl.operation_journal import OperationJournal
    from daimon_matrix import operator_messaging
    from daimon_matrix.messaging_config import read_publication

    _original_source, first, _peer, peer_bundle, _old = group_source
    source, group, _owner_journal, initial, native = initial_publication(group_source, 'source')
    baseline = source.group_publication(initial, authority_closure={})
    target = Target(tmp_path / 'candidate/guest', first.plan,
        document(tmp_path / 'candidate/custody' / digest(first.plan) / 'genesis.json'))
    entrant_name = target.plan['name']
    founder_bundle = first.document_bundle()
    founder, entrant = founder_bundle['manifest']['being_ref'], peer_bundle['manifest']['being_ref']
    destination = dict(bot_id=1, chat_id=-123, topic_id=None, representation='compact-text/v1')
    issued = time.time_ns() // 1_000_000
    def configuration(directory):
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
        token, proof = b'1:SYNTHETIC_NOT_A_TOKEN', os.urandom(32)
        for name, raw in (('telegram.token', token), ('proof.key', proof)):
            path = directory / name
            path.write_bytes(raw)
            path.chmod(0o600)
        return dict(destination=destination,
            secrets=dict(telegram_token_file='telegram.token', telegram_token_sha256=hashlib.sha256(token).hexdigest(),
                proof_key_file='proof.key'),
            telegram_qualification=dict(schema='dm.messaging.telegram-qualification/v1', qualified_at_ms=issued,
                token_sha256=hashlib.sha256(token).hexdigest(), get_me_bot_id=1, probe_chat_id=-123,
                probe_topic_id=None, probe_message_id=1, probe_text_sha256='b'*64))
    def baseline_request(step, action, params):
        return source.group_publication(dict(operation_id=initial['operation_id'], step=step,
            action=action, params=params), authority_closure={})
    disclosure = baseline_request('disclosure', 'visibility-disclosure', dict(
        approved_destination=destination, issued_at_ms=issued))['disclosure']
    bindings = baseline_request('accept', 'visibility-accept', dict(
        approved_destination=destination, disclosures=[disclosure]))['bindings']
    visibility = baseline_request('visibility', 'visibility-publish', dict(disclosure=disclosure,
        bindings=[item['binding'] for item in bindings], expected_installation_sha256=None,
        initial_configuration=configuration(group/'visibility')))
    baseline_request('selection', 'selection', dict(expected_selection_sha256=None))
    from clusterctl.onboarding_receiving_update import source_bootstrap_group
    before_group = source_bootstrap_group(source, founder_bundle)
    original_stores = {role:json.loads(binding.observation) for role, binding in native.service.loaded_stores.items()}
    old_selection = digest(being_seed._read(group/'selection.json'))
    application, metadata = read_publication(native, group/'application')
    client = (metadata/'client.json').read_bytes()
    key = (metadata/'client.key').read_bytes()
    peer_key = tmp_path/'peer-route.key'
    peer_key.write_bytes(os.urandom(32))
    peer_key.chmod(0o600)
    route = dict(provider_ref='peer', route_ref='peer', key_ref='peer',
        endpoint='http://127.0.0.1:48676/dm-messaging/v1/message', secret_file=peer_key.name,
        secret_sha256=hashlib.sha256(peer_key.read_bytes()).hexdigest())
    peer_row = dict(being_ref=entrant, embodiment_id=peer_bundle['local_origin']['embodiment_id'],
        body_ref=peer_bundle['local_origin']['body_ref'], route=route)
    operation = str(uuid.uuid4())
    full_closure = {**closure(founder_bundle), **closure(peer_bundle)}
    locals_ = {'founder':source, entrant_name:target}
    roots = {'founder':source.root, entrant_name:target.package/'runtime'}
    bundles = {'founder':founder_bundle, entrant_name:peer_bundle}
    pins = {name: owner.group_publication(dict(operation_id=operation, step='context', action='context-preview', params={}),
        authority_closure={ref: value for ref, value in full_closure.items()
            if ref != bundles[name]['manifest']['being_ref']})['owner_context_sha256'] for name, owner in locals_.items()}
    invite = invitation(source, peer_bundle)['params']['payload']
    declaration = application['relationship_events'][0]
    receivers = {name: dict(being_ref=bundles[name]['manifest']['being_ref'],
        embodiment_id=bundles[name]['local_origin']['embodiment_id'], root=str(root), socket=str(root/'tribe.sock'),
        candidate=dict(code=str(tmp_path/'qualified-code'), code_uid=0),
        recipe=dict(profile='source' if name == 'founder' else 'guest',
            prepared=dict(being_ref=bundles[name]['manifest']['being_ref'],
                embodiment_id=bundles[name]['local_origin']['embodiment_id'], code_digest='a'*64,
                matrix_wheel_sha256='b'*64), tooling={'profile':'matrix-only'})) for name, root in roots.items()}
    sender = dict(name='founder', root=str(source.root), socket=str(source.root/'tribe.sock'),
        being_ref=founder, server=founder_bundle['local_origin'], process={}, gate={})
    admission = dict(schema='cluster-receiving-admission/v1', tribe_ref=invite['tribe_ref'],
        entrant=dict(being_ref=entrant, embodiment_ids=[peer_bundle['local_origin']['embodiment_id']]), receivers=receivers,
        activation=dict(manifest_path=str(tmp_path/'manifest.json'), manifest_uid=0,
            expires_at_ms=invite['expires_at_ms'], observation_window_ms=1000))
    membership = dict(schema='cluster-membership-admission/v1', operation_id=operation,
        founder_owner='founder', entrant_owner=entrant_name, authority_closure=full_closure,
        governance=[declaration], invitation=invite, membership_sequence=0,
        previous_membership_terminal_ref=None, acceptance_not_after_ms=invite['expires_at_ms'], owner_contexts=pins)
    steps = dict(application='application', disclosure='disclosure', acceptance='acceptance',
        visibility='visibility', selection='selection', snapshot='snapshot')
    preparations = dict(founder=dict(profile='source', unit=str(tmp_path/'source.service'), home=str(tmp_path),
        steps={key: steps[key] for key in ('application', 'visibility', 'selection', 'snapshot')}))
    preparations['founder']['steps']['snapshot'] = 'lifecycle-snapshot'
    specification = copy.deepcopy(initial['params']['specification'])
    specification['authorities'] = [full_closure[ref]['authority'] for ref in sorted(full_closure)]
    specification['relationship_mode'].update(runtime_id=peer_bundle['runtime_id'], state_root=str(roots[entrant_name]),
        store_filename=peer_bundle['relationships']['store_filename'])
    specification['tribe']['policy']['membership_ref'] = None
    specification['listen']['port'] = 48676
    specification['intake'] = route
    specification['roster'].append(peer_row)
    owner_recipes = {
        'founder':dict(steps=steps, application=dict(expected_application_sha256=baseline['application_sha256'],
            specification=None, additions=dict(authorities=[full_closure[entrant]['authority']],
                relationship_events=[], roster=[peer_row]), admitted_being_refs=[entrant],
            secret_sources={peer_key.name:str(peer_key)}),
            disclosure=dict(approved_destination=destination, issued_at_ms=issued),
            visibility=dict(expected_installation_sha256=visibility['installation_sha256'], initial_configuration=None),
            selection=dict(expected_selection_sha256=old_selection)),
        entrant_name:dict(steps=steps, application=dict(expected_application_sha256=None, specification=specification,
            additions=None, admitted_being_refs=[], secret_sources={**initial['params']['secret_sources'], peer_key.name:str(peer_key)}),
            disclosure=dict(approved_destination=destination, issued_at_ms=issued),
            visibility=dict(expected_installation_sha256=None, initial_configuration=configuration(target.root/'tribe/visibility')),
            selection=dict(expected_selection_sha256=None))}
    recipe = dict(schema='cluster-admission-publications/v1', owners=owner_recipes, signers={founder:'founder', entrant:entrant_name})
    assert social.publication_recipe(recipe, admission, membership, [sender], preparations) == recipe
    for mutate in (
        lambda value: value['signers'].update({founder:entrant_name}),
        lambda value: value['owners'][entrant_name]['application']['specification']['tribe']['policy'].update(membership_ref='invented'),
        lambda value: value['owners']['founder']['application']['additions']['relationship_events'].append({'invented':True}),
        lambda value: value['owners']['founder']['steps'].update(application='another-child-step'),
        lambda value: value['owners']['founder']['steps'].update(snapshot='lifecycle-snapshot'),
        lambda value: value['owners']['founder']['steps'].update(disclosure='lifecycle-snapshot'),
        lambda value: value['owners'][entrant_name]['steps'].update(disclosure='communication-prepare'),
        lambda value: value['owners'][entrant_name]['disclosure'].update(approved_destination={**destination, 'chat_id':-999}),
        lambda value: value['owners']['founder']['application']['additions'].update(roster=[]),
        lambda value: value['owners'][entrant_name]['application']['specification']['listen'].update(port=0),
        lambda value: value['owners'][entrant_name]['application']['specification'].update(roster=[]),
        lambda value: value['owners'][entrant_name]['application'].update(secret_sources={}),
        lambda value: value['owners'][entrant_name]['visibility']['initial_configuration']['secrets'].update(proof_key_file='../outside'),
        lambda value: value['owners'][entrant_name]['visibility']['initial_configuration']['telegram_qualification'].update(probe_chat_id=-999),
    ):
        changed = copy.deepcopy(recipe)
        mutate(changed)
        with pytest.raises(OnboardingError, match='publication_recipe_required'):
            social.publication_recipe(changed, admission, membership, [sender], preparations)
    calls, fault = [], dict(barrier='stopped', visibility=True, winner=None)
    def renew_application():
        from daimon_matrix.messaging_config import config_digest
        with source.writer():
            current = social.load_owner_runtime(source.root, source._reader,
                authorities=social.public_authorities(founder_bundle, closure(peer_bundle)))
            selected = read_publication(current, group/'application')[0]
            operator_messaging.renew(current, group/'application', expected_application_sha256=config_digest(selected))
        paths = [group/'application/publication.json', group/'visibility/installation.json', group/'selection.json']
        return {path:path.read_bytes() for path in paths}
    class Owner:
        deadline_ns = None
        def __init__(self, name):
            self.name, self.root, self.socket = name, roots[name], roots[name]/'tribe.sock'
        def group_relationship(self, value, **options):
            return locals_[self.name].group_relationship(value, **options)
        def group_publication(self, value, **options):
            assert self.deadline_ns > time.monotonic_ns()
            calls.append((self.name, copy.deepcopy(value)))
            # Arm a later winner only after the retained lost entrant reply;
            # real plan names need not sort before the founder's owner name.
            if (not fault['visibility'] and outcome == 'dispatch-winner'
                    and self.name == 'founder' and value['action'] == 'visibility-publish'):
                fault['winner'] = renew_application()
            if (not fault['visibility'] and outcome == 'visibility-winner'
                    and self.name == 'founder' and value['action'] == 'selection'):
                from daimon_matrix.canonical import canonical_bytes
                from daimon_matrix.messaging_config import config_digest, create_binding, read_document
                with source.writer():
                    current = social.load_owner_runtime(source.root, source._reader,
                        authorities=social.public_authorities(founder_bundle, closure(peer_bundle)))
                    installation = group/'visibility/installation.json'
                    successor = copy.deepcopy(read_document(installation)['document'])
                    successor['generation'] += 1
                    successor['policy']['generation'] = successor['generation']
                    installation.write_bytes(canonical_bytes(dict(document=successor, binding=create_binding(current, successor))))
                    app = read_publication(current, group/'application')[0]
                    # Authenticate the later owner-signed installation through
                    # exactly the existing native receiving validator.
                    operator_messaging._owner_visibility_controller(
                        authorities=operator_messaging._application_authorities(app),
                        application_sha256=config_digest(app), installation_path=installation,
                        authority=operator_messaging._runtime_authority(current), origin=current.service.origin,
                        runtime_id=current.service.runtime_id, runtime_label=current.service.runtime_label,
                        signer_public_key=current.service.signer.public_key, clock=current.service.clock,
                        catalog_mode='validate')
                fault['winner'] = {path:path.read_bytes() for path in
                    (installation, group/'application/publication.json', group/'selection.json')}
            result = locals_[self.name].group_publication(value, **options)
            if self.name == entrant_name and value['action'] == 'visibility-publish' and fault['visibility']:
                fault['visibility'] = False
                raise OSError('synthetic lost entrant visibility response')
            return result
    owners = {name:Owner(name) for name in locals_}
    journal = OperationJournal(tmp_path/'group-phase')
    row = plan_update(journal, manifest_digest='f'*64, target='receiving:'+admission['tribe_ref'],
        expected_precondition=dict(tribe_ref=admission['tribe_ref'], senders=[sender], receiver_selections={name:None for name in owners}),
        intended_transition=dict(cohort_admission=admission, portal_admission=dict(schema='cluster-portal-group-admission/v2', plan_digest=digest(target.plan), social=membership),
            admission_preparations=preparations, admission_publications=recipe), audit_identity={'actor':'synthetic-host'})
    # Join actual initial controller publication to the immutable original
    # social recipe. Native owner effects use the same actual admitted name.
    from clusterctl.onboarding_receiving_update import GuestOwnerBootstrap, freeze_guest_bootstrap
    frozen_owner = freeze_guest_bootstrap(target, deadline_ns=time.monotonic_ns()+60_000_000_000, initial=True)
    controller_request = dict(schema='cluster-guest-owner-initial/v1', operation_id=str(uuid.uuid4()),
        **{key:frozen_owner[key] for key in ('plan_digest', 'genesis_digest', 'code_digest', 'runtime_sha256',
            'group_sha256', 'predecessor', 'mode', 'preservation')}, expires_at_ms=admission['activation']['expires_at_ms'],
        group_context=dict(operation_id=operation, owner_name=entrant_name,
            authority_closure=closure(founder_bundle), expected_context_sha256=pins[entrant_name]))
    controller = GuestOwnerBootstrap(target, controller_request)
    staged = controller.execute('stage', deadline_ns=time.monotonic_ns()+60_000_000_000)
    published = controller.execute('publish', deadline_ns=time.monotonic_ns()+60_000_000_000,
        ready_sha256=staged['ready_sha256'])
    native_publication = (controller.records/'capability_published.json').read_bytes()
    journal.advance(row['operation_id'], row['state'], runtime_observation=dict(portal_admission=dict(
        controller_intent=controller_request, controller_stage=staged, controller_prepared=published)))
    derived_contexts = social.admission_owner_contexts(journal.get(row['operation_id']), membership)
    assert derived_contexts['founder'] == pins['founder']
    assert derived_contexts[entrant_name] != pins[entrant_name]
    assert journal.get(row['operation_id'])['intended_transition']['portal_admission']['social'] == membership
    schema_preview = target.group_publication(dict(operation_id=operation, step='communication-context',
        action='context-preview', params={}), authority_closure=closure(founder_bundle),
        expected_context_sha256=derived_contexts[entrant_name])
    target.group_publication(dict(operation_id=operation, step='communication-prepare',
        action='communication-prepare', params=dict(expected_plan_sha256=schema_preview['communication_plan']['plan_sha256'],
            expires_at_ms=admission['activation']['expires_at_ms'])), authority_closure=closure(founder_bundle),
        expected_context_sha256=derived_contexts[entrant_name])
    original_identity = {name: {file:(root/file).read_bytes() for file in ('runtime.json', 'custody.json')}
                         for name, root in roots.items()}
    cohort = CohortController(journal, row['operation_id'], owners)
    monkeypatch.setattr(cohort, 'require_revocation_barrier', lambda: dict(
        schema='cluster-receiving-admission-barrier/v1', current_senders={'founder':dict(state=fault['barrier'])}))
    with pytest.raises(OnboardingError, match='membership_unobserved'):
        cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    assert calls == []
    joined = cohort.admit_membership(deadline_ns=time.monotonic_ns()+60_000_000_000)
    fault['barrier'] = 'revoked-original'
    with pytest.raises(OnboardingError, match='quiescence_required'):
        cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    assert calls == []
    fault['barrier'] = 'stopped'
    admit = operator_messaging.admit_group_application
    def lost_application(*args, **options):
        admit(*args, **options)
        raise OSError('synthetic lost additive publication response')
    monkeypatch.setattr(operator_messaging, 'admit_group_application', lost_application)
    with pytest.raises(OSError, match='lost additive'):
        cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    monkeypatch.setattr(operator_messaging, 'admit_group_application', admit)
    with pytest.raises(OSError, match='lost entrant visibility'):
        cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    if outcome == 'later-winner':
        renew_application()
        paths = [group/'application/publication.json', group/'visibility/installation.json',
            group/'selection.json', target.root/'tribe/visibility/installation.json']
        winner = {path:path.read_bytes() for path in paths}
        with pytest.raises((ValueError, OnboardingError)):
            cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
        assert {path:path.read_bytes() for path in paths} == winner
        assert not (target.root/'tribe/selection.json').exists()
        assert 'result' not in journal.get(row['operation_id'])['runtime_observation']['group_publication']
        return
    if outcome in {'dispatch-winner', 'visibility-winner'}:
        rejected = 'publication_application_changed' if outcome == 'dispatch-winner' else 'publication_visibility_changed'
        with pytest.raises(OnboardingError, match=rejected):
            cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
        assert fault['winner'] and {path:path.read_bytes() for path in fault['winner']} == fault['winner']
        assert 'result' not in journal.get(row['operation_id'])['runtime_observation']['group_publication']
        return
    result = cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    assert result['receiving_readiness'] == 'unobserved' and set(result['snapshots']) == set(owners)
    assert result['membership_sha256'] == digest(joined)
    assert journal.get(row['operation_id'])['state'] == 'planned'
    frozen = journal.get(row['operation_id'])['runtime_observation']['group_publication']['requests']
    assert frozen[entrant_name]['application']['command']['params']['specification']['tribe']['policy']['membership_ref'] == joined['acceptance']['event_id']
    assert (group/'application/client.json').read_bytes() == client
    assert (group/'application/client.key').read_bytes() == key
    # The generic publication snapshot must not occupy the child's original
    # stronger owner-local request. Native store checks and the existing
    # derivation consumer still accept that distinct request and its exact retry.
    from clusterctl.onboarding_receiving_update import admission_group_derivation
    stores = original_stores
    child_snapshot = dict(operation_id=operation, step='lifecycle-snapshot', action='snapshot', params=dict(
        application_step='application', visibility_step='visibility', selection_step='selection',
        owner_context_sha256=pins['founder'], expected_stores=stores))
    stronger = source.group_publication(child_snapshot, authority_closure=closure(peer_bundle))
    assert source.group_publication(child_snapshot, authority_closure=closure(peer_bundle)) == stronger
    link = dict(cohort_operation_id=row['operation_id'], cohort_intent_sha256=digest(row['intent']),
        tribe_ref=admission['tribe_ref'], snapshot_request=child_snapshot)
    derivation = admission_group_derivation(link, stronger, previous=before_group, stores=stores)
    assert derivation['snapshot'] == stronger
    assert child_snapshot['step'] != recipe['owners']['founder']['steps']['snapshot']
    total = len(calls)
    monkeypatch.setattr(cohort, 'require_revocation_barrier', lambda:pytest.fail('completed publication quiesced replacements'))
    assert cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000) == result
    assert len(calls) == total
    assert {name: {file:(root/file).read_bytes() for file in ('runtime.json', 'custody.json')}
            for name, root in roots.items()} == original_identity
    assert all(owner.deadline_ns is None for owner in owners.values())
    assert not any((root/'tribe.sock').exists() for root in roots.values())
    assert (controller.records/'capability_published.json').read_bytes() == native_publication


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
    guard = dict(application_step='application', application_sha256='a'*64)
    assert publication_command({**value, 'application_precondition':guard})['application_precondition'] == guard
    for invalid in ({**guard, 'extra':True}, {**guard, 'application_step':'../other'},
                    {**guard, 'application_sha256':'unknown'}):
        with pytest.raises(OnboardingError, match='publication_command_required'):
            publication_command({**value, 'application_precondition':invalid})
    visibility = dict(visibility_step='visibility', installation_sha256='b'*64)
    assert publication_command({**value, 'visibility_precondition':visibility})['visibility_precondition'] == visibility
    with pytest.raises(OnboardingError, match='publication_command_required'):
        publication_command({**value, 'visibility_precondition':{**visibility, 'visibility_step':'../outside'}})
    assert request_packet(dict(command=value, offline=True, authority_closure={}))['command'] == value
    preview = {**value, 'action': 'context-preview', 'params': {}}
    assert publication_command(preview) == preview
    preparation = {**value, 'action':'communication-prepare',
        'params':dict(expected_plan_sha256='1'*64, expires_at_ms=123)}
    assert publication_command(preparation) == preparation
    for invalid in ({'expected_plan_sha256':'invalid'}, {'expires_at_ms':True},
                    {'expires_at_ms':-1}, {'extra':True}):
        with pytest.raises(OnboardingError, match='publication_command_required'):
            publication_command({**preparation, 'params':{**preparation['params'], **invalid}})
    with pytest.raises(OnboardingError, match='publication_command_required'):
        publication_command({**preparation, 'application_precondition':guard})
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
