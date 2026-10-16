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
    locals_ = dict(founder=source, entrant=target)
    roots = dict(founder=source.root, entrant=target.package/'runtime')
    bundles = dict(founder=founder_bundle, entrant=peer_bundle)
    # Explicit preparation prerequisite, not an automatic publication feature:
    # fresh receiving fixtures have the legacy communication schema. Exercise
    # the maintained offline migration, never suppress its group-load refusal.
    from daimon_matrix import operator_communication_migration as migration
    def prepare_communication():
        with target._runtime_writer():
            prepared = social.load_owner_runtime(roots['entrant'], target._reader,
                authorities=social.public_authorities(peer_bundle, closure(founder_bundle)))
            preview = migration.plan(prepared.service.communication.ledger.path)
            migration.apply(prepared.service.communication, tmp_path/'entrant-schema-preparation', preview['plan_sha256'])
    pins = {name: owner.group_publication(dict(operation_id=operation, step='context', action='context-preview', params={}),
        authority_closure={ref: value for ref, value in full_closure.items()
            if ref != bundles[name]['manifest']['being_ref']})['owner_context_sha256'] for name, owner in locals_.items()}
    original_identity = {name: {file: (root/file).read_bytes() for file in ('runtime.json', 'custody.json')}
                         for name, root in roots.items()}
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
        founder_owner='founder', entrant_owner='entrant', authority_closure=full_closure,
        governance=[declaration], invitation=invite, membership_sequence=0,
        previous_membership_terminal_ref=None, acceptance_not_after_ms=invite['expires_at_ms'], owner_contexts=pins)
    steps = dict(application='application', disclosure='disclosure', acceptance='acceptance',
        visibility='visibility', selection='selection', snapshot='snapshot')
    preparations = dict(founder=dict(profile='source', unit=str(tmp_path/'source.service'), home=str(tmp_path),
        steps={key: steps[key] for key in ('application', 'visibility', 'selection', 'snapshot')}))
    preparations['founder']['steps']['snapshot'] = 'lifecycle-snapshot'
    specification = copy.deepcopy(initial['params']['specification'])
    specification['authorities'] = [full_closure[ref]['authority'] for ref in sorted(full_closure)]
    specification['relationship_mode'].update(runtime_id=peer_bundle['runtime_id'], state_root=str(roots['entrant']),
        store_filename=peer_bundle['relationships']['store_filename'])
    specification['tribe']['policy']['membership_ref'] = None
    specification['listen']['port'] = 48676
    specification['intake'] = route
    specification['roster'].append(peer_row)
    owner_recipes = dict(
        founder=dict(steps=steps, application=dict(expected_application_sha256=baseline['application_sha256'],
            specification=None, additions=dict(authorities=[full_closure[entrant]['authority']],
                relationship_events=[], roster=[peer_row]), admitted_being_refs=[entrant],
            secret_sources={peer_key.name:str(peer_key)}),
            disclosure=dict(approved_destination=destination, issued_at_ms=issued),
            visibility=dict(expected_installation_sha256=visibility['installation_sha256'], initial_configuration=None),
            selection=dict(expected_selection_sha256=old_selection)),
        entrant=dict(steps=steps, application=dict(expected_application_sha256=None, specification=specification,
            additions=None, admitted_being_refs=[], secret_sources={**initial['params']['secret_sources'], peer_key.name:str(peer_key)}),
            disclosure=dict(approved_destination=destination, issued_at_ms=issued),
            visibility=dict(expected_installation_sha256=None, initial_configuration=configuration(target.root/'tribe/visibility')),
            selection=dict(expected_selection_sha256=None)))
    recipe = dict(schema='cluster-admission-publications/v1', owners=owner_recipes, signers={founder:'founder', entrant:'entrant'})
    assert social.publication_recipe(recipe, admission, membership, [sender], preparations) == recipe
    for mutate in (
        lambda value: value['signers'].update({founder:'entrant'}),
        lambda value: value['owners']['entrant']['application']['specification']['tribe']['policy'].update(membership_ref='invented'),
        lambda value: value['owners']['founder']['application']['additions']['relationship_events'].append({'invented':True}),
        lambda value: value['owners']['founder']['steps'].update(application='another-child-step'),
        lambda value: value['owners']['founder']['steps'].update(snapshot='lifecycle-snapshot'),
        lambda value: value['owners']['founder']['steps'].update(disclosure='lifecycle-snapshot'),
        lambda value: value['owners']['entrant']['disclosure'].update(approved_destination={**destination, 'chat_id':-999}),
        lambda value: value['owners']['founder']['application']['additions'].update(roster=[]),
        lambda value: value['owners']['entrant']['application']['specification']['listen'].update(port=0),
        lambda value: value['owners']['entrant']['application']['specification'].update(roster=[]),
        lambda value: value['owners']['entrant']['application'].update(secret_sources={}),
        lambda value: value['owners']['entrant']['visibility']['initial_configuration']['secrets'].update(proof_key_file='../outside'),
        lambda value: value['owners']['entrant']['visibility']['initial_configuration']['telegram_qualification'].update(probe_chat_id=-999),
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
            if outcome == 'dispatch-winner' and self.name == 'founder' and value['action'] == 'visibility-publish':
                fault['winner'] = renew_application()
            if outcome == 'visibility-winner' and self.name == 'founder' and value['action'] == 'selection':
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
            if self.name == 'entrant' and value['action'] == 'visibility-publish' and fault['visibility']:
                fault['visibility'] = False
                raise OSError('synthetic lost entrant visibility response')
            return result
    owners = {name:Owner(name) for name in locals_}
    journal = OperationJournal(tmp_path/'group-phase')
    row = plan_update(journal, manifest_digest='f'*64, target='receiving:'+admission['tribe_ref'],
        expected_precondition=dict(tribe_ref=admission['tribe_ref'], senders=[sender], receiver_selections={name:None for name in owners}),
        intended_transition=dict(cohort_admission=admission, portal_admission=dict(schema='cluster-portal-group-admission/v2', social=membership),
            admission_preparations=preparations, admission_publications=recipe), audit_identity={'actor':'synthetic-host'})
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
    from daimon_matrix.messaging_config import MessagingConfigError
    with pytest.raises(MessagingConfigError, match='semantic_migration_required'):
        cohort.publish_admission_group(deadline_ns=time.monotonic_ns()+60_000_000_000)
    assert not (target.root/'tribe/application').exists()
    # This explicit prerequisite is intentionally not claimed automated. The
    # native migration's partial-recovery gap remains future preparation work.
    prepare_communication()
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
    assert frozen['entrant']['application']['command']['params']['specification']['tribe']['policy']['membership_ref'] == joined['acceptance']['event_id']
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
