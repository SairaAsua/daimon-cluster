"""The real worker/operation/job locks retain a distinct native prerequisite.

Owners, manager and native preparation are explicit seams. No synthetic custody,
real service or model is created, and this is not full admission qualification.
"""
import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_group_coordinator import CALLER_SCHEMA, SCHEMA, GroupCoordinator, configuration
from clusterctl.onboarding_worker import Worker
from clusterctl.operation_journal import OperationJournal
from tests.test_onboarding import FixtureBackend, plan
from tests.test_receiving_cohort_control import admission_fixture


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    _cohort, owners, _journal, original, _activation = admission_fixture(tmp_path)
    store = JobStore(tmp_path/'jobs')
    stages = FixtureBackend()
    plans = {name: plan(name=name, browser=False) for name in owners}
    for value in plans.values():
        store.submit(value, stages)
    for _ in range(3):
        store.tick('newcomer', stages)
    owner_rows = {name: dict(profile='guest', plan=plans[name], root=str(owner.root),
        candidate=dict(code=original['intended_transition']['cohort_admission']['receivers'][name]['candidate']['code'],
            digest=original['intended_transition']['cohort_admission']['receivers'][name]['recipe']['prepared']['code_digest']))
        for name, owner in owners.items()}
    transition = copy.deepcopy(original['intended_transition'])
    for name, item in transition['cohort_admission']['receivers'].items():
        item['recipe']['tooling'] = dict(profile='codex', attachment=str(owners[name].root/'attachment'),
            codex_home=str(owners[name].root/'codex'), connections=[], native_endpoint=str(owners[name].root/'native.sock'),
            native_threads=[], tribe_channel='tribe')
    transition['portal_admission'] = dict(schema=CALLER_SCHEMA, plan_digest=digest(plans['newcomer']),
        matrix_operation_id=JobStore.operation_id(digest(plans['newcomer']), 'matrix'), owners_sha256=digest(owner_rows))
    journal = OperationJournal(tmp_path/'worker-receiving')
    row = plan_update(journal, manifest_digest=original['intent']['runtime_call']['manifest_digest'],
        target=original['target'], expected_precondition=original['expected_precondition'],
        intended_transition=transition, audit_identity={'actor': 'synthetic-host'})
    path = tmp_path/'group-coordinator.json'
    selected = dict(schema=SCHEMA, tribe_ref='tribe:fixture', journal=str(journal.path.parent),
        owners=owner_rows, admissions={digest(plans['newcomer']): row['operation_id']})
    being_seed._write(path, selected)
    calls, native = [], {'state': 'absent', 'lost': False}
    def command(value, action, **options):
        assert options['deadline_ns'] > 0
        calls.append(action)
        if action == 'native-observe':
            return {'native_state': native['state']}
        assert action == 'native-install'
        native['state'] = 'active'
        if native['lost']:
            raise OnboardingError('onboarding_host_operation_failed')
        return {'native_started': True}
    backend = SimpleNamespace(config=SimpleNamespace(group_admission=path, jobs=store.root),
        authorize=lambda *a: stages.granted, _decision=lambda p: {'approved': True}, _consented=lambda *a, **k: True,
        _ceremony=lambda p: SimpleNamespace(authorize=lambda p: True),
        _target_call=lambda *a, **k: {'phase': 'v8'},
        _telegram_command=command,
        _attach_telegram=lambda *a, **k: calls.append('attach-native-code'),
        _telegram_probe=lambda *a, **k: calls.append('probe'))
    backend.prepare_group_target = lambda p, candidate, **k: backend._target_call(p, 'observe')['phase'] == 'v8'
    for name, owner in owners.items():
        owner.deadline_ns = None
        def preflight(endpoint, *, name=name, owner=owner):
            # The public owner route can own its job independently of caller.
            with being_seed._locked(store.directory(name)):
                calls.append('preflight-'+name)
                return dict(schema='cluster-native-endpoint-readiness/v1', native_process=owner.process,
                    acceptance='native-endpoint-only', model_turns_started=0, messages_sent=0)
        owner.preflight_native = preflight
    body = dict(registered=False, physical_lost=False, publish_lost=False, preserve_lost=False,
        publications=0, mode='issue')
    expected = dict(being_ref=owners['newcomer'].being, body_ref='codex:fixture:newcomer',
        embodiment_id=owners['newcomer'].server['embodiment_id'], incarnation_id='incarnation:newcomer')
    profile = dict(enrollment=expected)
    from clusterctl.onboarding_managed import ManagedRuntime as NativeManagedRuntime
    class Managed(NativeManagedRuntime):
        settings = {'synthetic': 'fixed-physical-authority'}
        def __init__(self, _backend):
            pass
        def _expected(self, plan):
            return copy.deepcopy(expected)
        def prepare_admission(self, selected_plan, **options):
            assert selected_plan == plans['newcomer']
            assert options['deadline_ns'] > 0 and options['candidate'] == (
                Path(owner_rows['newcomer']['candidate']['code']), owner_rows['newcomer']['candidate']['digest'])
            calls.append('physical-prepare')
            body['registered'] = True
            if body['physical_lost']:
                body['physical_lost'] = False
                raise OSError('synthetic lost physical preparation reply')
            return copy.deepcopy(profile)
        def _profile(self, _plan):
            return copy.deepcopy(profile) if body['registered'] else None
    managed = Managed(backend)
    monkeypatch.setattr('clusterctl.onboarding_managed.ManagedRuntime', Managed)
    def target_call(selected_plan, action, **options):
        if action == 'observe':
            return {'phase': 'v8'}
        assert selected_plan == plans['newcomer']
        assert 0 < options['bootstrap_timeout_seconds'] <= 30
        calls.append(action)
        if action == 'receiving-bootstrap-freeze':
            assert body['registered'], 'physical holder must precede controller freeze'
            return dict(plan_digest=digest(selected_plan), genesis_digest='1'*64,
                code_digest=owner_rows['newcomer']['candidate']['digest'], runtime_sha256='2'*64,
                being_ref=expected['being_ref'], origin={k:v for k,v in expected.items() if k != 'being_ref'},
                group=None, group_sha256=digest({'group': None}), predecessor=None, mode=body['mode'],
                preservation=None if body['mode'] == 'issue' else dict(
                    not_after_ms=row['intended_transition']['cohort_admission']['activation']['expires_at_ms']))
        request = options['bootstrap_request']
        if action == 'receiving-bootstrap-stage':
            if request['mode'] == 'preserve':
                if body['preserve_lost']:
                    body['preserve_lost'] = False
                    raise OSError('synthetic lost durable preservation reply')
                return dict(schema='cluster-receiving-owner-preserved/v1', operation_id=request['operation_id'],
                    runtime_sha256=request['runtime_sha256'], receiving_readiness='unobserved')
            return dict(schema='cluster-guest-owner-bootstrap-ready/v1', operation_id=request['operation_id'],
                ready_sha256='3'*64, receiving_readiness='unobserved')
        assert action == 'receiving-bootstrap-publish' and options['bootstrap_ready_sha256'] == '3'*64
        body['publications'] = 1  # Explicit native-owner seam retains exact publication.
        result = dict(schema='cluster-guest-owner-bootstrap-publication/v1', operation_id=request['operation_id'],
            ready_sha256='3'*64, runtime_sha256='4'*64, counter_after=1, receiving_readiness='unobserved')
        if body['publish_lost']:
            body['publish_lost'] = False
            raise OSError('synthetic lost controller publication reply')
        return result
    backend._target_call = target_call
    monkeypatch.setattr(GroupCoordinator, '_owners', lambda self, admission: owners)
    return SimpleNamespace(store=store, stages=stages, plans=plans, owners=owners, journal=journal,
        row=row, path=path, selected=selected, backend=backend, calls=calls, native=native, body=body,
        managed=managed, activation=_activation)


def test_worker_prepares_and_binds_every_old_child_without_stopping_members(fixture, monkeypatch):
    """Real worker/journal/binder; native governance/child producer are seams."""
    import uuid
    from clusterctl import onboarding_receiving_update as updates
    from clusterctl.onboarding_receiving_update import CohortController
    from tests.test_receiving_cohort_control import admission_child_fixture
    f = fixture
    transition = copy.deepcopy(f.row['intended_transition'])
    social = dict(operation_id=str(uuid.uuid4()), authority_closure={owner.being: {} for owner in f.owners.values()},
        owner_contexts={name: '4'*64 for name in f.owners})
    transition['portal_admission'].update(schema='cluster-portal-group-admission/v2', social=social)
    old = [item['name'] for item in f.row['expected_precondition']['senders']]
    transition['admission_preparations'] = {name: dict(profile='guest', steps=dict(
        application='application', visibility='visibility', selection='selection', snapshot='snapshot')) for name in old}
    before = copy.deepcopy(f.row['expected_precondition'])
    before['host_config'] = str(f.store.root.parent/'host.json')  # Resolved by the explicit producer seam below.
    journal = OperationJournal(f.store.root.parent/'child-cohort')
    row = plan_update(journal, manifest_digest=f.row['intent']['runtime_call']['manifest_digest'],
        target=f.row['target'], expected_precondition=before, intended_transition=transition,
        audit_identity={'actor': 'synthetic-host'})
    configured = copy.deepcopy(f.selected)
    configured.update(journal=str(journal.path.parent), admissions={digest(f.plans['newcomer']): row['operation_id']})
    being_seed._write(f.path, configured)
    monkeypatch.setattr('clusterctl.onboarding_group_admission.membership_recipe', lambda value, *a: copy.deepcopy(value))
    children, requests, lose = {}, [], [True]
    def prepare(backend, plan, selected_journal, request, **options):
        assert backend is f.backend and selected_journal.path == journal.path
        assert request['cohort_intent_sha256'] == digest(row['intent'])
        assert request['operation_id'] == social['operation_id']
        assert request['owner_context_sha256'] == social['owner_contexts'][plan['name']]
        assert 0 < options['deadline_ns'] - __import__('time').monotonic_ns() <= 30_000_000_000
        with being_seed._locked(f.store.directory(plan['name'])):
            pass  # Caller must release its job scope before the producer.
        requests.append(copy.deepcopy(request))
        name = plan['name']
        if name not in children:
            cohort = CohortController(journal, row['operation_id'], f.owners)
            _, _, _, _, recipe, _, _ = admission_child_fixture(f.store.root.parent,
                profile='guest', name=name, with_group=False, with_exit=False,
                setup=(cohort, f.owners, journal, row, f.activation))
            children[name] = recipe['lifecycle_operation_id']
        if lose[0]:
            lose[0] = False
            raise OSError('synthetic lost child preparation response')
        return dict(schema='cluster-guest-admission-prepared/v1', operation_id=children[name],
            request_sha256=digest(request), cohort_operation_id=row['operation_id'],
            cohort_intent_sha256=digest(row['intent']), receiving_readiness='unobserved')
    monkeypatch.setattr(updates, 'prepare_guest_admission', prepare)
    with pytest.raises(OSError, match='lost child preparation response'):
        GroupCoordinator(f.backend).advance('newcomer')
    result = GroupCoordinator(f.backend).advance('newcomer')
    assert result['lifecycle_prepared'] and result['receiving_readiness'] == 'unobserved'
    bound = journal.get(row['operation_id'])['runtime_observation']['admission_lifecycles']
    assert {name: binding['lifecycle_operation_id'] for name, binding in bound.items()} == children
    count = len(requests)
    assert GroupCoordinator(f.backend).advance('newcomer') == result
    assert len(requests) == count and requests[0] == requests[1]
    assert journal.get(row['operation_id'])['state'] == 'planned'
    assert all(owner.effects == 0 for owner in f.owners.values())


def test_worker_prepares_native_outside_job_lock_and_cannot_complete_matrix(fixture):
    f = fixture
    backend = f.backend
    backend.advance_group_admission = lambda name: GroupCoordinator(backend).advance(name)
    backend.observe = lambda p, stage, identifier: GroupCoordinator(backend).observe(p)
    backend.execute = lambda *a: pytest.fail('pending admission fell through to ordinary install')
    worker = Worker(f.store, lambda: backend, advance_group_admission=backend.advance_group_admission)
    result = worker._tick('newcomer')
    assert result['stage'] == 'matrix' and result['reason'] == 'group_admission_pending'
    current = f.journal.get(f.row['operation_id'])
    assert current['state'] == 'planned'
    assert set(current['runtime_observation']['portal_admission']) == {'native_intent', 'native_dispatch', 'native_ready',
        'physical_intent', 'physical_ready', 'controller_intent', 'controller_stage', 'controller_prepared'}
    assert f.calls.count('native-install') == 1
    worker._tick('newcomer')
    assert f.calls.count('native-install') == 1
    assert all(owner.effects == 0 for owner in f.owners.values()), 'native prep must never fence a Matrix sender'


def test_lost_native_install_reply_is_observed_without_another_start(fixture):
    f = fixture
    f.native['lost'] = True
    with pytest.raises(OnboardingError, match='onboarding_host_operation_failed'):
        GroupCoordinator(f.backend).advance('newcomer')
    assert f.native['state'] == 'active'
    f.native['lost'] = False
    assert GroupCoordinator(f.backend).advance('newcomer')['native_prepared'] is True
    assert f.calls.count('native-install') == 1
    assert f.calls.count('native-observe') == 2


@pytest.mark.parametrize('change', ['owner-map', 'job', 'operation', 'expired', 'revoked'])
def test_wrong_or_expired_binding_cannot_prepare_or_fence(fixture, monkeypatch, change):
    f = fixture
    selected = copy.deepcopy(f.selected)
    if change == 'owner-map':
        selected['owners']['eko']['root'] += '/other'
    elif change == 'job':
        selected['admissions'] = {digest(f.plans['eko']): f.row['operation_id']}
    elif change == 'operation':
        selected['admissions'][digest(f.plans['newcomer'])] = 'missing-operation'
    elif change == 'expired':
        from clusterctl import onboarding_group_coordinator as caller
        future = f.row['intended_transition']['cohort_admission']['activation']['expires_at_ms'] + 1
        # Local clock seam only; no new authorization horizon is minted.
        monkeypatch.setattr(caller, 'time', SimpleNamespace(
            monotonic_ns=caller.time.monotonic_ns, time_ns=lambda: future*1_000_000))
    else:
        f.stages.granted = False
    being_seed._write(f.path, selected)
    coordinator = GroupCoordinator(f.backend)
    if change in {'owner-map', 'expired', 'revoked'}:
        with pytest.raises(OnboardingError):
            coordinator.advance('newcomer')
    else:
        assert coordinator.advance('newcomer') is None
    assert not f.calls and all(owner.effects == 0 for owner in f.owners.values())


def test_incomplete_v8_and_active_manager_never_manufacture_admission(fixture):
    f = fixture
    f.backend._target_call = lambda *a, **k: {'phase': 'v8-published'}
    assert GroupCoordinator(f.backend).advance('newcomer') is None
    assert not f.calls
    f.backend._target_call = lambda *a, **k: {'phase': 'v8'}
    f.native['state'] = 'pending'
    assert GroupCoordinator(f.backend).advance('newcomer')['native_prepared'] is False
    assert 'native-install' not in f.calls
    assert GroupCoordinator(f.backend).observe(f.plans['newcomer']).state == 'waiting'


def test_worker_resolves_runtime_again_inside_job_lock_after_outside_admission(tmp_path):
    store = JobStore(tmp_path/'jobs')
    backend = FixtureBackend()
    store.submit(plan(), backend)
    old = SimpleNamespace(advance_group_admission=lambda name: None,
        observe=lambda *a: pytest.fail('worker reused outside-lock runtime selection'))
    factories = iter((old, backend))
    def backend_factory():
        return next(factories)
    assert Worker(store, backend_factory,
        advance_group_admission=lambda name: backend_factory().advance_group_admission(name))._tick('eko')['stage'] == 'context'


@pytest.mark.parametrize('field', ['command', 'owners'])
def test_coordinator_configuration_rejects_open_command_or_missing_owner_map(fixture, field):
    selected = copy.deepcopy(fixture.selected)
    if field == 'command':
        selected[field] = ['/unapproved/program']
    else:
        selected[field] = {}
    being_seed._write(fixture.path, selected)
    with pytest.raises(OnboardingError, match='coordinator_configuration_required'):
        configuration(fixture.path)


def test_configured_matrix_stage_cannot_bypass_pending_transaction_for_selected_app(fixture, tmp_path, monkeypatch):
    from clusterctl.onboarding_host import HostBackend
    from clusterctl.onboarding_managed import ManagedRuntime
    from clusterctl.onboarding_peer_host import PeerHost
    from tests.test_onboarding_host import configured
    f = fixture
    root = tmp_path/'host'
    root.mkdir(mode=0o700)
    config, _, _, _ = configured(root)
    code = root/'code'
    (code/'sdk').mkdir(parents=True)
    (code/'sdk/sdk.json').write_text('{}')
    backend = HostBackend(replace(config, code=code, custody=root/'custody', custody_grants=root/'custody-grants',
        group_admission=f.path, admission=root/'admission', peer=root/'peer', jobs=f.store.root, views=root/'views'))
    backend.authorize = lambda *a: True
    backend._decision = f.backend._decision
    backend._consented = f.backend._consented
    backend._ceremony = lambda p: SimpleNamespace(authorize=lambda p: True, observe=lambda p: {'ready': True})
    backend._guest_paths = lambda p: (root, code, {})
    backend._runtime_paths = lambda *a, **k: (code, [], {})
    backend._matrix_mount = lambda p: {}
    backend._mounted = lambda *a: True
    backend._sdk_successor = lambda p: False
    backend._matrix_command = lambda *a: {'phase': 'v8', 'group': {'selected': True}}
    backend._matrix_execute = lambda *a: True
    monkeypatch.setattr(PeerHost, 'application', lambda *a: pytest.fail('selected app bypassed transaction'))
    monkeypatch.setattr(ManagedRuntime, 'execute', lambda *a: pytest.fail('ordinary start bypassed transaction'))
    monkeypatch.setattr(ManagedRuntime, 'observe', lambda *a: pytest.fail('managed presence bypassed transaction'))
    assert backend.observe(f.plans['newcomer'], 'matrix', 'fixture').reason == 'group_admission_pending'
    backend.execute(f.plans['newcomer'], 'matrix', 'fixture')
    assert backend.observe(f.plans['newcomer'], 'acceptance', 'fixture').reason == 'group_admission_pending'
    backend.execute(f.plans['newcomer'], 'acceptance', 'fixture')


@pytest.mark.parametrize('action', ['observe', 'sdk-observe', 'sdk-prepare'])
@pytest.mark.parametrize('late', [False, True])
def test_actual_target_cli_accepts_preparation_budget_and_rejects_late_result(tmp_path, monkeypatch, capsys, action, late):
    import sys
    from clusterctl import onboarding_target as target
    clock = [0]
    monkeypatch.setattr(target, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0]))
    monkeypatch.setattr(target.onboarding_sdk, 'time', target.time)
    plan_path, genesis = tmp_path/'plan.json', tmp_path/'genesis.json'
    being_seed._write(plan_path, plan(browser=False))
    being_seed._write(genesis, {})
    monkeypatch.setattr(target.onboarding_code_successor, 'selection', lambda *a, **k: tmp_path/'code')
    monkeypatch.setattr(target.onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {})
    def sdk(*a, **k):
        assert target.onboarding_sdk.probe_timeout(180) == 2
        if late:
            clock[0] = 3_000_000_000
        return Path(sys.prefix)
    monkeypatch.setattr(target.onboarding_sdk, 'observe', sdk)
    monkeypatch.setattr(target.onboarding_sdk, 'install', sdk)
    monkeypatch.setattr(target, 'Target', lambda *a, **k: SimpleNamespace(observe=lambda: {'phase': 'v8'}))
    arguments = [action, '--home', str(tmp_path), '--code', str(tmp_path/'code'),
        '--plan', str(plan_path), '--genesis', str(genesis), '--observation-timeout-seconds', '2']
    assert target.main(arguments) == (1 if late else 0)
    output = capsys.readouterr().out
    assert ('"error"' in output) == late
    assert target.onboarding_sdk.probe_timeout(180) == 180


def test_native_ready_durability_cannot_return_acceptance_after_budget(fixture, monkeypatch):
    from clusterctl import onboarding_group_coordinator as caller
    f = fixture
    clock = [caller.time.monotonic_ns()]
    monkeypatch.setattr(caller, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0], time_ns=caller.time.time_ns))
    retain = GroupCoordinator._retain
    def late(self, journal, row, key, value):
        result = retain(self, journal, row, key, value)
        if key == 'native_ready':
            clock[0] += 31_000_000_000
        return result
    monkeypatch.setattr(GroupCoordinator, '_retain', late)
    with pytest.raises(OnboardingError, match='receiving_host_deadline_expired'):
        GroupCoordinator(f.backend).advance('newcomer')
    retained = f.journal.get(f.row['operation_id'])
    assert 'native_ready' in retained['runtime_observation']['portal_admission']
    assert retained['state'] == 'planned'


@pytest.mark.parametrize('phase', ['physical', 'controller'])
def test_body_preparation_reuses_original_intent_after_lost_reply(fixture, phase):
    f = fixture
    f.body['physical_lost' if phase == 'physical' else 'publish_lost'] = True
    with pytest.raises(OSError, match='synthetic lost'):
        GroupCoordinator(f.backend).advance('newcomer')
    prior = copy.deepcopy(f.journal.get(f.row['operation_id'])['runtime_observation']['portal_admission'])
    result = GroupCoordinator(f.backend).advance('newcomer')
    assert result['physical_prepared'] and result['controller_prepared']
    retained = f.journal.get(f.row['operation_id'])['runtime_observation']['portal_admission']
    assert retained['native_ready'] == prior['native_ready']
    if phase == 'controller':
        assert retained['controller_intent'] == prior['controller_intent']
        assert f.calls.count('receiving-bootstrap-freeze') == 1
        assert f.calls.count('receiving-bootstrap-stage') == 1
    assert f.body['publications'] == 1
    assert f.calls.count('native-install') == 1
    assert all(owner.effects == 0 for owner in f.owners.values())
    calls = list(f.calls)
    GroupCoordinator(f.backend).advance('newcomer')
    assert f.calls == calls, 'historical preparation must not re-dispatch each cadence'
    assert f.journal.get(f.row['operation_id'])['state'] == 'planned'


def test_existing_initial_controller_is_preserved_without_publication(fixture):
    fixture.body['mode'] = 'preserve'
    assert GroupCoordinator(fixture.backend).advance('newcomer')['controller_prepared']
    assert 'receiving-bootstrap-publish' not in fixture.calls
    assert fixture.body['publications'] == 0


@pytest.mark.parametrize('mode', ['issue', 'preserve'])
def test_expired_authorization_reconciles_only_original_final_owner_call(fixture, monkeypatch, mode):
    from clusterctl import onboarding_group_coordinator as caller
    f = fixture
    f.body['mode'] = mode
    f.body['preserve_lost' if mode == 'preserve' else 'publish_lost'] = True
    with pytest.raises(OSError, match='synthetic lost'):
        GroupCoordinator(f.backend).advance('newcomer')
    prior = copy.deepcopy(f.journal.get(f.row['operation_id'])['runtime_observation']['portal_admission'])
    future = f.row['intended_transition']['cohort_admission']['activation']['expires_at_ms'] + 1
    monkeypatch.setattr(caller, 'time', SimpleNamespace(
        monotonic_ns=caller.time.monotonic_ns, time_ns=lambda: future*1_000_000))
    calls = list(f.calls)
    assert GroupCoordinator(f.backend).advance('newcomer')['controller_prepared']
    expected_action = 'receiving-bootstrap-stage' if mode == 'preserve' else 'receiving-bootstrap-publish'
    assert f.calls == calls + [expected_action]
    retained = f.journal.get(f.row['operation_id'])['runtime_observation']['portal_admission']
    assert retained['controller_intent'] == prior['controller_intent']
    assert retained['physical_ready'] == prior['physical_ready']
    assert f.body['publications'] == (0 if mode == 'preserve' else 1)
    calls = list(f.calls)
    assert GroupCoordinator(f.backend).advance('newcomer')['controller_prepared']
    assert f.calls == calls
    assert f.journal.get(f.row['operation_id'])['state'] == 'planned'
    assert all(owner.effects == 0 for owner in f.owners.values())


def test_expired_authorization_cannot_resume_unfinished_physical_preparation(fixture, monkeypatch):
    from clusterctl import onboarding_group_coordinator as caller
    f = fixture
    f.body['physical_lost'] = True
    with pytest.raises(OSError, match='lost physical'):
        GroupCoordinator(f.backend).advance('newcomer')
    future = f.row['intended_transition']['cohort_admission']['activation']['expires_at_ms'] + 1
    monkeypatch.setattr(caller, 'time', SimpleNamespace(
        monotonic_ns=caller.time.monotonic_ns, time_ns=lambda: future*1_000_000))
    calls = list(f.calls)
    with pytest.raises(OnboardingError, match='authorization_expired'):
        GroupCoordinator(f.backend).advance('newcomer')
    assert f.calls == calls


def qualified_target_cli(tmp_path, monkeypatch, *, late=False):
    """Actual CLI grammar/startup; SDK custody is an explicit qualification seam."""
    from clusterctl import onboarding_target as target
    home, code = tmp_path/'home', tmp_path/'code'
    plan_path, genesis = tmp_path/'plan.json', tmp_path/'genesis.json'
    being_seed._write(plan_path, plan(browser=False))
    being_seed._write(genesis, {})
    (code/'sdk').mkdir(mode=0o700, parents=True)
    being_seed._write(code/'sdk/sdk.json', {})
    venv = home/'.local/share/daimon-matrix/sdk'/digest({})/'venv'
    imports = venv.parent/'runtime-imports'
    venv.parent.mkdir(mode=0o700, parents=True)
    imports.mkdir(mode=0o700)
    being_seed._write(venv.parent/'runtime-imports.json', {})
    clock, calls = [1_000_000_000], []
    monkeypatch.setattr(target, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0], time_ns=lambda: 1_000_000_000_000))
    monkeypatch.setattr(target.onboarding_sdk, 'time', target.time)
    monkeypatch.setattr(target, 'sys', SimpleNamespace(prefix=str(venv), argv=[]))
    monkeypatch.setattr(target.onboarding_code_successor, 'selection', lambda *a, **k: code)
    monkeypatch.setattr(target.onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {
        'matrix_commit': target.onboarding_sdk.MATRIX_COMMIT, 'matrix_wheel_sha256': 'a'*64})
    monkeypatch.setattr(target.onboarding_release, 'regular', lambda path, **k: Path(path).read_bytes())
    monkeypatch.setattr(target.onboarding_sdk, 'startup_context', lambda *a: True)
    def startup(*a, **k):
        clock[0] += 3_000_000_000 if late else 200_000_000
        return {'synthetic': 'qualified-startup'}
    monkeypatch.setattr(target.onboarding_sdk, 'qualified_startup', startup)
    monkeypatch.setattr(target, 'Target', lambda *a, **k: SimpleNamespace())
    args = ['--home', str(home), '--code', str(code), '--plan', str(plan_path), '--genesis', str(genesis)]
    return target, args, calls


@pytest.mark.parametrize('action', ['admission-prepare', 'admission-check', 'admission-enroll'])
@pytest.mark.parametrize('late', [False, True])
def test_actual_physical_cli_keeps_expiry_through_sdk_before_effect(tmp_path, monkeypatch, capsys, action, late):
    target, args, calls = qualified_target_cli(tmp_path, monkeypatch, late=late)
    class Holder:
        def __init__(self, target): pass
        def request(self, *, deadline_ns):
            calls.append(('prepare', deadline_ns))
            return {'synthetic': 'public-proof'}
        def ensure_enrolled(self, profile, *, enroll, deadline_ns):
            assert profile == {'synthetic': 'public-profile'}
            calls.append(('enroll' if enroll else 'check', deadline_ns))
            return True
    monkeypatch.setattr('clusterctl.onboarding_admission.ReceivingHolder', Holder)
    args += ['--observation-timeout-seconds', '2', '--authorization-expires-at-ms', '1000500']
    if action != 'admission-prepare':
        args += ['--public-profile-json', '{"synthetic":"public-profile"}']
    assert target.main([action, *args]) == (1 if late else 0)
    assert calls == ([] if late else [(action.removeprefix('admission-'), 1_500_000_000)])
    assert ('"error"' in capsys.readouterr().out) == late


@pytest.mark.parametrize('publication', [False, True])
def test_actual_target_cli_keeps_approved_context_guard(tmp_path, monkeypatch, capsys, publication):
    import io
    import json
    import uuid
    target, args, calls = qualified_target_cli(tmp_path, monkeypatch)
    command = dict(operation_id=str(uuid.uuid4()), step='invite', method='tribe.invite', params={})
    if publication:
        command = dict(operation_id=command['operation_id'], step='context', action='context-preview', params={})
    packet = dict(command=command, offline=True, authority_closure={}, expected_context_sha256='a'*64)
    target.sys.stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))
    def submit(value, **options):
        calls.append((value, options))
        return {'status': 'recorded'}
    monkeypatch.setattr(target, 'Target', lambda *a, **k: SimpleNamespace(
        group_publication=submit, group_relationship=submit))
    assert target.main(['group-publication' if publication else 'group-relationship', *args,
        '--observation-timeout-seconds', '2', '--group-request', '-']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'recorded'
    assert calls == [(command, dict(authority_closure={}, deadline_ns=3_000_000_000,
        expected_context_sha256='a'*64))]


def test_initial_bootstrap_cli_budget_starts_before_sdk_qualification(tmp_path, monkeypatch):
    target, args, calls = qualified_target_cli(tmp_path, monkeypatch)
    def freeze(target, *, deadline_ns, initial, initial_service):
        assert initial and not initial_service
        calls.append(deadline_ns)
        return {'synthetic': 'initial-owner-context'}
    monkeypatch.setattr('clusterctl.onboarding_receiving_update.freeze_guest_bootstrap', freeze)
    assert target.main(['receiving-bootstrap-freeze', *args, '--bootstrap-initial',
        '--bootstrap-timeout-seconds', '2']) == 0
    assert calls == [3_000_000_000], 'SDK work must consume the original budget'


@pytest.mark.parametrize('field', ['being_ref', 'embodiment_id'])
def test_wrong_physical_identity_cannot_create_proxy_or_enroll(fixture, field):
    expected = fixture.managed._expected(fixture.plans['newcomer'])
    fixture.managed._expected = lambda plan: {**expected, field: 'unapproved'}
    # The receiver adapter is a local fixture class; apply its changed subject
    # to the same class constructed by the actual coordinator.
    type(fixture.managed)._expected = lambda self, plan: {**expected, field: 'unapproved'}
    with pytest.raises(OnboardingError, match='admission_binding_changed'):
        GroupCoordinator(fixture.backend).advance('newcomer')
    assert 'physical-prepare' not in fixture.calls
    assert 'receiving-bootstrap-freeze' not in fixture.calls
    assert fixture.body['registered'] is False


def test_retry_cannot_change_physical_coordinates_after_lost_enrollment(fixture):
    f = fixture
    f.body['physical_lost'] = True
    with pytest.raises(OSError, match='lost physical'):
        GroupCoordinator(f.backend).advance('newcomer')
    expected = f.managed._expected(f.plans['newcomer'])
    type(f.managed)._expected = lambda self, plan: {**expected, 'credential_id': 'replacement'}
    from clusterctl.operation_journal import JournalConflict
    with pytest.raises(JournalConflict, match='evidence changed'):
        GroupCoordinator(f.backend).advance('newcomer')
    assert f.calls.count('physical-prepare') == 1
    assert 'receiving-bootstrap-freeze' not in f.calls
