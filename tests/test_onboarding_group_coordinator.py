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
    monkeypatch.setattr(GroupCoordinator, '_owners', lambda self, admission: owners)
    return SimpleNamespace(store=store, stages=stages, plans=plans, owners=owners, journal=journal,
        row=row, path=path, selected=selected, backend=backend, calls=calls, native=native)


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
    assert set(current['runtime_observation']['portal_admission']) == {'native_intent', 'native_dispatch', 'native_ready'}
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
    plan_path, genesis = tmp_path/'plan.json', tmp_path/'genesis.json'
    being_seed._write(plan_path, plan(browser=False))
    being_seed._write(genesis, {})
    monkeypatch.setattr(target.onboarding_code_successor, 'selection', lambda *a, **k: tmp_path/'code')
    monkeypatch.setattr(target.onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {})
    def sdk(*a, **k):
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
