"""Host orchestration with real journal/job locks and explicit dual-route fakes.

These do not establish native publication, systemd or actual cohort readiness.
"""
import copy
import os
import time
import uuid
from pathlib import Path

import pytest

from clusterctl import being_seed, onboarding_receiving_update as updates
from clusterctl.onboarding import JobStore, OnboardingError, digest
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_host import HostConfig
from clusterctl.onboarding_receiving_update import GuestBootstrapController
from clusterctl.onboarding_service import command
from clusterctl.operation_journal import JournalConflict, OperationJournal
from tests.test_receiving_host_selection import fixture as host_fixture
from tests.test_onboarding import FixtureBackend, plan


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    path, original, runtime, _, _ = host_fixture(tmp_path)
    config = HostConfig.load(path)
    value = {**plan(), 'release_digest': original['release_digest']}
    process = dict(pid=123, uid=1000, start_ticks=10, boot_id=str(uuid.uuid4()))
    parent = {**process, 'pid': 122, 'start_ticks': 9}
    group = dict(selected=dict(tribe_ref='synthetic-tribe', channel_id='tribe',
        application='/home/agent/group/application', visibility='/home/agent/group/visibility.json',
        socket='/home/agent/body/runtime/tribe.sock'), application_sha256='1' * 64,
        publication_sha256='7' * 64, installation_sha256='8' * 64)
    owner = dict(plan_digest=digest(value), genesis_digest='2' * 64, code_digest=runtime['runtime_digest'],
        runtime_sha256='3' * 64, group_sha256=digest(group), group=group,
        being_ref='being:synthetic', origin=dict(embodiment_id='body:synthetic'),
        predecessor=dict(process=process, admission_parent=parent))
    manager = dict(MainPID='122', InvocationID='old', ControlGroup='synthetic-group',
        ActiveState='active', SubState='running', User='agent', Group='agent')
    root = dict(service=dict(unit_sha256='4' * 64, manager=manager),
        scope=dict(process=process, admission_parent=parent, control_group='synthetic-group', invocation_id='old'))
    checked = dict(code_digest=runtime['runtime_digest'], being_ref=owner['being_ref'],
        embodiment_id=owner['origin']['embodiment_id'], release_digest='a' * 64,
        matrix_revision='b' * 40, matrix_wheel_sha256='c' * 64, sdk_digest='d' * 64,
        reader={'contract': {'interpreter': {'implementation': 'cpython', 'version': [3, 13, 5]}}})
    owner['observer_startup'] = dict(code_digest=checked['code_digest'], matrix_commit=checked['matrix_revision'],
        matrix_wheel_sha256=checked['matrix_wheel_sha256'], sdk_digest=checked['sdk_digest'],
        reader=checked['reader'], interpreter={**checked['reader']['contract']['interpreter'],
            'executable_sha256': '9' * 64})
    selected = dict(**runtime, manifest_path=str(tmp_path / 'manifest.json'), manifest_uid=os.geteuid(),
        code_uid=os.geteuid(), prepared=checked, expires_at_ms=12345,
        argv=command(Path('/opt/daimon-onboarding') / value['release_digest'], receive_only=False,
            visibility=Path(group['selected']['visibility']),
            runtime_code=Path('/opt/daimon-onboarding-runtime') / runtime['runtime_digest'],
            runtime_digest=runtime['runtime_digest']))
    selected['expires_at_ms'] = time.time_ns() // 1_000_000 + 3600000
    journal = OperationJournal(tmp_path / 'guest-journal')
    row = plan_update(journal, manifest_digest='a' * 64, target='receiving:synthetic-guest',
        expected_precondition=dict(host_config=str(path), host_configuration=original,
            host_config_sha256=digest(original), guest_bootstraps={'eko': dict(plan=value, owner=owner, root=root)}),
        intended_transition=dict(guest_bootstraps={'eko': selected}), audit_identity={'actor': 'synthetic'})
    monkeypatch.setattr(updates, 'preflight', lambda *_args, **_kwargs: copy.deepcopy(checked))
    new_process, new_parent = {**process, 'pid': 333, 'start_ticks': 12}, {**parent, 'pid': 322, 'start_ticks': 11}
    started = dict(manager={**manager, 'MainPID': '322', 'InvocationID': 'new'})
    calls = []
    class Backend:
        def __init__(self):
            self.config = config
            self.active = True
            self.stops = self.starts = self.stages = self.publications = 0
            self.done = set()
            self.fail = None
            self.gate = dict(controlled=True, process_id=333, phase='unselected', readers=[])
        def lose(self, phase, result):
            if self.fail == phase:
                self.fail = None
                raise OSError('synthetic lost ' + phase + ' reply')
            return result
        def _guest_service_call(self, _plan, action, **options):
            calls.append(action)
            if action == 'bootstrap-validate':
                assert self.active and not self.starts
                return {'candidate_sha256': 'f' * 64}
            if action == 'bootstrap-quiesce':
                if self.starts:
                    raise OnboardingError('replacement unit must not be stopped')
                if self.active:
                    self.active = False
                    self.stops += 1
                return self.lose('quiesce', {'exits': {'process': True, 'admission_parent': True}})
            if action == 'bootstrap-select':
                assert not self.active
                self.done.add('select')
                return self.lose('select', {'selected': True, 'selected_sha256': 'e' * 64})
            if action == 'bootstrap-start':
                assert 'select' in self.done
                if not self.active:
                    self.active = True
                    self.starts += 1
                return self.lose('start', copy.deepcopy(started))
            assert action == 'bootstrap-inspect'
            if not self.starts:
                result = copy.deepcopy(root)
                if not self.active:
                    result['service']['manager'].update(ActiveState='inactive', SubState='dead', MainPID='0')
                return result
            return dict(service={**copy.deepcopy(started), 'unit_sha256': 'e' * 64},
                scope=dict(process=new_process, admission_parent=new_parent))
        def _target_call(self, _plan, action, **options):
            calls.append(action)
            if action == 'receiving-bootstrap-freeze':
                assert self.active and not self.starts
                return copy.deepcopy(owner)
            if action == 'receiving-bootstrap-stage':
                assert not self.active
                if 'stage' not in self.done:
                    self.stages += 1
                    self.done.add('stage')
                return self.lose('stage', {'ready_sha256': '5' * 64})
            if action == 'receiving-bootstrap-publish':
                assert not self.active and options['bootstrap_ready_sha256'] == '5' * 64
                if 'publish' not in self.done:
                    self.publications += 1
                    self.done.add('publish')
                return self.lose('publish', {'runtime_sha256': '6' * 64})
            assert action == 'admitted-running' and self.active and options['require_loaded']
            startup = dict(code_digest=selected['runtime_digest'], matrix_commit=checked['matrix_revision'],
                sdk_digest=checked['sdk_digest'], matrix_wheel_sha256=checked['matrix_wheel_sha256'],
                reader=checked['reader'], process_id=new_process['pid'], startup_instance_id='synthetic-startup')
            return dict(process=new_process, admission_parent=new_parent, runtime_sha256='6' * 64,
                origin=owner['origin'], group=group['selected'],
                responder_association='same-connection',
                runtime_status={'loaded_runtime': {'qualified_startup': startup, 'runtime_bundle_sha256': '6' * 64}},
                group_runtime_status=dict(loaded_application={'application_sha256': group['application_sha256'],
                    'publication_sha256': group['publication_sha256'],
                    'visibility': {'installation_sha256': group['installation_sha256']}},
                    receiving={'channels': {'tribe': self.gate}}))
    backend = Backend()
    return GuestBootstrapController(journal, row['operation_id'], backend, 'eko'), backend, calls, path


def test_full_dual_route_effects_and_exact_retry_never_repeat_stop_or_keys(fixture):
    controller, backend, calls, _ = fixture
    result = controller.execute()
    assert result['receiving_readiness'] == 'unobserved'
    assert controller.execute() == result
    assert backend.stops == backend.starts == backend.stages == backend.publications == 1
    assert calls[-2:] == ['admitted-running', 'bootstrap-inspect']
    # Later cohort projection does not erase historical bootstrap/load proof.
    backend.gate = dict(controlled=True, process_id=333, phase='selected', readers=['synthetic-reader'])
    assert controller.execute() == result


def test_quiesce_retains_the_same_lifecycle_without_publishing_or_starting(fixture):
    controller, backend, calls, _ = fixture
    result = controller.quiesce()
    assert result == {'exits': {'process': True, 'admission_parent': True}}
    assert not backend.active and backend.stops == 1
    assert backend.starts == backend.stages == backend.publications == 0
    assert calls[-1] == 'bootstrap-quiesce'
    assert controller.quiesce() == result
    assert backend.stops == 1 and calls[-1] == 'bootstrap-quiesce'
    effects = controller._row()[0]['runtime_observation']['guest_bootstraps']['eko']
    assert set(effects) == {'candidate_validated', 'quiesced'}
    assert controller.execute()['receiving_readiness'] == 'unobserved'
    assert backend.stops == backend.starts == backend.stages == backend.publications == 1


def test_quiesce_lost_reply_resumes_the_same_root_operation(fixture):
    controller, backend, _, _ = fixture
    backend.fail = 'quiesce'
    with pytest.raises(OSError, match='lost quiesce'):
        controller.quiesce()
    assert backend.stops == 1 and not backend.active
    assert controller.quiesce()['exits'] == {'process': True, 'admission_parent': True}
    assert backend.stops == 1 and backend.starts == backend.stages == backend.publications == 0


@pytest.mark.parametrize('lost_start_reply', [False, True])
def test_quiesce_cannot_stop_a_started_replacement(fixture, lost_start_reply):
    controller, backend, calls, _ = fixture
    if lost_start_reply:
        backend.fail = 'start'
        with pytest.raises(OSError, match='lost start'):
            controller.execute()
    else:
        controller.execute()
    before = list(calls)
    with pytest.raises(OnboardingError, match='already_started|replacement unit'):
        controller.quiesce()
    assert backend.active and backend.stops == backend.starts == 1
    if not lost_start_reply:
        assert calls == before


def test_quiesce_rechecks_current_root_instead_of_trusting_retained_exit(fixture):
    controller, backend, _, _ = fixture
    controller.quiesce()
    backend.active = True
    backend.starts = 1
    with pytest.raises(OnboardingError, match='replacement unit'):
        controller.quiesce()
    assert backend.active and backend.stops == 1


@pytest.mark.parametrize('outside_horizon', [False, True])
def test_expired_controller_uses_existing_owner_route_and_checks_horizon_before_stop(fixture, outside_horizon):
    controller, backend, calls, _ = fixture
    original = controller.journal.get(controller.operation_id)
    before = copy.deepcopy(original['expected_precondition'])
    owner = before['guest_bootstraps']['eko']['owner']
    expiry = original['intended_transition']['guest_bootstraps']['eko']['expires_at_ms']
    owner.update(mode='renew', renewal_not_after_ms=expiry + (-1 if outside_horizon else 60000),
        preservation=dict(runtime_sha256=owner['runtime_sha256'], origin=owner['origin']))
    row = plan_update(controller.journal, manifest_digest='a' * 64, target='expired-guest:fixture',
        expected_precondition=before, intended_transition=original['intended_transition'],
        audit_identity={'actor': 'fixture'})
    controller = GuestBootstrapController(controller.journal, row['operation_id'], backend, 'eko')
    actual = backend._target_call
    def renewal(plan, action, **options):
        if action == 'receiving-bootstrap-freeze':
            return copy.deepcopy(owner)
        if options.get('bootstrap_request') is not None:
            assert options['bootstrap_request']['mode'] == 'renew'
            assert options['bootstrap_request']['preservation'] == owner['preservation']
        return actual(plan, action, **options)
    backend._target_call = renewal
    if outside_horizon:
        with pytest.raises(OnboardingError, match='renewal_authorization_expired'):
            controller.execute()
        assert backend.stops == backend.stages == 0
    else:
        backend.fail = 'publish'
        with pytest.raises(OSError, match='lost publish'):
            controller.execute()
        result = controller.execute()
        assert controller.execute() == result
        assert backend.stops == backend.starts == backend.stages == backend.publications == 1
        assert 'receiving-bootstrap-publish' in calls


def test_journal_reference_becomes_one_stable_uuid_for_both_native_routes(fixture):
    controller, backend, _, _ = fixture
    assert controller.operation_id.startswith('operation:')
    root_call, owner_call = backend._guest_service_call, backend._target_call
    requests = []
    def root(*args, **options):
        if options.get('request') is not None:
            value = options['request']['operation_id']
            assert str(uuid.UUID(value)) == value  # Actual root/owner CLI contract.
            requests.append(('root', value))
        return root_call(*args, **options)
    def owner(*args, **options):
        if options.get('bootstrap_request') is not None:
            value = options['bootstrap_request']['operation_id']
            assert str(uuid.UUID(value)) == value
            requests.append(('owner', value))
        return owner_call(*args, **options)
    backend._guest_service_call, backend._target_call = root, owner
    first = controller.execute()
    assert controller.execute() == first
    assert {route for route, _ in requests} == {'root', 'owner'}
    assert {value for _, value in requests} == {str(uuid.uuid5(uuid.NAMESPACE_URL,
        'cluster-guest-bootstrap:' + controller.operation_id))}
    assert backend.stops == backend.starts == backend.stages == backend.publications == 1


def test_noncanonical_journal_ids_do_not_alias_canonical_native_requests():
    controller = object.__new__(GuestBootstrapController)
    canonical = 'a1234567-89ab-4cde-8fab-0123456789ab'
    labels = [canonical, canonical.upper(), canonical.replace('-', ''),
        'urn:uuid:' + canonical, 'operation:' + canonical]
    mapped = []
    for label in labels:
        controller.operation_id = label
        mapped.append(controller._native_operation_id())
    assert mapped[0] == canonical and len(set(mapped)) == len(labels)
    assert all(str(uuid.UUID(value)) == value for value in mapped)


def test_loaded_proof_preserves_the_frozen_root_dropin_vector(fixture):
    controller, backend, _, _ = fixture
    controller.execute()
    actual = backend._guest_service_call
    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        result['service']['dropins'] = {'/new-dropin.conf': 'e' * 64}
        return result
    backend._guest_service_call = changed
    with pytest.raises(OnboardingError, match='loaded_conflict'):
        controller.execute()
    assert backend.stops == backend.starts == 1


@pytest.mark.parametrize('phase', ['quiesce', 'stage', 'publish', 'select', 'start'])
def test_lost_concrete_reply_recovers_the_same_operation(fixture, phase):
    controller, backend, _, _ = fixture
    backend.fail = phase
    with pytest.raises(OSError):
        controller.execute()
    result = controller.execute()
    assert result['receiving_readiness'] == 'unobserved'
    assert backend.stops == backend.starts == backend.stages == backend.publications == 1


def test_changed_host_configuration_and_replacement_job_owner_prevent_effects(fixture):
    controller, backend, calls, path = fixture
    original = being_seed._read(path)
    being_seed._write(path, {**original, 'concurrency': 2})
    with pytest.raises(OnboardingError, match='binding_conflict'):
        controller.execute()
    assert not calls and backend.stops == 0
    being_seed._write(path, original)
    store = JobStore(backend.config.jobs)
    store.submit(plan(), FixtureBackend())
    job = store.directory('eko')
    with being_seed._locked(job):
        with pytest.raises(being_seed.SeedError, match='in_progress'):
            controller.execute()
    assert not calls


@pytest.mark.parametrize('action', ['execute', 'quiesce'])
def test_journal_and_jobs_are_owned_during_both_typed_routes(fixture, action):
    controller, backend, _, _ = fixture
    competitor = OperationJournal(controller.journal.path.parent)
    root = backend._guest_service_call
    def checked(*args, **kwargs):
        with pytest.raises(JournalConflict, match='mutation is in progress'):
            competitor.advance(controller.operation_id, 'degraded')
        with pytest.raises(being_seed.SeedError, match='in_progress'):
            with being_seed._locked(backend.config.jobs):
                pytest.fail('jobs parent is not owned')
        return root(*args, **kwargs)
    backend._guest_service_call = checked
    result = getattr(controller, action)()
    if action == 'execute':
        assert result['receiving_readiness'] == 'unobserved'
    else:
        assert result['exits'] == {'process': True, 'admission_parent': True}


def test_preparation_reuses_maintained_command_and_refuses_sdk_mismatch_before_root(fixture, monkeypatch):
    controller, backend, calls, _ = fixture
    row, frozen, candidate = controller._row()
    manifest = dict(provenance={'matrix_revision': candidate['prepared']['matrix_revision']},
        artifacts={'matrix_sdk': candidate['prepared']['matrix_wheel_sha256']},
        required_receivers=[{'artifacts': {'receiving_code': candidate['runtime_digest']}}])
    monkeypatch.setattr(updates, '_manifest', lambda *_args, **_kwargs: manifest)
    monkeypatch.setattr(updates.onboarding_sdk, 'verify', lambda *_args, **_kwargs: {})
    actual = backend._target_call
    def prepare(_plan, action, **kwargs):
        if action == 'sdk-prepare':
            return dict(ready=True, matrix_commit=candidate['prepared']['matrix_revision'])
        if action == 'receiving-bootstrap-freeze':
            return copy.deepcopy(frozen['owner'])
        return actual(_plan, action, **kwargs)
    backend._target_call = prepare
    backend._receiving_base = lambda _plan: Path('/opt/daimon-onboarding') / frozen['plan']['release_digest']
    backend._runtime_paths = lambda _plan, _base, **_kwargs: (
        Path('/opt/daimon-onboarding-runtime') / candidate['runtime_digest'], [], {})
    root = backend._guest_service_call
    backend._guest_service_call = lambda _plan, action, **_kwargs: (
        copy.deepcopy(frozen['root']) if action == 'bootstrap-inspect' else root(_plan, action, **_kwargs))
    prepared, selected = updates.prepare_guest_bootstrap(backend, frozen['plan'],
        candidate=(Path(candidate['runtime_code']), candidate['runtime_digest']),
        manifest_path=Path(candidate['manifest_path']), manifest_digest=row['intent']['runtime_call']['manifest_digest'],
        expires_at_ms=candidate['expires_at_ms'], manifest_uid=candidate['manifest_uid'])
    assert prepared == frozen and selected == candidate and backend.stops == backend.starts == 0
    backend._target_call = lambda _plan, action, **kwargs: (
        {'ready': True, 'matrix_commit': '0' * 40} if action == 'sdk-prepare' else copy.deepcopy(frozen['owner']))
    with pytest.raises(OnboardingError, match='candidate_required'):
        updates.prepare_guest_bootstrap(backend, frozen['plan'],
            candidate=(Path(candidate['runtime_code']), candidate['runtime_digest']),
            manifest_path=Path(candidate['manifest_path']), manifest_digest=row['intent']['runtime_call']['manifest_digest'],
            expires_at_ms=candidate['expires_at_ms'], manifest_uid=candidate['manifest_uid'])
    assert not calls


def test_loaded_proof_rejects_replacement_and_changed_unit_without_restarting(fixture):
    controller, backend, _, _ = fixture
    controller.execute()
    actual = backend._guest_service_call
    def changed(_plan, action, **kwargs):
        result = actual(_plan, action, **kwargs)
        if action == 'bootstrap-inspect':
            result['service']['unit_sha256'] = 'f' * 64
        return result
    backend._guest_service_call = changed
    with pytest.raises(OnboardingError, match='loaded_conflict'):
        controller.execute()
    assert backend.stops == backend.starts == 1


@pytest.mark.parametrize('change', ['bundle', 'publication', 'visibility', 'gate-pid', 'gate-bool', 'startup-instance'])
def test_loaded_contract_mismatches_are_not_readiness_or_restart_requests(fixture, change):
    controller, backend, _, _ = fixture
    controller.execute()
    actual = backend._target_call
    def changed(_plan, action, **kwargs):
        result = actual(_plan, action, **kwargs)
        if action == 'admitted-running':
            if change == 'bundle':
                result['runtime_status']['loaded_runtime']['runtime_bundle_sha256'] = '0' * 64
            elif change == 'publication':
                result['group_runtime_status']['loaded_application']['publication_sha256'] = '0' * 64
            elif change == 'visibility':
                result['group_runtime_status']['loaded_application']['visibility']['installation_sha256'] = '0' * 64
            elif change == 'gate-pid':
                result['group_runtime_status']['receiving']['channels']['tribe']['process_id'] = 444
            elif change == 'gate-bool':
                result['group_runtime_status']['receiving']['channels']['tribe']['controlled'] = 1
            else:
                result['runtime_status']['loaded_runtime']['qualified_startup']['startup_instance_id'] = 'replacement'
        return result
    backend._target_call = changed
    with pytest.raises(OnboardingError, match='loaded_conflict'):
        controller.execute()
    assert backend.stops == backend.starts == 1


def test_bad_manifest_is_refused_before_candidate_dispatch(fixture, monkeypatch):
    controller, backend, calls, _ = fixture
    _, frozen, candidate = controller._row()
    def refused(*_args, **_kwargs):
        raise OnboardingError('receiving_manifest_digest_mismatch')
    monkeypatch.setattr(updates, '_manifest', refused)
    with pytest.raises(OnboardingError, match='manifest_digest'):
        updates.prepare_guest_bootstrap(backend, frozen['plan'],
            candidate=(Path(candidate['runtime_code']), candidate['runtime_digest']),
            manifest_path=Path(candidate['manifest_path']), manifest_digest='a' * 64,
            expires_at_ms=candidate['expires_at_ms'])
    assert not calls


def test_changed_guest_observer_interpreter_is_refused_before_stop(fixture):
    controller, backend, _, _ = fixture
    actual = backend._target_call
    def wrong(_plan, action, **kwargs):
        result = actual(_plan, action, **kwargs)
        if action == 'receiving-bootstrap-freeze':
            result['observer_startup']['interpreter'] = {'wrong': True}
        return result
    backend._target_call = wrong
    with pytest.raises(OnboardingError, match='candidate_required'):
        controller.execute()
    assert backend.stops == backend.starts == 0


def test_expiry_refuses_first_stop_but_preserves_committed_publication_retry(fixture, monkeypatch):
    controller, backend, _, _ = fixture
    _, _, candidate = controller._row()
    expires = candidate['expires_at_ms']
    now = time.time_ns()
    monkeypatch.setattr(time, 'time_ns', lambda: (expires + 1) * 1_000_000)
    with pytest.raises(OnboardingError, match='expiry_changed'):
        controller.execute()
    assert backend.stops == 0
    monkeypatch.setattr(time, 'time_ns', lambda: now)
    backend.fail = 'publish'
    with pytest.raises(OSError):
        controller.execute()
    monkeypatch.setattr(time, 'time_ns', lambda: (expires + 1) * 1_000_000)
    assert controller.execute()['receiving_readiness'] == 'unobserved'
    assert backend.stops == backend.starts == backend.publications == 1


def test_fresh_qualification_cannot_consume_issuance_interval_then_stop(fixture, monkeypatch):
    controller, backend, _, _ = fixture
    _, _, candidate = controller._row()
    actual = backend._target_call
    now = [time.time_ns()]
    monkeypatch.setattr(time, 'time_ns', lambda: now[0])
    def late(_plan, action, **kwargs):
        result = actual(_plan, action, **kwargs)
        if action == 'receiving-bootstrap-freeze':
            now[0] = (candidate['expires_at_ms'] + 1) * 1_000_000
        return result
    backend._target_call = late
    with pytest.raises(OnboardingError, match='authorization_expired'):
        controller.execute()
    assert backend.stops == backend.starts == 0


def test_fresh_observer_pid_nonce_may_change_without_changing_guest_interpreter(fixture):
    controller, backend, _, _ = fixture
    actual = backend._target_call
    def fresh(_plan, action, **kwargs):
        result = actual(_plan, action, **kwargs)
        if action == 'receiving-bootstrap-freeze':
            result['observer_startup'].update(process_id=777, startup_instance_id='fresh-observer-only')
        return result
    backend._target_call = fresh
    assert controller.execute()['receiving_readiness'] == 'unobserved'
    assert backend.stops == backend.starts == 1


@pytest.mark.parametrize('lost_phase', [None, 'stage', 'start'])
def test_controlled_guest_software_adoption_preserves_authority_and_recovers_lost_reply(fixture, lost_phase):
    controller, backend, calls, _ = fixture
    original = controller.journal.get(controller.operation_id)
    before = copy.deepcopy(original['expected_precondition'])
    owner = before['guest_bootstraps']['eko']['owner']
    owner.update(mode='preserve', preservation=dict(not_before_ms=time.time_ns() // 1_000_000 - 1000,
        not_after_ms=time.time_ns() // 1_000_000 + 7200000, immutable_sha256='a' * 64,
        runtime_sha256=owner['runtime_sha256'], origin=owner['origin'], active=True))
    row = plan_update(controller.journal, manifest_digest='a' * 64, target='controlled-guest:fixture',
        expected_precondition=before, intended_transition=original['intended_transition'],
        audit_identity={'actor': 'fixture'})
    controller = GuestBootstrapController(controller.journal, row['operation_id'], backend, 'eko')
    target_call = backend._target_call
    def controlled(plan, action, **options):
        if action == 'receiving-bootstrap-freeze':
            return copy.deepcopy(owner)
        if action == 'receiving-bootstrap-stage':
            calls.append(action)
            assert not backend.active
            if 'preserve' not in backend.done:
                backend.stages += 1
                backend.done.add('preserve')
            return backend.lose('stage', dict(mode='preserve', preservation=owner['preservation'],
                request_sha256=digest(options['bootstrap_request']), runtime_sha256=owner['runtime_sha256']))
        assert action != 'receiving-bootstrap-publish'
        result = target_call(plan, action, **options)
        if action == 'admitted-running':
            result['runtime_sha256'] = owner['runtime_sha256']
            result['runtime_status']['loaded_runtime']['runtime_bundle_sha256'] = owner['runtime_sha256']
        return result
    backend._target_call = controlled
    backend.fail = lost_phase
    if lost_phase is not None:
        with pytest.raises(OSError):
            controller.execute()
    result = controller.execute()
    assert controller.execute() == result
    assert backend.stages == backend.starts == backend.stops == 1 and backend.publications == 0
    effects = controller.journal.get(row['operation_id'])['runtime_observation']['guest_bootstraps']['eko']
    assert 'owner_preserved' in effects and not {'owner_ready', 'owner_published'} & effects.keys()
