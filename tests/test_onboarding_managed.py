"""Managed reconciliation uses native admission and preserves uncertain effects."""
import copy
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_admission import ReceivingHolder
from clusterctl.onboarding_managed import ManagedRuntime
from clusterctl.onboarding_runtime import AdmittedDaemon
from clusterctl.onboarding_target import Target
from tests.test_admission import _key
from tests.test_onboarding_target import receiving
from tests import test_guest_service_bootstrap as service_fixtures

fixture = service_fixtures.fixture
initial = service_fixtures.initial


def test_initial_proxy_observation_uses_the_existing_bounded_inventory_route():
    managed = object.__new__(ManagedRuntime)
    managed.settings = dict(host_port=1234, guest_port=5678)
    calls = []
    def dispatch(plan, argv, **options):
        calls.append((argv, options))
        return json.dumps([dict(name='dm-newcomer', expanded_devices={
            'onboarding-admission': managed._proxy()})])
    managed.backend = SimpleNamespace(_dispatch=dispatch, instance=lambda _: 'dm-newcomer')
    assert managed._check_proxy({}, deadline_ns=12345)
    assert calls == [(['list', '--format=json'], {'deadline_ns': 12345})]


def test_each_receiving_body_selects_its_verified_peer_application(monkeypatch):
    managed = object.__new__(ManagedRuntime)
    managed.backend = SimpleNamespace(config=SimpleNamespace(peer=Path('configured'), qualification=False))
    managed.settings = {'visibility_installation': '/home/agent/another-being/visibility',
                        'messaging_application': '/home/agent/another-being/application'}
    def host(backend):
        def application(plan):
            if plan['name'] == 'waiting':
                return None
            root = '/home/agent/.local/state/daimon-onboarding/' + plan['name'] + '/matrix/peer'
            return root + '/application', root + '/visibility/installation.json'
        return SimpleNamespace(application=application)
    monkeypatch.setattr('clusterctl.onboarding_peer_host.PeerHost', host)
    for name in ('eko', 'oliva'):
        app, visibility = managed._selection({'name': name})
        assert '/' + name + '/matrix/peer/' in app and '/' + name + '/matrix/peer/' in visibility
        assert managed._ready({'name': name})
    assert managed._selection({'name': 'waiting'}) == (None, None)
    assert not managed._ready({'name': 'waiting'})


def test_lost_enrollment_and_registry_ack_resume_same_holder_and_native_body(tmp_path, monkeypatch):
    ceremony, plan, blank = receiving(tmp_path)
    ceremony.prepare(plan, identity_mode='first')
    registrar = _key(tmp_path / 'host/registrar.pem', 'registrar')
    signer = _key(tmp_path / 'host/authority.pem', 'authority')
    authority = AdmissionAuthority(tmp_path / 'authority', signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key})
    server = AdmissionTCPServer(('127.0.0.1', 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network('127.0.0.1', server.server_address[1])
    for name in ('service-state', 'registry'):
        (tmp_path / name).mkdir(mode=0o700)
    settings = dict(schema='cluster-onboarding-managed-runtime/v1',
        host_port=server.server_address[1], guest_port=server.server_address[1],
        authority_key_id=signer.key_id, authority_public_key=signer.public_key,
        registrar_key_id=registrar.key_id, registrar_key=str(tmp_path / 'host/registrar.pem'),
        registry=str(tmp_path / 'registry'), state=str(tmp_path / 'service-state'), visibility_installation=None)
    being_seed._write(tmp_path / 'managed.json', settings)
    published = []
    monkeypatch.setattr('clusterctl.onboarding_mounts.prepare_matrix_public',
                        lambda _root, _plan, documents: published.append(documents))
    with tempfile.TemporaryDirectory(prefix='dm-') as home:
        target = Target(Path(home), plan, blank.genesis)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        holder = ReceivingHolder(target)
        instances = [dict(name='dm-' + plan['name'], expanded_devices={})]
        active = []
        failures = ['enroll', 'registry']
        calls = []
        def target_call(_plan, action, *, profile=None):
            calls.append(action)
            if action == 'admission-prepare':
                return holder.request()
            if action in {'admission-check', 'admission-enroll'}:
                result = dict(registered=holder.ensure_enrolled(profile, enroll=action == 'admission-enroll'))
                if action == 'admission-enroll' and 'enroll' in failures:
                    failures.remove('enroll')
                    raise OSError('lost ACK after authority registration')
                return result
            assert action == 'admitted-running'
            return target.running(admitted=True)
        def dispatch(_plan, argv):
            if argv[:3] == ['config', 'device', 'add']:
                instances[0]['expanded_devices'][argv[4]] = dict(type=argv[5],
                    **dict(item.split('=', 1) for item in argv[6:]))
                return ''
            if 'systemctl' in argv:
                return 'ActiveState=active\nMainPID=1\n' if active else 'ActiveState=inactive\nMainPID=0\n'
            assert 'python3' in argv
            if not active:
                client = holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
                daemon = AdmittedDaemon(target, client)
                daemon.start(receive_only=True)
                active.append(daemon)
            return json.dumps(dict(installed=True))
        backend = SimpleNamespace(config=SimpleNamespace(admission=tmp_path / 'managed.json', qualification=True,
            custody=ceremony.root, custody_grants=ceremony.grants, views=tmp_path / 'views'),
            instance=lambda _plan: instances[0]['name'], _inventory=lambda: (instances, []),
            _dispatch=dispatch, _target_call=target_call,
            _guest_paths=lambda _plan: (None, Path('/opt/qualified-code'), {}),
            _runtime_paths=lambda _plan, code: (code, [], {}))
        backend._ceremony = lambda _plan: ceremony
        managed = ManagedRuntime(backend)
        # Receive-only is a disposable qualification mode, never a live fallback.
        assert managed.observe({**plan, 'name': 'eko'}).state == 'waiting'
        original_adopt = managed.registry.adopt_running
        def adopt(**origin):
            result = original_adopt(**origin)
            if 'registry' in failures:
                failures.remove('registry')
                raise OSError('lost ACK after registry publication')
            return result
        managed.registry.adopt_running = adopt
        try:
            assert managed.observe(plan).state == 'absent'
            with pytest.raises(OSError, match='authority registration'):
                managed.prepare_admission(plan)
            preserved_key = holder.key.read_bytes()
            proposal = being_seed._read(tmp_path / 'service-state' / digest(plan) / 'candidate.json')
            # A shared-group owner context must be frozen after native profile
            # preparation, while no application/service has been selected yet.
            # The real authority has already accepted the lost enrollment ACK.
            ready = managed._ready
            managed._ready = lambda _plan: False
            with pytest.raises(OnboardingError, match='visibility_selection_required'):
                managed.execute(plan)
            assert managed.prepare_admission(plan) == proposal
            assert managed.prepare_admission(plan) == proposal
            assert active == []
            assert not managed._registered(managed._expected(plan))
            managed._ready = ready
            with pytest.raises(OSError, match='registry publication'):
                managed.execute(plan)
            pid = active[0].process.pid
            before = managed.registry.path.read_bytes()
            observed = managed.observe(plan)
            observed.validate()
            assert observed.state == 'complete' and observed.facts['identity_verified'] is True
            managed.execute(plan)
            assert managed.registry.path.read_bytes() == before
            assert len(active) == 1 and active[0].process.pid == pid
            assert holder.key.read_bytes() == preserved_key
            assert calls.count('admission-prepare') == calls.count('admission-enroll') == 1
            assert all(documents['admission.json'] == proposal for documents in published)
            active[0].close()
            active.clear()
            assert managed.observe(plan).state == 'absent'
            # Registry is continuity history; its row alone never proves presence.
            assert managed.registry.path.read_bytes() == before
        finally:
            for daemon in active:
                daemon.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def initial_managed_fixture(tmp_path, initial):
    """Real journal/job/reader/root orchestration, fake manager and native RPC.

    This does not qualify an actual guest, signed application, native process
    or canonical registry adoption. Native authority is tested separately above.
    """
    from clusterctl.onboarding import JobStore
    from tests.test_onboarding import plan as make_plan
    from tests.test_receiving_cohort_control import admission_fixture
    cohort, owners, journal, row, _ = admission_fixture(tmp_path)
    plan = make_plan('newcomer')
    jobs = tmp_path / 'jobs'
    jobs.mkdir(mode=0o700)
    backend = SimpleNamespace(config=SimpleNamespace(jobs=jobs), authorize=lambda *_: True)
    JobStore(jobs).submit(plan, backend)
    cohort.revoke_senders()
    barrier = cohort.require_revocation_barrier
    def bounded_barrier():
        assert all(getattr(cohort.owners[sender['name']], 'deadline_ns', 0) > time.monotonic_ns()
            for sender in row['expected_precondition']['senders'])
        return barrier()
    cohort.require_revocation_barrier = bounded_barrier
    approved = row['intended_transition']['cohort_admission']['receivers']['newcomer']
    prepared = approved['recipe']['prepared']
    root_controller, manager, _ = initial
    parent = root_controller._parent({})
    process = {**parent, 'pid': 223, 'start_ticks': 10}
    expected = dict(body_ref='codex:fixture:newcomer', embodiment_id=approved['embodiment_id'],
        incarnation_id='incarnation:fixture')
    selected = dict(tribe_ref='tribe:fixture', socket=str(owners['newcomer'].socket),
        application='/home/agent/synthetic/application', visibility='/home/agent/synthetic/visibility.json')
    group = dict(selected=selected, application_sha256='a' * 64,
        publication_sha256='b' * 64, installation_sha256='c' * 64)
    startup = dict(code_digest=prepared['code_digest'], matrix_commit=prepared['matrix_revision'],
        sdk_digest=prepared['sdk_digest'], matrix_wheel_sha256=prepared['matrix_wheel_sha256'],
        reader=prepared['reader'], process_id=process['pid'], startup_instance_id='fixture-first-start')
    owner = dict(plan_digest=digest(plan), genesis_digest='d' * 64, origin=expected,
        being_ref=approved['being_ref'], runtime_sha256='e' * 64, group=group,
        group_sha256=digest(group), predecessor=None, observer_startup=startup, mode='preserve',
        preservation=dict(active=True, not_before_ms=0, not_after_ms=time.time_ns() // 1_000_000 + 600000))
    gate = dict(controlled=True, process_id=process['pid'], phase='unselected', readers=[])
    observed = dict(origin=expected, process=process, admission_parent=parent, group=selected,
        runtime_sha256=owner['runtime_sha256'], responder_association='same-connection',
        runtime_status={'loaded_runtime': dict(qualified_startup=startup,
            runtime_bundle_sha256=owner['runtime_sha256'], process_id=process['pid'])},
        group_runtime_status=dict(loaded_application=dict(application_sha256=group['application_sha256'],
            publication_sha256=group['publication_sha256'], visibility={'installation_sha256': group['installation_sha256']},
            reader_gates={'tribe': gate}), receiving={'channels': {'tribe': gate}}))
    calls, adopted = [], []
    fault = []
    def target_call(_plan, action, **options):
        calls.append(action)
        if action == 'receiving-bootstrap-freeze':
            assert options['bootstrap_initial_service'] is True
            return copy.deepcopy(owner)
        assert action == 'admitted-running' and options['require_loaded'] is True
        if 'load' in fault:
            fault.remove('load')
            raise OSError('synthetic lost loaded observation')
        return copy.deepcopy(observed)
    def root_call(_plan, action, *, timeout_seconds, request=None, owner_observation=None, **_):
        backend.root_budgets.append((action, timeout_seconds))
        expiry = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        if action == 'bootstrap-inspect':
            return root_controller.inspect(owner_observation, deadline_ns=expiry)
        result = root_controller.execute(action.removeprefix('bootstrap-'), request, deadline_ns=expiry)
        if action == 'bootstrap-select' and hasattr(backend, 'after_select'):
            backend.after_select()
        step = action.removeprefix('bootstrap-')
        if step in fault:
            fault.remove(step)
            raise OSError('synthetic lost ' + step + ' return')
        return result
    def adopt(**origin):
        adopted.append(origin)
        if 'registry' in fault:
            fault.remove('registry')
            raise OSError('synthetic lost registry adoption return')
    backend._target_call, backend._guest_service_call = target_call, root_call
    backend.frozen_owner = owner
    backend.root_budgets = []
    backend._receiving_base = lambda _: Path('/opt/frozen-base')
    backend._runtime_paths = lambda _plan, _base, candidate: (
        Path('/opt/daimon-onboarding-runtime') / candidate[1], [], {})
    managed = object.__new__(ManagedRuntime)
    managed.backend, managed.registry = backend, SimpleNamespace(adopt_running=adopt)
    managed._profile = lambda _: {'synthetic': 'already prepared profile'}
    managed._expected = lambda _: copy.deepcopy(expected)
    managed._registered = lambda _: False
    managed._check_proxy = lambda _, **_options: True
    return managed, plan, cohort, manager, observed, calls, adopted, fault


@pytest.mark.parametrize('lost', ['start', 'load', 'registry'])
def test_initial_managed_load_resumes_same_operation_without_second_start(tmp_path, initial, lost):
    managed, plan, cohort, manager, observed, calls, adopted, fault = initial_managed_fixture(tmp_path, initial)
    fault.append(lost)
    with pytest.raises(OSError, match='synthetic lost'):
        managed.execute_initial(plan, cohort)
    row = cohort._row()
    intent = copy.deepcopy(row['runtime_observation']['initial_managed']['newcomer']['intent'])
    loaded = managed.execute_initial(plan, cohort)
    assert loaded == managed.execute_initial(plan, cohort)
    assert loaded['process'] == observed['process'] and loaded['admission_parent'] == observed['admission_parent']
    assert loaded['schema'] == 'cluster-guest-initial-loaded/v1' and loaded['receiving_readiness'] == 'unobserved'
    assert calls.count('receiving-bootstrap-freeze') == 2
    assert manager.starts == manager.enables == 1
    assert cohort._row()['runtime_observation']['initial_managed']['newcomer']['intent'] == intent
    assert all(owner.gate['phase'] == 'revoke' for name, owner in cohort.owners.items() if name != 'newcomer')
    assert observed['group_runtime_status']['receiving']['channels']['tribe']['readers'] == []
    assert adopted and all(origin == observed['origin'] for origin in adopted)
    manager.invocation = 'unexpected replacement'
    with pytest.raises(OnboardingError, match='started_process_changed'):
        managed.execute_initial(plan, cohort)
    assert manager.starts == 1


@pytest.mark.parametrize('drift', ['group', 'gate', 'process', 'profile'])
def test_initial_managed_load_refuses_changed_context_without_readiness(tmp_path, initial, drift):
    managed, plan, cohort, manager, observed, calls, adopted, fault = initial_managed_fixture(tmp_path, initial)
    if drift == 'profile':
        fault.append('start')
        with pytest.raises(OSError):
            managed.execute_initial(plan, cohort)
        managed._profile = lambda _: {'synthetic': 'unexpected replacement profile'}
    elif drift == 'group':
        observed['group_runtime_status']['loaded_application']['publication_sha256'] = 'f' * 64
    elif drift == 'gate':
        observed['group_runtime_status']['receiving']['channels']['tribe']['phase'] = 'select'
    else:
        observed['runtime_status']['loaded_runtime']['qualified_startup']['process_id'] += 1
    with pytest.raises(OnboardingError, match='loaded_conflict|binding_changed'):
        managed.execute_initial(plan, cohort)
    assert manager.starts == 1 and not adopted
    assert 'controlled_loaded' not in cohort._row()['runtime_observation']['initial_managed']['newcomer']


def test_changed_owner_after_lost_selection_is_refused_before_first_start(tmp_path, initial):
    managed, plan, cohort, manager, _, _, adopted, fault = initial_managed_fixture(tmp_path, initial)
    fault.append('select')
    with pytest.raises(OSError, match='lost select'):
        managed.execute_initial(plan, cohort)
    assert manager.starts == 0
    managed.backend.frozen_owner['runtime_sha256'] = 'f' * 64
    with pytest.raises(OnboardingError, match='initial_owner_changed'):
        managed.execute_initial(plan, cohort)
    assert manager.starts == 0 and not adopted


def test_expired_horizon_does_not_block_retained_start_observation(tmp_path, initial, monkeypatch):
    managed, plan, cohort, manager, _, _, _, fault = initial_managed_fixture(tmp_path, initial)
    fault.append('start')
    with pytest.raises(OSError, match='lost start'):
        managed.execute_initial(plan, cohort)
    expiry = cohort._row()['intended_transition']['cohort_admission']['activation']['expires_at_ms']
    monkeypatch.setattr('clusterctl.onboarding_managed.time.time_ns', lambda: (expiry + 1) * 1_000_000)
    assert managed.execute_initial(plan, cohort)['receiving_readiness'] == 'unobserved'
    assert manager.starts == 1


def test_expiry_during_selection_cannot_authorize_a_first_start(tmp_path, initial, monkeypatch):
    managed, plan, cohort, manager, _, _, adopted, _ = initial_managed_fixture(tmp_path, initial)
    expiry = cohort._row()['intended_transition']['cohort_admission']['activation']['expires_at_ms']
    managed.backend.after_select = lambda: monkeypatch.setattr(
        'clusterctl.onboarding_managed.time.time_ns', lambda: (expiry + 1) * 1_000_000)
    with pytest.raises(OnboardingError, match='authorization_expired'):
        managed.execute_initial(plan, cohort)
    assert manager.starts == 0 and not adopted


def test_fresh_root_effects_share_the_fixed_authorization_remainder(tmp_path, initial, monkeypatch):
    managed, plan, cohort, _, _, _, _, _ = initial_managed_fixture(tmp_path, initial)
    expiry = cohort._row()['intended_transition']['cohort_admission']['activation']['expires_at_ms']
    monkeypatch.setattr('clusterctl.onboarding_managed.time.time_ns', lambda: (expiry - 700) * 1_000_000)
    managed.execute_initial(plan, cohort)
    assert all(0 < budget <= .7 for action, budget in managed.backend.root_budgets
        if action in {'bootstrap-start', 'bootstrap-select'})
