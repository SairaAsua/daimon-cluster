"""Managed reconciliation uses native admission and preserves uncertain effects."""
import copy
import json
import tempfile
import time
from pathlib import Path
from types import MethodType, SimpleNamespace

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


@pytest.mark.parametrize('bounded', [False, True])
def test_lost_enrollment_and_registry_ack_resume_same_holder_and_native_body(tmp_path, monkeypatch, bounded):
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
        deadline = time.monotonic_ns() + 60_000_000_000
        expiry = time.time_ns() // 1_000_000 + 60000
        bounds = dict(candidate=(Path('/opt/approved-candidate'), 'a'*64), deadline_ns=deadline,
            authorization_expires_at_ms=expiry) if bounded else {}
        def target_call(_plan, action, *, profile=None, **options):
            calls.append(action)
            if options:
                assert options['candidate'] == bounds['candidate']
                assert 0 < options['observation_timeout_seconds'] <= 60
                assert options['authorization_expires_at_ms'] == expiry
            if action == 'admission-prepare':
                return holder.request(**({'deadline_ns': deadline} if options else {}))
            if action in {'admission-check', 'admission-enroll'}:
                result = dict(registered=holder.ensure_enrolled(profile, enroll=action == 'admission-enroll',
                    **({'deadline_ns': deadline} if options else {})))
                if action == 'admission-enroll' and 'enroll' in failures:
                    failures.remove('enroll')
                    raise OSError('lost ACK after authority registration')
                return result
            assert action == 'admitted-running'
            return target.running(admitted=True)
        def dispatch(_plan, argv, **options):
            if options:
                assert options['deadline_ns'] == deadline
            if argv == ['list', '--format=json']:
                return json.dumps(instances)
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
                managed.prepare_admission(plan, **bounds)
            preserved_key = holder.key.read_bytes()
            proposal = being_seed._read(tmp_path / 'service-state' / digest(plan) / 'candidate.json')
            # A shared-group owner context must be frozen after native profile
            # preparation, while no application/service has been selected yet.
            # The real authority has already accepted the lost enrollment ACK.
            ready = managed._ready
            managed._ready = lambda _plan: False
            with pytest.raises(OnboardingError, match='visibility_selection_required'):
                managed.execute(plan)
            assert managed.prepare_admission(plan, **bounds) == proposal
            assert managed.prepare_admission(plan, **bounds) == proposal
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


def initial_managed_fixture(tmp_path, initial, *, complete_origins=False):
    """Real journal/job/reader/root orchestration, fake manager and native RPC.

    This does not qualify an actual guest, signed application, native process
    or canonical registry adoption. Native authority is tested separately above.
    """
    from clusterctl.onboarding import JobStore
    from tests.test_onboarding import plan as make_plan
    from tests.test_receiving_cohort_control import admission_fixture
    cohort, owners, journal, row, _ = admission_fixture(tmp_path, complete_origins=complete_origins)
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
        incarnation_id=owners['newcomer'].server.get('incarnation_id', 'incarnation:fixture'))
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
        preservation=dict(schema='cluster-receiving-controller-preservation/v1', runtime_sha256='e' * 64,
            origin=expected, active=True, not_before_ms=0, not_after_ms=time.time_ns() // 1_000_000 + 600000))
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


def admission_activation_fixture(tmp_path, initial):
    """Connect the real first-load journal producer to fake qualified peers.

    The SDK reader, job, root state machine and controls use real protected
    records. Native/group/manager/identity/registry seams remain explicit fakes;
    this does not claim installed or genuine three-being receiving acceptance.
    """
    from tests.test_receiving_cohort_control import admission_child_fixture
    managed, plan, cohort, manager, observed, _, _, _ = initial_managed_fixture(
        tmp_path, initial, complete_origins=True)
    row = cohort._row()
    admission = row['intended_transition']['cohort_admission']
    epoch = '1' * 64
    application = observed['group_runtime_status']['loaded_application']
    application.update(loaded_view_sha256='9' * 64, tribe={'policy': {'tribe_ref': admission['tribe_ref']}},
        shared_relationships=True, communication_store_role='ledger',
        shared_stores={'ledger': {'schema_versions': {'communication': 4}}},
        authorities={owner.being: dict(accepted_manifest_hashes=[epoch], active_manifest_hash=epoch,
            active_control_head='control:fixture') for owner in cohort.owners.values()})
    application['visibility'].update(catalog_mode='validate', catalog_validation='validated',
        release_enabled=True, catalog_schema_version=1)
    observed['runtime_status']['loaded_runtime'].update(authority_epoch={'accepted_manifest_hashes': [epoch]},
        runtime_id='runtime:newcomer')
    newcomer = cohort.owners['newcomer']
    observed['group_runtime_status']['receiving']['channels']['tribe'].update({key: value for key, value
        in newcomer.gate.items() if key not in {'controlled', 'process_id', 'phase', 'readers'}})
    observed['group_runtime_status']['receiving']['channels']['tribe']['process_instance_id'] = 'newcomer:first'
    managed.execute_initial(plan, cohort)
    recipes = {}
    for name, owner in cohort.owners.items():
        if name == 'newcomer':
            owner.process, owner.parent = observed['process'], observed['admission_parent']
            owner.gate = copy.deepcopy(observed['group_runtime_status']['receiving']['channels']['tribe'])
        else:
            owner.parent = dict(uid=1, pid=1, start_ticks=2, boot_id='fixture')
        owner.loaded = copy.deepcopy(observed['runtime_status']['loaded_runtime'])
        owner.loaded.update(process_id=owner.process['pid'], runtime_id='runtime:' + name)
        owner.loaded['qualified_startup'].update(process_id=owner.process['pid'], startup_instance_id=(
            'fixture-first-start' if name == 'newcomer' else name))
        owner.application = {key: copy.deepcopy(value) for key, value in application.items() if key != 'reader_gates'}
        owner.identity = dict(being_ref=owner.being, manifest_hash=epoch, credential_ref='credential:' + name)
        original = owner.status
        def status(self, original=original):
            result = original()
            result['runtime_status'].update(loaded_runtime=copy.deepcopy(self.loaded),
                loaded_application=copy.deepcopy(self.application), receiving=dict(features=['signed-roster-cas/v1'],
                    rosters={'tribe': dict(schema='dm.runtime.tribe-roster/v1', roster_sha256='5' * 64,
                        required_authority_epochs=[epoch])}))
            return result
        owner.status = MethodType(status, owner)
        def qualified(self, *, expires_at_ms, require_admitted, **_):
            assert require_admitted
            return {**self.status(), 'admission_parent': copy.deepcopy(self.parent), 'identity': self.identity,
                'verified_identity': dict(identity=self.identity, runtime_bundle_sha256=self.loaded['runtime_bundle_sha256'],
                    authority_control_head='control:fixture', expires_at_ms=expires_at_ms)}
        owner.qualified_identity = MethodType(qualified, owner)
        startup = owner.loaded['qualified_startup']
        recipes[name] = {**admission['receivers'][name]['recipe'], 'lifecycle_operation_id': cohort.operation_id,
            'selection': dict(receiving_code=startup['code_digest'], matrix_sdk=startup['matrix_wheel_sha256'],
                runtime_bundle_sha256=owner.loaded['runtime_bundle_sha256'],
                application_sha256=application['application_sha256'], publication_sha256=application['publication_sha256'],
                visibility_installation_sha256=application['visibility']['installation_sha256'])}
        if name != 'newcomer':
            # Retain a real child association before the simulated old exit;
            # these process/native seams are not operational load evidence.
            _, _, _, _, child_recipe, _, effects = admission_child_fixture(tmp_path,
                profile='guest', with_group=False, with_exit=False, name=name,
                setup=(cohort, cohort.owners, cohort.journal, row, {'receivers': recipes}))
            cohort.bind_admission_lifecycle(name, child_recipe['lifecycle_operation_id'])
            owner.process = {**owner.process, 'start_ticks': owner.process['start_ticks'] + 1}
            owner.parent = {**owner.parent, 'start_ticks': owner.parent['start_ticks'] + 1}
            owner.gate = {**owner.gate, 'process_instance_id': name + ':replacement', 'phase': 'unselected',
                'request_sha256': None, 'operation_id': None, 'release_digest': None}
            effects['controlled_loaded'] = dict(process=owner.process, admission_parent=owner.parent,
                loaded_runtime=owner.loaded, loaded_application=owner.application)
            cohort.journal.advance(child_recipe['lifecycle_operation_id'], 'runtime-dispatching',
                runtime_observation={'guest_bootstraps': {name: effects}})
            recipes[name] = child_recipe
    cohort.retain_admission_activation({**admission['activation'], 'roster_sha256': '5' * 64, 'receivers': recipes})
    return cohort, manager, managed, plan


def test_first_load_is_consumed_by_the_same_cohort_and_all_senders_activate(tmp_path, initial):
    cohort, manager, _, _ = admission_activation_fixture(tmp_path, initial)
    before = copy.deepcopy(cohort._row()['runtime_observation']['sender_revocations'])
    prepared = cohort.prepare_activation()
    row = cohort._row()
    assert row['runtime_observation']['sender_revocations'] == before
    assert set(row['runtime_observation']['sender_initials']) == {'newcomer'}
    assert all(owner.gate['phase'] == 'revoke' and owner.gate['readers'] == [] for owner in cohort.owners.values())
    result = cohort.activate()
    assert len(result['readers']) == 3 and result['readers'] == prepared['readers']
    assert all(owner.gate['readers'] == result['readers'] for owner in cohort.owners.values())
    counts = [owner.effects for owner in cohort.owners.values()]
    assert cohort.activate() == result and [owner.effects for owner in cohort.owners.values()] == counts
    assert manager.starts == 1


def test_lost_initial_revoke_is_recoverable_before_any_activation_vector(tmp_path, initial, monkeypatch):
    cohort, _, _, _ = admission_activation_fixture(tmp_path, initial)
    owner = cohort.owners['newcomer']
    actual = owner.prepare_apply_control
    def lost(*args):
        actual(*args)
        raise OSError('synthetic lost initial revoke return')
    monkeypatch.setattr(owner, 'prepare_apply_control', lost)
    with pytest.raises(OSError, match='lost initial revoke'):
        cohort.prepare_activation()
    row = cohort._row()
    assert 'cohort_activation' not in row['runtime_observation']
    assert 'accepted' not in row['runtime_observation']['sender_initials']['newcomer']
    assert all(peer.gate['readers'] == [] for peer in cohort.owners.values())
    monkeypatch.setattr(owner, 'prepare_apply_control', actual)
    repairs = cohort.reconcile_reassessment()
    assert set(repairs) == set(cohort.owners) and all(value['state'] == 'disabled' for value in repairs.values())
    assert all(peer.gate['phase'] == 'select' and peer.gate['readers'] == [] for peer in cohort.owners.values())


def test_missing_initial_revoke_cannot_enable_an_old_sender(tmp_path, initial):
    cohort, _, _, _ = admission_activation_fixture(tmp_path, initial)
    cohort.prepare_activation()
    row = cohort._row()
    changed = copy.deepcopy(row['runtime_observation'])
    del changed['sender_initials']['newcomer']['accepted']
    cohort.journal.advance(cohort.operation_id, row['state'], runtime_observation=changed,
        expected_runtime_observation=row['runtime_observation'])
    with pytest.raises(OnboardingError, match='sender_barrier_changed'):
        cohort.activate()
    assert all(peer.gate['readers'] == [] for peer in cohort.owners.values())


def test_initial_context_marker_cannot_replace_the_produced_load(tmp_path, initial):
    cohort, _, _, _ = admission_activation_fixture(tmp_path, initial)
    row = cohort._row()
    changed = copy.deepcopy(row['runtime_observation'])
    changed['initial_managed']['newcomer']['intent']['request']['not_after_ms'] += 1
    cohort.journal.advance(cohort.operation_id, row['state'], runtime_observation=changed,
        expected_runtime_observation=row['runtime_observation'])
    with pytest.raises(OnboardingError, match='initial_managed_lifecycle_unobserved'):
        cohort.prepare_activation()
    assert all(peer.gate['readers'] == [] for peer in cohort.owners.values())


def test_initial_steady_requires_selected_cohort_and_keeps_same_running_body(tmp_path, initial):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    initial_record = copy.deepcopy(cohort._row()['runtime_observation']['initial_managed'])
    with pytest.raises(OnboardingError, match='cohort_selection_required'):
        managed.complete_initial(plan, cohort)
    assert manager.reloads == 0 and '--initial-context-json' in manager.unit.read_text()
    cohort.activate()
    result = managed.complete_initial(plan, cohort)
    assert result['receiving_readiness'] == 'qualified-local-projection'
    assert result['communication_acceptance'] == 'unobserved'
    assert '--initial-context-json' not in manager.unit.read_text()
    assert cohort._row()['runtime_observation']['initial_managed'] == initial_record
    assert managed.complete_initial(plan, cohort) == result
    assert managed.execute_initial(plan, cohort) == initial_record['newcomer']['controlled_loaded']
    assert manager.starts == manager.reloads == manager.enables == 1 and manager.stops == 0


def test_lost_steady_host_reply_does_not_repeat_the_first_start(tmp_path, initial, monkeypatch):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    cohort.activate()
    actual = managed.backend._guest_service_call
    lost = []
    def root_call(*args, **options):
        result = actual(*args, **options)
        if args[1] == 'bootstrap-steady' and not lost:
            lost.append(True)
            raise OSError('synthetic lost steady return')
        return result
    monkeypatch.setattr(managed.backend, '_guest_service_call', root_call)
    with pytest.raises(OSError, match='lost steady'):
        managed.complete_initial(plan, cohort)
    assert 'selected' not in cohort._row()['runtime_observation']['initial_steady']['newcomer']
    assert '--initial-context-json' not in manager.unit.read_text()
    managed.execute_initial(plan, cohort)
    assert 'completed' in cohort._row()['runtime_observation']['initial_steady']['newcomer']
    assert manager.reloads == manager.starts == 1 and manager.stops == 0


def test_post_steady_qualification_failure_keeps_the_physical_selection(tmp_path, initial, monkeypatch):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    cohort.activate()
    actual = cohort._confirmed_selection
    confirmed = []
    def observe(*args):
        confirmed.append(True)
        if len(confirmed) > 1:
            raise OnboardingError('synthetic expired post-handoff observation')
        return actual(*args)
    monkeypatch.setattr(cohort, '_confirmed_selection', observe)
    with pytest.raises(OnboardingError, match='expired post-handoff'):
        managed.complete_initial(plan, cohort)
    row = cohort._row()
    assert 'selected' in row['runtime_observation']['initial_steady']['newcomer']
    assert 'completed' not in row['runtime_observation']['initial_steady']['newcomer']
    assert '--initial-context-json' not in manager.unit.read_text()
    with pytest.raises(OnboardingError, match='cohort_reassessment_required'):
        managed.execute_initial(plan, cohort)
    assert manager.reloads == manager.starts == 1 and manager.stops == 0
    assert 'cohort_reassessment' in cohort._row()['runtime_observation']
    assert all(owner.gate['readers'] == [] for owner in cohort.owners.values())


def test_post_steady_gate_drift_uses_existing_forward_repair(tmp_path, initial, monkeypatch):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    cohort.activate()
    actual = managed.backend._guest_service_call
    drifted = []
    def root_call(*args, **options):
        result = actual(*args, **options)
        if args[1] == 'bootstrap-steady' and not drifted:
            drifted.append(True)
            cohort.owners['eko'].gate['head'] = '0' * 64
        return result
    monkeypatch.setattr(managed.backend, '_guest_service_call', root_call)
    with pytest.raises(OnboardingError, match='cohort_selection_changed'):
        managed.complete_initial(plan, cohort)
    row = cohort._row()
    assert 'selected' in row['runtime_observation']['initial_steady']['newcomer']
    assert 'completed' not in row['runtime_observation']['initial_steady']['newcomer']
    assert all(owner.gate['readers'] == [] for owner in cohort.owners.values())
    assert '--initial-context-json' not in manager.unit.read_text()
    with pytest.raises(OnboardingError, match='cohort_reassessment_required'):
        managed.execute_initial(plan, cohort)
    assert manager.reloads == manager.starts == 1 and manager.stops == 0


def test_unavailable_native_load_after_steady_selection_retains_and_repairs(tmp_path, initial, monkeypatch):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    cohort.activate()
    def unavailable(*_args, **_options):
        raise OSError('synthetic unavailable loaded owner')
    monkeypatch.setattr(managed.backend, '_target_call', unavailable)
    with pytest.raises(OSError, match='unavailable loaded owner'):
        managed.complete_initial(plan, cohort)
    row = cohort._row()
    assert 'selected' in row['runtime_observation']['initial_steady']['newcomer']
    assert 'completed' not in row['runtime_observation']['initial_steady']['newcomer']
    assert 'cohort_reassessment' in row['runtime_observation']
    assert all(owner.gate['readers'] == [] for owner in cohort.owners.values())
    assert manager.starts == manager.reloads == 1 and manager.stops == 0


def test_expired_post_steady_budget_retains_repair_without_more_owner_calls(tmp_path, initial, monkeypatch):
    cohort, manager, managed, plan = admission_activation_fixture(tmp_path, initial)
    cohort.activate()
    effects = {name: owner.effects for name, owner in cohort.owners.items()}
    actual = managed.backend._guest_service_call
    monotonic_ns = time.monotonic_ns
    expired = []
    def root_call(*args, **options):
        result = actual(*args, **options)
        if args[1] == 'bootstrap-steady':
            expired.append(True)
        return result
    monkeypatch.setattr(managed.backend, '_guest_service_call', root_call)
    monkeypatch.setattr(time, 'monotonic_ns', lambda: monotonic_ns() + (10**12 if expired else 0))
    with pytest.raises(OnboardingError, match='host_deadline_expired'):
        managed.complete_initial(plan, cohort)
    row = cohort._row()
    assert 'selected' in row['runtime_observation']['initial_steady']['newcomer']
    assert row['runtime_observation']['cohort_reassessment'] == {}
    assert {name: owner.effects for name, owner in cohort.owners.items()} == effects
    assert '--initial-context-json' not in manager.unit.read_text()
    assert manager.starts == manager.reloads == 1 and manager.stops == 0
    expired.clear()
    assert all(value['state'] == 'disabled' for value in cohort.reconcile_reassessment().values())
