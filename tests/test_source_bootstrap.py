"""Bootstrap orchestration with fake owner/manager and real journal/unit locks.

Actual signed capability/visibility/native-process qualification is separate.
"""
import copy
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from clusterctl import being_seed
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.onboarding_receiving_update import SourceBootstrapController, freeze_source_bootstrap
from clusterctl.onboarding_service import MatrixUserService, selection_lock
from clusterctl.operation_journal import OperationJournal


class FakeManager:
    def __init__(self, unit):
        self.unit = unit
        self.live = True
        self.stops = 0
        self.invocation = 'fixture-invocation'

    def inspect(self, **_):
        return dict(unit_sha256=hashlib.sha256(self.unit.read_bytes()).hexdigest(), manager={
            'ActiveState': 'active' if self.live else 'inactive',
            'SubState': 'running' if self.live else 'dead', 'MainPID': '123' if self.live else '0',
            'InvocationID': self.invocation, 'Result': 'success'})

    def bind_process(self, process, inspected):
        assert process['pid'] == int(inspected['manager']['MainPID'])
        return dict(process=process, control_group='fixture-scope', invocation_id=self.invocation)

    def stop(self):
        self.stops += 1
        self.live = False


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    from clusterctl import onboarding_receiving_update as updates, owner_process
    root = tmp_path / 'runtime'
    root.mkdir(mode=0o700)
    bundle = dict(manifest={'being_ref': 'fixture-being'}, local_origin={'embodiment_id': 'fixture-body'})
    being_seed._write(root / 'runtime.json', bundle)
    visibility = tmp_path / 'visibility.json'
    being_seed._write(visibility, {'document': {'fixture': True}, 'binding': {}})
    unit = tmp_path / 'daimon-matrix-fixture.service'
    unit.write_bytes(b'[Service]\nExecStart=/old/loader\nKillMode=control-group\n')
    unit.chmod(0o600)
    manager = FakeManager(unit)
    locked = []
    @contextmanager
    def writer():
        locked.append(True)
        yield
    source = SimpleNamespace(root=root, visibility=visibility, settings={'fixture': 'source'}, writer=writer)
    process = dict(pid=123, uid=1, start_ticks=2, boot_id='fixture')
    class FakeOwner:
        def __init__(self, *_):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def base_status(self):
            if not manager.live:
                raise OSError('fixture socket closed')
            return dict(process=copy.deepcopy(process), server=copy.deepcopy(bundle['local_origin']),
                runtime_status={'being_ref': bundle['manifest']['being_ref'], 'local_origin': bundle['local_origin']},
                receiving_readiness='unobserved')
        def wait_for_exit(self, _timeout):
            return not manager.live
    monkeypatch.setattr(updates, 'OwnerGroupClient', FakeOwner)
    class FakePresence(FakeOwner):
        pass
    monkeypatch.setattr(owner_process, 'ProcessPresence', FakePresence)
    monkeypatch.setattr(owner_process, 'observe_process_exit', lambda *_: not manager.live)
    frozen = freeze_source_bootstrap(source, manager)
    candidate = dict(transaction=str(root.parent / 'upgrade'), expires_at_ms=12345, argv=['/qualified/loader'])
    journal = OperationJournal(tmp_path / 'journal')
    row = plan_update(journal, manifest_digest='a'*64, target='source-bootstrap:fixture',
        expected_precondition={'source_bootstrap': frozen}, intended_transition={'source_bootstrap': candidate},
        audit_identity={'actor': 'fixture'})
    return source, manager, journal, row['operation_id'], locked


def test_quiescence_retains_actual_journal_stage_and_exact_retry(fixture):
    source, manager, journal, identifier, locked = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    result = controller.quiesce()
    assert result['exit_observed'] and result['writer_available']
    assert result['graceful_delivery'] == 'unobserved'
    assert controller.quiesce() == result and manager.stops == 1
    assert len(locked) == 2
    assert set(journal.get(identifier)['runtime_observation']['source_bootstrap']) == {'stop_intent', 'quiesced'}


@pytest.mark.parametrize('late_at', ['after-exit', 'status', 'active-stop-intent'])
def test_renewal_checks_expiry_at_stop_but_retains_exit_after_expiry(fixture, monkeypatch, late_at):
    from clusterctl import onboarding_receiving_update as updates
    from clusterctl.onboarding import digest
    import time
    source, manager, journal, identifier, _ = fixture
    original = journal.get(identifier)
    before, after = copy.deepcopy(original['expected_precondition']), copy.deepcopy(original['intended_transition'])
    frozen = before['source_bootstrap']
    preservation = dict(runtime_sha256=frozen['bundle_sha256'], origin=frozen['predecessor']['server'])
    frozen.update(mode='renew', preservation=preservation)
    now = [time.time_ns() // 1_000_000]
    expiry = now[0] + 60000
    after['source_bootstrap'].update(expires_at_ms=expiry, qualification={'group': {}})
    row = plan_update(journal, manifest_digest='a' * 64, target='source:renewal-expiry',
        expected_precondition=before, intended_transition=after, audit_identity={'actor': 'fixture'})
    controller = SourceBootstrapController(journal, row['operation_id'], source, manager)
    monkeypatch.setattr(controller, '_qualify_candidate', lambda *_: {})
    monkeypatch.setattr(updates, 'controller_preservation', lambda *_: preservation)
    monkeypatch.setattr(time, 'time_ns', lambda: now[0] * 1_000_000)
    checks = []
    def authorized(_bundle, expires):
        checks.append(now[0])
        if now[0] >= expires:
            raise OnboardingError('synthetic_renewal_expired')
    monkeypatch.setattr(updates, 'renewal_authorization', authorized)
    if late_at == 'after-exit':
        result = controller.quiesce()
        now[0] = expiry + 1
        assert controller.quiesce() == result and manager.stops == len(checks) == 1
    else:
        if late_at == 'active-stop-intent':
            controller._record('stop_intent', dict(scope=frozen['scope'], unit_sha256=frozen['service']['unit_sha256']))
            now[0] = expiry + 1
        else:
            actual = updates.OwnerGroupClient.base_status
            def late(self):
                result = actual(self)
                now[0] = expiry + 1
                return result
            monkeypatch.setattr(updates.OwnerGroupClient, 'base_status', late)
        with pytest.raises(OnboardingError, match='synthetic_renewal_expired'):
            controller.quiesce()
        assert manager.stops == 0 and len(checks) == 1
    assert digest(journal.get(row['operation_id'])['expected_precondition']) == digest(before)


def test_lost_stop_reply_reconciles_exit_without_a_second_stop(fixture, monkeypatch):
    source, manager, journal, identifier, _ = fixture
    stop = manager.stop
    def lost():
        stop()
        raise OSError('fixture lost stop reply')
    monkeypatch.setattr(manager, 'stop', lost)
    controller = SourceBootstrapController(journal, identifier, source, manager)
    assert controller.quiesce()['exit_observed']
    assert controller.quiesce()['exit_observed'] and manager.stops == 1


def test_crash_after_stop_before_exit_record_recovers_retained_intent(fixture, monkeypatch):
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    record = controller._record
    def crash(key, value):
        if key == 'quiesced':
            raise OSError('fixture journal reply lost before record')
        return record(key, value)
    monkeypatch.setattr(controller, '_record', crash)
    with pytest.raises(OSError):
        controller.quiesce()
    assert set(journal.get(identifier)['runtime_observation']['source_bootstrap']) == {'stop_intent'}
    restored = SourceBootstrapController(journal, identifier, source, manager)
    assert restored.quiesce()['exit_observed'] and manager.stops == 1


def test_crash_before_stop_dispatch_resumes_exact_retained_action(fixture, monkeypatch):
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    record = controller._record
    def crash(key, value):
        result = record(key, value)
        if key == 'stop_intent':
            raise OSError('fixture crash before dispatch')
        return result
    monkeypatch.setattr(controller, '_record', crash)
    with pytest.raises(OSError):
        controller.quiesce()
    assert manager.live and manager.stops == 0
    restored = SourceBootstrapController(journal, identifier, source, manager)
    assert restored.quiesce()['exit_observed'] and manager.stops == 1


def test_retained_stop_never_dispatches_to_a_replacement(fixture):
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    _, frozen, _ = controller._row()
    controller._record('stop_intent', dict(scope=frozen['scope'], unit_sha256=frozen['service']['unit_sha256']))
    manager.invocation = 'replacement'
    with pytest.raises(OnboardingError, match='predecessor_changed'):
        controller.quiesce()
    assert manager.live and manager.stops == 0


def test_incomplete_archive_recovers_failed_file_sync_before_retaining(fixture, monkeypatch):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    controller.quiesce()
    (source.root / upgrade.LOCK).touch(mode=0o600)
    _, frozen, candidate = controller._row()
    transaction = Path(candidate['transaction'])
    transaction.mkdir(mode=0o700)
    child = transaction / 'successor'
    child.mkdir(mode=0o700)
    payload = child / 'unpublished-key'
    payload.write_bytes(b'synthetic-unused-key-evidence')
    payload.chmod(0o600)
    expected = upgrade.inventory_digest(transaction)
    intent = dict(source_sha256=upgrade.inventory_digest(source.root))
    sync = os.fsync
    calls = []
    def fail(fd):
        path = os.readlink('/proc/self/fd/' + str(fd))
        calls.append(path)
        if path.endswith('/unpublished-key'):
            raise OSError('fixture archived file fsync failed')
        return sync(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os, 'fsync', fail)
        with pytest.raises(OSError, match='archived file fsync'):
            controller._recover_stage(upgrade, transaction, intent, frozen, candidate)
    stages = journal.get(identifier)['runtime_observation']['source_bootstrap']
    assert 'capability_archive_0' in stages and 'capability_archive_0_retained' not in stages
    archive = Path(stages['capability_archive_0']['path'])
    assert not transaction.exists() and upgrade.inventory_digest(archive) == expected
    controller._recover_stage(upgrade, transaction, intent, frozen, candidate)
    stages = journal.get(identifier)['runtime_observation']['source_bootstrap']
    assert stages['capability_archive_0_retained']['sha256'] == expected
    assert (archive / 'successor/unpublished-key').read_bytes() == b'synthetic-unused-key-evidence'
    assert any(name.endswith('/unpublished-key') for name in calls)


def test_partial_stage_is_preserved_when_original_source_changed(fixture):
    from daimon_matrix import operator_runtime_upgrade as upgrade
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    controller.quiesce()
    (source.root / upgrade.LOCK).touch(mode=0o600)
    _, frozen, candidate = controller._row()
    intent = dict(source_sha256=upgrade.inventory_digest(source.root))
    transaction = Path(candidate['transaction'])
    transaction.mkdir(mode=0o700)
    being_seed._write(source.root / 'foreign-change.json', dict(changed=True))
    with pytest.raises(OnboardingError, match='source_changed'):
        controller._recover_stage(upgrade, transaction, intent, frozen, candidate)
    assert transaction.is_dir()
    assert not any(name.startswith('capability_archive') for name in journal.get(identifier)['runtime_observation']['source_bootstrap'])


def test_unexpected_restart_cannot_reuse_old_quiescence(fixture):
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    controller.quiesce()
    manager.invocation = 'replacement-invocation'
    with pytest.raises(OnboardingError, match='quiescence_required'):
        controller.quiesce()
    assert manager.stops == 1


def test_invalid_wait_and_unquiesced_publish_have_no_effect(fixture):
    source, manager, journal, identifier, _ = fixture
    controller = SourceBootstrapController(journal, identifier, source, manager)
    for value in (-1, True, float('nan'), 61):
        with pytest.raises(OnboardingError, match='invalid_wait'):
            controller.quiesce(timeout_seconds=value)
    with pytest.raises(OnboardingError, match='quiescence_required'):
        controller.publish()
    assert manager.stops == 0 and journal.get(identifier)['state'] == 'planned'


def test_source_manager_uses_only_named_user_unit_and_rejects_different_fragment(tmp_path):
    unit = tmp_path / 'daimon-matrix-fixture.service'
    unit.write_bytes(b'[Service]\nExecStart=/existing/loader\n')
    unit.chmod(0o600)
    values = dict(Id=unit.name, ActiveState='active', SubState='running', MainPID='123',
        ControlGroup='/fixture/' + unit.name, InvocationID='fixture', FragmentPath=str(unit),
        DropInPaths='', KillMode='control-group', Result='success')
    calls = []
    def run(argv):
        calls.append(argv)
        return '\n'.join(key+'='+value for key, value in values.items()) if 'show' in argv else ''
    manager = MatrixUserService(unit, run=run)
    assert manager.inspect()['unit_sha256'] == hashlib.sha256(unit.read_bytes()).hexdigest()
    manager.stop()
    assert calls[-1] == ['systemctl', '--user', '--no-block', 'stop', unit.name]
    values['DropInPaths'] = '/run/systemd/system/service.d/zzz-lxc-service.conf'
    with pytest.raises(OnboardingError, match='scope_required'):
        manager.inspect()
    values['DropInPaths'] = ''
    values['FragmentPath'] = str(tmp_path / 'different.service')
    with pytest.raises(OnboardingError, match='scope_required'):
        manager.inspect()
    with pytest.raises(OnboardingError, match='qualified_matrix_service'):
        MatrixUserService(Path('/unrelated.service'))


def test_unit_selection_lock_reenters_same_thread_and_releases_outer_owner(tmp_path):
    unit = tmp_path / 'daimon-matrix-fixture.service'
    with selection_lock(unit):
        with selection_lock(unit):
            pass
    with selection_lock(unit):
        pass


def test_forked_child_cannot_reuse_parent_selection_ownership(tmp_path):
    unit = tmp_path / 'daimon-matrix-fixture.service'
    with selection_lock(unit):
        child = os.fork()
        if child == 0:
            try:
                with selection_lock(unit):
                    os._exit(2)
            except being_seed.SeedError:
                os._exit(0)
            except BaseException:
                os._exit(3)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0


def prepared_start_fixture(fixture, monkeypatch):
    """Explicit fake loaded observations; no actual SDK/startup claim."""
    source, manager, journal, identifier, _ = fixture
    previous = journal.get(identifier)
    group = dict(selected={'channel_id': 'tribe'}, application_sha256='7'*64,
        publication_sha256='8'*64, installation_sha256='9'*64)
    candidate = {**previous['intended_transition']['source_bootstrap'], 'qualification': {'group': group}}
    monkeypatch.setattr('clusterctl.onboarding_receiving_update.source_bootstrap_group', lambda *_: group)
    row = plan_update(journal, manifest_digest='a'*64, target='source-bootstrap:qualified-fixture',
        expected_precondition=previous['expected_precondition'],
        intended_transition={'source_bootstrap': candidate}, audit_identity={'actor': 'fixture'})
    controller = SourceBootstrapController(journal, row['operation_id'], source, manager)
    checked = dict(code_digest='b'*64, matrix_revision='c'*40, sdk_digest='d'*64,
        matrix_wheel_sha256='e'*64, reader={'fixture': 'reader'})
    monkeypatch.setattr(controller, '_qualify_candidate', lambda *_: checked)
    selected = hashlib.sha256(manager.unit.read_bytes()).hexdigest()
    controller._record('unit_selected', dict(selected=True, selected_sha256=selected))
    published_bundle = hashlib.sha256((source.root / 'runtime.json').read_bytes()).hexdigest()
    controller._record('capability_published', dict(runtime_sha256=published_bundle))
    controller._record('visibility_published', dict(installation_sha256=hashlib.sha256(source.visibility.read_bytes()).hexdigest()))
    monkeypatch.setattr('clusterctl.owner_process.observe_process_exit', lambda *_: True)
    process = dict(pid=456, uid=1, start_ticks=3, boot_id='fixture')
    gate = dict(controlled=True, process_id=456, process_instance_id='new-instance', phase='unselected', readers=[])
    startup = dict(code_digest=checked['code_digest'], matrix_commit=checked['matrix_revision'],
        sdk_digest=checked['sdk_digest'], matrix_wheel_sha256=checked['matrix_wheel_sha256'],
        reader=checked['reader'], process_id=456)
    actual = dict(process=process, group=group['selected'], responder_association='same-connection',
        base_runtime_status=dict(loaded_runtime=dict(qualified_startup=startup, runtime_bundle_sha256=published_bundle)),
        runtime_status=dict(loaded_application=dict(application_sha256='7'*64, publication_sha256='8'*64,
            visibility={'installation_sha256': '9'*64}, reader_gates=gate),
            receiving=dict(channels=dict(tribe=gate))))
    manager.starts = 0
    manager.live = False
    inspect = manager.inspect
    def observed_manager(**_):
        value = inspect()
        value['manager']['MainPID'] = '456' if manager.live else '0'
        return value
    monkeypatch.setattr(manager, 'inspect', observed_manager)
    def start(**_):
        manager.starts += 1
        manager.live = True
    monkeypatch.setattr(manager, 'start', start, raising=False)
    monkeypatch.setattr(source, 'observe', lambda **_: copy.deepcopy(actual), raising=False)
    return controller, manager, actual


def test_publication_only_operation_cannot_start_an_unqualified_command(fixture):
    source, manager, journal, identifier, _ = fixture
    with pytest.raises(OnboardingError, match='qualified_bootstrap_candidate_required'):
        SourceBootstrapController(journal, identifier, source, manager).start()
    assert manager.stops == 0


def test_start_retains_controlled_load_without_positive_readiness_and_no_restart(fixture, monkeypatch):
    controller, manager, actual = prepared_start_fixture(fixture, monkeypatch)
    result = controller.start()
    assert result['initial_gate']['phase'] == 'unselected'
    assert result['receiving_readiness'] == 'unobserved'
    assert controller.start() == result and manager.starts == 1
    # Current normal control can move on; retained startup evidence is stable.
    actual['runtime_status']['receiving']['channels']['tribe']['phase'] = 'revoke'
    assert controller.start() == result and manager.starts == 1
    manager.live = False
    with pytest.raises(OnboardingError, match='loaded_process_changed'):
        controller.start()
    assert manager.starts == 1


def test_lost_start_reply_observes_existing_candidate_without_second_start(fixture, monkeypatch):
    controller, manager, _ = prepared_start_fixture(fixture, monkeypatch)
    start = manager.start
    def lost(**arguments):
        start(**arguments)
        raise OSError('fixture lost start reply')
    monkeypatch.setattr(manager, 'start', lost)
    assert controller.start()['process']['pid'] == 456
    assert controller.start()['process']['pid'] == 456 and manager.starts == 1


@pytest.mark.parametrize('correction', ['sdk', 'bundle', 'gate'])
def test_wrong_actual_candidate_or_preselected_gate_cannot_become_load_proof(fixture, monkeypatch, correction):
    controller, manager, actual = prepared_start_fixture(fixture, monkeypatch)
    if correction == 'sdk':
        actual['base_runtime_status']['loaded_runtime']['qualified_startup']['matrix_commit'] = '0'*40
    elif correction == 'bundle':
        actual['base_runtime_status']['loaded_runtime']['runtime_bundle_sha256'] = '0'*64
    else:
        actual['runtime_status']['receiving']['channels']['tribe']['phase'] = 'select'
    with pytest.raises(OnboardingError, match='loaded_candidate_conflict|initial_gate_conflict'):
        controller.start()
    row = controller.journal.get(controller.operation_id)
    assert 'controlled_loaded' not in row['runtime_observation']['source_bootstrap']
    assert manager.starts == 1


def test_candidate_requalification_failure_precedes_any_start(fixture, monkeypatch):
    controller, manager, _ = prepared_start_fixture(fixture, monkeypatch)
    def changed(*_):
        raise OnboardingError('receiving_bootstrap_candidate_changed')
    monkeypatch.setattr(controller, '_qualify_candidate', changed)
    with pytest.raises(OnboardingError, match='candidate_changed'):
        controller.start()
    assert manager.starts == 0


@pytest.mark.parametrize('part', ['runtime', 'visibility'])
def test_changed_stopped_publication_cannot_start_uncontrolled_legacy(fixture, monkeypatch, part):
    controller, manager, _ = prepared_start_fixture(fixture, monkeypatch)
    path = controller.source.root / 'runtime.json' if part == 'runtime' else controller.source.visibility
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(OnboardingError, match='publication_changed'):
        controller.start()
    assert manager.starts == 0


@pytest.mark.parametrize('part', ['publication_sha256', 'installation_sha256'])
def test_unrelated_controlled_group_does_not_satisfy_the_frozen_selection(fixture, monkeypatch, part):
    controller, manager, actual = prepared_start_fixture(fixture, monkeypatch)
    application = actual['runtime_status']['loaded_application']
    if part == 'installation_sha256':
        application['visibility'][part] = '0'*64
    else:
        application[part] = '0'*64
    with pytest.raises(OnboardingError, match='loaded_group_conflict'):
        controller.start()
    assert 'controlled_loaded' not in controller.journal.get(controller.operation_id)['runtime_observation']['source_bootstrap']
    assert manager.starts == 1


def test_deadline_expiry_after_start_cannot_record_a_late_loaded_success(fixture, monkeypatch):
    controller, manager, _ = prepared_start_fixture(fixture, monkeypatch)
    from clusterctl import onboarding_receiving_update
    current = [1_000_000_000]
    monkeypatch.setattr(onboarding_receiving_update.time, 'monotonic_ns', lambda: current[0])
    start = manager.start
    def slow(**arguments):
        start(**arguments)
        current[0] += 2_000_000_000
    monkeypatch.setattr(manager, 'start', slow)
    with pytest.raises(OnboardingError, match='start_unobserved'):
        controller.start(timeout_seconds=1)
    assert 'controlled_loaded' not in controller.journal.get(controller.operation_id)['runtime_observation']['source_bootstrap']
    assert manager.starts == 1


def test_expired_manager_budget_dispatches_no_command(tmp_path):
    unit = tmp_path / 'daimon-matrix-fixture.service'
    calls = []
    manager = MatrixUserService(unit, run=lambda command: calls.append(command))
    with pytest.raises(OnboardingError, match='deadline_expired'):
        manager.start(deadline_ns=0)
    assert calls == []


@pytest.mark.parametrize('changed', ['command', 'unit'])
def test_actual_prepared_command_is_rechecked_before_quiescence(tmp_path, fixture, monkeypatch, changed):
    import json
    from clusterctl import onboarding_code_successor, onboarding_release
    from clusterctl.onboarding_receiving_update import prepare_source_bootstrap
    # This case qualifies the real SDK/command path; signed group selection
    # has its separate composition coverage and is an explicit seam here.
    monkeypatch.setattr('clusterctl.onboarding_receiving_update.source_bootstrap_group',
        lambda *_: dict(selected={'channel_id': 'tribe'}, hashes={'fixture': 'group'}))
    from tests.test_receiving_update_preflight import fixture as sdk_fixture, manifest_digest, BEING, BODY, REVISION
    workspace = tmp_path / 'sdk-fixture'
    workspace.mkdir()
    code, _, home, path, manifest, marker = sdk_fixture(workspace)
    (code / 'clusterctl').mkdir(exist_ok=True)
    (code / 'clusterctl').chmod(0o755)
    (code / 'clusterctl/onboarding_source.py').write_text('raise RuntimeError("never execute during preparation")\n')
    (code / onboarding_code_successor.MARKER).write_text(json.dumps(dict(
        schema=onboarding_code_successor.QUALIFIED_SDK_SCHEMA, matrix_commit=REVISION,
        matrix_wheel_sha256=manifest['artifacts']['matrix_sdk'])))
    (code / onboarding_code_successor.MARKER).chmod(0o644)
    (code / 'clusterctl/onboarding_source.py').chmod(0o644)
    profile = json.loads((code / 'release.json').read_bytes())['profile']
    (code / 'release.json').unlink()
    checksum = onboarding_release.seal(code, profile)
    manifest['required_receivers'][0]['artifacts']['receiving_code'] = checksum
    path.write_text(json.dumps(manifest))
    source, manager, journal, identifier, _ = fixture
    bundle = being_seed._read(source.root / 'runtime.json')
    bundle.update(manifest={'being_ref': BEING}, local_origin={'embodiment_id': BODY})
    being_seed._write(source.root / 'runtime.json', bundle)
    config = tmp_path / 'source-config.json'
    being_seed._write(config, source.settings)
    candidate = prepare_source_bootstrap(source, home=home, code=code, code_digest=checksum,
        config=config, manifest_path=path, manifest_digest=manifest_digest(manifest),
        transaction=source.root.parent / 'prepared-upgrade', expires_at_ms=12345,
        code_uid=os.geteuid(), manifest_uid=os.geteuid())
    original = journal.get(identifier)
    before = copy.deepcopy(original['expected_precondition'])
    before['source_bootstrap']['predecessor'].update(server=bundle['local_origin'],
        runtime_status=dict(being_ref=BEING, local_origin=bundle['local_origin']))
    if changed == 'command':
        candidate['argv'].append('--unapproved-option')
    else:
        manager.unit.write_bytes(manager.unit.read_bytes() + b'ExecStart=/unexpected/second-command\n')
    row = plan_update(journal, manifest_digest=manifest_digest(manifest), target='source-bootstrap:real-candidate-fixture',
        expected_precondition=before, intended_transition=dict(source_bootstrap=candidate),
        audit_identity={'actor': 'fixture'})
    expected = 'candidate_changed' if changed == 'command' else 'qualified_matrix_entrypoint_required'
    with pytest.raises(OnboardingError, match=expected):
        SourceBootstrapController(journal, row['operation_id'], source, manager).quiesce()
    assert manager.stops == 0 and not marker.exists()


@pytest.mark.parametrize('retained', [False, True])
def test_source_preservation_expiry_distinguishes_new_stop_from_retained_quiescence(fixture, monkeypatch, retained):
    import time
    from clusterctl import onboarding_receiving_update as updates
    source, manager, journal, identifier, _ = fixture
    old = journal.get(identifier)
    frozen = copy.deepcopy(old['expected_precondition']['source_bootstrap'])
    now = time.time_ns() // 1_000_000
    pins = dict(runtime_sha256=frozen['bundle_sha256'], origin=frozen['predecessor']['server'],
        active=True, not_before_ms=now - 1000, not_after_ms=now + 7200000)
    frozen.update(mode='preserve', preservation=pins)
    candidate = {**old['intended_transition']['source_bootstrap'], 'expires_at_ms': now + 60000,
        'qualification': {'fixture': 'qualified code seam'}}
    row = plan_update(journal, manifest_digest='a' * 64, target='source:preserved-quiescence',
        expected_precondition={'source_bootstrap': frozen}, intended_transition={'source_bootstrap': candidate},
        audit_identity={'actor': 'fixture'})
    controller = SourceBootstrapController(journal, row['operation_id'], source, manager)
    monkeypatch.setattr(controller, '_qualify_candidate', lambda *_: {})
    monkeypatch.setattr(updates, 'controller_preservation', lambda *_: copy.deepcopy(pins))
    if retained:
        first = controller.quiesce()
    monkeypatch.setattr(time, 'time_ns', lambda: (candidate['expires_at_ms'] + 1) * 1_000_000)
    if retained:
        assert controller.quiesce() == first and manager.stops == 1
    else:
        with pytest.raises(OnboardingError, match='authorization_expired'):
            controller.quiesce()
        assert manager.live is True and manager.stops == 0
