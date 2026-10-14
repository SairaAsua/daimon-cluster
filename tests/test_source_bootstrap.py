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

    def inspect(self):
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
    bundle = dict(local_origin={'embodiment_id': 'fixture-body'})
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
            return dict(process=copy.deepcopy(process), server={'fixture': 'origin'},
                runtime_status={'local_origin': bundle['local_origin']}, receiving_readiness='unobserved')
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
