"""Fixed-worker ownership with actual durable journals and injected manager IO."""
import copy

import pytest

from clusterctl import receiving_worker as worker
from clusterctl.onboarding import OnboardingError, digest, STAGES
from clusterctl.onboarding_code_successor import plan_update
from clusterctl.operation_journal import OperationJournal
from tests.test_receiving_maintenance import spec_fixture


class Manager:
    wait = worker.WorkerManager.wait

    def __init__(self, root, *, active=True):
        self.unit = root / worker.UNIT
        self.state = dict(definition='a' * 64, state='active' if active else 'inactive',
            substate='running' if active else 'dead', pid='123' if active else '0',
            invocation='original' if active else '', job='0', result='success',
            exit_code='0' if active else '1', exit_status='0')
        self.stops = self.starts = 0
        self.lose_stop = self.lose_start = self.forced = False

    def inspect(self):
        return copy.deepcopy(self.state)

    def stop(self):
        self.stops += 1
        self.state.update(state='inactive', substate='dead', pid='0', invocation='', exit_code='1')
        if self.forced:
            self.state.update(result='timeout', exit_code='2', exit_status='9')
        if self.lose_stop:
            raise OnboardingError('receiving_worker_manager_unavailable')

    def start(self):
        self.starts += 1
        self.state.update(state='active', substate='running', pid='456',
            invocation='resumed:' + str(self.starts), result='success', exit_code='0', exit_status='0')
        if self.lose_start:
            raise OnboardingError('receiving_worker_manager_unavailable')


@pytest.mark.parametrize('active', [False, True])
@pytest.mark.parametrize('loss', [None, 'stop', 'start'])
def test_original_state_and_lost_manager_reply_are_reconciled(tmp_path, active, loss):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path, active=active)
    manager.lose_stop, manager.lose_start = loss == 'stop', loss == 'start'
    pause = worker.WorkerPause(journal, 'parent:one', 'b' * 64, manager)
    try:
        pause.pause()
        assert manager.state['state'] == 'inactive'
    finally:
        pause.restore()
    assert (manager.state['state'] == 'active') == active
    assert manager.stops == manager.starts == int(active)
    retained = journal.get(pause.row['operation_id'])
    assert retained['expected_precondition']['baseline']['state'] == ('active' if active else 'inactive')
    assert retained['runtime_observation']['restored'].get('original_active', False) == active
    worker.WorkerPause(journal, 'parent:one', 'b' * 64, manager).recover()
    assert manager.stops == manager.starts == int(active)


def test_forced_stop_blocks_work_and_restores_original_worker(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    manager.forced = True
    pause = worker.WorkerPause(journal, 'parent', 'b' * 64, manager)
    with pytest.raises(OnboardingError, match='drain_uncertain'):
        try:
            pause.pause()
            pytest.fail('forced stop admitted lifecycle dispatch')
        finally:
            pause.restore()
    assert manager.state['state'] == 'active' and manager.starts == 1
    assert 'stopped' not in pause.row['runtime_observation']


def test_unresolved_pause_belongs_to_its_original_operation_and_new_retry_gets_new_cycle(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    original = worker.WorkerPause(journal, 'parent:first', 'b' * 64, manager)
    original.pause()
    with pytest.raises(OnboardingError, match='other_operation_pending'):
        worker.WorkerPause(journal, 'parent:other', 'c' * 64, manager).pause()
    assert manager.state['state'] == 'inactive' and manager.stops == 1
    worker.WorkerPause(journal, 'parent:first', 'b' * 64, manager).recover()
    second = worker.WorkerPause(journal, 'parent:first', 'b' * 64, manager)
    try:
        second.pause()
    finally:
        second.restore()
    assert second.row['operation_id'] != original.row['operation_id']
    assert second.row['expected_precondition']['cycle'] == 2
    assert journal.get(original.row['operation_id'])['runtime_observation']['restored']
    assert manager.stops == manager.starts == 2


def test_same_spec_recovers_before_failed_constructor_preflight(tmp_path, monkeypatch):
    from clusterctl.receiving_maintenance import ReceivingMaintenance
    root = tmp_path / 'journal'
    monkeypatch.setattr(worker, 'JOURNAL', root)
    spec = spec_fixture(tmp_path)
    spec['journal'] = str(root)
    spec['worker'] = {'unit': worker.UNIT}
    journal = OperationJournal(root)
    row = plan_update(journal, target='receiving-maintenance:' + spec['name'] + ':' + digest(spec),
        manifest_digest=spec['candidate']['manifest_digest'],
        expected_precondition={'maintenance_spec': spec}, intended_transition={}, audit_identity={'actor': 'fixture'})
    manager = Manager(tmp_path)
    pause = worker.WorkerPause(journal, row['operation_id'], digest(spec), manager)
    pause.pause()  # A prior coordinator died after stop; no finally was reached.
    monkeypatch.setattr(worker, 'WorkerManager', lambda: manager)
    assert worker.restoration_pending(spec)
    with pytest.raises(FileNotFoundError):
        ReceivingMaintenance(spec)  # HostConfig is deliberately absent.
    assert manager.state['state'] == 'active' and manager.stops == manager.starts == 1
    assert not worker.restoration_pending(spec)


def test_changed_unit_cannot_be_started_as_a_retained_restoration(tmp_path):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    pause = worker.WorkerPause(journal, 'parent', 'b' * 64, manager)
    pause.pause()
    manager.state['definition'] = 'f' * 64
    with pytest.raises(OnboardingError, match='configuration_changed'):
        worker.WorkerPause(journal, 'parent', 'b' * 64, manager).recover()
    assert manager.starts == 0 and manager.state['state'] == 'inactive'
    assert 'restored' not in journal.get(pause.row['operation_id'])['runtime_observation']


def test_only_complete_or_terminal_acceptance_jobs_are_eligible():
    from clusterctl.receiving_maintenance import needs_worker_pause
    assert not needs_worker_pause({'state': 'complete'}, {})
    job = dict(state='attention-required', stage='acceptance',
        steps={stage: {'state': 'pending' if stage == 'acceptance' else 'complete'} for stage in STAGES})
    original = copy.deepcopy(job)
    assert needs_worker_pause(job, {'worker': {'unit': worker.UNIT}})
    with pytest.raises(OnboardingError, match='worker_binding_required'):
        needs_worker_pause(job, {})
    job['steps']['matrix']['state'] = 'pending'
    with pytest.raises(OnboardingError, match='admitted_job_required'):
        needs_worker_pause(job, {'worker': {'unit': worker.UNIT}})
    job['steps']['matrix']['state'] = 'complete'
    assert job == original


def test_native_inspect_keeps_static_command_and_separates_execution_metadata(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(worker.os, 'geteuid', lambda: 0)
    manager = worker.WorkerManager()
    manager.unit = tmp_path / worker.UNIT
    manager.unit.write_text('[Service]\nExecStart=/usr/bin/python3 -m worker\n')
    monkeypatch.setattr(worker.onboarding_release, 'regular', lambda path, **kw: path.read_bytes())
    state = dict(Id=worker.UNIT, LoadState='loaded', ActiveState='active',
        SubState='running', MainPID='123', InvocationID='first', Job='', Result='success',
        ExecMainCode='0', ExecMainStatus='0', FragmentPath=str(manager.unit), DropInPaths='',
        User='root', Group='', KillMode='control-group', TimeoutStopUSec='30s')
    command = ['/usr/bin/python3', ['/usr/bin/python3', '-m', 'worker'], False, 1, 2, 3, 4, 123, 0, 0]
    def run(*args, bus=False):
        if bus and args[-1] == 'EnvironmentFiles':
            return json.dumps({'type': 'a(sb)', 'data': []})
        if bus:
            return json.dumps({'type': 'a(sasbttttuii)', 'data': [command]})
        return '\n'.join(key + '=' + value for key, value in state.items())
    monkeypatch.setattr(manager, '_run', run)
    active = manager.inspect()
    command[3:] = [5, 6, 7, 8, 0, 1, 0]
    state.update(ActiveState='inactive', SubState='dead', MainPID='0', ExecMainCode='1')
    stopped = manager.inspect()
    assert stopped['definition'] == active['definition']
    command[3:] = [9, 10, 0, 0, 456, 0, 0]
    state.update(ActiveState='active', SubState='running', MainPID='456', InvocationID='second')
    assert manager.inspect()['definition'] == active['definition']
    command[1] = ['/usr/bin/python3', '-m', 'different']
    assert manager.inspect()['definition'] != active['definition']


def test_crash_before_claim_publication_does_not_reserve_the_next_cycle(tmp_path, monkeypatch):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    original_advance = journal.advance
    def fail_claim(*args, **kwargs):
        raise RuntimeError('lost before claim CAS')
    monkeypatch.setattr(journal, 'advance', fail_claim)
    orphan = worker.WorkerPause(journal, 'parent:first', 'b' * 64, manager)
    with pytest.raises(RuntimeError, match='before claim'):
        orphan.pause()
    assert manager.stops == manager.starts == 0
    monkeypatch.setattr(journal, 'advance', original_advance)
    manager.state['pid'] = '789'
    next_pause = worker.WorkerPause(journal, 'parent:second', 'c' * 64, manager)
    try:
        next_pause.pause()
    finally:
        next_pause.restore()
    assert next_pause.row['operation_id'] != orphan.row['operation_id']
    assert manager.stops == manager.starts == 1


def test_external_stop_before_owned_intent_is_not_undone(tmp_path, monkeypatch):
    journal = OperationJournal(tmp_path / 'journal')
    manager = Manager(tmp_path)
    original_inspect = manager.inspect
    reads = 0
    def inspect():
        nonlocal reads
        reads += 1
        if reads == 2:
            manager.state.update(state='inactive', substate='dead', pid='0', exit_code='1')
        return original_inspect()
    monkeypatch.setattr(manager, 'inspect', inspect)
    pause = worker.WorkerPause(journal, 'parent', 'b' * 64, manager)
    with pytest.raises(OnboardingError, match='state_uncertain'):
        try:
            pause.pause()
        finally:
            pause.restore()
    assert manager.stops == manager.starts == 0 and manager.state['state'] == 'inactive'
    assert pause.row['runtime_observation']['restored'] == {'no_owned_effect': True}
