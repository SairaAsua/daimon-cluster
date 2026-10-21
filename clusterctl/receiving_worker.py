"""Fixed onboarding-worker pause with durable original-state restoration.

This controls no Matrix body, Codex harness, Telegram process or global Stop.
The single supported worker uses the canonical maintenance journal so a second
operation cannot mistake an earlier outstanding pause for an inactive baseline.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from . import onboarding_release
from .onboarding import OnboardingError, digest
from .onboarding_code_successor import plan_update
from .onboarding_service import selection_lock
from .operation_journal import OperationJournal

UNIT = 'daimon-onboarding-worker.service'
JOURNAL = Path('/var/lib/daimon-cluster-receiving-maintenance/operations')
PUBLIC_ERRORS = frozenset({'receiving_worker_binding_required', 'receiving_worker_manager_unavailable',
    'receiving_worker_configuration_changed', 'receiving_worker_state_uncertain',
    'receiving_worker_other_operation_pending', 'receiving_worker_drain_uncertain',
    'receiving_worker_restore_uncertain'})


class WorkerManager:
    def __init__(self, *, config_path: Path | None = None):
        if os.geteuid() != 0:
            raise OnboardingError('receiving_worker_binding_required')
        self.unit = Path('/etc/systemd/system') / UNIT
        self.config_path = config_path

    def _run(self, *arguments: str, bus: bool = False) -> str:
        try:
            result = subprocess.run(['/usr/bin/busctl' if bus else '/usr/bin/systemctl', *arguments], capture_output=True,
                text=True, timeout=45, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError('receiving_worker_manager_unavailable') from None
        if result.returncode or len(result.stdout.encode()) > 65536:
            raise OnboardingError('receiving_worker_manager_unavailable')
        return result.stdout

    def inspect(self) -> dict:
        fields = {'Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'Job',
            'Result', 'ExecMainCode', 'ExecMainStatus', 'FragmentPath', 'DropInPaths',
            'User', 'Group', 'KillMode', 'TimeoutStopUSec'}
        lines = [line.split('=', 1) for line in self._run('show', UNIT, '--no-pager', '--all',
            '--property=' + ','.join(sorted(fields))).splitlines()]
        if (len(lines) != len(fields) or any(len(row) != 2 for row in lines)
                or {row[0] for row in lines} != fields):
            raise OnboardingError('receiving_worker_manager_unavailable')
        values = dict(lines)
        if (values['Id'] != UNIT or values['LoadState'] != 'loaded'
                or values['FragmentPath'] != str(self.unit) or values['KillMode'] != 'control-group'):
            raise OnboardingError('receiving_worker_binding_required')
        files = [self.unit, *map(Path, values['DropInPaths'].split())]
        hashes = {str(path): hashlib.sha256(onboarding_release.regular(path, uid=0)).hexdigest()
                  for path in files}
        # ExecStart's systemctl text also includes process timestamps/results.
        # Use its typed D-Bus command prefix; execution metadata must not change
        # the static definition when this very operation stops/starts the worker.
        try:
            commands = json.loads(self._run('--system', '--json=short', 'get-property',
                'org.freedesktop.systemd1',
                '/org/freedesktop/systemd1/unit/daimon_2donboarding_2dworker_2eservice',
                'org.freedesktop.systemd1.Service', 'ExecStart', bus=True))
            rows = commands['data']
            if (commands['type'] != 'a(sasbttttuii)' or not isinstance(rows, list) or not rows
                    or any(not isinstance(row, list) or len(row) != 10
                        or not isinstance(row[0], str) or not isinstance(row[1], list)
                        or not all(isinstance(arg, str) for arg in row[1])
                        or type(row[2]) is not bool for row in rows)):
                raise ValueError
            static_commands = [row[:3] for row in rows]
            if self.config_path is not None:
                arguments = rows[0][1]
                if (len(rows) != 1 or len(arguments) not in {5, 7}
                        or arguments[0] != rows[0][0]
                        or arguments[1:4] != ['-m', 'clusterctl.onboarding_worker', '--config']
                        or arguments[4] != str(self.config_path)
                        or len(arguments) == 7 and (arguments[5] != '--home-placements'
                            or not Path(arguments[6]).is_absolute() or '..' in Path(arguments[6]).parts)):
                    raise OnboardingError('receiving_worker_binding_required')
            environment_files = json.loads(self._run('--system', '--json=short', 'get-property',
                'org.freedesktop.systemd1',
                '/org/freedesktop/systemd1/unit/daimon_2donboarding_2dworker_2eservice',
                'org.freedesktop.systemd1.Service', 'EnvironmentFiles', bus=True))
            if environment_files != {'type': 'a(sb)', 'data': []}:
                raise OnboardingError('receiving_worker_binding_required')
        except OnboardingError:
            raise
        except (ValueError, KeyError, TypeError):
            raise OnboardingError('receiving_worker_manager_unavailable') from None
        # Retain only hashes, never raw command/environment text.
        execution = {key: values[key] for key in ('User', 'Group', 'KillMode',
            'TimeoutStopUSec', 'FragmentPath', 'DropInPaths')}
        return dict(definition=digest({'files': hashes, 'execution': execution, 'commands': static_commands}),
            state=values['ActiveState'], substate=values['SubState'], pid=values['MainPID'],
            invocation=values['InvocationID'], job=values['Job'] or '0', result=values['Result'],
            exit_code=values['ExecMainCode'], exit_status=values['ExecMainStatus'])

    def stop(self) -> None:
        self._run('--no-block', 'stop', UNIT)

    def start(self) -> None:
        self._run('--no-block', 'start', UNIT)

    def wait(self, baseline: dict, *, active: bool) -> dict:
        deadline = time.monotonic() + 45
        while True:
            current = self.inspect()
            if current['definition'] != baseline['definition']:
                raise OnboardingError('receiving_worker_configuration_changed')
            if current['job'] == '0':
                if active and current['state'] == 'active' and current['pid'] != '0':
                    return current
                if not active and current['state'] == 'inactive' and current['pid'] == '0':
                    if (current['substate'], current['result'], current['exit_code'], current['exit_status']) != (
                            'dead', 'success', '1', '0'):
                        raise OnboardingError('receiving_worker_drain_uncertain')
                    return current
                if current['state'] == 'failed':
                    raise OnboardingError('receiving_worker_restore_uncertain' if active else 'receiving_worker_drain_uncertain')
            if time.monotonic() >= deadline:
                raise OnboardingError('receiving_worker_restore_uncertain' if active else 'receiving_worker_drain_uncertain')
            time.sleep(.1)


class WorkerPause:
    """Use inside the fixed unit selection lock; never hold an outer jobs lock."""
    def __init__(self, journal: OperationJournal, parent: str, binding: str, manager=None):
        self.journal, self.parent, self.binding = journal, parent, binding
        self.manager = manager or WorkerManager()
        self.target = 'receiving-worker:' + UNIT
        self.claim_digest = digest({'unit': UNIT, 'profile': 'scoped-worker-preservation/v1'})
        self.row: dict | None = None

    def _claim(self):
        return self.journal.latest_for_idempotency_key(
            'receiving-update:' + self.target + ':' + self.claim_digest)

    def _latest_open(self):
        claim = self._claim()
        selected = {} if claim is None else (claim['runtime_observation'] or {})
        row = self.journal.get(selected['cycle_id']) if 'cycle_id' in selected else None
        if row and 'restored' not in (row['runtime_observation'] or {}):
            if row['expected_precondition'].get('parent') != self.parent or row['expected_precondition'].get('binding') != self.binding:
                raise OnboardingError('receiving_worker_other_operation_pending')
            return row
        return None

    def _record(self, name: str, value: dict) -> None:
        if self.row is None:
            raise OnboardingError('receiving_worker_state_uncertain')
        row = self.journal.get(self.row['operation_id'])
        if row is None:
            raise OnboardingError('receiving_worker_state_uncertain')
        observed = dict(row['runtime_observation'] or {})
        if name in observed and observed[name] != value:
            raise OnboardingError('receiving_worker_state_uncertain')
        observed[name] = value
        self.row = self.journal.advance(row['operation_id'], row['state'],
            runtime_observation=observed, expected_runtime_observation=row['runtime_observation'])

    def recover(self) -> None:
        self.row = self._latest_open()
        if self.row is not None:
            self.restore()

    def pause(self) -> None:
        if self._latest_open() is not None:
            raise OnboardingError('receiving_worker_state_uncertain')
        before = self.manager.inspect()
        if before['job'] != '0' or before['state'] not in {'active', 'inactive', 'failed'}:
            raise OnboardingError('receiving_worker_state_uncertain')
        claim = plan_update(self.journal, target=self.target, manifest_digest=self.claim_digest,
            expected_precondition={'unit': UNIT}, intended_transition={'profile': 'scoped-worker-preservation/v1'},
            audit_identity={'actor': 'receiving-maintenance-worker'})
        selected = claim['runtime_observation'] or {}
        cycle = selected.get('cycle', 0) + 1
        self.row = plan_update(self.journal, target='receiving-worker-cycle:' + UNIT + ':' + str(cycle) + ':' + str(uuid.uuid4()),
            manifest_digest=digest({'parent': self.parent, 'binding': self.binding}),
            expected_precondition=dict(parent=self.parent, binding=self.binding, cycle=cycle, baseline=before),
            intended_transition={'restore_active': before['state'] == 'active'},
            audit_identity={'actor': 'receiving-maintenance-worker'})
        # Publish the single fixed-unit claim BEFORE stop intent/dispatch. A
        # crash before this CAS can leave only an inert child, never a pause.
        self.journal.advance(claim['operation_id'], claim['state'],
            runtime_observation={'cycle': cycle, 'cycle_id': self.row['operation_id']},
            expected_runtime_observation=claim['runtime_observation'])
        if before['state'] != 'active':
            self._record('stopped', {'already_inactive': True})
            return
        if self.manager.inspect() != before:
            raise OnboardingError('receiving_worker_state_uncertain')
        self._record('stop_intent', {'original': before})
        try:
            self.manager.stop()
        except OnboardingError:
            pass  # Observe the actual manager outcome after a lost response.
        self._record('stopped', self.manager.wait(before, active=False))

    def restore(self) -> None:
        if self.row is None or 'restored' in (self.row['runtime_observation'] or {}):
            return
        if 'stop_intent' not in (self.row['runtime_observation'] or {}):
            self._record('restored', {'no_owned_effect': True})
            return
        before = self.row['expected_precondition']['baseline']
        current = self.manager.inspect()
        if current['definition'] != before['definition']:
            raise OnboardingError('receiving_worker_configuration_changed')
        if before['state'] == 'active':
            if 'restore_intent' not in (self.row['runtime_observation'] or {}):
                self._record('restore_intent', {'original_active': True})
            if current['state'] != 'active' or current['job'] != '0':
                try:
                    self.manager.start()
                except OnboardingError:
                    pass
            current = self.manager.wait(before, active=True)
        elif current['state'] not in {'inactive', 'failed'} or current['job'] != '0':
            # Preserve an external start; do not stop another process to restore.
            raise OnboardingError('receiving_worker_restore_uncertain')
        self._record('restored', {'observed': current, 'original_active': before['state'] == 'active'})


def recover_before_preflight(spec: dict) -> None:
    """A bad candidate/expired horizon must never strand a prior stopped worker."""
    if 'worker' not in spec:
        return
    journal = OperationJournal.existing(JOURNAL)
    if journal is None:
        return
    target = 'receiving-maintenance:' + spec['name'] + ':' + digest(spec)
    row = journal.latest_for_idempotency_key('receiving-update:' + target + ':' + spec['candidate']['manifest_digest'])
    if row is None or row['expected_precondition'] != {'maintenance_spec': spec}:
        return
    manager = WorkerManager()
    with selection_lock(manager.unit):
        WorkerPause(journal, row['operation_id'], digest(spec), manager).recover()


def restoration_pending(spec: dict) -> bool:
    if 'worker' not in spec:
        return False
    journal = OperationJournal.existing(JOURNAL)
    if journal is None:
        return False
    target = 'receiving-worker:' + UNIT
    checksum = digest({'unit': UNIT, 'profile': 'scoped-worker-preservation/v1'})
    claim = journal.latest_for_idempotency_key('receiving-update:' + target + ':' + checksum)
    selected = {} if claim is None else (claim['runtime_observation'] or {})
    row = journal.get(selected['cycle_id']) if 'cycle_id' in selected else None
    return row is not None and 'restored' not in (row['runtime_observation'] or {})


@contextmanager
def job_drain_barrier(jobs: Path):
    """Exclude pending ticks/home-provider calls only until clean worker stop.

    The installed worker resolves both backend routes after these same job
    locks. Nonblocking contention has no stop intent and is safe to resume.
    Release before lifecycle/host selector effects and before worker restoration.
    """
    from . import being_seed
    from .onboarding import JobStore, private_directory
    store = JobStore(jobs)
    with ExitStack() as locks:
        locks.enter_context(being_seed._locked(private_directory(jobs)))
        for name in sorted(store.names()):
            locks.enter_context(being_seed._locked(private_directory(store.directory(name))))
        yield
