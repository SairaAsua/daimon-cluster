"""Persistent service installation in a newly provisioned onboarding guest."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from collections.abc import Callable

from . import being_seed, onboarding_code_successor, onboarding_release
from .onboarding import OnboardingError, digest, private_directory, refusal_diagnostic, validate_plan

UNIT = 'daimon-onboarding-matrix.service'
_selection_owners = threading.local()


@contextmanager
def selection_lock(unit: Path):
    """Shared ownership for first installation and subsequent Matrix selection."""
    unit = being_seed._path(unit)
    process_id = os.getpid()
    owned: set[Path] = (getattr(_selection_owners, 'units', set())
                        if getattr(_selection_owners, 'process_id', None) == process_id else set())
    if unit in owned:
        yield
        return
    directory = unit.parent
    being_seed._path(directory)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise OnboardingError('onboarding_service_directory_rejected')
    lock = private_directory(directory / ('.' + unit.name + '.selection'), create=True)
    with being_seed._locked(lock):
        _selection_owners.units = owned | {unit}
        _selection_owners.process_id = process_id
        try:
            yield
        finally:
            _selection_owners.units = owned


class MatrixUserService:
    """Existing owner-local systemd user route for one Matrix-only Source unit.

    Inspection and mutation use that same named unit and owner. This is not a
    sessions coordinator or a guest instance stop. The bootstrap controller
    additionally binds its authenticated native PID to this manager scope.
    """

    def __init__(self, unit: Path, *, run=None):
        if not re.fullmatch(r'daimon-matrix-[a-z0-9-]+\.service', unit.name):
            raise OnboardingError('qualified_matrix_service_required')
        self.unit = being_seed._path(unit)
        self.run = run or self._run
        self._injected_run = run is not None
        self._manager_prefix = ['systemctl', '--user']
        self._unit_uid = os.geteuid()

    def _run(self, argv: list[str], *, timeout_seconds: float = 45) -> str:
        try:
            environment = {'PATH': os.defpath, 'LANG': 'C.UTF-8'}
            if '--user' in self._manager_prefix:
                environment.update(XDG_RUNTIME_DIR='/run/user/' + str(os.geteuid()),
                    DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/' + str(os.geteuid()) + '/bus')
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds, check=False,
                env=environment)
            if result.returncode or len(result.stdout.encode()) > 65536:
                raise OnboardingError('receiving_matrix_manager_unavailable')
            return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError('receiving_matrix_manager_unavailable') from None

    def _execute(self, argv: list[str], deadline_ns: int | None = None) -> str:
        remaining = 45 if deadline_ns is None else (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise OnboardingError('receiving_matrix_deadline_expired')
        # Injected runners are explicit test seams, not a bounded live route.
        result = self.run(argv) if self._injected_run else self._run(argv, timeout_seconds=min(45, remaining))
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_matrix_deadline_expired')
        return result

    def inspect(self, *, deadline_ns: int | None = None) -> dict:
        fields = {'Id', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup', 'InvocationID',
                  'FragmentPath', 'DropInPaths', 'KillMode', 'Result'}
        identity = getattr(self, '_required_execution', {})
        fields |= set(identity)
        raw = self._execute([*self._manager_prefix, 'show', self.unit.name,
                        '--property=' + ','.join(sorted(fields)), '--no-pager'], deadline_ns)
        lines = [line.split('=', 1) for line in raw.splitlines()]
        if (any(len(row) != 2 for row in lines) or len(lines) != len(fields)
                or {row[0] for row in lines} != fields):
            raise OnboardingError('receiving_matrix_service_scope_required')
        values = dict(lines)
        if (values['Id'] != self.unit.name or values['FragmentPath'] != str(self.unit)
                or values['DropInPaths'] and not identity or values['KillMode'] != 'control-group'
                or not values['MainPID'].isdigit()
                or values['ControlGroup'] and not values['ControlGroup'].endswith('/' + self.unit.name)
                or any(values[key] != value for key, value in identity.items())):
            raise OnboardingError('receiving_matrix_service_scope_required')
        content = onboarding_release.regular(self.unit, uid=self._unit_uid)
        if identity:
            guest_execution_identity(content)
        result = dict(unit_sha256=hashlib.sha256(content).hexdigest(), manager=values)
        if identity and values['DropInPaths']:
            result['dropins'] = self._guest_dropins(values['DropInPaths'])
        return result

    def _guest_dropins(self, paths: str) -> dict:
        """Freeze exact maintained guest additions, never executable overrides."""
        expected = {
            Path('/run/systemd/system/service.d/zzz-lxc-service.conf'): (
                b'[Service]\nProcSubset=all\nProtectProc=default\nProtectControlGroups=no\n'
                b'ProtectKernelTunables=no\nNoNewPrivileges=no\nLoadCredential=\n'
                b'PrivateNetwork=no\nImportCredential=\n'),
            self.unit.with_name(self.unit.name + '.d') / 'tribu-reference-cache.conf': (
                b'[Service]\nEnvironment=DM_TRIBU_REFERENCE_DIRECTORY='
                b'/home/agent/.local/state/tribu-reference-cache\n'),
        }
        selected = [Path(path) for path in paths.split()]
        if len(set(selected)) != len(selected) or any(path not in expected for path in selected):
            raise OnboardingError('receiving_matrix_service_scope_required')
        result = {}
        for path in selected:
            raw = onboarding_release.regular(path, uid=self._unit_uid)
            if raw != expected[path]:
                raise OnboardingError('receiving_matrix_service_scope_required')
            result[str(path)] = hashlib.sha256(raw).hexdigest()
        return result

    def stop(self, *, deadline_ns: int | None = None) -> None:
        # Do not wait for the CLI to imply drain. The controller observes the
        # pinned process and manager completion independently. StopUnit targets
        # the named Matrix-only unit; it is not an atomic process/invocation CAS.
        self._execute([*self._manager_prefix, '--no-block', 'stop', self.unit.name], deadline_ns)

    def bind_process(self, process: dict, inspected: dict) -> dict:
        values = inspected['manager']
        if (values['ActiveState'] != 'active' or int(values['MainPID']) != process['pid']
                or not values['ControlGroup']):
            raise OnboardingError('receiving_matrix_process_scope_required')
        lines = (Path('/proc') / str(process['pid']) / 'cgroup').read_text().splitlines()
        if '0::' + values['ControlGroup'] not in lines:
            raise OnboardingError('receiving_matrix_process_scope_required')
        return dict(process=process, control_group=values['ControlGroup'],
                    invocation_id=values['InvocationID'])

    def start(self, *, deadline_ns: int | None = None) -> None:
        self._execute([*self._manager_prefix, 'daemon-reload'], deadline_ns)
        self._execute([*self._manager_prefix, '--no-block', 'start', self.unit.name], deadline_ns)


class MatrixGuestService(MatrixUserService):
    """The installed guest's Matrix-only system unit, never the guest or harness.

    No sudo or alternative transport is introduced. Mutations use the caller's
    existing system-manager authority. The unit remains root-owned while its
    admitted parent and native child run as the configured receiving owner.
    """

    def __init__(self, unit: Path, *, run=None):
        if unit.name != UNIT:
            raise OnboardingError('qualified_matrix_service_required')
        self.unit = being_seed._path(unit)
        self.run = run or self._run
        self._injected_run = run is not None
        self._manager_prefix = ['systemctl']
        self._unit_uid = 0
        self._required_execution = dict(User='agent', Group='agent')

    def enable(self, *, deadline_ns: int) -> None:
        self._execute([*self._manager_prefix, '--no-reload', 'enable', self.unit.name], deadline_ns)

    def reload(self, *, deadline_ns: int) -> None:
        self._execute([*self._manager_prefix, 'daemon-reload'], deadline_ns)

    def start(self, *, deadline_ns: int | None = None,
              pre_start: Callable[[], None] | None = None) -> None:
        self._execute([*self._manager_prefix, 'daemon-reload'], deadline_ns)
        # Reload can expose an override absent from the old manager snapshot.
        # Validate that effective configuration before dispatching StartUnit.
        if pre_start is not None:
            pre_start()
        self._execute([*self._manager_prefix, '--no-block', 'start', self.unit.name], deadline_ns)

    def initial_state(self, *, deadline_ns: int) -> dict:
        """Observe an actual absent/inactive unit without inventing a process."""
        content = (onboarding_release.regular(self.unit, uid=self._unit_uid)
                   if self.unit.exists() or self.unit.is_symlink() else None)
        raw = self._execute([*self._manager_prefix, 'list-units', '--all', '--no-pager',
            '--output=json', '--', self.unit.name], deadline_ns)
        loaded = json.loads(raw)
        if (not isinstance(loaded, list) or len(loaded) > 1
                or loaded and (not isinstance(loaded[0], dict) or loaded[0].get('unit') != self.unit.name)):
            raise OnboardingError('receiving_matrix_service_scope_required')
        service = None
        if loaded:
            if content is None or loaded[0].get('load') != 'loaded':
                raise OnboardingError('receiving_matrix_service_scope_required')
            service = self.inspect(deadline_ns=deadline_ns)
        return dict(unit_sha256=None if content is None else hashlib.sha256(content).hexdigest(),
                    service=service)

    def bind_admitted_process(self, observed: dict, inspected: dict) -> dict:
        """Associate the manager's parent with the authenticated native child.

        Parent ancestry alone does not qualify code, SDK, loaded application or
        admission. Those remain the receiving observation's separate evidence.
        Re-pin both retained tuples and require their actual same-unit cgroup.
        """
        from .owner_process import ParentProcessPresence, PresenceError
        try:
            with ParentProcessPresence(observed['process']) as family:
                if family.process != observed['admission_parent']:
                    raise OnboardingError('receiving_matrix_process_scope_required')
                binding = self.bind_process(family.process, inspected)
                lines = (Path('/proc') / str(observed['process']['pid']) / 'cgroup').read_text().splitlines()
                if '0::' + binding['control_group'] not in lines:
                    raise OnboardingError('receiving_matrix_process_scope_required')
                family.verify()
                return dict(process=dict(observed['process']), admission_parent=family.process,
                    control_group=binding['control_group'], invocation_id=binding['invocation_id'])
        except (OSError, ValueError, KeyError, TypeError, PresenceError):
            raise OnboardingError('receiving_matrix_process_scope_required') from None


class GuestServiceBootstrap:
    """Root-side effects for the existing Matrix-only guest unit.

    The host owns qualification and the operation journal. These immutable
    request-bound artifacts retain effects across lost CLI replies; they are
    neither another authority nor receiving readiness. Owner SDK/custody code
    is never executed here. Caller retains host job ownership across the split.
    """

    def __init__(self, manager: MatrixGuestService):
        self.manager = manager

    def inspect(self, observed: dict | None = None, *, deadline_ns: int) -> dict:
        self._budget(deadline_ns)
        current = self.manager.inspect(deadline_ns=deadline_ns)
        scope = None if observed is None else self.manager.bind_admitted_process(observed, current)
        self._budget(deadline_ns)
        return dict(service=current, scope=scope, receiving_readiness='unobserved')

    @staticmethod
    def _budget(deadline_ns: int) -> None:
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_matrix_deadline_expired')

    def _request(self, request: dict) -> tuple[Path, dict, bytes]:
        from .owner_process import validate_process
        if (set(request) != {'schema', 'operation_id', 'plan_digest', 'predecessor', 'argv'}
                or request['schema'] != 'cluster-guest-service-bootstrap/v1'
                or not re.fullmatch(r'[0-9a-f]{64}', request['plan_digest'])
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']):
            raise OnboardingError('receiving_guest_service_request_required')
        previous = request['predecessor']
        if set(previous) != {'service', 'scope', 'process', 'admission_parent'}:
            raise OnboardingError('receiving_guest_service_request_required')
        process, parent = validate_process(previous['process']), validate_process(previous['admission_parent'])
        if (process['uid'] != 1000 or parent['uid'] != 1000 or process['pid'] == parent['pid']
                or process['boot_id'] != parent['boot_id']
                or previous['service']['manager']['ActiveState'] != 'active'
                or previous['service']['manager']['MainPID'] != str(parent['pid'])
                or not previous['service']['manager']['ControlGroup'].endswith('/'+self.manager.unit.name)
                or not previous['service']['manager']['InvocationID']
                or previous['service']['manager'].get('User') != 'agent'
                or previous['service']['manager'].get('Group') != 'agent'
                or previous['scope'] != dict(process=process, admission_parent=parent,
                    control_group=previous['service']['manager']['ControlGroup'],
                    invocation_id=previous['service']['manager']['InvocationID'])):
            raise OnboardingError('receiving_guest_service_request_required')
        original_hash = previous['service']['unit_sha256']
        if not re.fullmatch(r'[0-9a-f]{64}', original_hash):
            raise OnboardingError('receiving_guest_service_request_required')
        current = onboarding_release.regular(self.manager.unit, uid=self.manager._unit_uid)
        # Bind on-disk additions before daemon-reload, not only their paths.
        if previous['service'].get('dropins'):
            if (not hasattr(self.manager, '_guest_dropins')
                    or self.manager._guest_dropins(previous['service']['manager']['DropInPaths'])
                    != previous['service']['dropins']):
                raise OnboardingError('receiving_guest_service_request_conflict')
        retained = self.manager.unit.with_name(self.manager.unit.name+'.'+original_hash+'.previous')
        original = current if hashlib.sha256(current).hexdigest() == original_hash else onboarding_release.regular(
            retained, uid=self.manager._unit_uid)
        if hashlib.sha256(original).hexdigest() != original_hash:
            raise OnboardingError('receiving_guest_service_request_conflict')
        candidate = entrypoint(original, request['argv'])
        guest_execution_identity(original)
        guest_execution_identity(current)
        if current not in (original, candidate):
            raise OnboardingError('receiving_guest_service_request_conflict')
        directory = private_directory(self.manager.unit.parent / ('.'+self.manager.unit.name+'.selection'))
        operations = private_directory(directory/'operations', create=True)
        root = private_directory(operations/request['operation_id'], create=True)
        self._record(root/'request.json', request)
        return root, previous, candidate

    @staticmethod
    def _record(path: Path, value: dict) -> dict:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        private_directory(path.parent)
        if path.exists() or path.is_symlink():
            if (onboarding_release.regular(path, uid=os.geteuid()) != encoded
                    or stat.S_IMODE(path.stat().st_mode) != 0o600):
                raise OnboardingError('receiving_guest_service_request_conflict')
        else:
            # This namespace is owned by the existing unit selection lock.
            # Rename leaves one link even if publication loses its reply.
            temporary = path.parent / ('.bootstrap-effect-'+uuid.uuid4().hex)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
                os.rename(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        # A lost response can follow rename/link but precede parent fsync.
        # Repeated immutable publication must complete that durability too.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for directory in (path.parent, path.parent.parent, path.parent.parent.parent,
                          path.parent.parent.parent.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return value

    @staticmethod
    def _retained(root: Path, name: str) -> dict | None:
        path = root/(name+'.json')
        if not path.exists():
            return None
        raw = onboarding_release.regular(path, uid=os.geteuid())
        if path.stat().st_mode & 0o077:
            raise OnboardingError('receiving_guest_service_request_conflict')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise OnboardingError('receiving_guest_service_request_conflict')
        GuestServiceBootstrap._record(path, value)
        return value

    def _stopped(self, previous: dict, candidate: bytes, *, deadline_ns: int) -> dict:
        inspected = self.manager.inspect(deadline_ns=deadline_ns)
        values = inspected['manager']
        if (inspected['unit_sha256'] not in {previous['service']['unit_sha256'], hashlib.sha256(candidate).hexdigest()}
                or inspected.get('dropins', {}) != previous['service'].get('dropins', {})
                or values['ActiveState'] != 'inactive' or values['SubState'] != 'dead'
                or values['MainPID'] != '0' or values['InvocationID'] not in {'', previous['scope']['invocation_id']}):
            raise OnboardingError('receiving_guest_service_quiescence_required')
        return inspected

    def _parent(self, values: dict) -> dict:
        from .owner_process import ProcessPresence
        pid = int(values['MainPID'])
        root = Path('/proc')/str(pid)
        fields = (root/'stat').read_text().rpartition(')')[2].split()
        process = dict(pid=pid, uid=1000, start_ticks=int(fields[19]),
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        with ProcessPresence(process) as presence:
            self.manager.bind_process(process, dict(manager=values))
            presence.verify()
        return process

    def _initial(self, action: str, request: dict, *, deadline_ns: int) -> dict:
        """Retain a genuine first unit/start, with no predecessor exit receipt."""
        from .owner_process import PresenceError
        if (set(request) - {'not_after_ms'} != {'schema', 'operation_id', 'plan_digest', 'predecessor', 'argv'}
                or request['schema'] != 'cluster-guest-service-initial/v1'
                or 'not_after_ms' in request and (type(request['not_after_ms']) is not int
                    or not 0 < request['not_after_ms'] < 2**53)
                or request['predecessor'] is not None or action == 'quiesce'
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or re.fullmatch('[0-9a-f]{64}', request['plan_digest']) is None):
            raise OnboardingError('receiving_guest_service_request_required')
        candidate = unit_content(request['argv'])
        fingerprint = hashlib.sha256(candidate).hexdigest()
        selection = private_directory(self.manager.unit.parent / ('.' + self.manager.unit.name + '.selection'))
        operations = private_directory(selection / 'operations', create=True)
        root = private_directory(operations / request['operation_id'], create=True)
        self._record(root / 'request.json', request)

        def owned() -> None:
            if (not self.manager.unit.exists() or
                    onboarding_release.regular(self.manager.unit, uid=self.manager._unit_uid) != candidate):
                raise OnboardingError('receiving_guest_service_candidate_changed')

        def authorized_effect() -> None:
            if request.get('not_after_ms', 2**53 - 1) <= time.time_ns() // 1_000_000:
                raise OnboardingError('receiving_preservation_authorization_expired')

        def inactive(*, require_loaded: bool = False) -> dict:
            if require_loaded:
                service = self.manager.inspect(deadline_ns=deadline_ns)
                state = dict(unit_sha256=service['unit_sha256'], service=service)
            else:
                state = self.manager.initial_state(deadline_ns=deadline_ns)
            if state['unit_sha256'] not in {None, fingerprint}:
                raise OnboardingError('receiving_guest_service_candidate_changed')
            service = state['service']
            if service is not None:
                values = service['manager']
                if (values['ActiveState'] != 'inactive' or values['SubState'] != 'dead'
                        or values['MainPID'] != '0' or values['InvocationID']):
                    raise OnboardingError('receiving_guest_service_initial_inactive_required')
            return state

        prepared = self._retained(root, 'initial-prepared')
        if action == 'validate':
            if prepared is None:
                prepared = self._record(root / 'initial-prepared.json', dict(
                    schema='cluster-guest-service-initial-candidate/v1', candidate_sha256=fingerprint,
                    initial_service=inactive(), receiving_readiness='unobserved'))
            elif self._retained(root, 'selected') is not None:
                owned()
            else:
                inactive()
            self._budget(deadline_ns)
            # Preparation stays immutable. Dispatch classification is a fresh
            # observation used to distinguish a possible first effect from
            # observation-only recovery of an uncertain/recorded invocation.
            dispatch = ('started-recorded' if self._retained(root, 'initial-started') is not None else
                'intent-retained' if self._retained(root, 'initial-start-intent') is not None else 'not-dispatched')
            self._budget(deadline_ns)
            return {**prepared, 'dispatch_state': dispatch}
        if prepared is None or prepared['candidate_sha256'] != fingerprint:
            raise OnboardingError('receiving_guest_service_initial_preparation_required')
        if action == 'select':
            retained = self._retained(root, 'selected')
            if retained is not None:
                owned()
            else:
                inactive()
                authorized_effect()
                publish(self.manager.unit, candidate)
                authorized_effect()
                self.manager.enable(deadline_ns=deadline_ns)
                retained = self._record(root / 'selected.json', dict(
                    selected_sha256=fingerprint, receiving_readiness='unobserved'))
            self._budget(deadline_ns)
            return retained
        selected = self._retained(root, 'selected')
        if selected is None or selected['selected_sha256'] != fingerprint:
            raise OnboardingError('receiving_guest_service_selection_required')
        owned()
        started = self._retained(root, 'initial-started')
        if started is not None:
            current = self.manager.inspect(deadline_ns=deadline_ns)
            if (current != started['service'] or current['manager']['ActiveState'] != 'active'
                    or self._parent(current['manager']) != started['admission_parent']):
                raise OnboardingError('receiving_guest_service_started_process_changed')
            self._budget(deadline_ns)
            return started
        intent = self._retained(root, 'initial-start-intent')
        if intent is None:
            authorized_effect()
            inactive()
            def before_start() -> None:
                owned()
                observed = inactive(require_loaded=True)
                authorized_effect()
                self._record(root / 'initial-start-intent.json', dict(
                    selected_sha256=fingerprint, launch_precondition=observed))
                self._budget(deadline_ns)
                authorized_effect()
            self.manager.start(deadline_ns=deadline_ns, pre_start=before_start)
            intent = self._retained(root, 'initial-start-intent')
        precondition = None if intent is None else intent.get('launch_precondition')
        launch = precondition.get('service') if isinstance(precondition, dict) else None
        if (intent is None or intent.get('selected_sha256') != fingerprint
                or not isinstance(launch, dict) or launch.get('unit_sha256') != fingerprint):
            raise OnboardingError('receiving_guest_service_initial_start_uncertain')
        pending = self._retained(root, 'initial-pending-parent')
        while True:
            self._budget(deadline_ns)
            owned()
            current = self.manager.inspect(deadline_ns=deadline_ns)
            if (current['unit_sha256'] != launch['unit_sha256']
                    or current.get('dropins', {}) != launch.get('dropins', {})):
                raise OnboardingError('receiving_guest_service_candidate_changed')
            values = current['manager']
            if values['ActiveState'] == 'active':
                association = {key: values[key] for key in ('MainPID', 'InvocationID', 'ControlGroup')}
                if pending is not None and association != pending:
                    raise OnboardingError('receiving_guest_service_started_process_changed')
                pending = self._record(root / 'initial-pending-parent.json', association)
                try:
                    parent = self._parent(values)
                except PresenceError:
                    pass  # Observe this same Type=simple invocation's UID switch.
                else:
                    result = self._record(root / 'initial-started.json', dict(
                        schema='cluster-guest-service-initial-start/v1', service=current,
                        initial_service=prepared['initial_service'],
                        admission_parent=parent, receiving_readiness='unobserved'))
                    self._budget(deadline_ns)
                    return result
            elif values['ActiveState'] != 'activating' or pending is not None:
                # An intent alone does not prove StartUnit absent. Never repeat
                # it after a dead/failed/unknown first invocation to clear doubt.
                raise OnboardingError('receiving_guest_service_initial_start_uncertain')
            time.sleep(min(0.05, max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)))

    def _steady(self, request: dict, *, deadline_ns: int) -> dict:
        """Remove only the first-start guard, preserving the actual invocation.

        The privileged host confirms the complete receiving cohort before this
        request. Root binds that intent to its original first-service records;
        it does not infer receiving acceptance from a unit-file selection.
        """
        from .owner_process import validate_process
        fields = {'schema', 'operation_id', 'plan_digest', 'initial_request_sha256',
                  'cohort_selection_sha256', 'process', 'admission_parent', 'not_after_ms'}
        if (set(request) != fields or request['schema'] != 'cluster-guest-service-steady/v1'
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or type(request['not_after_ms']) is not int or not 0 < request['not_after_ms'] < 2**53
                or any(not isinstance(request[key], str) or re.fullmatch('[0-9a-f]{64}', request[key]) is None
                    for key in ('plan_digest', 'initial_request_sha256', 'cohort_selection_sha256'))):
            raise OnboardingError('receiving_guest_service_request_required')
        process = validate_process(request['process'])
        parent = validate_process(request['admission_parent'])
        if (process['uid'] != 1000 or parent['uid'] != 1000 or process['pid'] == parent['pid']
                or process['boot_id'] != parent['boot_id']):
            raise OnboardingError('receiving_guest_service_request_required')
        selection = private_directory(self.manager.unit.parent / ('.' + self.manager.unit.name + '.selection'))
        root = private_directory(selection / 'operations' / request['operation_id'])
        original = self._retained(root, 'request')
        started = self._retained(root, 'initial-started')
        if (original is None or started is None or digest(original) != request['initial_request_sha256']
                or original.get('schema') != 'cluster-guest-service-initial/v1'
                or original['plan_digest'] != request['plan_digest']
                or started['admission_parent'] != parent):
            raise OnboardingError('receiving_guest_service_initial_preparation_required')
        argv = original['argv']
        if argv.count('--initial-context-json') != 1:
            raise OnboardingError('receiving_initial_context_required')
        index = argv.index('--initial-context-json')
        context = initial_context(json.loads(argv[index + 1]))
        if (context['not_after_ms'] != original.get('not_after_ms')
                or request['not_after_ms'] > context['not_after_ms']):
            raise OnboardingError('receiving_initial_context_required')
        ordinary = argv[:index] + argv[index + 2:]
        initial_sha256 = hashlib.sha256(unit_content(argv)).hexdigest()
        steady_sha256 = hashlib.sha256(unit_content(ordinary)).hexdigest()
        if initial_sha256 != started['service']['unit_sha256']:
            raise OnboardingError('receiving_guest_service_candidate_changed')
        retained = self._retained(root, 'steady-request')

        def observed() -> dict:
            current = self.manager.inspect(deadline_ns=deadline_ns)
            if (current['unit_sha256'] not in {initial_sha256, steady_sha256}
                    or {**current, 'unit_sha256': initial_sha256} != started['service']
                    or current['manager']['ActiveState'] != 'active'
                    or self._parent(current['manager']) != parent
                    or retained is None and current['unit_sha256'] != initial_sha256):
                raise OnboardingError('receiving_guest_service_started_process_changed')
            scope = self.manager.bind_admitted_process(request, current)
            if scope != dict(process=process, admission_parent=parent,
                    control_group=current['manager']['ControlGroup'],
                    invocation_id=current['manager']['InvocationID']):
                raise OnboardingError('receiving_guest_service_started_process_changed')
            self._budget(deadline_ns)
            return current

        observed()
        retained = self._record(root / 'steady-request.json', request)
        completed = self._retained(root, 'steady')
        if completed is None:
            def before_replace() -> None:
                self._budget(deadline_ns)
                observed()
                if request['not_after_ms'] <= time.time_ns() // 1_000_000:
                    raise OnboardingError('receiving_preservation_authorization_expired')
            # Durable private preparation can consume the remaining horizon or
            # outlive this invocation. Check at the actual file-selection edge.
            selected = select_entrypoint(self.manager.unit, ordinary, previous_sha256=initial_sha256,
                pre_replace=before_replace)
            self._budget(deadline_ns)
            # Reload changes future restart policy, not the current execution.
            self.manager.reload(deadline_ns=deadline_ns)
            current = observed()
            if current['unit_sha256'] != steady_sha256:
                raise OnboardingError('receiving_guest_service_candidate_changed')
            completed = self._record(root / 'steady.json', dict(
                schema='cluster-guest-service-steady-selection/v1', request_sha256=digest(request),
                selected=selected, service=current, process=process, admission_parent=parent,
                loaded_readiness='unobserved'))
        elif (completed['request_sha256'] != digest(request) or observed() != completed['service']
                or completed['service']['unit_sha256'] != steady_sha256):
            raise OnboardingError('receiving_guest_service_started_process_changed')
        self._budget(deadline_ns)
        return completed

    def execute(self, action: str, request: dict, *, deadline_ns: int) -> dict:
        from .owner_process import PresenceError, ProcessPresence, observe_process_exit
        from contextlib import ExitStack
        if action not in {'validate', 'quiesce', 'select', 'start', 'steady'}:
            raise OnboardingError('receiving_guest_service_request_required')
        self._budget(deadline_ns)
        with selection_lock(self.manager.unit):
            if action == 'steady':
                return self._steady(request, deadline_ns=deadline_ns)
            if request.get('schema') == 'cluster-guest-service-initial/v1':
                return self._initial(action, request, deadline_ns=deadline_ns)
            root, previous, candidate = self._request(request)
            self._budget(deadline_ns)
            if action == 'validate':
                current = self.manager.inspect(deadline_ns=deadline_ns)
                if (current != previous['service'] or self.manager.bind_admitted_process(previous, current)
                        != previous['scope']):
                    raise OnboardingError('receiving_guest_service_predecessor_changed')
                self._budget(deadline_ns)
                return dict(schema='cluster-guest-service-candidate/v1',
                    candidate_sha256=hashlib.sha256(candidate).hexdigest(), receiving_readiness='unobserved')
            if action == 'quiesce':
                retained = self._retained(root, 'quiesced')
                if retained is not None:
                    self._stopped(previous, candidate, deadline_ns=deadline_ns)
                    self._budget(deadline_ns)
                    return retained
                current = self.manager.inspect(deadline_ns=deadline_ns)
                if current['unit_sha256'] != previous['service']['unit_sha256']:
                    raise OnboardingError('receiving_guest_service_predecessor_changed')
                with ExitStack() as pins:
                    pinned = {}
                    if current['manager']['ActiveState'] == 'active':
                        if (current != previous['service'] or self.manager.bind_admitted_process(previous, current)
                                != previous['scope']):
                            raise OnboardingError('receiving_guest_service_predecessor_changed')
                        for name in ('process', 'admission_parent'):
                            pinned[name] = pins.enter_context(ProcessPresence(previous[name]))
                        self._record(root/'stop-intent.json', dict(scope=previous['scope']))
                        self._budget(deadline_ns)
                        try:
                            self.manager.stop(deadline_ns=deadline_ns)
                        except (OSError, OnboardingError):
                            # Technical exit evidence can survive a lost/late
                            # manager reply without claiming current quiescence.
                            for name, presence in pinned.items():
                                if presence.wait_for_exit(0):
                                    self._record(root/(name+'-exited.json'), dict(process=previous[name], exited=True))
                            raise
                    elif current['manager']['ActiveState'] == 'deactivating':
                        values = current['manager']
                        if (self._retained(root, 'stop-intent') is None
                                or values['InvocationID'] != previous['scope']['invocation_id']
                                or values['MainPID'] not in {'0', str(previous['admission_parent']['pid'])}
                                or values['ControlGroup'] not in {'', previous['scope']['control_group']}):
                            raise OnboardingError('receiving_guest_service_predecessor_changed')
                    else:
                        self._stopped(previous, candidate, deadline_ns=deadline_ns)
                    while True:
                        self._budget(deadline_ns)
                        exited = {}
                        for name in ('process', 'admission_parent'):
                            retained_exit = self._retained(root, name+'-exited')
                            if retained_exit is not None and retained_exit != dict(process=previous[name], exited=True):
                                raise OnboardingError('receiving_guest_service_request_conflict')
                            done = (retained_exit is not None or (pinned[name].wait_for_exit(0) if name in pinned
                                    else observe_process_exit(previous[name])))
                            if done:
                                self._record(root/(name+'-exited.json'), dict(process=previous[name], exited=True))
                            exited[name] = done
                        if all(exited.values()):
                            self._stopped(previous, candidate, deadline_ns=deadline_ns)
                            result = self._record(root/'quiesced.json', dict(
                                schema='cluster-guest-service-quiescence/v1', process=previous['process'],
                                admission_parent=previous['admission_parent'], exits=exited,
                                graceful_delivery='unobserved'))
                            self._budget(deadline_ns)
                            return result
                        time.sleep(min(0.05, max(0, (deadline_ns-time.monotonic_ns())/1_000_000_000)))
            if self._retained(root, 'quiesced') is None:
                raise OnboardingError('receiving_guest_service_quiescence_required')
            if action == 'select':
                self._stopped(previous, candidate, deadline_ns=deadline_ns)
                self._budget(deadline_ns)
                result = select_entrypoint(self.manager.unit, request['argv'],
                    previous_sha256=previous['service']['unit_sha256'])
                result = self._record(root/'selected.json', result)
                self._budget(deadline_ns)
                return result
            selected = self._retained(root, 'selected')
            if selected is None:
                raise OnboardingError('receiving_guest_service_selection_required')
            current = self.manager.inspect(deadline_ns=deadline_ns)
            if current['unit_sha256'] != selected['selected_sha256']:
                raise OnboardingError('receiving_guest_service_candidate_changed')
            if current.get('dropins', {}) != previous['service'].get('dropins', {}):
                raise OnboardingError('receiving_guest_service_candidate_changed')
            retained = self._retained(root, 'started')
            if retained is not None:
                if (current['manager']['ActiveState'] != 'active'
                        or any(current['manager'][key] != retained['manager'][key]
                               for key in ('MainPID', 'InvocationID', 'ControlGroup'))
                        or self._parent(current['manager']) != retained['admission_parent']):
                    raise OnboardingError('receiving_guest_service_started_process_changed')
                self._budget(deadline_ns)
                return retained
            intent = self._retained(root, 'start-intent')
            pending_parent = self._retained(root, 'pending-parent')
            if current['manager']['ActiveState'] == 'inactive':
                if pending_parent is not None:
                    raise OnboardingError('receiving_guest_service_started_process_changed')
                self._stopped(previous, candidate, deadline_ns=deadline_ns)
                self._record(root/'start-intent.json', dict(selected_sha256=selected['selected_sha256']))
                self._budget(deadline_ns)
                def before_start() -> None:
                    reloaded = self._stopped(previous, candidate, deadline_ns=deadline_ns)
                    if reloaded['unit_sha256'] != selected['selected_sha256']:
                        raise OnboardingError('receiving_guest_service_candidate_changed')
                self.manager.start(deadline_ns=deadline_ns, pre_start=before_start)
            elif current['manager']['ActiveState'] not in {'active', 'activating'} or intent is None:
                raise OnboardingError('receiving_guest_service_started_process_changed')
            while True:
                self._budget(deadline_ns)
                current = self.manager.inspect(deadline_ns=deadline_ns)
                if current['unit_sha256'] != selected['selected_sha256']:
                    raise OnboardingError('receiving_guest_service_candidate_changed')
                if current.get('dropins', {}) != previous['service'].get('dropins', {}):
                    raise OnboardingError('receiving_guest_service_candidate_changed')
                if current['manager']['ActiveState'] == 'active':
                    association = {key: current['manager'][key] for key in ('MainPID', 'InvocationID', 'ControlGroup')}
                    if pending_parent is not None and association != pending_parent:
                        raise OnboardingError('receiving_guest_service_started_process_changed')
                    pending_parent = self._record(root/'pending-parent.json', association)
                    try:
                        parent = self._parent(current['manager'])
                    except PresenceError:
                        # Type=simple can become active before its fork switches
                        # to User=agent. Observe this same invocation within the
                        # budget; do not start again or adopt another process.
                        pass
                    else:
                        result = self._record(root/'started.json', dict(schema='cluster-guest-service-start/v1',
                            manager=current['manager'], admission_parent=parent,
                            receiving_readiness='unobserved'))
                        self._budget(deadline_ns)
                        return result
                elif current['manager']['ActiveState'] != 'activating' or pending_parent is not None:
                    raise OnboardingError('receiving_guest_service_start_unobserved')
                time.sleep(min(0.05, max(0, (deadline_ns-time.monotonic_ns())/1_000_000_000)))


def guest_execution_identity(content: bytes) -> None:
    """Preserved disk directives must agree with the maintained guest owner.

    A previously loaded manager can lag an edited unit until daemon-reload.
    Reject duplicate/reset/continued execution directives rather than infer
    the next command's owner from the predecessor process UID.
    """
    section = None
    services = 0
    identity: dict = {}
    for raw in content.split(b'\n'):
        line = raw.strip(b' \t\r')
        if not line or line.startswith((b'#', b';')):
            continue
        if line.endswith(b'\\'):
            raise OnboardingError('receiving_guest_execution_identity_required')
        if line.startswith(b'['):
            section = line
            services += int(line == b'[Service]')
        elif b'=' in line:
            key, value = (piece.strip(b' \t\r') for piece in line.split(b'=', 1))
            if key in {b'User', b'Group'}:
                if section != b'[Service]' or key in identity:
                    raise OnboardingError('receiving_guest_execution_identity_required')
                identity[key] = value
    if services != 1 or identity != {b'User': b'agent', b'Group': b'agent'}:
        raise OnboardingError('receiving_guest_execution_identity_required')


def code_command(python: Path, code: Path, module: str, arguments: list[str]) -> list[str]:
    """Hook-free initial import of the already approved stdlib bootstrap code."""
    if not re.fullmatch(r'clusterctl\.[a-z][a-z0-9_]*', module):
        raise OnboardingError('qualified_matrix_entrypoint_required')
    launcher = '''import sys,importlib
from pathlib import Path
code = sys.argv.pop(1)
module = sys.argv.pop(1)
cache = code + '/.disabled-bytecode'
if Path(cache).exists() or Path(cache).is_symlink():
    raise SystemExit(1)
sys.pycache_prefix = cache
sys.dont_write_bytecode = True
sys.path.insert(0, code)
raise SystemExit(importlib.import_module(module).main())
'''
    return [str(python), '-B', '-I', '-S', '-c', launcher, str(code), module, *arguments]


def entrypoint(original: bytes, argv: list[str]) -> bytes:
    """Change the one exact ExecStart line, preserving every other unit byte."""
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 100
            or any(not isinstance(arg, str) or '\0' in arg for arg in argv)
            or not Path(argv[0]).is_absolute() or len(json.dumps(argv).encode()) > 65536
            or original.count(b'\nExecStart=') != 1 or original.startswith(b'ExecStart=')):
        raise OnboardingError('qualified_matrix_entrypoint_required')
    # JSON string quoting escapes CR/LF inside one physical ExecStart line.
    # The maintained -c launchers contain real newlines as argument data.
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return b'\n'.join(('ExecStart=' + encoded).encode() if line.startswith(b'ExecStart=') else line
                      for line in original.split(b'\n'))


def select_entrypoint(unit: Path, argv: list[str], *, previous_sha256: str,
                      pre_replace: Callable[[], None] | None = None) -> dict:
    """CAS an approved Matrix unit under a persistent kernel selection lock.

    Called only with the protected operation's exact unit, predecessor and
    qualified command. This selects a file, never a live process: no reload,
    stop/start, authority adoption, native-input replay or readiness claim occurs.
    The retained predecessor supports lost-ACK recovery, not obsolete authority.
    All supported selectors of this unit must use this same lock.
    """
    if (not isinstance(previous_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', previous_sha256)
            or unit.name != UNIT and not re.fullmatch(r'daimon-matrix-[a-z0-9-]+\.service', unit.name)):
        raise OnboardingError('qualified_matrix_entrypoint_required')
    directory = unit.parent
    with selection_lock(unit):
        current = onboarding_release.regular(unit, uid=os.geteuid())
        mode = stat.S_IMODE(unit.stat().st_mode)
        if mode not in {0o600, 0o640, 0o644}:
            raise OnboardingError('existing_onboarding_service_preserved')
        retained = directory / (unit.name + '.' + previous_sha256 + '.previous')
        original = (current if hashlib.sha256(current).hexdigest() == previous_sha256
                    else onboarding_release.regular(retained, uid=os.geteuid()))
        if hashlib.sha256(original).hexdigest() != previous_sha256:
            raise OnboardingError('existing_onboarding_service_preserved')
        candidate = entrypoint(original, argv)
        candidate_sha256 = hashlib.sha256(candidate).hexdigest()
        result = dict(previous_sha256=previous_sha256, selected_sha256=candidate_sha256,
                      selected=True, loaded_readiness='unobserved')
        if current == candidate:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return result
        if current != original:
            raise OnboardingError('existing_onboarding_service_preserved')
        # Freeze original bytes before replacement, retaining exact permissions.
        publish(retained, original, mode=mode)
        temporary = directory / ('.onboarding-selection-' + uuid.uuid4().hex)
        try:
            publish(temporary, candidate, mode=mode)
            if pre_replace is not None:
                pre_replace()
            if onboarding_release.regular(unit, uid=os.geteuid()) != original:
                raise OnboardingError('existing_onboarding_service_preserved')
            os.replace(temporary, unit)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)
        return result


def initial_context(value: dict) -> dict:
    """Closed public pins for an initial child's native pre-load assertion."""
    if (not isinstance(value, dict) or set(value) != {'schema', 'owner_sha256', 'profile_sha256', 'not_after_ms'}
            or value['schema'] != 'cluster-initial-start-context/v1'
            or type(value['not_after_ms']) is not int or not 0 < value['not_after_ms'] < 2**53
            or any(not isinstance(value[key], str) or re.fullmatch('[0-9a-f]{64}', value[key]) is None
                for key in ('owner_sha256', 'profile_sha256'))):
        raise OnboardingError('receiving_initial_context_required')
    return dict(value)


def command(code: Path, *, receive_only: bool, visibility: Path | None = None,
            runtime_code: Path | None = None, runtime_digest: str | None = None,
            messaging_application: Path | None = None, expected_initial_context: dict | None = None) -> list[str]:
    if receive_only == (visibility is not None):
        raise OnboardingError('onboarding_visibility_selection_required')
    if messaging_application is not None and receive_only:
        raise OnboardingError('onboarding_visibility_selection_required')
    if (runtime_code is None) != (runtime_digest is None):
        raise OnboardingError('qualified_onboarding_runtime_required')
    runtime_args = ([] if runtime_code is None else
                    ['--runtime-code', str(runtime_code), '--runtime-digest', str(runtime_digest)])
    public = '/home/agent/.onboarding-matrix/'
    arguments = ['admitted-serve',
            '--home', '/home/agent', '--code', str(code), *runtime_args,
            '--plan', '/home/agent/.onboarding-input/plan.json',
            '--genesis', public + 'genesis.json', '--admission-profile', public + 'admission.json',
            *(['--messaging-application', str(messaging_application)] if messaging_application is not None else [])]
    arguments += (['--receive-only'] if receive_only else ['--visibility-installation', str(visibility)])
    if expected_initial_context is not None:
        if receive_only:
            raise OnboardingError('receiving_initial_context_required')
        arguments += ['--initial-context-json', json.dumps(initial_context(expected_initial_context),
            sort_keys=True, separators=(',', ':'))]
    return code_command(Path('/usr/bin/python3'), runtime_code or code, 'clusterctl.onboarding_target', arguments)


def unit_content(argv: list[str]) -> bytes:
    """Render the maintained guest unit for both initial and legacy install."""
    template = ('[Unit]\nDescription=Admitted native onboarding body\nAfter=network-online.target\n'
           'Wants=network-online.target\n[Service]\nType=simple\nUser=agent\nGroup=agent\n'
           'Environment=HOME=/home/agent\nUMask=0077\nRestart=on-failure\nRestartSec=5\n'
           'KillMode=control-group\nTimeoutStopSec=30\nExecStart=/prepared\n'
           '[Install]\nWantedBy=multi-user.target\n').encode()
    return entrypoint(template, argv)


def install(code: Path, *, receive_only: bool, visibility: Path | None = None,
            runtime_code: Path | None = None, runtime_digest: str | None = None,
            messaging_application: Path | None = None,
            directory: Path = Path('/etc/systemd/system'), run=None) -> None:
    """Preserve foreign units; publication/reload/enable are independently retryable."""
    being_seed._path(directory)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise OnboardingError('onboarding_service_directory_rejected')
    argv = command(code, receive_only=receive_only, visibility=visibility,
                   runtime_code=runtime_code, runtime_digest=runtime_digest, messaging_application=messaging_application)
    raw = unit_content(argv)
    with selection_lock(directory / UNIT):
        publish(directory / UNIT, raw)
        execute = run or _run
        execute(['systemctl', 'daemon-reload'])
        execute(['systemctl', 'enable', '--now', UNIT])


def publish(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    """Atomic owned publication, refusing replacement of an existing candidate."""
    directory = path.parent
    being_seed._path(directory)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise OnboardingError('onboarding_service_directory_rejected')
    if path.exists() or path.is_symlink():
        if (onboarding_release.regular(path, uid=os.geteuid()) != raw
                or stat.S_IMODE(path.stat().st_mode) != mode):
            raise OnboardingError('existing_onboarding_service_preserved')
    else:
        temporary = directory / ('.onboarding-service-' + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                os.fchmod(output.fileno(), mode)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, path, follow_symlinks=False)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            temporary.unlink(missing_ok=True)


def _run(argv: list[str]) -> None:
    try:
        result = subprocess.run(argv, capture_output=True, timeout=40, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise OnboardingError('onboarding_service_operation_failed') from None
    if result.returncode:
        raise OnboardingError('onboarding_service_operation_failed')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics', action='store_true', help='write bounded nonsecret refusal detail to stderr')
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--runtime-code', type=Path)
    parser.add_argument('--runtime-digest')
    parser.add_argument('--messaging-application', type=Path)
    parser.add_argument('--action', choices=('install', 'bootstrap-inspect', 'bootstrap-validate', 'bootstrap-quiesce',
        'bootstrap-select', 'bootstrap-start', 'bootstrap-steady'), default='install')
    parser.add_argument('--bootstrap-request-json')
    parser.add_argument('--owner-observation-json')
    parser.add_argument('--timeout-seconds', type=float, default=30)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--receive-only', action='store_true')
    selection.add_argument('--visibility-installation', type=Path)
    args = parser.parse_args(argv)
    stage = 'public-release'
    try:
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        onboarding_code_successor.selection(args.runtime_code, args.runtime_digest, args.code,
                                             plan['release_digest'], uid=0)
        if os.geteuid() != 0 or args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_service_required')
        if (args.runtime_code is not None
                and args.runtime_code != Path('/opt/daimon-onboarding-runtime') / args.runtime_digest):
            raise OnboardingError('qualified_guest_service_required')
        if args.action != 'install':
            stage = args.action
            if (not math.isfinite(args.timeout_seconds) or not 0 < args.timeout_seconds <= 60
                    or args.receive_only or args.visibility_installation is not None or args.messaging_application is not None):
                raise OnboardingError('receiving_guest_service_request_required')
            deadline_ns = time.monotonic_ns()+int(args.timeout_seconds*1_000_000_000)
            controller = GuestServiceBootstrap(MatrixGuestService(Path('/etc/systemd/system')/UNIT))
            if args.action == 'bootstrap-inspect':
                if args.bootstrap_request_json is not None or (args.owner_observation_json is not None
                        and len(args.owner_observation_json.encode()) > 2*1024**2):
                    raise OnboardingError('receiving_guest_service_request_required')
                observed = None if args.owner_observation_json is None else json.loads(args.owner_observation_json)
                result = controller.inspect(observed, deadline_ns=deadline_ns)
            else:
                if (args.owner_observation_json is not None or args.bootstrap_request_json is None
                        or len(args.bootstrap_request_json.encode()) > 65536):
                    raise OnboardingError('receiving_guest_service_request_required')
                request = json.loads(args.bootstrap_request_json)
                from .onboarding import digest
                if request.get('plan_digest') != digest(plan):
                    raise OnboardingError('receiving_guest_service_request_required')
                result = controller.execute(args.action.removeprefix('bootstrap-'), request, deadline_ns=deadline_ns)
            print(json.dumps(result))
            return 0
        if args.bootstrap_request_json is not None or args.owner_observation_json is not None:
            raise OnboardingError('receiving_guest_service_request_required')
        stage = 'service-installation'
        install(args.code, receive_only=args.receive_only, visibility=args.visibility_installation,
                runtime_code=args.runtime_code, runtime_digest=args.runtime_digest, messaging_application=args.messaging_application)
        print(json.dumps(dict(installed=True)))
        return 0
    except (OSError, ValueError, TypeError, KeyError, OnboardingError) as error:
        if args.diagnostics:
            print(json.dumps(refusal_diagnostic(error, stage=stage)), file=sys.stderr)
        print(json.dumps(dict(installed=False, error='onboarding_service_operation_failed')))
        return 1
