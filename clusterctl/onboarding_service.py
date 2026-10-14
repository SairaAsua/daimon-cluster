"""Persistent service installation in a newly provisioned onboarding guest."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import being_seed, onboarding_code_successor, onboarding_release
from .onboarding import OnboardingError, private_directory, validate_plan

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

    def _run(self, argv: list[str], *, timeout_seconds: float = 45) -> str:
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds, check=False,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                     'XDG_RUNTIME_DIR': '/run/user/' + str(os.geteuid()),
                     'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.geteuid()) + '/bus'})
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
        raw = self._execute(['systemctl', '--user', 'show', self.unit.name,
                        '--property=' + ','.join(sorted(fields)), '--no-pager'], deadline_ns)
        lines = [line.split('=', 1) for line in raw.splitlines()]
        if (any(len(row) != 2 for row in lines) or len(lines) != len(fields)
                or {row[0] for row in lines} != fields):
            raise OnboardingError('receiving_matrix_service_scope_required')
        values = dict(lines)
        if (values['Id'] != self.unit.name or values['FragmentPath'] != str(self.unit)
                or values['DropInPaths'] or values['KillMode'] != 'control-group'
                or not values['MainPID'].isdigit()
                or values['ControlGroup'] and not values['ControlGroup'].endswith('/' + self.unit.name)):
            raise OnboardingError('receiving_matrix_service_scope_required')
        content = onboarding_release.regular(self.unit, uid=os.geteuid())
        return dict(unit_sha256=hashlib.sha256(content).hexdigest(), manager=values)

    def stop(self) -> None:
        # Do not wait for the CLI to imply drain. The controller observes the
        # pinned process and manager completion independently. StopUnit targets
        # the named Matrix-only unit; it is not an atomic process/invocation CAS.
        self.run(['systemctl', '--user', '--no-block', 'stop', self.unit.name])

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
        self._execute(['systemctl', '--user', 'daemon-reload'], deadline_ns)
        self._execute(['systemctl', '--user', '--no-block', 'start', self.unit.name], deadline_ns)


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
            or any(not isinstance(arg, str) or '\n' in arg or '\r' in arg or '\0' in arg for arg in argv)
            or not Path(argv[0]).is_absolute() or len(json.dumps(argv).encode()) > 65536
            or original.count(b'\nExecStart=') != 1 or original.startswith(b'ExecStart=')):
        raise OnboardingError('qualified_matrix_entrypoint_required')
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return b'\n'.join(('ExecStart=' + encoded).encode() if line.startswith(b'ExecStart=') else line
                      for line in original.split(b'\n'))


def select_entrypoint(unit: Path, argv: list[str], *, previous_sha256: str) -> dict:
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


def command(code: Path, *, receive_only: bool, visibility: Path | None = None,
            runtime_code: Path | None = None, runtime_digest: str | None = None,
            messaging_application: Path | None = None) -> list[str]:
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
    return code_command(Path('/usr/bin/python3'), runtime_code or code, 'clusterctl.onboarding_target', arguments)


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
    # systemd's ExecStart syntax, not a shell command. Escape substitutions.
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    raw = ('[Unit]\nDescription=Admitted native onboarding body\nAfter=network-online.target\n'
           'Wants=network-online.target\n[Service]\nType=simple\nUser=agent\nGroup=agent\n'
           'Environment=HOME=/home/agent\nUMask=0077\nRestart=on-failure\nRestartSec=5\n'
           'KillMode=control-group\nTimeoutStopSec=30\nExecStart=' + encoded +
           '\n[Install]\nWantedBy=multi-user.target\n').encode()
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
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--runtime-code', type=Path)
    parser.add_argument('--runtime-digest')
    parser.add_argument('--messaging-application', type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--receive-only', action='store_true')
    selection.add_argument('--visibility-installation', type=Path)
    args = parser.parse_args(argv)
    try:
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        onboarding_code_successor.selection(args.runtime_code, args.runtime_digest, args.code,
                                             plan['release_digest'], uid=0)
        if os.geteuid() != 0 or args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_service_required')
        if (args.runtime_code is not None
                and args.runtime_code != Path('/opt/daimon-onboarding-runtime') / args.runtime_digest):
            raise OnboardingError('qualified_guest_service_required')
        install(args.code, receive_only=args.receive_only, visibility=args.visibility_installation,
                runtime_code=args.runtime_code, runtime_digest=args.runtime_digest, messaging_application=args.messaging_application)
        print(json.dumps(dict(installed=True)))
        return 0
    except (OSError, ValueError, OnboardingError):
        print(json.dumps(dict(installed=False, error='onboarding_service_operation_failed')))
        return 1
