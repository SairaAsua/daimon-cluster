"""Kernel observations belong to the actual RPC connection, not an earlier probe."""
import os
import ast
import inspect
import multiprocessing
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from clusterctl.owner_process import ConnectedProcessObserver, ParentProcessPresence, PresenceError, observe_process_exit


def test_initial_native_socket_can_appear_within_the_same_observation_budget(tmp_path):
    from clusterctl.onboarding_target import _socket_identity
    path = tmp_path / 'matrix.sock'
    published = threading.Event()
    release = threading.Event()
    def serve():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            time.sleep(.05)
            listener.bind(str(path))
            listener.listen(1)
            published.set()
            release.wait(5)
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        identity = _socket_identity(path, time.monotonic_ns() + 2_000_000_000)
        assert published.wait(1)
        assert (identity.st_dev, identity.st_ino) == (path.lstat().st_dev, path.lstat().st_ino)
    finally:
        release.set()
        thread.join(5)
        assert not thread.is_alive()


def test_socket_wait_never_extends_deadline_or_retries_unbounded_status(tmp_path):
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_target import _socket_identity
    path = tmp_path / 'matrix.sock'
    with pytest.raises(FileNotFoundError):
        _socket_identity(path, None)
    deadline = time.monotonic_ns() + 20_000_000
    with pytest.raises(OnboardingError, match='onboarding_observation_deadline_expired'):
        _socket_identity(path, deadline)
    # Even an existing socket cannot turn a late observation into success.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        with pytest.raises(OnboardingError, match='onboarding_observation_deadline_expired'):
            _socket_identity(path, deadline)


def test_both_actual_admitted_child_launchers_compile_before_spawn():
    from clusterctl.onboarding_runtime import AdmittedDaemon
    tree = ast.parse(Path(inspect.getfile(AdmittedDaemon)).read_text())
    launchers = [node.value for node in ast.walk(tree)
                 if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                 and isinstance(node.value.value, str) and any(
                     isinstance(target, ast.Name) and target.id in {'launcher', 'child_launcher'}
                     for target in node.targets)]
    assert len(launchers) == 2
    for launcher in launchers:
        compile(launcher.value, '<actual-admitted-child-launcher>', 'exec')


@pytest.mark.parametrize('qualified', [False, True])
def test_guest_observation_deadline_refuses_before_custody_or_unbounded_rpc(monkeypatch, qualified):
    from clusterctl.onboarding import OnboardingError
    from clusterctl.onboarding_target import Target
    from daimon_matrix import client
    from types import SimpleNamespace
    import time
    fields=dict(getattr(client.LocalClient,'__dataclass_fields__',{}))
    if qualified:
        fields['deadline_ns']=None
    else:
        fields.pop('deadline_ns',None)
    # Explicit API availability seam only, never loaded/startup qualification.
    monkeypatch.setattr(client.LocalClient,'__dataclass_fields__',fields)
    target=SimpleNamespace(observe=lambda:pytest.fail('refused observation opened custody'))
    error='onboarding_observation_deadline_expired' if qualified else 'qualified_onboarding_deadline_client_required'
    with pytest.raises(OnboardingError,match=error):
        Target.running(target,deadline_ns=time.monotonic_ns()-1)


@pytest.mark.parametrize('action,timeout', [('observe','1'),('running','0'),('admitted-running','-1'),
                                         ('running','nan'),('running','inf'),('running','61')])
def test_guest_cli_rejects_invalid_observation_budget_before_sdk_or_body(capsys, monkeypatch, action, timeout):
    from clusterctl import onboarding_target
    monkeypatch.setattr(onboarding_target.being_seed,'_read',lambda *_args,**_kwargs:
        pytest.fail('invalid observation budget opened a plan'))
    assert onboarding_target.main([action,'--home','/unused','--plan','/unused/plan',
        '--genesis','/unused/genesis','--code','/unused/code',
        '--observation-timeout-seconds',timeout])==1
    assert capsys.readouterr().out=='{"error": "native_onboarding_target_refused"}\n'


def child_listener(path, ready):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(1)
        ready.send(True)
        with listener.accept()[0] as connection:
            connection.recv(1)


def test_connected_process_retains_pin_and_snapshot_without_extra_probe():
    left, right = socket.socketpair()
    try:
        with ConnectedProcessObserver() as observer:
            with observer(left):
                assert observer.process['pid'] == os.getpid()
                snapshot = observer.process
                snapshot['pid'] = 1
                assert observer.process['pid'] == os.getpid()
            observer.verify()
            descriptor = observer._presence.descriptor
            assert os.fstat(descriptor)
            with observer(right):
                assert observer.process['pid'] == os.getpid()
        with pytest.raises(OSError):
            os.fstat(descriptor)
        with pytest.raises(PresenceError, match='observation_rejected'):
            with observer:
                pass
    finally:
        left.close()
        right.close()


def test_actual_parent_and_child_are_pinned_as_distinct_processes():
    child = subprocess.Popen([sys.executable, '-I', '-c',
        'import sys; print("READY", flush=True); sys.stdin.readline()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'READY\n'
        process = dict(uid=os.geteuid(), pid=child.pid,
            start_ticks=int((Path('/proc') / str(child.pid) / 'stat').read_text().rpartition(')')[2].split()[19]),
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        with pytest.raises(PresenceError, match='parent_process_unavailable'):
            ParentProcessPresence({**process, 'start_ticks': process['start_ticks'] + 1})
        with ParentProcessPresence(process) as family:
            assert family.child.process == process
            assert family.process['pid'] == os.getpid()
            snapshot = family.process
            snapshot['pid'] = 1
            assert family.process['pid'] == os.getpid()
            descriptors = (family.child.descriptor, family.parent.descriptor)
            assert all(os.fstat(descriptor) for descriptor in descriptors)
            family.verify()
            child.stdin.write(b'exit\n')
            child.stdin.flush()
            child.wait(timeout=5)
            with pytest.raises(PresenceError, match='parent_process_unavailable'):
                family.verify()
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        with pytest.raises(PresenceError, match='parent_process_unavailable'):
            family.verify()
        with pytest.raises(PresenceError, match='parent_process_unavailable'):
            ParentProcessPresence(process)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()


def test_later_connection_to_another_actual_process_is_refused(tmp_path):
    path = str(tmp_path / 'peer.sock')
    receiver, sender = multiprocessing.Pipe(duplex=False)
    child = multiprocessing.Process(target=child_listener, args=(path, sender))
    child.start()
    sender.close()
    left, right = socket.socketpair()
    try:
        assert receiver.poll(5)
        assert receiver.recv() is True
        with ConnectedProcessObserver() as observer:
            with observer(left):
                pass
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
                other.connect(path)
                with pytest.raises(PresenceError, match='observation_rejected'):
                    with observer(other):
                        pytest.fail('RPC to the other process must not start')
            observer.verify()
        child.join(5)
        assert child.exitcode == 0
    finally:
        receiver.close()
        left.close()
        right.close()
        if child.is_alive():
            child.terminate()
        child.join(5)


@pytest.mark.parametrize('arguments', [
    ['--prepare-control', 'revoke.json'],
    ['--apply-control', 'revoke.json', '--control-command', 'command.json'],
    ['--prepare-control', 'revoke.json', '--control-command', 'command.json', '--observe'],
    ['--prepare-control', 'revoke.json', '--control-command', 'command.json', '--ready-fd', '1'],
])
def test_source_control_cli_refuses_invalid_modes_before_owner_state(tmp_path, monkeypatch, capsys, arguments):
    from clusterctl import onboarding_source
    monkeypatch.setattr(onboarding_source.being_seed, '_read', lambda *_:
        pytest.fail('invalid control opened owner state'))
    assert onboarding_source.main(['--config', str(tmp_path / 'unused.json'), *arguments]) == 1
    assert capsys.readouterr().out == '{"error": "native_onboarding_source_refused"}\n'


@pytest.mark.parametrize('action,arguments', [
    ('observe', ['--require-loaded']),
    ('running', ['--current-native', '--require-loaded', '--observation-timeout-seconds', '5']),
    ('admitted-running', ['--current-native', '--observation-timeout-seconds', '5']),
    ('admitted-running', ['--current-native', '--require-loaded']),
    ('receiving-control-prepare', ['--control-file', 'revoke.json']),
    ('receiving-control-apply', ['--control-file', 'revoke.json', '--control-command', 'command.json']),
    ('running', ['--control-file', 'revoke.json']),
])
def test_guest_control_cli_refuses_invalid_modes_before_owner_state(tmp_path, monkeypatch, capsys, action, arguments):
    from clusterctl import onboarding_target
    monkeypatch.setattr(onboarding_target.being_seed, '_read', lambda *_:
        pytest.fail('invalid control opened owner state'))
    required = [action, '--home', str(tmp_path), '--code', str(tmp_path),
                '--plan', str(tmp_path / 'plan.json'), '--genesis', str(tmp_path / 'genesis.json')]
    assert onboarding_target.main([*required, *arguments]) == 1
    assert capsys.readouterr().out == '{"error": "native_onboarding_target_refused"}\n'


@pytest.mark.parametrize('option', ['--observation-timeout-seconds=5', '--observation-timeout-seconds'])
def test_guest_reexec_does_not_refund_slow_import_preparation(tmp_path, monkeypatch, capsys, option):
    from clusterctl import onboarding_target as module
    from tests.test_onboarding import plan
    clock = [1_000_000_000]
    reads = []
    monkeypatch.setattr(module.time, 'monotonic_ns', lambda: clock[0])
    monkeypatch.setattr(module.being_seed, '_read', lambda *_: (reads.append(True), plan())[1])
    monkeypatch.setattr(module.onboarding_code_successor, 'selection', lambda *_args, **_kw: tmp_path)
    monkeypatch.setattr(module.onboarding_code_successor, 'sdk_parameters', lambda *_: {'matrix_commit': 'a'*40})
    # This clock/dispatch seam consumes a prepared V4 path. SDK closure has
    # separate real-wheel coverage; the old observe mock no longer selects it.
    sdk_path = tmp_path / 'sdk/sdk.json'
    sdk_path.parent.mkdir()
    sdk_path.write_text('{}')
    sdk_path.chmod(0o644)
    generation = tmp_path / '.local/share/daimon-matrix/sdk' / module.digest({})
    imports = generation / 'runtime-imports'
    imports.mkdir(parents=True, mode=0o700)
    generation.chmod(0o700)
    module.being_seed._write(generation / 'runtime-imports.json', {})
    regular = module.onboarding_release.regular
    monkeypatch.setattr(module.onboarding_release, 'regular', lambda path, **kw:
        regular(path, **{**kw, 'uid': os.geteuid()}) if path == sdk_path else regular(path, **kw))
    monkeypatch.setattr(module.onboarding_sdk, 'startup_context', lambda *_: False)
    def slow(*_args, **_kw):
        clock[0] += 10_000_000_000
        return imports
    monkeypatch.setattr(module.onboarding_sdk, 'runtime_imports', slow)
    monkeypatch.setattr(module.onboarding_sdk, 'runtime_command',
        lambda _venv, _imports, _code, _module, arguments: ['python', *arguments])
    monkeypatch.setattr(module, 'Target', lambda *_args, **_kw: pytest.fail('expired handoff opened target custody'))
    def reenter(_path, arguments):
        assert arguments[arguments.index('--observation-deadline-ns')+1] == '6000000000'
        raise SystemExit(module.main(arguments[1:]))
    monkeypatch.setattr(module.os, 'execv', reenter)
    budget = [option] if '=' in option else [option, '5']
    arguments = ['receiving-control-prepare', '--home', str(tmp_path), '--code', str(tmp_path),
        '--plan', str(tmp_path/'plan.json'), '--genesis', str(tmp_path/'genesis.json'),
        '--control-file', 'revoke.json', '--control-command', '-', *budget]
    with pytest.raises(SystemExit) as stopped:
        module.main(arguments)
    assert stopped.value.code == 1 and reads == [True]
    assert capsys.readouterr().out == '{"error": "native_onboarding_target_refused"}\n'


@pytest.mark.parametrize('action,arguments', [
    ('receiving-identity', ['--identity-expires-at-ms','1']),
    ('running', ['--identity-expires-at-ms','1']),
    ('running', ['--observation-deadline-ns','100']),
    ('running', ['--observation-timeout-seconds','5','--observation-deadline-ns','-1']),
])
def test_invalid_identity_or_absolute_budget_refuses_before_plan_read(tmp_path, monkeypatch, capsys, action, arguments):
    from clusterctl import onboarding_target as module
    monkeypatch.setattr(module.being_seed, '_read', lambda *_: pytest.fail('invalid request read owner plan'))
    assert module.main([action,'--home',str(tmp_path),'--code',str(tmp_path),
        '--plan',str(tmp_path/'plan.json'),'--genesis',str(tmp_path/'genesis.json'),*arguments]) == 1
    assert capsys.readouterr().out == '{"error": "native_onboarding_target_refused"}\n'


def test_pinned_exit_wait_distinguishes_running_exited_and_closed_observer():
    from clusterctl.owner_process import ProcessPresence
    child = subprocess.Popen([sys.executable, '-I', '-c',
        'import sys; print("READY", flush=True); sys.stdin.readline()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'READY\n'
        process = dict(uid=os.geteuid(), pid=child.pid,
            start_ticks=int((Path('/proc') / str(child.pid) / 'stat').read_text().rpartition(')')[2].split()[19]),
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        with ProcessPresence(process) as presence:
            assert observe_process_exit(process) is False
            with pytest.raises(PresenceError, match='exit_observation_rejected'):
                observe_process_exit({**process, 'start_ticks': process['start_ticks'] + 1})
            assert presence.wait_for_exit(0) is False
            child.stdin.write(b'exit\n')
            child.stdin.flush()
            assert presence.wait_for_exit(5) is True
            child.wait(timeout=5)
            assert presence.wait_for_exit(0) is True
            assert observe_process_exit(process) is True
        with pytest.raises(PresenceError, match='exit_observation_rejected'):
            presence.wait_for_exit(0)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()


@pytest.mark.parametrize('timeout', [True, -1, 61, 2**2048, float('nan'), float('inf')])
def test_exit_observation_rejects_invalid_bound_without_signal(timeout):
    with ConnectedProcessObserver() as observer:
        left, right = socket.socketpair()
        try:
            with observer(left):
                pass
            with pytest.raises(PresenceError, match='exit_observation_rejected'):
                observer.wait_for_exit(timeout)
        finally:
            left.close()
            right.close()


@pytest.mark.parametrize('fault', [None, 'base-process', 'base-runtime', 'application', 'loaded-bundle',
                                  'binding', 'bundle', 'group', 'socket', 'expired'])
def test_current_maintenance_observation_never_reconstructs_birth_or_pair_history(tmp_path, monkeypatch, fault):
    """Authenticated RPC seam; real protected files, socket inodes and parent pin.

    Existing owner-client tests cover HMAC/credential validity. This checks that
    their composition preserves process/public selections without old custody.
    """
    import copy
    import hashlib
    from types import SimpleNamespace
    from clusterctl import being_seed, onboarding_peer, onboarding_receiving_update as updates
    from clusterctl.onboarding import OnboardingError, digest
    from clusterctl.onboarding_target import Target
    from daimon_matrix.canonical import canonical_bytes
    target = Target.__new__(Target)
    target.plan, target.genesis = {'name': 'fixture'}, {'synthetic': True}
    target.root = tmp_path / 'matrix'
    target.package = target.root / 'package'
    root = target.package / 'runtime'
    root.mkdir(parents=True, mode=0o700)
    target.package.chmod(0o700)
    target.root.chmod(0o700)
    being_seed._write(target.root / 'plan.json', target._binding())
    bundle = {'synthetic-public-bundle': True}
    being_seed._write(root / 'runtime.json', bundle)
    process = dict(uid=os.geteuid(), pid=os.getpid(),
        start_ticks=int(Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19]),
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    loaded = dict(runtime_id='runtime:fixture', qualified_startup={'sdk': 'exact'},
        runtime_bundle_sha256=digest(bundle), process_id=process['pid'])
    application = dict(loaded_base_sha256=hashlib.sha256(canonical_bytes(loaded)).hexdigest())
    current = dict(process=process, server={'body': 'fixture'}, identity={'admitted': True},
        verified_identity=dict(runtime_bundle_sha256=digest(bundle)),
        runtime_status=dict(loaded_runtime=loaded, loaded_application=application))
    native = copy.deepcopy(current)
    selected = dict(channel_id='tribe', socket=str(root / 'tribe.sock'))
    checks = []
    monkeypatch.setattr(onboarding_peer, 'observed_group', lambda *_: copy.deepcopy(selected))
    target.observe = lambda: pytest.fail('maintenance reopened birth/custody/pair history')
    class Owner:
        def __init__(self, _root, path, **options):
            assert options['deadline_ns'] > time.monotonic_ns()
            self.path = path
            self._observer = SimpleNamespace(verify=lambda: checks.append('verified'))
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def qualified_identity(self, **options):
            assert options['require_admitted'] is True
            assert options['expires_at_ms'] > time.time_ns() // 1_000_000
            return copy.deepcopy(current)
        def base_status(self):
            if fault == 'binding':
                being_seed._write(target.root / 'plan.json', {'changed': True})
            if fault == 'bundle':
                being_seed._write(root / 'runtime.json', {'changed': True})
            if fault == 'group':
                selected['changed'] = True
            if fault == 'socket':
                (root / 'tribe.sock').unlink()
                replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                replacement.bind(str(root / 'tribe.sock'))
                listeners.append(replacement)
            if fault == 'expired':
                monkeypatch.setattr(time, 'monotonic_ns', lambda: deadline + 1)
            return copy.deepcopy(native)
    monkeypatch.setattr(updates, 'OwnerGroupClient', Owner)
    if fault == 'base-process':
        native['process']['start_ticks'] += 1
    if fault == 'base-runtime':
        native['runtime_status']['loaded_runtime']['runtime_id'] = 'different'
    if fault == 'application':
        current['runtime_status']['loaded_application']['loaded_base_sha256'] = 'wrong'
    if fault == 'loaded-bundle':
        # The base/group can agree on B while the captured selection is A.
        current['runtime_status']['loaded_runtime']['runtime_bundle_sha256'] = 'different'
        native['runtime_status']['loaded_runtime'] = copy.deepcopy(current['runtime_status']['loaded_runtime'])
        current['runtime_status']['loaded_application']['loaded_base_sha256'] = hashlib.sha256(
            canonical_bytes(current['runtime_status']['loaded_runtime'])).hexdigest()
    listeners = []
    deadline = time.monotonic_ns() + 5_000_000_000
    try:
        for name in ('matrix.sock', 'tribe.sock'):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(root / name))
            listeners.append(listener)
        if fault:
            with pytest.raises(OnboardingError):
                target.current_running(deadline_ns=deadline)
        else:
            result = target.current_running(deadline_ns=deadline)
            assert result['admission_parent']['pid'] == os.getppid()
            assert result['runtime_sha256'] == digest(bundle)
            assert result['group'] == selected and result['receiving_readiness'] == 'unobserved'
            assert checks == ['verified', 'verified']
    finally:
        for listener in listeners:
            listener.close()
