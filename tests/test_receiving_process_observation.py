"""Kernel observations belong to the actual RPC connection, not an earlier probe."""
import os
import ast
import inspect
import multiprocessing
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from clusterctl.owner_process import ConnectedProcessObserver, ParentProcessPresence, PresenceError, observe_process_exit


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
