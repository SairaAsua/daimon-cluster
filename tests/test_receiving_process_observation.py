"""Kernel observations belong to the actual RPC connection, not an earlier probe."""
import os
import ast
import inspect
import multiprocessing
import socket
from pathlib import Path

import pytest

from clusterctl.owner_process import ConnectedProcessObserver, PresenceError


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
