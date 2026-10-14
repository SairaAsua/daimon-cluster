"""Persistent guest service publication survives effects with missing ACKs."""
from pathlib import Path

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_service import UNIT, install


def test_guest_manager_uses_existing_system_unit_and_root_owned_fragment(tmp_path, monkeypatch):
    import hashlib
    import time
    from clusterctl import onboarding_service
    from clusterctl.onboarding_service import MatrixGuestService, MatrixUserService
    unit = tmp_path / UNIT
    content = b'[Service]\nUser=agent\nKillMode=control-group\nExecStart=/qualified-loader\n'
    calls, reads = [], []
    def execute(argv):
        calls.append(argv)
        if 'show' in argv:
            values = dict(Id=UNIT, ActiveState='active', SubState='running', MainPID='123',
                ControlGroup='/system.slice/'+UNIT, InvocationID='synthetic-manager',
                FragmentPath=str(unit), DropInPaths='', KillMode='control-group', Result='success')
            return '\n'.join(key+'='+value for key, value in values.items())
        return ''
    def regular(path, *, uid):
        reads.append((path, uid))
        return content
    monkeypatch.setattr(onboarding_service.onboarding_release, 'regular', regular)
    manager = MatrixGuestService(unit, run=execute)
    inspected = manager.inspect()
    assert inspected['unit_sha256'] == hashlib.sha256(content).hexdigest()
    assert reads == [(unit, 0)]
    manager.stop()
    manager.start(deadline_ns=time.monotonic_ns()+1_000_000_000)
    assert all(argv[0]=='systemctl' and '--user' not in argv for argv in calls)
    assert calls[1:] == [['systemctl','--no-block','stop',UNIT],
        ['systemctl','daemon-reload'], ['systemctl','--no-block','start',UNIT]]
    with pytest.raises(OnboardingError, match='qualified_matrix_service_required'):
        MatrixGuestService(tmp_path/'other.service', run=execute)
    with pytest.raises(OnboardingError, match='qualified_matrix_service_required'):
        MatrixUserService(unit, run=execute)


def test_matrix_stop_uses_remaining_local_budget_and_retains_timeout_uncertainty(tmp_path, monkeypatch):
    import time
    import subprocess
    from clusterctl import onboarding_service
    from clusterctl.onboarding_service import MatrixGuestService
    calls=[]
    def lost(argv, **kwargs):
        calls.append((argv,kwargs['timeout']))
        raise subprocess.TimeoutExpired(argv,kwargs['timeout'])
    monkeypatch.setattr(onboarding_service.subprocess,'run',lost)
    manager=MatrixGuestService(tmp_path/UNIT)
    with pytest.raises(OnboardingError,match='receiving_matrix_deadline_expired'):
        manager.stop(deadline_ns=time.monotonic_ns()-1)
    assert not calls
    with pytest.raises(OnboardingError,match='receiving_matrix_manager_unavailable'):
        manager.stop(deadline_ns=time.monotonic_ns()+1_000_000_000)
    assert len(calls)==1 and calls[0][0]==['systemctl','--no-block','stop',UNIT]
    assert 0<calls[0][1]<=1


def test_guest_manager_binds_real_parent_and_child_with_explicit_synthetic_cgroup(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys
    from clusterctl.owner_process import ParentProcessPresence
    from clusterctl.onboarding_service import MatrixGuestService
    child = subprocess.Popen([sys.executable, '-I', '-c',
        'import sys; print("READY", flush=True); sys.stdin.readline()'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b'READY\n'
        process = dict(uid=os.geteuid(), pid=child.pid,
            start_ticks=int((Path('/proc')/str(child.pid)/'stat').read_text().rpartition(')')[2].split()[19]),
            boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        with ParentProcessPresence(process) as family:
            observed = dict(process=process, admission_parent=family.process)
        group = '/system.slice/'+UNIT
        actual_read = Path.read_text
        outside_child = False
        def read(path, *args, **kwargs):
            if path == Path('/proc')/str(child.pid)/'cgroup':
                return '0::'+('/unrelated' if outside_child else group)+'\n'
            if path == Path('/proc')/str(os.getpid())/'cgroup':
                return '0::'+group+'\n'
            return actual_read(path, *args, **kwargs)
        # No actual systemd deployment is claimed by this manager/cgroup seam.
        monkeypatch.setattr(Path, 'read_text', read)
        inspected = dict(manager=dict(ActiveState='active', MainPID=str(os.getpid()),
            ControlGroup=group, InvocationID='synthetic-manager'))
        manager = MatrixGuestService(tmp_path/UNIT, run=lambda *_: pytest.fail('binding dispatched a service effect'))
        binding = manager.bind_admitted_process(observed, inspected)
        assert binding['process']==process and binding['admission_parent']==observed['admission_parent']
        for invalid in (
            {**observed, 'admission_parent':process},
            {**observed, 'admission_parent':{**observed['admission_parent'], 'start_ticks':1}},
        ):
            with pytest.raises(OnboardingError, match='process_scope_required'):
                manager.bind_admitted_process(invalid, inspected)
        with pytest.raises(OnboardingError, match='process_scope_required'):
            manager.bind_admitted_process(observed, dict(manager={**inspected['manager'], 'MainPID':str(child.pid)}))
        outside_child = True
        with pytest.raises(OnboardingError, match='process_scope_required'):
            manager.bind_admitted_process(observed, inspected)
        assert child.poll() is None
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()


def test_retry_after_enable_ack_loss_keeps_unit_bytes_and_no_restart(tmp_path):
    calls = []
    def execute(argv):
        calls.append(argv)
        if len(calls) == 2:
            raise OSError('lost acknowledgement after enable')
    with pytest.raises(OSError):
        install(Path('/opt/daimon-onboarding') / ('a' * 64), receive_only=True,
                directory=tmp_path, run=execute)
    original = (tmp_path / UNIT).read_bytes()
    install(Path('/opt/daimon-onboarding') / ('a' * 64), receive_only=True,
            directory=tmp_path, run=execute)
    assert (tmp_path / UNIT).read_bytes() == original
    assert calls == [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]] * 2
    assert not list(tmp_path.glob('.onboarding-service-*'))
    assert b'User=agent\nGroup=agent' in original
    assert b'Restart=on-failure' in original and b'WantedBy=multi-user.target' in original


@pytest.mark.parametrize('foreign', ['bytes', 'symlink', 'different-release'])
def test_foreign_unit_is_preserved_before_any_systemctl_effect(tmp_path, foreign):
    calls = []
    code = Path('/opt/daimon-onboarding') / ('a' * 64)
    unit = tmp_path / UNIT
    if foreign == 'symlink':
        (tmp_path / 'other').write_text('original')
        unit.symlink_to(tmp_path / 'other')
    elif foreign == 'different-release':
        install(code, receive_only=True, directory=tmp_path, run=lambda _: None)
        code = Path('/opt/daimon-onboarding') / ('b' * 64)
    else:
        unit.write_bytes(b'original')
    original = unit.read_bytes()
    with pytest.raises((OnboardingError, ValueError)):
        install(code, receive_only=True, directory=tmp_path, run=calls.append)
    assert unit.read_bytes() == original and not calls
