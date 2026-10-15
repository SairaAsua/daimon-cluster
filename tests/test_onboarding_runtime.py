"""Real native receiving daemon under actual signed TCP admission supervision."""
import tempfile
import subprocess
import sys
import os
import select
import json
import uuid
import time
from pathlib import Path

import pytest
from daimon_matrix.client import ClientConfig, LocalClient

from clusterctl.admission import AdmissionAuthority, AdmissionEndpoint, AdmissionTCPServer, serve_in_thread
from clusterctl.production_fences import create_holder_enrollment
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_admission import ReceivingHolder, enrollment, profile
from clusterctl.onboarding_custody import document
from clusterctl.onboarding_runtime import AdmittedDaemon
from clusterctl.onboarding_target import Target
from tests.test_admission import _key
from tests.test_onboarding_target import receiving


def test_actual_receiving_scope_reports_running_only_under_current_shared_lease(tmp_path):
    ceremony, plan, blank = receiving(tmp_path)
    ceremony.prepare(plan, identity_mode='first')
    with tempfile.TemporaryDirectory(prefix='dm-') as short:
        target = Target(Path(short), plan, blank.genesis)
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        holder = ReceivingHolder(target)
        registrar = _key(tmp_path/'host/registrar.pem','registrar')
        signer = _key(tmp_path/'host/authority.pem','authority')
        authority = AdmissionAuthority(tmp_path/'authority', signer=signer,
            holder_registrars={registrar.key_id:registrar.public_key})
        server = AdmissionTCPServer(('127.0.0.1',0),authority)
        thread = serve_in_thread(server)
        endpoint = AdmissionEndpoint.network('127.0.0.1',server.server_address[1])
        def client():
            return holder.client(endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key)
        first = client()
        first.enroll(enrollment(plan,holder.request(),ceremony.admission_coordinates(plan),registrar))
        root = target.package/'runtime'
        observer = LocalClient(root/'matrix.sock',ClientConfig.load(root/'client.json',bytearray((root/'client.key').read_bytes())))
        origin = target.observe()['receipt']['origin']
        custody = (root/'custody.json').read_bytes()
        runtime = (root/'runtime.json').read_bytes()
        pids = []
        try:
            for _ in range(2):
                owned = client()
                admitted = AdmittedDaemon(target,owned)
                try:
                    presence = admitted.start(receive_only=True)
                    pids.append(presence['process']['pid'])
                    assert presence['origin'] == origin
                    me = observer.scope_me()[1]
                    assert me['ok'] is True and me['result']['body']['state'] == 'running'
                    assert me['result']['origin'] == origin
                    current = target.running(admitted=True)
                    assert current['process']['pid'] == presence['process']['pid']
                    assert current['receiving_identity']['credential_ref'] == me['result']['credential_ref']
                    assert current['receiving_identity']['incarnation_authorization_ref'] == me['result']['incarnation_authorization_ref']
                    assert current['receiving_identity']['origin'] == origin
                    assert not {'body', 'heads', 'effective', 'body_capabilities'} & set(current['receiving_identity'])
                    assert admitted.supervisor.verify_current(minimum_remaining_s=1) is not None
                    request = {key:origin[key] for key in ('body_ref','embodiment_id','incarnation_id')}
                    request['evaluated_at_ms'] = time.time_ns()//1_000_000
                    with pytest.raises(OnboardingError,match='origin_rejected'):
                        admitted.snapshot({**request,'body_ref':'foreign'})
                    assert admitted.snapshot(request)['state'] == 'running'
                finally:
                    admitted.close()
                assert owned.current() is None
                assert admitted.presence.descriptor == -1
                with pytest.raises(OSError):
                    target.running()
                assert (root/'custody.json').read_bytes() == custody
                assert (root/'runtime.json').read_bytes() == runtime
            revoked = client()
            admitted = AdmittedDaemon(target,revoked)
            try:
                admitted.start(receive_only=True)
                with admitted.supervisor._client_lock:
                    revoked.release()
                unavailable = observer.scope_me()[1]
                assert unavailable['ok'] is False
                admitted.process.wait(timeout=8)
                assert admitted.process.returncode != 0
            finally:
                admitted.close()
            assert revoked.current() is None
            configuration = profile(plan,holder.request(),ceremony.admission_coordinates(plan),registrar,
                endpoint=endpoint,authority_key_id=signer.key_id,authority_public_key=signer.public_key)
            # The authority already remembers the exact holder binding. An old
            # enrollment document must not prevent a legitimate service restart.
            public = holder.prepare()
            configuration['enrollment'] = create_holder_enrollment(registrar,
                holder_key_id=public['holder_key_id'],holder_pubkey=public['holder_pubkey'],
                issued_ms=time.time_ns()//1_000_000-10_000,ttl_s=1,nonce=str(uuid.uuid4()),
                **public['coordinates'])
            reader,writer = os.pipe()
            launch = ("import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                      "from clusterctl.onboarding_target import Target;"
                      "from clusterctl.onboarding_runtime import serve;"
                      "raise SystemExit(serve(Target(Path(sys.argv[2]),json.loads(sys.argv[3]),"
                      "json.loads(sys.argv[4])),json.loads(sys.argv[5]),receive_only=True,"
                      "ready_descriptor=int(sys.argv[6])))")
            parent = subprocess.Popen([sys.executable,'-B','-I','-c',launch,str(Path(__file__).resolve().parents[1]),
                str(target.home),json.dumps(plan),json.dumps(target.genesis),json.dumps(configuration),str(writer)],
                pass_fds=(writer,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.close(writer)
            try:
                assert select.select([reader],[],[],10)[0]
                assert os.read(reader,16) == b'READY\n'
                assert observer.scope_me()[1]['result']['body']['state'] == 'running'
                child_pid = target.running()['process']['pid']
                parent.kill()
                parent.wait(timeout=5)
                deadline = time.monotonic()+3
                while time.monotonic()<deadline:
                    try:
                        with open('/proc/'+str(child_pid)+'/stat') as state:
                            exited = state.read().rpartition(')')[2].split()[0] in {'Z','X','x'}
                        if exited:
                            break
                    except FileNotFoundError:
                        break
                    time.sleep(0.05)
                else:
                    pytest.fail('native daemon outlived its admission parent')
                assert parent.returncode != 0
            finally:
                os.close(reader)
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=5)
            assert pids[0] != pids[1]
            assert document(target.root/'admission/holder.json')['coordinates'] == ceremony.admission_coordinates(plan)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


@pytest.mark.parametrize('receive_only', [False, True])
@pytest.mark.parametrize('context', ['ordinary', 'same', 'changed', 'expired', 'authority-expired'])
def test_signed_group_is_selected_before_base_visibility_composition(tmp_path, monkeypatch, receive_only, context):
    """Composition-order seam only; actual group startup has its own qualification."""
    import socket
    from types import SimpleNamespace
    from clusterctl import onboarding_runtime, onboarding_target, onboarding_code_successor, onboarding_peer
    from daimon_matrix import runtime, daemon
    selected=dict(application=str(tmp_path/'tribe/application'),
        visibility=str(tmp_path/'tribe/visibility/installation.json'))
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *_args, **_kwargs:{})
    monkeypatch.setattr(onboarding_target, 'Target', lambda *_args, **_kwargs:
        SimpleNamespace(observe=lambda:dict(phase='v8',group=selected), package=tmp_path,
            root=tmp_path/'matrix', document_bundle=lambda:{},
            _reader=lambda: pytest.fail('composition test opened custody')))
    # Signed authority loading is covered by the native group-authority tests.
    def authorities(*_args):
        if context == 'authority-expired':
            monkeypatch.setattr(onboarding_runtime.time, 'time_ns',
                lambda: expected_context['not_after_ms'] * 1_000_000)
        return {}
    monkeypatch.setattr(onboarding_peer, 'approved_group_authorities', authorities)
    observed=[]
    def load(*_args, **kwargs):
        observed.append(kwargs)
        assert 'egress_factory' not in kwargs
        assert kwargs['egress'].release_enabled is False
        raise RuntimeError('composition-observed')
    monkeypatch.setattr(runtime, 'load_runtime', load)
    root=tmp_path/'runtime'
    root.mkdir(mode=0o700)
    acquire=daemon.acquire_lock
    monkeypatch.setattr(daemon, 'acquire_lock', lambda *_args:acquire(root))
    from clusterctl import onboarding_receiving_update
    from clusterctl.onboarding import digest
    frozen = {'synthetic': 'initial owner context'}
    def current_owner(*_args, **_kwargs):
        # A second descriptor proves the guard runs under the child's real
        # native writer, before runtime load or application composition.
        with pytest.raises(BlockingIOError):
            acquire(root)
        return {**frozen, 'synthetic': 'changed' if context == 'changed' else frozen['synthetic'],
            'observer_startup': {'separate': 'observer process'}}
    monkeypatch.setattr(onboarding_receiving_update, '_freeze_initial_guest_owner', current_owner)
    expected_context = None if context == 'ordinary' else dict(schema='cluster-initial-start-context/v1',
        owner_sha256=digest(frozen), profile_sha256='a' * 64,
        not_after_ms=time.time_ns() // 1_000_000 + (-1 if context == 'expired' else 60000))
    left,right=socket.socketpair()
    descriptor=left.detach()
    try:
        expected=OnboardingError if receive_only or context in {'changed', 'expired', 'authority-expired'} else RuntimeError
        match=('onboarding_visibility_selection_required' if receive_only else
            'receiving_initial_context_changed' if context == 'changed' else
            'authorization_expired' if context in {'expired', 'authority-expired'} else 'composition-observed')
        with pytest.raises(expected,match=match):
            onboarding_runtime.child_main(tmp_path,{'release_digest':'a'*64},{},descriptor,
                None,os.getppid(),receive_only,None,code_uid=os.geteuid(), expected_initial_context=expected_context)
        assert len(observed)==(0 if receive_only or context in {'changed', 'expired', 'authority-expired'} else 1)
    finally:
        right.close()
        # Explicit receive-only refusal happens before the child takes the FD.
        if receive_only:
            os.close(descriptor)


def test_initial_parent_refuses_a_changed_profile_before_admission(monkeypatch):
    from clusterctl import onboarding_runtime
    monkeypatch.setattr(onboarding_runtime, 'ReceivingHolder',
        lambda _: pytest.fail('changed profile reached admission'))
    with pytest.raises(OnboardingError, match='initial_context_changed'):
        onboarding_runtime.serve(None, {'synthetic': 'changed profile'}, expected_initial_context=dict(
            schema='cluster-initial-start-context/v1', owner_sha256='a' * 64, profile_sha256='b' * 64,
            not_after_ms=time.time_ns() // 1_000_000 + 60000))


@pytest.mark.parametrize('change', [
    'disappeared', 'appeared', 'appeared_receive_only',
    'tribe_ref', 'directory', 'visibility', 'socket',
])
def test_changed_group_selection_never_composes_an_application(tmp_path, monkeypatch, change):
    """Race seam: neither legacy fallback nor a new late group may start."""
    import socket
    from types import SimpleNamespace
    from clusterctl import onboarding_runtime, onboarding_target, onboarding_code_successor, onboarding_peer
    from daimon_matrix import runtime, chat_host
    state_root=tmp_path/'runtime'
    state_root.mkdir(mode=0o700)
    early=dict(tribe_ref='synthetic-tribe', application=str(tmp_path/'tribe/application'),
        visibility=str(tmp_path/'tribe/visibility/installation.json'),
        socket=str(state_root/'tribe.sock'))
    late=dict(tribe_ref=early['tribe_ref'], directory=early['application'],
        visibility=early['visibility'], socket='tribe.sock')
    if change == 'disappeared':
        late=None
    elif change.startswith('appeared'):
        early=None
    else:
        late[change]='changed-selection'
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *_args, **_kwargs:{})
    monkeypatch.setattr(onboarding_target, 'Target', lambda *_args, **_kwargs:
        SimpleNamespace(observe=lambda:dict(phase='v8',group=early), package=tmp_path,
            root=tmp_path/'matrix', document_bundle=lambda:{},
            _reader=lambda:pytest.fail('race test opened custody')))
    # Keep this seam focused on the early/late selection race.
    monkeypatch.setattr(onboarding_peer, 'approved_group_authorities', lambda *_args:{})
    monkeypatch.setattr(runtime, 'load_runtime', lambda *_args, **_kwargs:
        SimpleNamespace(state_root=state_root))
    monkeypatch.setattr(onboarding_peer, 'group_application', lambda *_args:late)
    monkeypatch.setattr(chat_host, 'application_view', lambda *_args:
        pytest.fail('changed selection composed an application'))
    left,right=socket.socketpair()
    descriptor=left.detach()
    try:
        with pytest.raises(OnboardingError, match='onboarding_group_selection_changed'):
            onboarding_runtime.child_main(tmp_path,{'release_digest':'a'*64},{},descriptor,
                None,os.getppid(),change=='appeared_receive_only',
                None if change=='appeared_receive_only' else tmp_path/'visibility.json',
                code_uid=os.geteuid())
        assert not (state_root/'peer.sock').exists()
        assert not (state_root/'tribe.sock').exists()
    finally:
        right.close()
