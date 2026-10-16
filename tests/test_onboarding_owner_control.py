"""Control recovery and deadlines through the existing native request contract."""
import copy
import os
import socket
import time
import uuid
from types import SimpleNamespace

import pytest

from clusterctl import onboarding_owner_control as control
from clusterctl.onboarding import OnboardingError
from daimon_matrix.local_api import CAPABILITY_SCHEMA, LocalCapability, create_request, request_hash


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    channel = tmp_path / 'tribe.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(channel))
    command = dict(channel_id='tribe', process_instance_id=str(uuid.uuid4()),
        expected_head='a'*64, operation_id=str(uuid.uuid4()), release_digest='b'*64,
        phase='select', readers=[{'selected': 'frozen-reader'}], expected_roster_sha256='c'*64)
    process = dict(uid=os.geteuid(), pid=os.getpid(), start_ticks=1, boot_id='test-boot')
    application = dict(application_sha256='c'*64, publication_sha256='d'*64,
        visibility=dict(installation_sha256='e'*64))
    runtime = dict(qualified_startup=dict(code_digest='f'*64, matrix_wheel_sha256='1'*64),
        runtime_bundle_sha256='2'*64)
    gate = dict(schema='dm.runtime.reader-state/v1', channel_id='tribe', controlled=True,
        process_instance_id=command['process_instance_id'], process_id=process['pid'],
        context_sha256='3'*64, head='a'*64, phase='revoke', readers=[],
        operation_id=command['operation_id'], release_digest=command['release_digest'], request_sha256='4'*64)
    state = dict(process=process, server={'embodiment_id': 'test-body'}, gate=gate,
        runtime_status=dict(loaded_runtime=runtime, loaded_application=application))
    capability = LocalCapability(dict(schema=CAPABILITY_SCHEMA, capability_id='test-cap',
        client_id='client:test', key_id='test-key', methods=['runtime.reader-selection'],
        status='active', not_before_ms=0, not_after_ms=2**53-1), b'x'*32)
    calls = []
    class Client:
        lost = False
        corrupt = None
        def prepare(self, method, params):
            calls.append('prepare')
            return create_request(capability, request_id=str(uuid.uuid4()),
                issued_at_ms=time.time_ns()//1_000_000, method=method, params=params, nonce=os.urandom(16))
        def send(self, request):
            calls.append(('send', copy.deepcopy(request)))
            result = {**state['gate'], **{k:command[k] for k in (
                'channel_id','process_instance_id','phase','operation_id','release_digest','readers')},
                'head':'5'*64, 'request_sha256':request_hash(request)}
            state['gate'] = copy.deepcopy(result)
            if self.lost:
                self.lost = False
                raise TimeoutError('lost reply after native CAS')
            if self.corrupt:
                result[self.corrupt] = 'invalid'
            return dict(ok=True, result=result)
    client = Client()
    class Owner:
        root = tmp_path
        socket = channel
        deadline_ns = time.monotonic_ns()+60_000_000_000
        _observer = SimpleNamespace(verify=lambda: calls.append('verify'))
        def status(self):
            calls.append('status')
            return copy.deepcopy(state)
        def _control_directory(self, path):
            path.parent.mkdir(mode=0o700, exist_ok=True)
            return path.parent
        def _client(self, role):
            assert role == 'receiving-controller'
            return client
        def _durable_control(self, path):
            calls.append('durable')
            assert path.exists()
    owner = Owner()
    expected = dict(process=copy.deepcopy(process), server=copy.deepcopy(state['server']),
        selection=control._selection(state))
    path = tmp_path/'receiving-control'/'select.json'
    return owner, client, expected, command, path, state, calls, listener


def test_one_status_and_authenticated_ack_with_exact_retry(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        first = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        raw = path.read_bytes()
        second = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert second == first and path.read_bytes() == raw
        assert calls.count('status') == 2 and calls.count('prepare') == 1
        sends = [v[1] for v in calls if isinstance(v,tuple)]
        assert sends[0] == sends[1]
        assert first['gate']['readers'] == command['readers']
    finally:
        listener.close()


def test_lost_ack_reuses_original_native_request_without_reauthoring(tmp_path):
    owner, client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        client.lost = True
        with pytest.raises(TimeoutError):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        raw = path.read_bytes()
        result = control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert result['gate']['phase'] == 'select' and path.read_bytes() == raw
        assert calls.count('prepare') == 1
        sends = [v[1] for v in calls if isinstance(v,tuple)]
        assert sends[0] == sends[1]
    finally:
        listener.close()


@pytest.mark.parametrize('field',['readers','process_instance_id','request_sha256','context_sha256','head'])
def test_invalid_control_ack_never_becomes_a_success(tmp_path,field):
    owner, client, expected, command, path, _state, _calls, listener = fixture(tmp_path)
    try:
        client.corrupt = field
        with pytest.raises(OnboardingError,match='completion_uncertain'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert path.exists()
    finally:
        listener.close()


@pytest.mark.parametrize('field',['process','server','selection'])
def test_changed_receiving_identity_or_selection_refuses_before_request(tmp_path,field):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        expected[field] = {}
        with pytest.raises(OnboardingError,match='process_changed'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not path.exists() and 'prepare' not in calls
    finally:
        listener.close()


def test_expired_budget_refuses_before_owner_read(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    try:
        owner.deadline_ns = time.monotonic_ns()-1
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not calls and not path.exists()
    finally:
        listener.close()


def test_guest_parent_mismatch_refuses_before_request(tmp_path,monkeypatch):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    class Parent:
        process = {'pid': -1}
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr(control,'ParentProcessPresence',lambda process:Parent())
    expected['admission_parent'] = {'pid':1}
    try:
        with pytest.raises(OnboardingError,match='parent_changed'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert not path.exists() and 'prepare' not in calls
    finally:
        listener.close()


def test_deadline_after_retention_keeps_request_without_dispatch(tmp_path):
    owner, _client, expected, command, path, _state, calls, listener = fixture(tmp_path)
    durable = owner._durable_control
    def slow_durable(selected):
        durable(selected)
        time.sleep(.12)
    owner._durable_control = slow_durable
    owner.deadline_ns = time.monotonic_ns()+50_000_000
    try:
        with pytest.raises(OnboardingError,match='deadline_expired'):
            control.execute(owner,command,path,expected=expected,deadline_ns=owner.deadline_ns)
        assert path.exists() and not any(isinstance(v,tuple) for v in calls)
    finally:
        listener.close()


def test_mismatched_time_namespace_refuses_before_opening_owner(monkeypatch,capsys):
    monkeypatch.setattr(control.sys,'argv',['owner-control','--root','/unopened',
        '--socket','/unopened/socket','--path','/unopened/request',
        '--deadline-ns',str(time.monotonic_ns()+5_000_000_000),'--time-namespace','time:[other]'])
    monkeypatch.setattr(control,'OwnerGroupClient',lambda *a,**k:pytest.fail('opened owner'))
    assert control.main()==1
    assert 'receiving_owner_deadline_binding_required' in capsys.readouterr().err


def test_observe_only_reads_known_receiver_once_without_authoring(tmp_path):
    owner, _client, expected, _command, path, _state, calls, listener = fixture(tmp_path)
    try:
        result = control.observe(owner,expected=expected,deadline_ns=owner.deadline_ns)
        assert result['process'] == expected['process']
        assert calls.count('status') == 1 and 'prepare' not in calls
        assert not path.exists()
    finally:
        listener.close()
