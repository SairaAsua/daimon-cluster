"""A real native daemon qualifies publication, retries and foreign-body refusal."""

import json
import os
import select
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from daimon_matrix.neutral_binding import OwnerClientPlan, render_owner_client
from daimon_matrix import operator_rebirth
from clusterctl.onboarding import Observation, OnboardingError
from clusterctl.onboarding_owner_client import OwnerClient, PROGRAM
from tests.test_onboarding_target import receiving

pytest_plugins = ["tests.test_onboarding_peer"]


def test_chat_successor_uses_closed_startup_and_qualifies_before_adapter(tmp_path, monkeypatch):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    venv = tmp_path / 'sdk/venv'
    code = tmp_path / 'code'
    binding = tmp_path / 'existing/binding.json'
    command = owner.chat_command(venv, venv.parent / 'runtime-imports', code,
        code_digest='a' * 64, binding=binding)
    assert command[:5] == [str(venv / 'bin/python'), '-B', '-I', '-S', '-c']
    assert command[6:10] == [str(venv), str(venv.parent / 'runtime-imports'),
        str(code), 'clusterctl.onboarding_owner_client']
    calls = []
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters',
        lambda *a, **k: {'matrix_commit': 'b' * 40, 'matrix_wheel_sha256': 'c' * 64})
    def qualify(*args, **kwargs):
        calls.append(('qualified', kwargs['code_digest']))
    def serve(args, **options):
        assert calls == [('qualified', 'a' * 64)]
        calls.append(('serve', args))
        return 0
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', qualify)
    monkeypatch.setattr(owner, '_serve_chat', serve)
    assert owner.main(command[10:] + ['mcp']) == 0
    assert calls[-1] == ('serve', ['mcp'])
    def refuse(*args, **kwargs):
        raise owner.OnboardingError('qualified_runtime_context_required')
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', refuse)
    with pytest.raises(owner.OnboardingError, match='qualified_runtime_context_required'):
        owner.main(command[10:] + ['mcp'])
    assert len(calls) == 2, 'failed qualification must never start the adapter'


def technical_adapter(monkeypatch, parameters, calls, *, prepare=lambda: None, send=lambda: None):
    """Keep native argument validation; replace only private binding and I/O."""
    import io
    from daimon_matrix import agent_chat
    from daimon_matrix.client import LocalClient
    selected = dict(schema='dm.agent-chat/v1', incoming_channels=['tribe'], outgoing_channels=['tribe'])
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(parameters).encode())))
    monkeypatch.setattr(agent_chat, 'load_binding', lambda path: selected)
    private_config = SimpleNamespace()
    def emit(client, request):
        assert client.config is private_config
        calls.append(('sent', request, client.deadline_ns))
        send()
        return dict(schema='dm.local.response/v1', ok=True, error=None, result={'retained':True},
            auth={'private':'must-not-cross-owner-boundary'})
    monkeypatch.setattr(LocalClient, 'send', emit)
    def request(method, value, operation_id):
        prepared = dict(method=method, params=value, operation_id=operation_id)
        calls.append(('prepared', prepared))
        prepare()
        return prepared
    adapter = SimpleNamespace(_prepare_operation=request)
    def bridge(value, *, timeout):
        adapter.client = LocalClient(Path('/synthetic/tribe.sock'), private_config, timeout)
        return adapter
    monkeypatch.setattr(agent_chat, 'bridge', bridge)
    return adapter


@pytest.mark.parametrize('expired_at', [None, 'startup', 'durability'])
@pytest.mark.parametrize('method', ['messaging_send', 'messaging_reply'])
def test_technical_authoring_expiry_is_checked_at_emission(tmp_path, monkeypatch, capsys, expired_at, method):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    calls = []
    clock = [1_000_000_000]
    monkeypatch.setattr(owner, 'time', SimpleNamespace(time_ns=lambda: clock[0], monotonic_ns=lambda: 0))
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {'matrix_commit':'b'*40})
    def startup(*args, **kwargs):
        calls.append('qualified')
        if expired_at == 'startup':
            clock[0] = 3_000_000_000
        return {}
    def prepare():
        if expired_at == 'durability':
            clock[0] = 3_000_000_000
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', startup)
    parameters = dict(channel_id='tribe', send_id='f396883c-66eb-4f96-a49a-d2c0469b0b80', text='Technical check')
    if method == 'messaging_reply':
        parameters.update(received_channel_id='tribe', message_id='ae98c945-5440-44b1-bc91-74b2b5e18e8a')
    else:
        parameters['thread_id'] = 'ae98c945-5440-44b1-bc91-74b2b5e18e8a'
    technical_adapter(monkeypatch, parameters, calls, prepare=prepare)
    arguments = ['--code-digest', 'a'*64, '--binding', str(tmp_path/'binding.json'),
        '--authoring-expires-at-ms', '2000', 'call', method]
    if expired_at:
        with pytest.raises(OnboardingError, match='communication_authorization_expired'):
            owner.main(arguments)
        assert not any(isinstance(call, tuple) and call[0] == 'sent' for call in calls)
        assert len(calls) == (1 if expired_at == 'startup' else 2)
    else:
        assert owner.main(arguments) == 0
        prepared, sent = calls[1:]
        assert sent[1] is prepared[1]
        assert sent[1]['operation_id'] == parameters['send_id']
        assert sent[2] == 1_000_000_000
        public = json.loads(capsys.readouterr().out)
        assert public['ok'] and 'auth' not in public


@pytest.mark.parametrize('expired_at', [None, 'durability', 'response', 'tiny-budget'])
def test_qualified_technical_tool_preserves_original_owner_deadline(tmp_path, monkeypatch, expired_at):
    from clusterctl import onboarding_owner_client as owner
    calls = []
    clock = [1_000_000_000]
    monkeypatch.setattr(owner, 'time', SimpleNamespace(monotonic_ns=lambda: clock[0]))
    def prepare():
        clock[0] = (3_000_000_000 if expired_at == 'durability' else
            1_005_000_000 if expired_at == 'tiny-budget' else 2_000_000_000)
    def send():
        if expired_at == 'response':
            clock[0] = 3_000_000_000
    parameters = dict(channel_id='tribe', send_id='f396883c-66eb-4f96-a49a-d2c0469b0b80')
    adapter = technical_adapter(monkeypatch, parameters, calls, prepare=prepare, send=send)
    options = dict(startup={}, binding=tmp_path/'binding.json', code=tmp_path, code_uid=0)
    if expired_at in {'durability', 'response'}:
        with pytest.raises(OnboardingError, match='owner_deadline_expired'):
            owner._serve_chat(['call','messaging_delivery','--timeout','45'], deadline_ns=3_000_000_000, **options)
        assert len(calls) == (1 if expired_at == 'durability' else 2)
    else:
        deadline = 1_010_000_000 if expired_at == 'tiny-budget' else 3_000_000_000
        assert owner._serve_chat(['call','messaging_delivery','--timeout','45'], deadline_ns=deadline, **options) == 0
        assert calls[-1][2] == adapter.client.deadline_ns == deadline
    count = len(calls)
    with pytest.raises(OnboardingError, match='owner_deadline_expired'):
        owner._serve_chat(['call','messaging_delivery'], deadline_ns=1_000_000_000, **options)
    assert len(calls) == count


def test_tooling_owner_entry_requires_explicit_native_home_after_qualification(tmp_path, monkeypatch, capsys):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {'matrix_commit': 'b'*40})
    startup = {'selected': True}
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', lambda *a, **k: startup)
    calls = []
    def reconcile(attachment, operation_id, **kwargs):
        assert kwargs['startup'] is startup
        assert kwargs['codex_home'] == tmp_path/'private-codex'
        calls.append((attachment, operation_id))
        return {'status': 'configured', 'catalog_acceptance': 'unobserved'}
    monkeypatch.setattr(owner, 'reconcile_chat_tooling', reconcile)
    arguments = ['--binding', str(tmp_path/'attachment/binding.json'),
        '--code-digest', 'a'*64, '--reconcile-tooling', 'operation:fixture']
    with pytest.raises(owner.OnboardingError, match='qualified_native_peer_tool_required'):
        owner.main(arguments)
    assert calls == []
    assert owner.main([*arguments, '--codex-home', str(tmp_path/'private-codex')]) == 0
    assert json.loads(capsys.readouterr().out)['catalog_acceptance'] == 'unobserved'
    assert calls == [(tmp_path/'attachment', 'operation:fixture')]


@pytest.mark.parametrize('invalid', [None, 'no-deadline', 'reconcile'])
def test_group_attachment_cli_qualifies_before_preparation(tmp_path, monkeypatch, capsys, invalid):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    calls = []
    startup = {'selected': True}
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {'matrix_commit': 'b'*40})
    def qualify(*args, **kwargs):
        calls.append('qualified')
        return startup
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', qualify)
    def prepare(attachment, request, **kwargs):
        assert calls == ['qualified'] and kwargs['startup'] is startup
        assert attachment == tmp_path/'attachment' and request == {'fixture': True}
        assert kwargs['codex_home'] == tmp_path/'codex' and kwargs['deadline_ns'] > 0
        calls.append('prepared')
        return {'receiving_readiness': 'unobserved'}
    monkeypatch.setattr(owner, 'prepare_group_chat_attachment', prepare)
    arguments = ['--code-digest', 'a'*64, '--binding', str(tmp_path/'attachment/binding.json'),
        '--prepare-group-attachment', '{"fixture":true}', '--codex-home', str(tmp_path/'codex')]
    if invalid != 'no-deadline':
        arguments += ['--observation-timeout-seconds', '2']
    if invalid == 'reconcile':
        arguments += ['--reconcile-tooling', 'operation']
    if invalid:
        with pytest.raises(OnboardingError, match='qualified_native_peer_tool_required'):
            owner.main(arguments)
        assert calls == []
    else:
        assert owner.main(arguments) == 0
        assert json.loads(capsys.readouterr().out) == {'receiving_readiness': 'unobserved'}
        assert calls == ['qualified', 'prepared']


@pytest.mark.parametrize('fault', [None, 'unobserved', 'principal', 'command', 'pending'])
def test_group_acceptance_preserves_approved_tooling_without_legacy_peer(tmp_path, monkeypatch, fault):
    import hashlib
    import uuid
    from daimon_matrix.canonical import canonical_bytes
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor, onboarding_group_coordinator
    from clusterctl.onboarding import digest
    from tests.test_onboarding import plan
    value = plan()
    approved_source, guest_code = tmp_path/'approved', Path('/guest/approved')
    attachment = '/home/agent/group-chat'
    sdk = dict(matrix_commit='b'*40, wheels=[dict(distribution='daimon-matrix', sha256='c'*64)])
    origin = dict(body_ref='codex:test:eko', embodiment_id='embodiment:test',
        incarnation_id='incarnation:test', principal_id='principal:test')
    operation = str(uuid.uuid4())
    venv = Path('/home/agent/.local/share/daimon-matrix/sdk')/digest(sdk)/'venv'
    command = owner.chat_command(venv, venv.parent/'runtime-imports', guest_code,
        code_digest='a'*64, binding=Path(attachment)/'binding.json', code_uid=0)
    selected = dict(channel_id='tribe', socket='/guest/runtime/tribe.sock',
        application='/guest/group/application', tribe_ref='tribe:test')
    approved = dict(candidate=dict(code=str(approved_source), code_uid=0), socket=selected['socket'],
        recipe=dict(prepared=dict(code_digest='a'*64, matrix_wheel_sha256='c'*64),
            tooling=dict(profile='codex', attachment=attachment, codex_home='/home/agent/.codex',
                connections=[], native_endpoint='/home/agent/native.sock', native_threads=[], tribe_channel='tribe')))
    accepted = dict(schema='cluster-native-chat-tooling/v1', status='configured', server=dict(origin),
        operation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'native-tooling:'+operation+':eko')),
        code_digest='a'*64, sdk_digest=digest(sdk), matrix_commit=sdk['matrix_commit'],
        matrix_wheel_sha256='c'*64, command_sha256=hashlib.sha256(canonical_bytes(command)).hexdigest())
    effects = dict(group_publication=dict(result=dict(snapshots=dict(eko=dict(group=dict(selected=selected))))),
        initial_managed=dict(eko=dict(intent=dict(owner=dict(origin=origin)))), native_tooling=dict(eko=accepted))
    row = dict(state='completed', operation_id=operation, expected_precondition=dict(tribe_ref='tribe:test'),
        runtime_observation=effects)
    if fault == 'unobserved':
        effects['native_tooling'].clear()
    elif fault == 'principal':
        accepted['server']['principal_id'] = 'principal:other'
    elif fault == 'command':
        accepted['command_sha256'] = '0'*64
    elif fault == 'pending':
        row['state'] = 'prepared'
    monkeypatch.setattr(onboarding_group_coordinator, 'GroupCoordinator',
        lambda host: SimpleNamespace(_binding=lambda p: (None, row, dict(receivers=dict(eko=approved)))))
    observed = []
    def verify(source, **kwargs):
        assert source == approved_source and kwargs['uid'] == 0
        observed.append('approved-sdk')
        return sdk
    monkeypatch.setattr(owner.onboarding_sdk, 'verify', verify)
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {})
    raw = (Path(owner.__file__).parent/owner.TOOLING_INSTALLER_MODULE).read_bytes()
    def read(path, **kwargs):
        assert path == approved_source/'clusterctl'/owner.TOOLING_INSTALLER_MODULE
        return raw
    monkeypatch.setattr(owner.onboarding_release, 'regular', read)
    def paths(*args, **kwargs):
        assert kwargs['candidate'] == (approved_source, 'a'*64)
        return guest_code, [], {}
    def target(p, action, **kwargs):
        assert action == 'sdk-observe' and kwargs['candidate'] == (approved_source, 'a'*64)
        observed.append('approved-runtime')
        return dict(ready=True)
    expected = dict(being_ref='being:eko', **origin)
    def dispatch(p, arguments):
        payload = json.loads(arguments[-1])
        assert payload['chat']['qualified_tooling']['command'] == command
        assert payload['chat']['socket'] == selected['socket']
        assert payload['chat']['incoming_channels'] == payload['chat']['outgoing_channels'] == ['tribe']
        assert payload['chat']['qualified_tooling']['accepted']['server'] == origin
        observed.append('qualified-acceptance')
        return json.dumps(dict(installed=True, plan_digest=digest(value), being_ref=expected['being_ref'],
            origin={key:origin[key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')}))
    host = SimpleNamespace(authorize=lambda *a: True, config=SimpleNamespace(group_admission={}, peer=None,
        runtime_code=tmp_path/'wrong-default', code=tmp_path/'wrong-base'),
        _receiving_base=lambda p: tmp_path/'base', _runtime_paths=paths,
        _target_call=target, instance=lambda p: 'dm-eko', _dispatch=dispatch)
    client = owner.OwnerClient(host)
    if fault:
        error = ('onboarding_group_admission_pending' if fault == 'pending'
            else 'receiving_native_tooling_changed' if fault == 'command' else 'receiving_native_tooling_unobserved')
        with pytest.raises(OnboardingError, match=error):
            client.execute(value, expected)
        assert 'approved-runtime' not in observed and 'qualified-acceptance' not in observed
    else:
        client.execute(value, expected)
        assert observed == ['approved-sdk', 'approved-runtime', 'qualified-acceptance']


@pytest.mark.parametrize("binding_filename", ["binding.json", "owner-binding.json"])
def test_host_tooling_reconciliation_uses_owner_cli_without_private_sdk_reads(tmp_path, monkeypatch, binding_filename):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    from clusterctl.onboarding import digest, OnboardingError
    from tests.test_onboarding import plan
    sdk = {'matrix_commit': 'b'*40, 'wheels': []}
    operation_id = 'operation:fixture'
    result = dict(schema='cluster-native-chat-tooling/v1', operation_id=operation_id,
        code_digest='a'*64, sdk_digest=digest(sdk), matrix_commit=sdk['matrix_commit'])
    calls = []
    def dispatch(value, command, **options):
        calls.append(command)
        return json.dumps(result)
    host = SimpleNamespace(authorize=lambda *a: True, _receiving_base=lambda p: Path('/public/base'),
        _runtime_paths=lambda *a, **k: (Path('/public/selected'), [], {}),
        _mounted=lambda *a, **k: True, instance=lambda p: 'dm-fixture', _dispatch=dispatch)
    monkeypatch.setattr(owner.onboarding_sdk, 'verify', lambda *a, **k: sdk)
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {})
    native_read = Path.read_bytes
    def read(path):
        assert not str(path).startswith('/home/agent/'), 'host opened owner-private bytes'
        return native_read(path)
    monkeypatch.setattr(Path, 'read_bytes', read)
    client = OwnerClient(host)
    arguments = dict(candidate=(tmp_path/'candidate', 'a'*64),
        attachment=Path('/home/agent/existing-attachment'), codex_home=Path('/home/agent/.codex'),
        binding_filename=binding_filename)
    assert client.reconcile(plan(), operation_id, **arguments) == result
    command = calls[0]
    assert command[:8] == ['exec', 'dm-fixture', '--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent']
    assert 'clusterctl.onboarding_owner_client' in command
    assert command[command.index('--codex-home')+1] == '/home/agent/.codex'
    assert command[command.index('--binding')+1] == '/home/agent/existing-attachment/'+binding_filename
    result['code_digest'] = 'c'*64
    with pytest.raises(OnboardingError, match='verification_failed'):
        client.reconcile(plan(), operation_id, **arguments)


@pytest.mark.parametrize('method', ['messaging_delivery', 'messaging_send'])
def test_guest_technical_messaging_preserves_qualified_uid_and_public_stdin(tmp_path, monkeypatch, method):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    from tests.test_onboarding import plan
    sdk = {'matrix_commit':'b'*40, 'wheels':[]}
    result = dict(schema='dm.local.response/v1', ok=True, error=None, result={'retained':True})
    parameters = dict(channel_id='tribe', send_id='f396883c-66eb-4f96-a49a-d2c0469b0b80')
    calls = []
    def dispatch(value, command, **options):
        assert json.loads(options['input_data']) == parameters
        assert command[:8] == ['exec','dm-fixture','--user','1000','--group','1000','--env','HOME=/home/agent']
        assert 'clusterctl.onboarding_owner_client' in command
        assert command[-4:-2] == ['call', method]
        assert options['timeout_seconds'] > 0 and options['deadline_ns'] > 0
        if method == 'messaging_send':
            assert command[command.index('--authoring-expires-at-ms')+1] == '2000'
        else:
            assert '--authoring-expires-at-ms' not in command
        calls.append(command)
        return json.dumps(result)
    def paths(value, base, *, candidate):
        assert candidate == (tmp_path/'candidate','a'*64)
        return Path('/public/selected'), [], {}
    host = SimpleNamespace(authorize=lambda *a: True, _receiving_base=lambda p: Path('/public/base'),
        _runtime_paths=paths, _mounted=lambda *a, **k: True, instance=lambda p:'dm-fixture', _dispatch=dispatch)
    monkeypatch.setattr(owner.onboarding_sdk, 'verify', lambda *a, **k:sdk)
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k:{})
    client = OwnerClient(host)
    options = dict(candidate=(tmp_path/'candidate','a'*64), binding=Path('/home/agent/group/binding.json'),
        **({'authoring_expires_at_ms':2000} if method == 'messaging_send' else {}))
    assert client.messaging(plan(), method, parameters, **options) == result
    result['schema'] = 'not-native'
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        client.messaging(plan(), method, parameters, **options)
    assert len(calls) == 2


@pytest.fixture
def native(tmp_path):
    # Native AF_UNIX endpoints must fit the kernel path budget.
    with tempfile.TemporaryDirectory(prefix="dm-") as short:
        ceremony, plan, target = receiving(Path(short))
        target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(
            ceremony.authorize_credential(plan, target.credential_request())
        )
        (target.home / "Projects").mkdir(mode=0o700)
        (target.home / "Projects/being").mkdir(mode=0o700)
        runtime = target.package / "runtime"
        keys = (runtime / "custody.json").read_bytes()
        bundle = (runtime / "runtime.json").read_bytes()
        client_key = (runtime / "client.key").read_bytes()
        origin = target.document_bundle()["local_origin"]
        relative = target.package.relative_to(target.home).as_posix()
        script = render_owner_client(
            OwnerClientPlan(
                venv_python=sys.executable,
                state_relative=relative,
                client_label="eko.codex@daimon-cluster",
                prog="eko-codex",
            )
        )
        payload = dict(
            home=str(target.home),
            state_relative=relative,
            prog="eko-codex",
            script=script.decode(),
            instructions="# Existing signed test body\n",
            plan_digest="a" * 64,
            origin=origin,
            being_ref=operator_rebirth.authority_from_runtime_bundle(
                target.document_bundle()
            ).state.being_ref,
            install=True,
        )
        invocation = (
            "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
            "from clusterctl.onboarding_target import Target;"
            "raise SystemExit(Target(Path(sys.argv[2]),json.loads(sys.argv[3]),"
            "json.loads(sys.argv[4])).serve(receive_only=True,ready_descriptor=int(sys.argv[5])))"
        )
        repository = str(Path(__file__).resolve().parents[1])
        reader, writer = os.pipe()
        process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-I",
                "-c",
                invocation,
                repository,
                str(target.home),
                json.dumps(plan),
                json.dumps(target.genesis),
                str(writer),
            ],
            pass_fds=(writer,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(writer)
        try:
            assert select.select([reader], [], [], 10)[0]
            assert os.read(reader, 16) == b"READY\n"
            yield target, payload
            assert (runtime / "custody.json").read_bytes() == keys
            assert (runtime / "runtime.json").read_bytes() == bundle
            assert (runtime / "client.key").read_bytes() == client_key
            assert not (target.package / "body.password").exists()
        finally:
            os.close(reader)
            process.terminate()
            process.wait(timeout=10)


def invoke(payload):
    return subprocess.run(
        [sys.executable, "-B", "-I", "-c", PROGRAM, json.dumps(payload)],
        capture_output=True,
        timeout=50,
        env={**os.environ, "HOME": payload["home"]},
    )


@pytest.mark.parametrize("native_mcp", [False, True])
def test_existing_owner_client_gains_native_peer_attachment_without_new_identity(
    journey, tmp_path, native_mcp, monkeypatch
):
    from hashlib import sha256
    from clusterctl import onboarding_peer
    from clusterctl.admission import (
        AdmissionAuthority,
        AdmissionEndpoint,
        AdmissionTCPServer,
        serve_in_thread,
    )
    from clusterctl.onboarding_admission import ReceivingHolder, enrollment
    from clusterctl.onboarding_runtime import AdmittedDaemon
    from tests.test_admission import _key

    _, sources, public, packet, _ = journey
    ceremony, target = sources[1]
    if native_mcp:
        # Emulate only the external Codex config-writer contract. Native Matrix
        # authentication and the receiving-owner program remain real below.
        codex_home = target.home / '.codex'
        codex_home.mkdir(mode=0o700)
        config = codex_home / 'config.toml'
        config.write_text('model = "preserved"\n')
        config.chmod(0o600)
        binary = target.home / 'bin'
        binary.mkdir(mode=0o700)
        codex = binary / 'codex'
        codex.write_text('#!'+sys.executable+'\n'+'''import sys,os,json
from pathlib import Path
assert sys.argv[1:5]==['mcp','add','matrix','--']
p=Path(os.environ['CODEX_HOME'])/'config.toml'
command=sys.argv[5:]
p.write_text(p.read_text()+'\\n[mcp_servers.matrix]\\ncommand = '+json.dumps(command[0])+'\\nargs = '+json.dumps(command[1:])+'\\n')
''')
        codex.chmod(0o700)
        monkeypatch.setenv('CODEX_HOME', str(codex_home))
        monkeypatch.setenv('PATH', str(binary)+os.pathsep+os.environ['PATH'])
    sender = public[0]["document"]["authority"]["manifest"]["being_ref"]
    onboarding_peer.accept(target, packet, expected_being=sender)
    holder = ReceivingHolder(target)
    registrar = _key(tmp_path / "host/registrar.pem", "registrar")
    signer = _key(tmp_path / "host/authority.pem", "authority")
    authority = AdmissionAuthority(
        tmp_path / "authority",
        signer=signer,
        holder_registrars={registrar.key_id: registrar.public_key},
    )
    server = AdmissionTCPServer(("127.0.0.1", 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network("127.0.0.1", server.server_address[1])
    client = holder.client(
        endpoint, authority_key_id=signer.key_id, authority_public_key=signer.public_key
    )
    client.enroll(
        enrollment(
            target.plan,
            holder.request(),
            ceremony.admission_coordinates(target.plan),
            registrar,
        )
    )
    root = target.package / "runtime"
    application = onboarding_peer.root(target) / "application"
    attachment = onboarding_peer.root(target) / "owner-client"
    original = {
        name: (root / name).read_bytes()
        for name in ("runtime.json", "custody.json", "client.json", "client.key")
    }
    (target.home / "Projects").mkdir(mode=0o700)
    (target.home / "Projects/being").mkdir(mode=0o700)
    relative = target.package.relative_to(target.home).as_posix()
    origin = target.document_bundle()["local_origin"]
    payload = dict(
        home=str(target.home),
        state_relative=relative,
        prog="eko-codex",
        script=render_owner_client(
            OwnerClientPlan(
                venv_python=sys.executable,
                state_relative=relative,
                client_label="eko.codex@daimon-cluster",
                prog="eko-codex",
            )
        ).decode(),
        instructions="# Previous managed binding\n",
        plan_digest="a" * 64,
        origin=origin,
        being_ref=operator_rebirth.authority_from_runtime_bundle(
            target.document_bundle()
        ).state.being_ref,
        install=True,
    )
    installer = (
        Path(__file__).resolve().parents[1]
        / "support/matrix-agent-chat/install_agent_chat.py"
    ).read_bytes()
    provenance = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "support/matrix-agent-chat/PROVENANCE.json"
        ).read_bytes()
    )
    assert sha256(installer).hexdigest() == provenance["sha256"]
    successor = {
        **payload,
        "legacy_instructions": payload["instructions"],
        "instructions": "# Previous managed binding\n\n# Native messaging attachment\n",
        "chat": dict(
            application=str(application),
            attachment=str(attachment),
            socket=str(root / "peer.sock"),
            installer=installer.decode(),
            installer_sha256=provenance["sha256"],
            codex_mcp=native_mcp,
        ),
    }
    admitted = AdmittedDaemon(target, client)
    try:
        admitted.start(
            visibility_installation=onboarding_peer.root(target)
            / "visibility/installation.json",
            messaging_application=application,
        )
        assert invoke(payload).returncode == 0
        old_receipt = (target.package / "owner-client/installation.json").read_bytes()
        assert json.loads(invoke({**successor, "install": False}).stdout) == {
            "installed": False
        }
        foreign = {
            **successor,
            "chat": {
                **successor["chat"],
                "application": str(sources[0][1].package / "runtime"),
            },
        }
        assert invoke(foreign).returncode != 0
        assert not attachment.exists()
        assert (target.home / "Projects/being/AGENTS.md").read_text() == payload[
            "instructions"
        ]
        result = invoke(successor)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["installed"] is True
        if native_mcp:
            import tomllib
            configured = tomllib.loads(config.read_text())
            assert configured['model']=='preserved'
            assert configured['mcp_servers']['matrix']['args'][-1]=='mcp'
        assert (target.home / "Projects/being/AGENTS.md").read_text() == successor[
            "instructions"
        ]
        assert (
            target.package
            / "owner-client"
            / ("previous-" + sha256(payload["instructions"].encode()).hexdigest())
        ).read_text() == payload["instructions"]
        assert (
            target.package
            / "owner-client"
            / ("previous-" + sha256(old_receipt).hexdigest())
        ).read_bytes() == old_receipt
        connection = json.loads((attachment / "connection.json").read_bytes())
        channels = subprocess.run(
            [*connection["command"], "channels"], capture_output=True, timeout=10
        )
        assert channels.returncode == 0, channels.stderr
        assert json.loads(channels.stdout)["outgoing_channels"] == ["peer-out"]
        saved = (attachment / "installation.json").read_bytes()
        # Crash after publishing instructions but before either final receipt:
        # observation must permit an exact repair, not wedge the worker.
        (attachment / "installation.json").unlink()
        (target.package / "owner-client/installation.json").write_bytes(old_receipt)
        assert json.loads(invoke({**successor, "install": False}).stdout) == {
            "installed": False
        }
        assert invoke(successor).returncode == 0
        assert (
            json.loads(invoke({**successor, "install": False}).stdout)["installed"]
            is True
        )
        assert (attachment / "installation.json").read_bytes() == saved
        for name, raw in original.items():
            assert (root / name).read_bytes() == raw
        edited = target.home / "Projects/being/AGENTS.md"
        edited.write_text("Preserve receiving changes")
        assert invoke(successor).returncode != 0
        assert edited.read_text() == "Preserve receiving changes"
        edited.write_text(successor["instructions"])
        (attachment / "connection.json").write_text(
            "Preserve receiving connection edits"
        )
        assert invoke(successor).returncode != 0
        assert invoke({**successor, "install": False}).returncode != 0
        assert (
            attachment / "connection.json"
        ).read_text() == "Preserve receiving connection edits"
    finally:
        admitted.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_native_owner_client_publication_and_reconciliation_keep_runtime_and_owner_writes(
    native,
):
    target, payload = native
    absent = invoke({**payload, "install": False})
    assert absent.returncode == 0, absent.stderr
    assert json.loads(absent.stdout) == {"installed": False}
    result = invoke(payload)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["installed"] is True
    receipt = target.package / "owner-client/installation.json"
    before = receipt.read_bytes()
    own = target.home / "own-memory"
    own.write_bytes(b"Owner writes after publication")
    assert invoke(payload).returncode == 0
    assert invoke({**payload, "install": False}).returncode == 0
    assert (
        receipt.read_bytes() == before
        and own.read_bytes() == b"Owner writes after publication"
    )


@pytest.mark.parametrize("mismatch", ["being_ref", "origin"])
def test_foreign_signed_body_is_refused_before_publication(native, mismatch):
    target, payload = native
    changed = dict(payload)
    if mismatch == "being_ref":
        changed["being_ref"] = "another-being"
    else:
        changed["origin"] = {**payload["origin"], "embodiment_id": "another-body"}
    assert invoke(changed).returncode != 0
    assert not (target.package / "owner-client").exists()
    assert not (target.home / "Projects/being/AGENTS.md").exists()


@pytest.mark.parametrize("changed", ["instructions", "client", "receipt", "symlink"])
def test_changed_receiving_files_are_preserved_and_never_reported_installed(
    native, changed
):
    target, payload = native
    assert invoke(payload).returncode == 0
    path = {
        "instructions": target.home / "Projects/being/AGENTS.md",
        "client": target.package / "owner-client/eko-codex",
        "receipt": target.package / "owner-client/installation.json",
        "symlink": target.package / "owner-client/eko-codex",
    }[changed]
    if changed == "symlink":
        path.unlink()
        path.symlink_to(target.home / "outside")
    else:
        path.write_bytes(b"Preserve receiving edits")
    assert invoke(payload).returncode != 0
    assert invoke({**payload, "install": False}).returncode != 0
    assert (
        path.is_symlink()
        if changed == "symlink"
        else path.read_bytes() == b"Preserve receiving edits"
    )


def test_interrupted_partial_publication_reuses_exact_client(native):
    target, payload = native
    parent = target.package / "owner-client"
    parent.mkdir(mode=0o700)
    client = parent / "eko-codex"
    client.write_text(payload["script"])
    client.chmod(0o700)
    before = client.stat().st_ino
    assert invoke(payload).returncode == 0
    assert client.stat().st_ino == before


@pytest.mark.parametrize('observer', ['owner-client', 'runtime-presence'])
def test_slow_authenticated_native_daemon_is_not_treated_as_departed(native, observer):
    import signal
    import socket
    import struct
    import threading

    target, payload = native
    # Delay the actual native process. A forwarding proxy changes SO_PEERCRED
    # and must not stand in for the same-connection responder we are testing.
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(str(target.package / "runtime/matrix.sock"))
        pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert uid == os.geteuid() and pid != os.getpid()
    descriptor = os.pidfd_open(pid)
    release = threading.Event()
    def resume():
        release.wait(6)
        signal.pidfd_send_signal(descriptor, signal.SIGCONT)
    signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
    thread = threading.Thread(target=resume)
    thread.start()
    try:
        if observer == 'owner-client':
            result = invoke(payload)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["installed"] is True
        else:
            result = target.running()
            assert result['origin'] == payload['origin']
            assert result['process']['pid'] == pid
            assert result['schema'] == 'cluster-onboarding-runtime-presence/v1'
    finally:
        release.set()
        thread.join(timeout=10)
        assert not thread.is_alive()
        os.close(descriptor)


def test_host_adapter_verifies_installed_sdk_and_current_plan_before_dispatch(
    monkeypatch,
):
    from tests.test_onboarding import plan

    selected = plan()
    client = OwnerClient(
        SimpleNamespace(
            authorize=lambda *args: True,
            instance=lambda p: "dm-eko",
            _target_call=lambda p, a: {"ready": False},
        )
    )
    monkeypatch.setattr(
        client, "_payload", lambda *args, **kw: {"python": sys.executable}
    )
    with pytest.raises(ValueError, match="verification_failed"):
        client.execute(selected, {})


def test_acceptance_installation_does_not_assert_human_or_delivery_acceptance(
    tmp_path, monkeypatch
):
    from dataclasses import replace
    from tests.test_onboarding_host import configured
    from clusterctl.onboarding_host import HostBackend

    config, plan, _, _ = configured(tmp_path)
    host = HostBackend(replace(config, admission=tmp_path / "managed"))
    managed = SimpleNamespace(
        observe=lambda p: Observation("complete", {"verified": True}),
        _expected=lambda p: {"own": "origin"},
    )
    monkeypatch.setattr(
        "clusterctl.onboarding_managed.ManagedRuntime", lambda host: managed
    )
    calls = []
    monkeypatch.setattr(
        OwnerClient,
        "observe",
        lambda *args: Observation("absent", safe_to_execute=True),
    )
    monkeypatch.setattr(
        OwnerClient, "execute", lambda self, p, origin: calls.append(origin)
    )
    assert host.observe(plan, "acceptance", "unused").safe_to_execute
    host.execute(plan, "acceptance", "unused")
    assert calls == [{"own": "origin"}]
    monkeypatch.setattr(
        OwnerClient,
        "observe",
        lambda *args: Observation("complete", {"verified": True}),
    )
    observed = host.observe(plan, "acceptance", "unused")
    assert observed.state == "waiting" and not observed.facts


@pytest.mark.parametrize("drift", [False, True])
@pytest.mark.parametrize("binding_filename", ["binding.json", "owner-binding.json"])
def test_native_server_version_binds_the_qualified_sdk_code_and_attachment(
    tmp_path, monkeypatch, drift, binding_filename
):
    from clusterctl import onboarding_owner_client as owner
    from daimon_matrix import agent_chat
    from clusterctl.onboarding import digest

    startup = dict(
        code_digest="a" * 64,
        sdk_digest="b" * 64,
        matrix_commit="c" * 40,
        matrix_wheel_sha256="d" * 64,
    )
    captured = {"captured_binding": True}
    snapshots = iter(
        [(captured, "e" * 64), (captured, "f" * 64 if drift else "e" * 64)]
    )
    monkeypatch.setattr(
        owner,
        "_installer",
        lambda *a: SimpleNamespace(_binding_fingerprint=lambda a, **kw: next(snapshots)),
    )
    monkeypatch.setattr(
        agent_chat,
        "load_binding",
        lambda p: pytest.fail("binding was reread outside snapshot"),
    )
    server = SimpleNamespace(version="old")
    observed = []

    def bridge(value):
        assert value is captured
        return SimpleNamespace(server=lambda: server)

    monkeypatch.setattr(agent_chat, "bridge", bridge)

    async def serve(value):
        observed.append(value.version)

    monkeypatch.setattr(agent_chat, "_run_stdio", serve)

    def invoke():
        return owner._serve_chat(
            ["mcp"],
            startup=startup,
            binding=tmp_path / binding_filename,
            code=tmp_path,
            code_uid=os.geteuid(),
        )

    if drift:
        with pytest.raises(owner.OnboardingError, match="tooling_changed"):
            invoke()
        assert observed == []
    else:
        assert invoke() == 0
        assert observed == [
            "cluster-native-tooling/" + digest({**startup, "binding_sha256": "e" * 64})
        ]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "old-sdk",
        "schema",
        "disabled",
        "unloaded",
        "config-drift",
        "stall",
        "pagination",
        "alias",
        "alias-drift",
        "starting",
        "stale-once",
        "threadless",
        "long-budget",
        "lost-reload",
        "mixed-starting",
        "stale-config-drift",
        "stale-alias-drift",
    ],
)
def test_native_catalog_pins_actual_peer_and_selected_context_without_turns(
    tmp_path, monkeypatch, fault
):
    import hashlib
    import threading
    import time
    import uuid
    from websockets.sync.server import unix_serve
    from clusterctl import onboarding_owner_client as owner
    from clusterctl.onboarding import OnboardingError
    from daimon_matrix import agent_chat

    # Short actual AF_UNIX socket; no native harness or model is created.
    with tempfile.TemporaryDirectory(prefix="dm-catalog-") as short:
        endpoint = Path(short) / "native.sock"
        selected_endpoint = endpoint
        if fault in {'alias', 'alias-drift', 'stale-alias-drift'}:
            selected_endpoint = Path(short) / 'control.sock'
            selected_endpoint.symlink_to(endpoint.name)
        home = tmp_path / "codex"
        home.mkdir(mode=0o700)
        config = home / "config.toml"
        config.write_text("# Existing owner configuration\n")
        config.chmod(0o600)
        config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
        thread_id = str(uuid.uuid4())
        second_thread = str(uuid.uuid4())
        startup = dict(
            code_digest="a" * 64,
            sdk_digest="b" * 64,
            matrix_commit="c" * 40,
            matrix_wheel_sha256="d" * 64,
        )
        schema = {"type": "object", "properties": {"channel_id": {"enum": ["tribe"]}}}
        expected = {
            name: schema
            for name in [
                "messaging_inbox",
                "messaging_send",
                "messaging_reply",
                "messaging_delivery",
            ]
        }

        async def list_tools(*a):
            return SimpleNamespace(
                tools=[
                    SimpleNamespace(name=n, input_schema=s) for n, s in expected.items()
                ]
            )

        monkeypatch.setattr(
            agent_chat, "bridge", lambda b: SimpleNamespace(list_tools=list_tools)
        )
        monkeypatch.setattr(
            owner,
            "_installer",
            lambda *a: SimpleNamespace(_binding_fingerprint=lambda a, **kw: ({}, "e" * 64)),
        )
        requests = []
        statuses = {}
        reloads = []
        deadlines = []
        if fault == "long-budget":
            import asyncio
            real_timeout = asyncio.timeout

            def timed(seconds):
                deadlines.append(seconds)
                return real_timeout(seconds)

            monkeypatch.setattr(asyncio, "timeout", timed)
        release = threading.Event()

        def respond(connection):
            for message in connection:
                request = json.loads(message)
                requests.append(request)
                method = request["method"]
                assert method in {
                    "initialize",
                    "initialized",
                    "config/mcpServer/reload",
                    "thread/loaded/list",
                    "mcpServerStatus/list",
                }
                if method == "initialized":
                    continue
                if fault == "stall":
                    release.wait(2)
                    return
                if method == "thread/loaded/list":
                    result = {
                        "data": [] if fault == "unloaded" else [thread_id, second_thread],
                        "nextCursor": "repeated" if fault == "pagination" else None,
                    }
                elif method == "mcpServerStatus/list":
                    selected = request["params"].get("threadId")
                    assert selected in (None, thread_id, second_thread)
                    assert (selected is None) == (fault == "threadless")
                    statuses[selected] = statuses.get(selected, 0) + 1
                    starting = (fault == "starting" or fault == "mixed-starting" and selected == second_thread) and statuses[selected] == 1
                    stale = fault in ("stale-once", "lost-reload", "mixed-starting", "stale-config-drift", "stale-alias-drift") and not reloads
                    if fault == "mixed-starting" and selected == second_thread:
                        stale = False
                    tools = {
                        n: {"name": n, "inputSchema": s} for n, s in expected.items()
                    }
                    if fault in ('alias-drift', 'stale-alias-drift'):
                        replacement = selected_endpoint.with_suffix('.next')
                        replacement.symlink_to(str(endpoint))
                        os.replace(replacement, selected_endpoint)
                    if fault == "schema":
                        tools["messaging_send"]["inputSchema"] = {"type": "object"}
                    result = {
                        "data": [
                            {
                                "name": "matrix",
                                "runtimeStatus": "disabled"
                                if fault == "disabled"
                                else "starting" if starting else "connected",
                                "tools": tools,
                                "serverInfo": {
                                    "version": "old"
                                    if fault == "old-sdk" or stale
                                    else owner.tooling_version(startup, "e" * 64)
                                },
                            }
                        ]
                    }
                    if fault in ("config-drift", "stale-config-drift"):
                        config.write_text("# Concurrent owner edit\n")
                elif method == "config/mcpServer/reload":
                    reloads.append(True)
                    assert len(reloads) == 1
                    if fault == "lost-reload":
                        return
                    result = {}
                else:
                    result = {}
                connection.send(json.dumps({"id": request["id"], "result": result}))

        with unix_serve(respond, str(endpoint), close_timeout=0.1) as server:
            endpoint.chmod(0o600)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:

                def observe():
                    return owner.native_catalog(
                        tmp_path,
                        code=tmp_path,
                        code_uid=os.geteuid(),
                        startup=startup,
                        codex_home=home,
                        endpoint=selected_endpoint,
                        threads=() if fault == "threadless" else (
                            (thread_id, second_thread) if fault == "mixed-starting" else (thread_id,)
                        ),
                        config_sha256=config_sha,
                        reload=True,
                        deadline_ns=time.monotonic_ns()
                        + int((0.1 if fault == "stall" else 45 if fault == "long-budget" else 3) * 1e9),
                    )

                if fault == "lost-reload":
                    from websockets.exceptions import ConnectionClosed
                    with pytest.raises(ConnectionClosed):
                        observe()
                if fault in (None, 'alias', 'starting', 'stale-once', 'threadless', 'long-budget', 'lost-reload', 'mixed-starting'):
                    result = observe()
                    assert result["acceptance"] == ("server-catalog-only" if fault == "threadless" else "selected-existing-contexts")
                    assert result["native_process"]["pid"] == os.getpid()
                    assert result["contexts"][0]["thread_id"] == (None if fault == "threadless" else thread_id)
                    assert result["model_turns_started"] == result["messages_sent"] == 0
                else:
                    with pytest.raises((OnboardingError, TimeoutError)):
                        observe()
                assert len(reloads) == (1 if fault in ("old-sdk", "stale-once", "lost-reload", "mixed-starting") else 0)
                if fault in ("starting", "mixed-starting"):
                    assert statuses[second_thread if fault == "mixed-starting" else thread_id] >= 2
                    first_reload = next((i for i, r in enumerate(requests) if r["method"] == "config/mcpServer/reload"), len(requests))
                    assert sum(r["method"] == "mcpServerStatus/list" for r in requests[:first_reload]) >= (4 if fault == "mixed-starting" else 2)
                if fault == "long-budget":
                    assert deadlines and deadlines[0] > 30
                if fault == "threadless":
                    assert sum(statuses.values()) == 1
                assert all(
                    r["method"]
                    not in {
                        "thread/start",
                        "thread/resume",
                        "turn/start",
                        "mcpServer/tool/call",
                    }
                    for r in requests
                )
            finally:
                release.set()
                server.shutdown()
                thread.join(3)
                assert not thread.is_alive()


@pytest.mark.parametrize('drift', [None, 'command', 'sdk', 'binding', 'connection-after-proof', 'other-body', 'pair-socket', 'multi'])
def test_tooling_observer_requires_selected_sdk_and_unchanged_connections(
    tmp_path, monkeypatch, drift
):
    import hashlib
    from clusterctl import onboarding_owner_client as owner
    from clusterctl.onboarding import OnboardingError
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix import agent_chat

    attachment = tmp_path / "attachment"
    attachment.mkdir(mode=0o700)
    startup = dict(
        code_digest="a" * 64,
        sdk_digest="b" * 64,
        matrix_commit="c" * 40,
        matrix_wheel_sha256="d" * 64,
    )
    recipe = dict(
        profile="codex",
        attachment=str(attachment),
        codex_home=str(tmp_path / "codex"),
        connections=[],
        native_endpoint=str(tmp_path / "native.sock"),
        native_threads=[],
        tribe_channel="tribe",
    )
    origin = {"embodiment_id": "body:fixture"}
    receiving = dict(
        server=origin,
        runtime_status={"loaded_runtime": {"runtime_id": "runtime:fixture"}},
        group={"channel_id": "tribe", "socket": "/runtime/tribe.sock"},
    )
    leg = dict(
        schema=agent_chat.SCHEMA,
        socket="/pair.sock" if drift == "pair-socket" else "/runtime/tribe.sock",
        incoming_channels=["tribe"],
        outgoing_channels=["tribe"],
    )
    binding = leg
    if drift == "multi":
        binding = dict(
            schema=agent_chat.MULTI_SCHEMA,
            links={"current": leg},
            incoming_channels=["current/tribe"],
            outgoing_channels=["current/tribe"],
        )
        recipe["tribe_channel"] = "current/tribe"
    monkeypatch.setattr(
        agent_chat,
        "bridge",
        lambda b: SimpleNamespace(
            client=SimpleNamespace(
                config=SimpleNamespace(
                    runtime_id="runtime:fixture",
                    expected_server={"embodiment_id": "other"}
                    if drift == "other-body"
                    else origin,
                )
            )
        ),
    )
    command = owner.chat_command(
        Path(sys.prefix),
        Path(sys.prefix).parent / "runtime-imports",
        tmp_path,
        code_digest=startup["code_digest"],
        binding=attachment / "binding.json",
        code_uid=os.geteuid(),
    )
    connection = dict(
        command=command, incoming_channels=binding["incoming_channels"], tools=[]
    )
    private = attachment / "connection.json"
    private.write_bytes(canonical_bytes(connection))
    private.chmod(0o600)
    accepted = dict(
        schema="cluster-native-chat-tooling/v1",
        status="configured",
        **startup,
        runtime_id="runtime:fixture",
        server=origin,
        binding_sha256="e" * 64,
        command_sha256=hashlib.sha256(canonical_bytes(command)).hexdigest(),
        config_sha256="f" * 64,
    )
    if drift == "command":
        accepted["command_sha256"] = "0" * 64
    if drift == "sdk":
        accepted["sdk_digest"] = "0" * 64
    if drift == "binding":
        accepted["binding_sha256"] = "0" * 64
    monkeypatch.setattr(
        owner,
        "_installer",
        lambda *a: SimpleNamespace(
            _binding_fingerprint=lambda p, **kw: (binding, "e" * 64),
            _tools=lambda: [],
        ),
    )
    observed = []

    def inspect(*args, **options):
        observed.append(options)
        if drift == "connection-after-proof":
            private.write_text('{"command":[]}')
        return {"schema": "cluster-native-tool-catalog/v1", "binding_sha256": "e" * 64}

    monkeypatch.setattr(owner, "native_catalog", inspect)

    def observe():
        return owner.observe_selected_tooling(
            {"recipe": recipe, "accepted": accepted},
            code=tmp_path,
            startup=startup,
            code_uid=os.geteuid(),
            deadline_ns=123,
            receiving=receiving,
        )

    if drift in (None, "multi"):
        assert observe()["schema"] == "cluster-native-tool-catalog/v1"
        assert observed[0]["deadline_ns"] == 123
        assert private.read_bytes() == canonical_bytes(connection)
    else:
        with pytest.raises(OnboardingError, match="tooling_"):
            observe()
        assert len(observed) == (1 if drift == "connection-after-proof" else 0)


def test_guest_tooling_budget_starts_before_qualification(tmp_path, monkeypatch):
    import time
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor

    clock = [1]
    monkeypatch.setattr(time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(
        onboarding_code_successor,
        "sdk_parameters",
        lambda *a, **k: {"matrix_commit": "b" * 40},
    )

    def qualify(*a, **k):
        clock[0] = 2_000_000_001
        return {"selected": True}

    monkeypatch.setattr(owner.onboarding_sdk, "qualified_startup", qualify)
    monkeypatch.setattr(
        owner,
        "reconcile_chat_tooling",
        lambda *a, **k: pytest.fail("late helper began publication"),
    )
    with pytest.raises(owner.OnboardingError, match="deadline_expired"):
        owner.main(
            [
                "--binding",
                str(tmp_path / "binding.json"),
                "--code-digest",
                "a" * 64,
                "--reconcile-tooling",
                "operation:fixture",
                "--codex-home",
                str(tmp_path / "codex"),
                "--observation-timeout-seconds",
                "1",
            ]
        )


@pytest.mark.parametrize('error,expected', [
    (OnboardingError('native_tooling_catalog_mismatch'), 'native_tooling_catalog_mismatch'),
    (OnboardingError('private_identifier'), 'native_matrix_tool_startup_refused'),
    (RuntimeError('native_tooling_catalog_mismatch'), 'native_matrix_tool_startup_refused'),
])
def test_startup_diagnostic_exposes_only_declared_domain_codes(error, expected):
    from clusterctl.onboarding_owner_client import _public_error
    assert _public_error(error) == expected


@pytest.mark.parametrize("filename", ["binding.json", "owner-binding.json", "../binding.json", "other.json", None, []])
def test_tooling_recipe_explicit_binding_filename_never_discovers_another_path(filename):
    from clusterctl.onboarding_owner_client import validate_tooling_recipe
    from clusterctl.onboarding import OnboardingError
    recipe = dict(profile='codex', attachment='/owner/tribe', codex_home='/owner/.codex',
        connections=[], native_endpoint='/owner/native.sock', native_threads=[],
        tribe_channel='tribe', binding_filename=filename)
    if filename in ('binding.json', 'owner-binding.json'):
        assert validate_tooling_recipe(recipe) is recipe
    else:
        with pytest.raises(OnboardingError, match='receiving_native_tooling_recipe_required'):
            validate_tooling_recipe(recipe)


@pytest.mark.parametrize('fault', [None, 'alias', 'alias-drift', 'unsafe-mode', 'refused', 'stall', 'expired',
    'empty-response', 'relative-home'])
def test_native_preflight_uses_exact_endpoint_without_binding_or_model(tmp_path, fault):
    import threading
    import time
    from websockets.sync.server import unix_serve
    from clusterctl import onboarding_owner_client as owner
    with tempfile.TemporaryDirectory(prefix='dm-preflight-') as short:
        endpoint = Path(short) / 'native.sock'
        selected = Path(short) / 'selected.sock'
        selected.symlink_to(endpoint.name)
        requests, release = [], threading.Event()
        def respond(connection):
            for message in connection:
                request = json.loads(message)
                requests.append(request['method'])
                assert request['method'] in {'initialize', 'initialized'}
                if request['method'] == 'initialized':
                    continue
                if fault == 'stall':
                    release.wait(2)
                    return
                if fault == 'alias-drift':
                    replacement = selected.with_suffix('.next')
                    replacement.symlink_to(endpoint.name)
                    os.replace(replacement, selected)
                response = {'id': request['id'], 'result': dict(userAgent='codex/test',
                    codexHome='/owner/.codex', platformFamily='unix', platformOs='linux')}
                if fault == 'empty-response':
                    response['result'] = {}
                if fault == 'relative-home':
                    response['result']['codexHome'] = 'relative/.codex'
                if fault == 'refused':
                    response = {'id': request['id'], 'error': {'message': 'private server detail'}}
                connection.send(json.dumps(response))
        with unix_serve(respond, str(endpoint), close_timeout=.1) as server:
            endpoint.chmod(0o622 if fault == 'unsafe-mode' else 0o600)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                deadline = time.monotonic_ns() + int((-.1 if fault == 'expired' else .1 if fault == 'stall' else 3)*1e9)
                def observe():
                    return owner.native_endpoint_readiness(
                        selected if fault in {'alias', 'alias-drift'} else endpoint, deadline_ns=deadline)
                if fault in {None, 'alias'}:
                    result = observe()
                    assert result['acceptance'] == 'native-endpoint-only'
                    assert result['native_process']['pid'] == os.getpid()
                    assert result['model_turns_started'] == result['messages_sent'] == 0
                    assert len(result['endpoint_sha256']) == 64
                else:
                    with pytest.raises((OnboardingError, TimeoutError)) as caught:
                        observe()
                    assert 'private server detail' not in str(caught.value)
                if fault in {'expired', 'unsafe-mode'}:
                    assert requests == []
            finally:
                release.set()
                server.shutdown()
                thread.join(3)
                assert not thread.is_alive()


@pytest.mark.parametrize('invalid', [None, 'binding', 'reconcile', 'thread', 'no-deadline', 'no-endpoint'])
def test_native_preflight_cli_qualifies_before_handshake_and_requires_closed_mode(tmp_path, monkeypatch, capsys, invalid):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    calls = []
    startup = dict(code_digest='a'*64, sdk_digest='b'*64, matrix_commit='c'*40, matrix_wheel_sha256='d'*64)
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {'matrix_commit': 'c'*40})
    def qualify(*args, **options):
        calls.append('qualified')
        return startup
    monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', qualify)
    def handshake(endpoint, *, deadline_ns):
        assert calls == ['qualified']
        assert endpoint == tmp_path/'native.sock' and deadline_ns > 0
        calls.append('handshake')
        return dict(schema='cluster-native-endpoint-readiness/v1', acceptance='native-endpoint-only')
    monkeypatch.setattr(owner, 'native_endpoint_readiness', handshake)
    arguments = ['--code-digest', 'a'*64, '--native-preflight']
    if invalid != 'no-endpoint':
        arguments += ['--native-endpoint', str(tmp_path/'native.sock')]
    if invalid != 'no-deadline':
        arguments += ['--observation-timeout-seconds', '2']
    arguments += {'binding': ['--binding', str(tmp_path/'binding.json')],
                  'reconcile': ['--reconcile-tooling', 'operation'],
                  'thread': ['--native-thread', '00000000-0000-0000-0000-000000000001']}.get(invalid, [])
    if invalid:
        with pytest.raises(OnboardingError, match='qualified_native_peer_tool_required'):
            owner.main(arguments)
        assert calls == []
    else:
        assert owner.main(arguments) == 0
        assert json.loads(capsys.readouterr().out)['qualification'] == startup
        assert calls == ['qualified', 'handshake']
        calls.clear()
        def refuse(*args, **kwargs):
            raise OnboardingError('qualified_runtime_context_required')
        monkeypatch.setattr(owner.onboarding_sdk, 'qualified_startup', refuse)
        with pytest.raises(OnboardingError, match='qualified_runtime_context_required'):
            owner.main(arguments)
        assert calls == []


def test_guest_native_preflight_uses_same_qualified_owner_route(tmp_path, monkeypatch):
    from clusterctl import onboarding_owner_client as owner, onboarding_code_successor
    from clusterctl.onboarding import digest
    from tests.test_onboarding import plan
    sdk = dict(schema=owner.onboarding_sdk.SCHEMA, matrix_commit='b'*40,
        wheels=[dict(distribution='daimon-matrix', sha256='c'*64,
            filename='daimon_matrix-1-py3-none-any.whl', version='1')])
    result = dict(schema='cluster-native-endpoint-readiness/v1', acceptance='native-endpoint-only',
        qualification=dict(code_digest='a'*64, sdk_digest=digest(sdk), matrix_commit=sdk['matrix_commit'],
            matrix_wheel_sha256='c'*64), model_turns_started=0, messages_sent=0)
    calls = []
    def dispatch(value, command, **options):
        calls.append((command, options))
        assert 0 < options['timeout_seconds'] <= 2
        return json.dumps(result)
    host = SimpleNamespace(authorize=lambda *a: True, _receiving_base=lambda p: Path('/public/base'),
        _runtime_paths=lambda *a, **k: (Path('/public/selected'), [], {}),
        _mounted=lambda *a, **k: True, instance=lambda p: 'dm-fixture', _dispatch=dispatch)
    monkeypatch.setattr(owner.onboarding_sdk, 'verify', lambda *a, **k: sdk)
    monkeypatch.setattr(onboarding_code_successor, 'sdk_parameters', lambda *a, **k: {})
    client = owner.OwnerClient(host)
    options = dict(candidate=(tmp_path/'candidate', 'a'*64), endpoint=Path('/home/agent/native.sock'), timeout_seconds=2)
    assert client.preflight_native(plan(), **options) == result
    command = calls[-1][0]
    assert command[:8] == ['exec', 'dm-fixture', '--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent']
    assert command[command.index('--native-endpoint')+1] == '/home/agent/native.sock'
    assert '--native-preflight' in command and '--binding' not in command
    result['qualification']['sdk_digest'] = 'd'*64
    with pytest.raises(OnboardingError, match='verification_failed'):
        client.preflight_native(plan(), **options)
    result['qualification']['sdk_digest'] = digest(sdk)
    clock = [0]
    decode = json.loads
    def late_decode(raw):
        clock[0] = 3_000_000_000
        return decode(raw)
    monkeypatch.setattr(owner.time, 'monotonic_ns', lambda: clock[0])
    monkeypatch.setattr(owner.json, 'loads', late_decode)
    with pytest.raises(OnboardingError, match='receiving_owner_deadline_expired'):
        client.preflight_native(plan(), **options)
