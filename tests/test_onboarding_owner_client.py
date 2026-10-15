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
from clusterctl.onboarding import Observation
from clusterctl.onboarding_owner_client import OwnerClient, PROGRAM
from tests.test_onboarding_target import receiving

pytest_plugins = ["tests.test_onboarding_peer"]


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
