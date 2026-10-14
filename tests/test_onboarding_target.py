"""Native receiving identity survives interrupted runtime publication/retries."""
import hashlib

import pytest

from clusterctl.onboarding import OnboardingError, digest
from clusterctl.onboarding_custody import document
from clusterctl.onboarding_target import Target
from tests.test_onboarding_custody import fixture


def receiving(tmp_path):
    ceremony, plan, _ = fixture(tmp_path)
    ceremony.prepare(plan, identity_mode="first")
    host = ceremony.root / digest(plan)
    home = tmp_path / "guest"
    home.mkdir(mode=0o700)
    return ceremony, plan, Target(home, plan, document(host / "genesis.json"))


def files(root):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_receiving_target_runtime_retries_keep_keys_origin_and_receiving_writes(tmp_path):
    ceremony, plan, target = receiving(tmp_path)
    assert target.observe() == dict(phase="absent", request=None, receipt=None)
    request = target.prepare()
    assert target.observe()["phase"] == "prepared"
    preserved = files(target.preparation)
    assert target.prepare() == request and files(target.preparation) == preserved
    activation = ceremony.authorize_target(plan, request)
    complete = target.activate(activation)
    assert complete["phase"] == "v7" and complete["receipt"]["root_seeds_in_target"] is False
    own = target.package / "runtime/own-later-state"
    own.write_bytes(b"Receiving writes after activation")
    original = files(target.package)
    assert target.activate(activation) == complete
    assert files(target.package) == original and files(target.preparation) == preserved
    assert not list(target.home.rglob("holder.json"))
    assert not list(target.home.rglob("root.unlock"))


def test_interrupted_ack_after_native_runtime_publication_does_not_recreate_package(tmp_path, monkeypatch):
    from daimon_matrix import operator_first_embodiment as first
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    activation = ceremony.authorize_target(plan, request)
    actual = first.activate_runtime
    def interrupted(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("process disappeared after atomic runtime publication")
    monkeypatch.setattr(first, "activate_runtime", interrupted)
    with pytest.raises(RuntimeError):
        target.activate(activation)
    published = files(target.package)
    observed = target.observe()
    assert observed["receipt"]["origin"] == request["body"]["origin"]
    assert target.activate(activation) == observed
    assert files(target.package) == published


def test_missing_unlock_or_changed_plan_cannot_replace_existing_identity(tmp_path):
    _, plan, target = receiving(tmp_path)
    target.prepare()
    original = files(target.preparation)
    (target.root / "body.unlock").unlink()
    with pytest.raises(OnboardingError, match="existing_onboarding_target_preserved"):
        target.prepare()
    assert files(target.preparation) == original
    other = Target(target.home, {**plan, "release_digest": "b" * 64}, target.genesis)
    with pytest.raises(OnboardingError, match="onboarding_target_binding_conflict"):
        other.prepare()
    assert files(target.preparation) == original


def test_receiving_credential_upgrade_keeps_origin_memory_and_runtime_reload(tmp_path):
    from clusterctl.onboarding_target import document
    ceremony, plan, target = receiving(tmp_path)
    request = target.prepare()
    before = target.activate(ceremony.authorize_target(plan, request))
    memory = target.home / "preserved-memory.db"
    memory.write_bytes(b"Own memory is outside native authority publication")
    prepared = files(target.preparation)
    native_keys = (target.package / "runtime/custody.json").read_bytes()
    proposal = target.credential_request()
    assert target.credential_request() == proposal
    response = ceremony.authorize_credential(plan, proposal)
    complete = target.apply_credential(response)
    assert complete["phase"] == "v8"
    assert complete["receipt"]["origin"] == before["receipt"]["origin"]
    assert target.apply_credential(response) == complete
    assert target.activate(ceremony.authorize_target(plan, request)) == complete
    assert files(target.preparation) == prepared
    assert (target.package / "runtime/custody.json").read_bytes() == native_keys
    assert memory.read_bytes() == b"Own memory is outside native authority publication"
    from daimon_matrix.runtime import load_runtime
    import time
    hosted = load_runtime(target.package / "runtime", "runtime.json", target._reader,
                          clock=lambda: time.time_ns() // 1_000_000)
    assert hosted.service.ledger.local_origin == before["receipt"]["origin"]
    assert document(target.package / "runtime/runtime.json")["authority_history"]


@pytest.mark.parametrize("phase", ["response", "candidate", "runtime", "receipt"])
def test_native_credential_publication_recovers_each_lost_ack_without_new_identity(tmp_path, monkeypatch, phase):
    from daimon_matrix import keystore
    ceremony, plan, target = receiving(tmp_path)
    original = target.activate(ceremony.authorize_target(plan, target.prepare()))
    proposed = target.credential_request()
    response = ceremony.authorize_credential(plan, proposed)
    interrupted_path = target.package / "runtime/runtime.json" if phase == "runtime" else target.credential / (phase + ".json")
    actual = keystore._atomic_write
    failures = []
    def interrupted(path, value):
        actual(path, value)
        if path == interrupted_path and not failures:
            failures.append(path)
            raise RuntimeError("acknowledgement lost after durable publication")
    monkeypatch.setattr(keystore, "_atomic_write", interrupted)
    with pytest.raises(RuntimeError, match="acknowledgement lost"):
        target.apply_credential(response)
    observed = target.observe()
    assert observed["phase"] in {"v7", "v8-published", "v8"}
    assert target.credential_request() == proposed
    assert ceremony.authorize_credential(plan, proposed) == response
    completed = target.apply_credential(response)
    assert completed["phase"] == "v8"
    assert completed["receipt"]["origin"] == original["receipt"]["origin"]
    assert len(failures) == 1


def test_credential_publication_refuses_running_writer_and_preserves_changed_runtime(tmp_path):
    import os
    from daimon_matrix import daemon, keystore, canonical
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan, target.prepare()))
    proposed = target.credential_request()
    response = ceremony.authorize_credential(plan, proposed)
    descriptor = daemon.acquire_lock(target.package / "runtime")
    try:
        with pytest.raises(BlockingIOError):
            target.apply_credential(response)
        assert not (target.credential / "response.json").exists()
    finally:
        os.close(descriptor)
    target.apply_credential(response)
    from clusterctl.onboarding_target import document
    path = target.package / "runtime/runtime.json"
    changed = {**document(path), "runtime_label": "own-changed-runtime"}
    raw = canonical.canonical_bytes(changed)
    keystore._atomic_write(path, raw)
    with pytest.raises(OnboardingError, match="existing_onboarding_target_preserved"):
        target.apply_credential(response)
    assert path.read_bytes() == raw


def test_native_receiving_daemon_restarts_same_authority_and_refuses_second_writer(tmp_path):
    import json
    import os
    import select
    import subprocess
    import sys
    import tempfile
    from pathlib import Path
    from daimon_matrix.client import ClientConfig, LocalClient
    from clusterctl.onboarding_target import document
    ceremony, plan, _ = fixture(tmp_path)
    ceremony.prepare(plan, identity_mode="first")
    genesis = document(ceremony.root / digest(plan) / "genesis.json")
    # AF_UNIX has a fixed kernel path budget; receiving homes must fit it.
    with tempfile.TemporaryDirectory(prefix="dm-") as short:
        home = Path(short)
        target = Target(home, plan, genesis)
        before = target.activate(ceremony.authorize_target(plan, target.prepare()))
        target.apply_credential(ceremony.authorize_credential(plan, target.credential_request()))
        runtime = target.package / "runtime"
        original_keys = (runtime / "custody.json").read_bytes()
        original_bundle = (runtime / "runtime.json").read_bytes()
        own = home / "own-history"
        own.write_bytes(b"new receiving history")
        invocation = ("import sys,json; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                      "from clusterctl.onboarding_target import Target; "
                      "raise SystemExit(Target(Path(sys.argv[2]),json.loads(sys.argv[3]),"
                      "json.loads(sys.argv[4])).serve(receive_only=True,ready_descriptor=int(sys.argv[5])))")
        repository = str(Path(__file__).resolve().parents[1])
        config = ClientConfig.load(runtime / "client.json", bytearray((runtime / "client.key").read_bytes()))
        client = LocalClient(runtime / "matrix.sock", config)
        for _ in range(2):
            reader, writer = os.pipe()
            process = subprocess.Popen([sys.executable, "-B", "-I", "-c", invocation, repository,
                str(home), json.dumps(plan), json.dumps(genesis), str(writer)], pass_fds=(writer,),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.close(writer)
            try:
                assert select.select([reader], [], [], 10)[0], "native daemon never became ready"
                assert os.read(reader, 16) == b"READY\n"
                _, status = client.runtime_status()
                assert status["ok"] is True
                assert status["server"]["embodiment_id"] == before["receipt"]["origin"]["embodiment_id"]
                assert status["server"]["incarnation_id"] == before["receipt"]["origin"]["incarnation_id"]
                observed = target.running()
                assert observed["process"]["pid"] == process.pid
                assert observed["origin"] == before["receipt"]["origin"]
                assert observed['runtime_status']['local_origin'] == observed['origin']
                assert observed['receiving_readiness'] == 'unobserved'
                assert target.serve(receive_only=True) == 1
                assert process.poll() is None
                assert client.runtime_status()[1]["ok"] is True
            finally:
                os.close(reader)
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
            assert process.returncode == 0
            assert target.serve(visibility_installation=home / "missing-visibility.json") == 1
            assert not (runtime / "matrix.sock").exists()
            with pytest.raises(OSError):
                target.running()
            assert (runtime / "custody.json").read_bytes() == original_keys
            assert (runtime / "runtime.json").read_bytes() == original_bundle
            assert own.read_bytes() == b"new receiving history"


def test_daemon_requires_explicit_visibility_and_current_authority(tmp_path):
    _, _, target = receiving(tmp_path)
    with pytest.raises(OnboardingError, match="onboarding_visibility_selection_required"):
        target.serve()
    with pytest.raises(OnboardingError, match="onboarding_visibility_selection_required"):
        target.serve(receive_only=True, visibility_installation=tmp_path / "unselected.json")
    with pytest.raises(OnboardingError, match="current_onboarding_target_required"):
        target.serve(receive_only=True)
