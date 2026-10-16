from __future__ import annotations

import copy
import multiprocessing
import os
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clusterctl.admission import (
    AdmissionAuthority,
    AdmissionClient,
    AdmissionConflict,
    AdmissionEndpoint,
    AdmissionError,
    AdmissionServer,
    AdmissionTCPServer,
    AdmissionUnavailable,
    FENCE_RECOVERY_PROOF_SCHEMA,
    FenceMutationClient,
    _canonical,
    admission_resource_ref,
    serve_in_thread,
)
from clusterctl.fences import Ed25519Signer
from clusterctl.production_fences import (
    create_holder_authorization,
    create_holder_enrollment,
)


class MutableClock:
    def __init__(self, value: int):
        self.value = value

    def __call__(self) -> int:
        return self.value


def _key(path: Path, key_id: str) -> Ed25519Signer:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return Ed25519Signer(path, key_id)


def _coordinates(label: str, *, being_ref: str = "dm:being:shared") -> dict[str, str]:
    return {
        "being_ref": being_ref,
        "body_ref": f"cluster:body:{label}",
        "embodiment_id": f"dm:embodiment:{label}",
        "incarnation_id": f"dm:incarnation:{label}",
        "activation_id": f"dm:activation:{label}",
        "credential_id": f"dm:credential:{label}",
        "manifest_hash": f"sha256:{label}",
    }


def _client(
    socket_path: Path | AdmissionEndpoint,
    holder: Ed25519Signer,
    authority: Ed25519Signer,
    coordinates: Mapping[str, str],
    *, timeout_s: float = 2.0,
) -> AdmissionClient:
    return AdmissionClient(
        socket_path,
        holder_signer=holder,
        authority_key_id=authority.key_id,
        authority_public_key=authority.public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
        timeout_s=timeout_s,
    )


def _fence_client(
    socket_path: Path | AdmissionEndpoint,
    holder: Ed25519Signer,
    authority: Ed25519Signer,
    coordinates: Mapping[str, str],
) -> FenceMutationClient:
    return FenceMutationClient(
        socket_path,
        holder_signer=holder,
        authority_key_id=authority.key_id,
        authority_public_key=authority.public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
    )


def _enroll(
    client: AdmissionClient,
    registrar: Ed25519Signer,
    holder: Ed25519Signer,
    coordinates: Mapping[str, str],
    now_ms: int,
) -> None:
    enrollment = create_holder_enrollment(
        registrar,
        holder_key_id=holder.key_id,
        holder_pubkey=holder.public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
        issued_ms=now_ms,
        nonce=str(uuid.uuid4()),
    )
    assert client.enroll(enrollment)["admitted"] is True


@pytest.fixture
def authority_fixture(tmp_path: Path):
    now_ms = time.time_ns() // 1_000_000
    clock = MutableClock(now_ms)
    authority_signer = _key(tmp_path / "keys/authority.pem", "admission-authority")
    registrar = _key(tmp_path / "keys/registrar.pem", "matrix-registrar")
    authority = AdmissionAuthority(
        tmp_path / "authority",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
        clock=clock,
    )
    socket_path = tmp_path / "run/admission.sock"
    server = AdmissionServer(socket_path, authority)
    thread = serve_in_thread(server)
    try:
        yield {
            "authority": authority_signer,
            "registrar": registrar,
            "clock": clock,
            "server": server,
            "thread": thread,
            "socket": socket_path,
            "state": tmp_path / "authority",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _race_worker(
    socket_path: str,
    holder_key: str,
    holder_key_id: str,
    authority_key_id: str,
    authority_public_key: str,
    coordinates: dict[str, str],
    gate: Any,
    results: Any,
) -> None:
    client = AdmissionClient(
        socket_path,
        holder_signer=Ed25519Signer(holder_key, holder_key_id),
        authority_key_id=authority_key_id,
        authority_public_key=authority_public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
    )
    gate.wait()
    try:
        receipt = client.acquire(ttl_s=10)
        results.put(("ready", receipt["fencing_token"]))
    except AdmissionConflict:
        results.put(("conflict", None))


def test_same_embodiment_race_across_processes_has_one_winner(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    socket_path = authority_fixture["socket"]
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("one")
    holder_path = tmp_path / "holder-state-a/holder.pem"
    holder = _key(holder_path, "holder-one")
    client = _client(socket_path, holder, authority, coordinates)
    _enroll(client, registrar, holder, coordinates, authority_fixture["clock"].value)

    # The contenders intentionally use distinct local state directories.  Only
    # their enrolled holder credential and the shared authority coordinate join them.
    (tmp_path / "holder-state-b").mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(3)
    results = context.Queue()
    arguments = (
        str(socket_path),
        str(holder_path),
        holder.key_id,
        authority.key_id,
        authority.public_key,
        coordinates,
        gate,
        results,
    )
    workers = [context.Process(target=_race_worker, args=arguments) for _ in range(2)]
    for worker in workers:
        worker.start()
    gate.wait()
    outcomes = [results.get(timeout=10)[0] for _ in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(outcomes) == ["conflict", "ready"]


def test_distinct_embodiments_of_same_being_do_not_contend(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    receipts = []
    for label in ("alpha", "beta"):
        coordinates = _coordinates(label)
        holder = _key(tmp_path / f"{label}/holder.pem", f"holder-{label}")
        client = _client(
            authority_fixture["socket"],
            holder,
            authority_fixture["authority"],
            coordinates,
        )
        _enroll(
            client,
            authority_fixture["registrar"],
            holder,
            coordinates,
            authority_fixture["clock"].value,
        )
        receipts.append(client.acquire())
    assert receipts[0]["being_ref"] == receipts[1]["being_ref"]
    assert receipts[0]["resource_ref"] != receipts[1]["resource_ref"]


def test_receipt_tamper_hostile_holder_replay_and_outage_fail_closed(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("secure")
    holder = _key(tmp_path / "secure/holder.pem", "holder-secure")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    hostile = _key(tmp_path / "hostile/holder.pem", "holder-hostile")
    hostile_client = _client(
        authority_fixture["socket"],
        hostile,
        authority_fixture["authority"],
        coordinates,
    )
    with pytest.raises(AdmissionError, match="absent|unknown"):
        hostile_client.acquire()
    _enroll(
        client,
        authority_fixture["registrar"],
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    receipt = client.acquire()
    copied_session = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    assert copied_session.current() is None
    with pytest.raises(AdmissionConflict, match="session"):
        copied_session.renew()
    with pytest.raises(AdmissionConflict, match="session"):
        copied_session.release()
    copied_session.session_id = client.session_id
    with pytest.raises(AdmissionError, match="session proof"):
        copied_session.renew()
    tampered = dict(receipt)
    tampered["fencing_token"] += 1
    with pytest.raises(AdmissionUnavailable, match="signature"):
        client.verify_receipt(tampered)

    renewed = client.renew()
    assert renewed["fencing_token"] == receipt["fencing_token"] + 1
    with pytest.raises(AdmissionConflict):
        client.acquire()

    authority_fixture["server"].shutdown()
    authority_fixture["server"].server_close()
    authority_fixture["thread"].join(timeout=5)
    with pytest.raises(AdmissionUnavailable, match="unavailable"):
        client.renew()


def test_crash_expiry_restart_and_high_water_preserve_fencing_token(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("restart")
    holder = _key(tmp_path / "restart/holder.pem", "holder-restart")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    _enroll(
        client,
        authority_fixture["registrar"],
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    first = client.acquire(ttl_s=1)
    authority_fixture["server"].shutdown()
    authority_fixture["server"].server_close()
    authority_fixture["thread"].join(timeout=5)
    authority_fixture["clock"].value += 1_001

    restarted_authority = AdmissionAuthority(
        authority_fixture["state"],
        signer=authority_fixture["authority"],
        holder_registrars={
            authority_fixture["registrar"].key_id: authority_fixture[
                "registrar"
            ].public_key
        },
        clock=authority_fixture["clock"],
    )
    server = AdmissionServer(authority_fixture["socket"], restarted_authority)
    thread = serve_in_thread(server)
    authority_fixture["server"] = server
    authority_fixture["thread"] = thread
    second = client.acquire(ttl_s=10)
    assert second["fencing_token"] > first["fencing_token"]
    assert second["proof_ref"] != first["proof_ref"]
    assert admission_resource_ref(
        coordinates["being_ref"], coordinates["embodiment_id"]
    ) == second["resource_ref"]


def test_client_has_no_authority_signer_or_database(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("separation")
    holder = _key(tmp_path / "separation/holder.pem", "holder-separation")
    client = _client(
        authority_fixture["socket"],
        holder,
        authority_fixture["authority"],
        coordinates,
    )
    assert not hasattr(client, "_store")
    assert not hasattr(client, "_signer")
    assert all(
        value != authority_fixture["authority"]
        for value in vars(client).values()
    )
    assert os.stat(authority_fixture["socket"]).st_mode & 0o777 == 0o600


def test_client_network_budget_cannot_consume_lease_failure_margin(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    coordinates = _coordinates("timeout-budget")
    holder = _key(tmp_path / "budget/holder.pem", "holder-budget")
    client = AdmissionClient(
        authority_fixture["socket"],
        holder_signer=holder,
        authority_key_id=authority_fixture["authority"].key_id,
        authority_public_key=authority_fixture["authority"].public_key,
        being_ref=coordinates["being_ref"],
        body_ref=coordinates["body_ref"],
        embodiment_id=coordinates["embodiment_id"],
        incarnation_id=coordinates["incarnation_id"],
        activation_id=coordinates["activation_id"],
        credential_id=coordinates["credential_id"],
        manifest_hash=coordinates["manifest_hash"],
        timeout_s=30,
        lease_ttl_s=3,
    )
    assert client.timeout_s == pytest.approx(0.3)
    assert 2 * client.timeout_s < client.lease_ttl_s / 2


def test_trickling_response_cannot_extend_admission_round_trip(tmp_path: Path, monkeypatch) -> None:
    import clusterctl.admission as admission
    holder = _key(tmp_path / "holder.pem", "holder")
    authority = _key(tmp_path / "authority.pem", "authority")
    client = _client(tmp_path / "unused.sock", holder, authority, _coordinates("trickle"), timeout_s=0.1)
    clock = [1_000_000_000]
    class Trickle:
        reads = 0
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def settimeout(self, timeout): assert 0 < timeout <= 0.1
        def sendall(self, _): pass
        def recv(self, _):
            self.reads += 1
            clock[0] += 40_000_000
            return b" " if self.reads < 10 else b""
    connection = Trickle()
    monkeypatch.setattr(admission.time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(AdmissionEndpoint, "connect", lambda self, timeout: connection)
    with pytest.raises(AdmissionUnavailable, match="deadline expired"):
        client.current()
    assert connection.reads <= 3


def test_late_valid_signature_cannot_report_admission_success(authority_fixture, tmp_path: Path, monkeypatch) -> None:
    import json
    import clusterctl.admission as admission
    holder = _key(tmp_path / "late-holder.pem", "late-holder")
    authority = authority_fixture["authority"]
    coordinates = _coordinates("late-signature")
    client = _client(authority_fixture["socket"], holder, authority, coordinates, timeout_s=0.1)
    _enroll(client, authority_fixture["registrar"], holder, coordinates, authority_fixture["clock"]())
    clock = [1_000_000_000]
    verify = admission._verify_ed25519
    def delayed_verify(payload, signature, public_key):
        valid = verify(payload, signature, public_key)
        if public_key == authority.public_key and json.loads(payload).get("schema") == admission.RESPONSE_SCHEMA:
            assert valid
            clock[0] += 200_000_000
        return valid
    monkeypatch.setattr(admission.time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(admission, "_verify_ed25519", delayed_verify)
    with pytest.raises(AdmissionUnavailable, match="deadline expired"):
        client.current()


def test_authenticated_tcp_endpoint_is_network_capable_and_pinned(
    tmp_path: Path,
) -> None:
    now_ms = time.time_ns() // 1_000_000
    authority_signer = _key(tmp_path / "authority.pem", "tcp-authority")
    registrar = _key(tmp_path / "registrar.pem", "tcp-registrar")
    holder = _key(tmp_path / "holder.pem", "tcp-holder")
    authority = AdmissionAuthority(
        tmp_path / "authority-state",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
        clock=MutableClock(now_ms),
    )
    server = AdmissionTCPServer(("127.0.0.1", 0), authority)
    thread = serve_in_thread(server)
    endpoint = AdmissionEndpoint.network("127.0.0.1", server.server_address[1])
    coordinates = _coordinates("tcp")
    client = _client(endpoint, holder, authority_signer, coordinates)
    try:
        _enroll(client, registrar, holder, coordinates, now_ms)
        assert client.acquire(ttl_s=10)["resource_ref"] == admission_resource_ref(
            coordinates["being_ref"], coordinates["embodiment_id"]
        )
        wrong_authority = _key(tmp_path / "wrong.pem", "wrong-authority")
        impostor_view = _client(endpoint, holder, wrong_authority, coordinates)
        with pytest.raises(AdmissionUnavailable, match="binding|signature"):
            impostor_view.current()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fence_client_commits_and_recovers_one_exact_signed_successor(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("handoff")
    holder = _key(tmp_path / "holder/handoff.pem", "holder-handoff")
    enrollment_client = _client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    _enroll(
        enrollment_client, registrar, holder, coordinates,
        authority_fixture["clock"].value,
    )
    client = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    resource_ref = "cluster:exclusive-volume:handoff-home"

    acquire = client.prepare(resource_ref, operation="acquire", ttl_s=30)
    acquired = client.commit(acquire)
    assert acquired["fencing_token"] == 0
    assert acquired["evidence"]["authorization_ref"] == acquire["authorization_ref"]

    renew = client.prepare(resource_ref, operation="renew", ttl_s=30)
    renewed = client.commit(renew)
    replay = client.commit(renew)
    assert replay["proof_ref"] == renewed["proof_ref"]
    assert replay["fencing_token"] == 1
    assert client.position(resource_ref) == {
        "resource_ref": resource_ref,
        "epoch": 1,
        "proof": renewed["proof_ref"],
        "current": True,
    }


def test_fence_prepared_ttl_tamper_fails_before_authority_mutation(
    authority_fixture: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("ttl-binding")
    holder = _key(tmp_path / "holder/ttl-binding.pem", "holder-ttl-binding")
    enrollment_client = _client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    _enroll(
        enrollment_client,
        registrar,
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    client = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    resource_ref = "cluster:exclusive-volume:ttl-binding-home"
    client.commit(client.prepare(resource_ref, operation="acquire", ttl_s=60))
    prepared = client.prepare(resource_ref, operation="renew", ttl_s=60)
    before = client.position(resource_ref)
    renew_calls = 0
    store = authority_fixture["server"].authority._store
    real_renew = store.renew

    def counted_renew(*args, **kwargs):
        nonlocal renew_calls
        renew_calls += 1
        return real_renew(*args, **kwargs)

    monkeypatch.setattr(store, "renew", counted_renew)
    tampered = copy.deepcopy(prepared)
    tampered["ttl_s"] = 300
    with pytest.raises(AdmissionError, match="binding"):
        client.commit(tampered)
    assert renew_calls == 0
    assert client.position(resource_ref) == before

    with pytest.raises(AdmissionError, match="binding"):
        client._call(
            "fence-renew",
            **client._coordinates(),
            resource_ref=resource_ref,
            expected_epoch=prepared["expected_position"]["epoch"],
            expected_proof=prepared["expected_position"]["proof"],
            authorization=prepared["authorization"],
            ttl_s=300,
        )
    assert renew_calls == 1
    assert client.position(resource_ref) == before

    renew_calls = 0
    committed = client.commit(prepared)
    replay = client.commit(prepared)
    assert renew_calls == 1
    assert replay["proof_ref"] == committed["proof_ref"]


def test_every_prepared_semantic_field_is_exactly_bound_before_mutation(
    authority_fixture: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("prepared-binding")
    holder = _key(
        tmp_path / "holder/prepared-binding.pem", "holder-prepared-binding"
    )
    enrollment_client = _client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    _enroll(
        enrollment_client,
        registrar,
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    client = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    resource_ref = "cluster:exclusive-volume:prepared-binding-home"
    client.commit(client.prepare(resource_ref, operation="acquire", ttl_s=60))
    prepared = client.prepare(resource_ref, operation="renew", ttl_s=60)
    before = client.position(resource_ref)
    renew_calls = 0
    store = authority_fixture["server"].authority._store
    real_renew = store.renew

    def counted_renew(*args, **kwargs):
        nonlocal renew_calls
        renew_calls += 1
        return real_renew(*args, **kwargs)

    monkeypatch.setattr(store, "renew", counted_renew)
    cases = {
        "schema": ("schema", "dm.cluster.fence-mutation-prepared/v1"),
        "operation": ("operation", "release"),
        "resource": ("resource_ref", resource_ref + ":other"),
        "predecessor-resource": (
            "expected_position.resource_ref",
            resource_ref + ":other",
        ),
        "predecessor-epoch": ("expected_position.epoch", 99),
        "predecessor-proof": ("expected_position.proof", "wrong-proof"),
        "predecessor-current": ("expected_position.current", False),
        "successor": ("successor_epoch", 99),
        "ttl": ("ttl_s", 300),
        "authorization-schema": (
            "authorization.schema",
            "resource-fence-holder-authorization/v1",
        ),
        "authorization-operation": ("authorization.operation", "release"),
        "authorization-body": ("authorization.body_ref", "cluster:body:other"),
        "authorization-embodiment": (
            "authorization.embodiment_id",
            "dm:embodiment:other",
        ),
        "authorization-incarnation": (
            "authorization.incarnation_id",
            "dm:incarnation:other",
        ),
        "authorization-resource": (
            "authorization.resource_ref",
            resource_ref + ":other",
        ),
        "authorization-key-id": ("authorization.holder_key_id", "other-key"),
        "authorization-key": ("authorization.holder_pubkey", "ssh-ed25519 bad"),
        "authorization-epoch": ("authorization.expected_epoch", 99),
        "authorization-proof": ("authorization.expected_proof", "wrong-proof"),
        "authorization-current": ("authorization.expected_current", False),
        "authorization-ttl": ("authorization.fence_ttl_s", 300),
        "authorization-issued": ("authorization.issued_ms", 1),
        "authorization-expiry": ("authorization.expires_at_ms", 2),
        "authorization-nonce": ("authorization.nonce", "other-nonce"),
        "authorization-signature": ("authorization.signature", "ED25519:bad"),
        "authorization-ref": ("authorization_ref", "cluster:fence-proof:v1:bad"),
    }
    for label, (path, replacement) in cases.items():
        tampered = copy.deepcopy(prepared)
        owner: dict[str, Any] = tampered
        segments = path.split(".")
        for segment in segments[:-1]:
            owner = owner[segment]
        owner[segments[-1]] = replacement
        with pytest.raises(AdmissionError, match="malformed|binding") as raised:
            client.commit(tampered)
        assert raised.value, label
        assert renew_calls == 0, label
        assert client.position(resource_ref) == before, label


def test_release_response_loss_recovers_exact_tombstone_after_client_restart(
    authority_fixture: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("release-recovery")
    holder = _key(
        tmp_path / "holder/release-recovery.pem", "holder-release-recovery"
    )
    enrollment_client = _client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    _enroll(
        enrollment_client,
        registrar,
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    client = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    resource_ref = "cluster:exclusive-volume:release-recovery-home"
    acquired = client.commit(
        client.prepare(resource_ref, operation="acquire", ttl_s=60)
    )
    predecessor = client.position(resource_ref)
    prepared = client.prepare(resource_ref, operation="release")
    different_request = client.prepare(resource_ref, operation="release")
    release_calls = 0
    store = authority_fixture["server"].authority._store
    real_release = store.release

    def counted_release(*args, **kwargs):
        nonlocal release_calls
        release_calls += 1
        return real_release(*args, **kwargs)

    monkeypatch.setattr(store, "release", counted_release)
    real_call = client._call

    class LostReleaseResponse(BaseException):
        pass

    def lose_release_response(action: str, **values):
        result = real_call(action, **values)
        if action == "fence-release":
            raise LostReleaseResponse
        return result

    monkeypatch.setattr(client, "_call", lose_release_response)
    with pytest.raises(LostReleaseResponse):
        client.commit(prepared)
    assert release_calls == 1
    assert client.position(resource_ref) == {
        "resource_ref": resource_ref,
        "epoch": predecessor["epoch"] + 1,
        "proof": store.position(resource_ref)["proof"],
        "current": False,
    }

    restarted = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    recovered = restarted.commit(prepared)
    replay = restarted.commit(prepared)
    assert release_calls == 1
    assert recovered["action"] == "release"
    assert replay["proof_ref"] == recovered["proof_ref"]
    assert recovered["fencing_token"] == prepared["successor_epoch"]
    assert (
        recovered["evidence"]["authorization_ref"]
        == prepared["authorization_ref"]
    )

    altered = copy.deepcopy(prepared)
    altered["authorization_ref"] = "cluster:fence-proof:v1:altered"
    with pytest.raises(AdmissionError, match="binding"):
        restarted.commit(altered)
    with pytest.raises(AdmissionConflict, match="exact release recovery binding"):
        restarted.commit(different_request)
    assert release_calls == 1

    impostor_coordinates = _coordinates("release-impostor")
    impostor = _key(tmp_path / "holder/release-impostor.pem", "release-impostor")
    impostor_enrollment = _client(
        authority_fixture["socket"], impostor, authority, impostor_coordinates
    )
    _enroll(
        impostor_enrollment,
        registrar,
        impostor,
        impostor_coordinates,
        authority_fixture["clock"].value,
    )
    impostor_client = _fence_client(
        authority_fixture["socket"], impostor, authority, impostor_coordinates
    )
    impostor_authorization = create_holder_authorization(
        impostor,
        operation="release",
        body_ref=impostor_coordinates["body_ref"],
        embodiment_id=impostor_coordinates["embodiment_id"],
        incarnation_id=impostor_coordinates["incarnation_id"],
        resource_ref=resource_ref,
        expected_epoch=predecessor["epoch"],
        expected_proof=predecessor["proof"],
        expected_current=True,
        fence_ttl_s=None,
        nonce="release-impostor-request",
    )
    impostor_prepared = {
        "schema": FenceMutationClient.PREPARED_SCHEMA,
        "operation": "release",
        "resource_ref": resource_ref,
        "expected_position": predecessor,
        "successor_epoch": predecessor["epoch"] + 1,
        "authorization": impostor_authorization,
        "authorization_ref": impostor_client.proof_ref(impostor_authorization),
        "ttl_s": None,
    }
    with pytest.raises(AdmissionConflict, match="holder does not match"):
        impostor_client.commit(impostor_prepared)
    assert release_calls == 1

    reacquired = restarted.commit(
        restarted.prepare(resource_ref, operation="acquire", ttl_s=60)
    )
    assert reacquired["fencing_token"] == prepared["successor_epoch"] + 1
    assert restarted.position(resource_ref)["current"] is True
    assert acquired["fencing_token"] == predecessor["epoch"]


def test_release_recovery_requires_fresh_holder_proof_and_rejects_replay(
    authority_fixture: dict[str, Any], tmp_path: Path
) -> None:
    authority = authority_fixture["authority"]
    registrar = authority_fixture["registrar"]
    coordinates = _coordinates("release-proof")
    holder = _key(tmp_path / "holder/release-proof.pem", "holder-release-proof")
    enrollment_client = _client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    _enroll(
        enrollment_client,
        registrar,
        holder,
        coordinates,
        authority_fixture["clock"].value,
    )
    client = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    resource_ref = "cluster:exclusive-volume:release-proof-home"
    client.commit(client.prepare(resource_ref, operation="acquire", ttl_s=60))
    prepared = client.prepare(resource_ref, operation="release")
    released = client.commit(prepared)

    class PublicOnlySigner:
        key_id = holder.key_id
        public_key = holder.public_key

        @staticmethod
        def verify(data: bytes, signature: str, public_key: str) -> bool:
            return holder.verify(data, signature, public_key)

        @staticmethod
        def sign(_data: bytes) -> str:
            raise RuntimeError("holder private key is unavailable")

    public_only = _fence_client(
        authority_fixture["socket"], PublicOnlySigner(), authority, coordinates  # type: ignore[arg-type]
    )
    public_calls: list[str] = []
    public_call = public_only._call

    def observe_public_call(action: str, **values):
        public_calls.append(action)
        return public_call(action, **values)

    public_only._call = observe_public_call  # type: ignore[method-assign]
    with pytest.raises(AdmissionError, match="proof of possession"):
        public_only.commit(prepared)
    assert public_calls == ["fence-recovery-challenge"]

    legitimate = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    recovery = copy.deepcopy(prepared)
    challenge = legitimate._call(
        "fence-recovery-challenge",
        **legitimate._coordinates(),
        resource_ref=resource_ref,
        recovery=recovery,
    )
    proof = {
        "schema": FENCE_RECOVERY_PROOF_SCHEMA,
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["challenge_nonce"],
        "session_id": legitimate.session_id,
        "recovery": recovery,
    }
    proof["signature"] = holder.sign(_canonical(proof))

    substituted_session = _fence_client(
        authority_fixture["socket"], holder, authority, coordinates
    )
    with pytest.raises(AdmissionError, match="proof binding"):
        substituted_session._call(
            "fence-last",
            **substituted_session._coordinates(),
            resource_ref=resource_ref,
            recovery_proof=proof,
        )
    observed = legitimate._call(
        "fence-last",
        **legitimate._coordinates(),
        resource_ref=resource_ref,
        recovery_proof=proof,
    )
    receipt = legitimate.verify_fence_receipt(
        observed["receipt"], resource_ref=resource_ref, expected_action="release"
    )
    assert receipt["proof_ref"] == released["proof_ref"]
    with pytest.raises(AdmissionError, match="absent or replayed"):
        legitimate._call(
            "fence-last",
            **legitimate._coordinates(),
            resource_ref=resource_ref,
            recovery_proof=proof,
        )

    challenge = legitimate._call(
        "fence-recovery-challenge",
        **legitimate._coordinates(),
        resource_ref=resource_ref,
        recovery=recovery,
    )
    altered_proof = {
        "schema": FENCE_RECOVERY_PROOF_SCHEMA,
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": "altered-challenge",
        "session_id": legitimate.session_id,
        "recovery": recovery,
    }
    altered_proof["signature"] = holder.sign(_canonical(altered_proof))
    with pytest.raises(AdmissionError, match="challenge binding"):
        legitimate._call(
            "fence-last",
            **legitimate._coordinates(),
            resource_ref=resource_ref,
            recovery_proof=altered_proof,
        )
