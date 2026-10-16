"""Shared, signed admission authority for embodiment launch fencing.

The authority owns the only mutable database and signing key. Hosts connect
through an explicitly local Unix fixture or an application-authenticated TCP
endpoint and prove possession of an explicitly enrolled holder key. The
exclusion key is exactly ``(being_ref,
embodiment_id)``: two legitimate embodiments of one being do not contend,
while two copies of one embodiment do.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import socketserver
import stat
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .fences import Ed25519Signer, FenceError
from .production_fences import (
    AUTHORIZATION_SCHEMA,
    MAX_FENCE_TTL_S,
    ProductionFenceStore,
    _verify_ed25519,
    create_holder_authorization,
    ed25519_fingerprint,
)

REQUEST_SCHEMA = "dm.cluster.admission-request/v1"
RESPONSE_SCHEMA = "dm.cluster.admission-response/v1"
RECEIPT_SCHEMA = "dm.cluster.admission-receipt/v1"
FENCE_RECEIPT_SCHEMA = "dm.cluster.fence-mutation-receipt/v1"
FENCE_MUTATION_PREPARED_SCHEMA = "dm.cluster.fence-mutation-prepared/v2"
FENCE_RECOVERY_CHALLENGE_SCHEMA = "dm.cluster.fence-recovery-challenge/v1"
FENCE_RECOVERY_PROOF_SCHEMA = "dm.cluster.fence-recovery-proof/v1"
FENCE_RECOVERY_CHALLENGE_TTL_MS = 30_000
MAX_MESSAGE_BYTES = 1024 * 1024
DEFAULT_LEASE_TTL_S = 15


class AdmissionError(RuntimeError):
    """Stable failure at the shared admission boundary."""


class AdmissionConflict(AdmissionError):
    """Another live holder owns the exact embodiment coordinate."""


class AdmissionUnavailable(AdmissionError):
    """The authority could not be reached or returned an invalid response."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {key: item for key, item in value.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_release_recovery(
    recovery: Any, binding: Mapping[str, Any]
) -> dict[str, Any]:
    """Recompute every signed release-recovery binding at the authority."""

    if not isinstance(recovery, dict) or set(recovery) != {
        "schema",
        "operation",
        "resource_ref",
        "expected_position",
        "successor_epoch",
        "authorization",
        "authorization_ref",
        "ttl_s",
    }:
        raise AdmissionError("release recovery binding is malformed")
    position = recovery.get("expected_position")
    authorization = recovery.get("authorization")
    resource_ref = recovery.get("resource_ref")
    authorization_fields = {
        "schema",
        "operation",
        "body_ref",
        "embodiment_id",
        "incarnation_id",
        "resource_ref",
        "holder_key_id",
        "holder_pubkey",
        "expected_epoch",
        "expected_proof",
        "expected_current",
        "fence_ttl_s",
        "issued_ms",
        "expires_at_ms",
        "nonce",
        "signature",
    }
    if (
        recovery.get("schema") != FENCE_MUTATION_PREPARED_SCHEMA
        or recovery.get("operation") != "release"
        or not isinstance(resource_ref, str)
        or not resource_ref
        or recovery.get("ttl_s") is not None
        or not isinstance(position, dict)
        or set(position) != {"resource_ref", "epoch", "proof", "current"}
        or position.get("resource_ref") != resource_ref
        or position.get("current") is not True
        or isinstance(position.get("epoch"), bool)
        or not isinstance(position.get("epoch"), int)
        or (
            position.get("proof") is not None
            and not isinstance(position.get("proof"), str)
        )
        or isinstance(recovery.get("successor_epoch"), bool)
        or recovery.get("successor_epoch") != position.get("epoch", -2) + 1
        or not isinstance(authorization, dict)
        or set(authorization) != authorization_fields
        or authorization.get("schema") != AUTHORIZATION_SCHEMA
        or authorization.get("operation") != "release"
        or authorization.get("body_ref") != binding.get("body_ref")
        or authorization.get("embodiment_id") != binding.get("embodiment_id")
        or authorization.get("incarnation_id") != binding.get("incarnation_id")
        or authorization.get("resource_ref") != resource_ref
        or authorization.get("holder_key_id") != binding.get("holder_key_id")
        or authorization.get("holder_pubkey") != binding.get("holder_pubkey")
        or authorization.get("expected_epoch") != position.get("epoch")
        or authorization.get("expected_proof") != position.get("proof")
        or authorization.get("expected_current") is not True
        or authorization.get("fence_ttl_s") is not None
        or not isinstance(authorization.get("nonce"), str)
        or not authorization.get("nonce")
        or not isinstance(authorization.get("signature"), str)
        or not _verify_ed25519(
            _canonical(authorization),
            str(authorization.get("signature")),
            str(binding.get("holder_pubkey")),
        )
        or recovery.get("authorization_ref")
        != ProductionFenceStore.proof_ref(authorization)
    ):
        raise AdmissionError("release recovery binding is invalid")
    return dict(recovery)


def _session_public(private_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")


def _session_signature(private_key: Any, request: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in request.items() if key != "session_signature"}
    return Ed25519Signer.PREFIX + base64.b64encode(
        private_key.sign(_canonical(payload))
    ).decode("ascii")


@dataclass(frozen=True)
class AdmissionEndpoint:
    """Explicit authority transport.

    Unix sockets are local fixtures only.  TCP is the network-capable transport;
    application-layer Ed25519 request/response authentication makes it safe to
    test without relying on host identity or transport locality.
    """

    transport: str
    address: str
    port: int | None = None

    @classmethod
    def local_fixture(cls, path: str | Path) -> AdmissionEndpoint:
        return cls("unix-local-fixture", os.path.abspath(path))

    @classmethod
    def network(cls, host: str, port: int) -> AdmissionEndpoint:
        if not host or isinstance(port, bool) or not 1 <= port <= 65535:
            raise AdmissionError("admission network endpoint is invalid")
        return cls("tcp-authenticated", host, port)

    def connect(self, timeout_s: float) -> socket.socket:
        if self.transport == "unix-local-fixture" and self.port is None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            target: Any = self.address
        elif self.transport == "tcp-authenticated" and self.port is not None:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target = (self.address, self.port)
        else:
            raise AdmissionError("admission endpoint transport is unsupported")
        try:
            connection.settimeout(timeout_s)
            connection.connect(target)
        except BaseException:
            connection.close()
            raise
        return connection


def admission_resource_ref(being_ref: str, embodiment_id: str) -> str:
    """Return a collision-resistant resource name for the exact logical key."""

    if not isinstance(being_ref, str) or not being_ref:
        raise AdmissionError("admission being reference is invalid")
    if not isinstance(embodiment_id, str) or not embodiment_id:
        raise AdmissionError("admission embodiment id is invalid")
    encoded = json.dumps(
        [being_ref, embodiment_id], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "embodiment-admission:sha256:" + hashlib.sha256(encoded).hexdigest()


def _lease_expiry(evidence: Mapping[str, Any]) -> int:
    created = evidence.get("created_ms")
    ttl_s = evidence.get("ttl_s")
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or isinstance(ttl_s, bool)
        or not isinstance(ttl_s, int)
        or ttl_s < 0
    ):
        raise AdmissionError("admission evidence time is invalid")
    return created + ttl_s * 1000


class AdmissionAuthority:
    """Key-owning dispatcher.  Keep this object inside the authority process."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        signer: Ed25519Signer,
        holder_registrars: Mapping[str, str],
        database_path: str | Path | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self._signer = signer
        arguments: dict[str, Any] = {
            "signer": signer,
            "key_id": signer.key_id,
            "database_path": database_path,
            "holder_registrars": holder_registrars,
        }
        if clock is not None:
            arguments["clock"] = clock
        self._store = ProductionFenceStore(state_dir, **arguments)
        self._recovery_challenges: dict[str, dict[str, Any]] = {}
        self._recovery_challenges_lock = threading.Lock()

    @property
    def authority_key_id(self) -> str:
        return self._signer.key_id

    @property
    def authority_public_key(self) -> str:
        return self._signer.public_key

    def _binding(self, request: Mapping[str, Any]) -> dict[str, Any]:
        holder_key_id = request.get("holder_key_id")
        if not isinstance(holder_key_id, str) or not holder_key_id:
            raise AdmissionError("admission holder key id is invalid")
        binding = self._store.holder_binding(holder_key_id)
        expected = {
            key: request.get(key)
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "activation_id",
                "credential_id",
                "manifest_hash",
            )
        }
        if any(binding.get(key) != value for key, value in expected.items()):
            raise AdmissionError("admission holder binding mismatch")
        if binding["holder_pubkey"] != request.get("holder_pubkey"):
            raise AdmissionError("admission holder public key mismatch")
        return binding

    def _receipt(
        self,
        action: str,
        binding: Mapping[str, Any],
        evidence: Mapping[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        resource_ref = admission_resource_ref(
            str(binding["being_ref"]), str(binding["embodiment_id"])
        )
        return self._resource_receipt(
            action, binding, evidence, session_id, resource_ref=resource_ref,
            schema=RECEIPT_SCHEMA,
        )

    def _resource_receipt(
        self,
        action: str,
        binding: Mapping[str, Any],
        evidence: Mapping[str, Any],
        session_id: str,
        *,
        resource_ref: str,
        schema: str,
    ) -> dict[str, Any]:
        if evidence.get("resource_ref") != resource_ref:
            raise AdmissionError("admission evidence resource mismatch")
        if any(
            evidence.get(field) != binding[binding_field]
            for field, binding_field in (
                ("body_ref", "body_ref"),
                ("holder_embodiment_id", "embodiment_id"),
                ("holder_incarnation_id", "incarnation_id"),
                ("holder_key_id", "holder_key_id"),
            )
        ):
            raise AdmissionError("admission evidence holder mismatch")
        if (
            schema == RECEIPT_SCHEMA
            and evidence.get("renewer") != f"admission-session:{session_id}"
        ):
            raise AdmissionError("admission evidence session mismatch")
        value: dict[str, Any] = {
            "schema": schema,
            "action": action,
            "being_ref": binding["being_ref"],
            "body_ref": binding["body_ref"],
            "embodiment_id": binding["embodiment_id"],
            "incarnation_id": binding["incarnation_id"],
            "activation_id": binding["activation_id"],
            "credential_id": binding["credential_id"],
            "manifest_hash": binding["manifest_hash"],
            "holder_key_id": binding["holder_key_id"],
            "session_id": session_id,
            "resource_ref": resource_ref,
            "fencing_token": evidence["epoch"],
            "proof_ref": self._store.proof_ref(dict(evidence)),
            "lease_expires_at_ms": _lease_expiry(evidence),
            "evidence": dict(evidence),
            "authority_key_id": self._signer.key_id,
        }
        value["signature"] = self._signer.sign(_canonical(value))
        return value

    def sign_response(self, response: Mapping[str, Any]) -> dict[str, Any]:
        value = {
            **dict(response),
            "authority_key_id": self._signer.key_id,
        }
        value["signature"] = self._signer.sign(_canonical(value))
        return value

    def registrar_position(self) -> dict[str, Any]:
        return self._store.holder_registrar_position()

    def transition_registrars(
        self, desired: Mapping[str, str], *, expected_generation: int
    ) -> dict[str, Any]:
        return self._store.transition_holder_registrars(
            desired, expected_generation=expected_generation
        )

    def revoke_registrar(
        self, key_id: str, *, expected_generation: int
    ) -> dict[str, Any]:
        return self._store.revoke_holder_registrar(
            key_id, expected_generation=expected_generation
        )

    @staticmethod
    def _verify_session(request: Mapping[str, Any]) -> str:
        session_id = request.get("session_id")
        public_key = request.get("session_public_key")
        signature = request.get("session_signature")
        if (
            not isinstance(session_id, str)
            or not session_id.startswith("SHA256:")
            or not isinstance(public_key, str)
            or ed25519_fingerprint(public_key) != session_id
            or not isinstance(signature, str)
            or not _verify_ed25519(
                _canonical(
                    {
                        key: value
                        for key, value in request.items()
                        if key != "session_signature"
                    }
                ),
                signature,
                public_key,
            )
        ):
            raise AdmissionError("admission session proof is invalid")
        return session_id

    def _issue_recovery_challenge(
        self,
        recovery: Any,
        binding: Mapping[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        exact = _validate_release_recovery(recovery, binding)
        observed = time.time_ns() // 1_000_000
        challenge_id = str(uuid.uuid4())
        challenge_nonce = str(uuid.uuid4())
        expires_at_ms = observed + FENCE_RECOVERY_CHALLENGE_TTL_MS
        stored = {
            "session_id": session_id,
            "holder_key_id": binding["holder_key_id"],
            "challenge_nonce": challenge_nonce,
            "expires_at_ms": expires_at_ms,
            "recovery": exact,
        }
        with self._recovery_challenges_lock:
            self._recovery_challenges = {
                key: value
                for key, value in self._recovery_challenges.items()
                if value["expires_at_ms"] > observed
            }
            if len(self._recovery_challenges) >= 1024:
                raise AdmissionError("too many pending fence recovery challenges")
            self._recovery_challenges[challenge_id] = stored
        return {
            "schema": FENCE_RECOVERY_CHALLENGE_SCHEMA,
            "challenge_id": challenge_id,
            "challenge_nonce": challenge_nonce,
            "expires_at_ms": expires_at_ms,
            "session_id": session_id,
            "resource_ref": exact["resource_ref"],
            "successor_epoch": exact["successor_epoch"],
            "operation": "release",
            "authorization_ref": exact["authorization_ref"],
        }

    def _consume_recovery_proof(
        self,
        proof: Any,
        binding: Mapping[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        if not isinstance(proof, dict) or set(proof) != {
            "schema",
            "challenge_id",
            "challenge_nonce",
            "session_id",
            "recovery",
            "signature",
        }:
            raise AdmissionError("fence recovery proof is malformed")
        challenge_id = proof.get("challenge_id")
        if (
            proof.get("schema") != FENCE_RECOVERY_PROOF_SCHEMA
            or not isinstance(challenge_id, str)
            or not challenge_id
            or proof.get("session_id") != session_id
        ):
            raise AdmissionError("fence recovery proof binding is invalid")
        observed = time.time_ns() // 1_000_000
        with self._recovery_challenges_lock:
            challenge = self._recovery_challenges.get(challenge_id)
            if challenge is None:
                raise AdmissionError("fence recovery challenge is absent or replayed")
            if (
                challenge["session_id"] != session_id
                or challenge["holder_key_id"] != binding["holder_key_id"]
            ):
                raise AdmissionError("fence recovery challenge session mismatch")
            self._recovery_challenges.pop(challenge_id)
        if (
            challenge["expires_at_ms"] <= observed
            or proof.get("challenge_nonce") != challenge["challenge_nonce"]
            or proof.get("recovery") != challenge["recovery"]
        ):
            raise AdmissionError("fence recovery challenge binding is invalid")
        signature = proof.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(proof), signature, str(binding["holder_pubkey"])
        ):
            raise AdmissionError("fence recovery holder proof is invalid")
        return _validate_release_recovery(proof.get("recovery"), binding)

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("schema") != REQUEST_SCHEMA:
            raise AdmissionError("admission request schema is unsupported")
        action = request.get("action")
        if action == "enroll":
            enrollment = request.get("enrollment")
            if not isinstance(enrollment, dict):
                raise AdmissionError("admission enrollment is missing")
            return self._store.admit_holder(enrollment)
        session_id = self._verify_session(request)
        if action == "fence-recovery-challenge":
            binding = self._binding(request)
            return self._issue_recovery_challenge(
                request.get("recovery"), binding, session_id
            )
        if action == "position":
            resource_ref = admission_resource_ref(
                str(request.get("being_ref", "")),
                str(request.get("embodiment_id", "")),
            )
            return self._store.position(resource_ref)
        if action in {
            "fence-position", "fence-current", "fence-last", "fence-acquire",
            "fence-renew", "fence-release",
        }:
            binding = self._binding(request)
            fence_resource_ref = request.get("resource_ref")
            if not isinstance(fence_resource_ref, str) or not fence_resource_ref:
                raise AdmissionError("fence resource reference is invalid")
            if action == "fence-position":
                return self._store.position(fence_resource_ref)
            if action == "fence-last":
                recovery = self._consume_recovery_proof(
                    request.get("recovery_proof"), binding, session_id
                )
                if recovery["resource_ref"] != fence_resource_ref:
                    raise AdmissionError("fence recovery resource mismatch")
                evidence = self._store.last(fence_resource_ref)
                if evidence is None or any(
                    evidence.get(field) != binding[binding_field]
                    for field, binding_field in (
                        ("body_ref", "body_ref"),
                        ("holder_embodiment_id", "embodiment_id"),
                        ("holder_incarnation_id", "incarnation_id"),
                        ("holder_key_id", "holder_key_id"),
                    )
                ):
                    raise AdmissionConflict("release recovery holder does not match")
                evidence_operation = evidence.get("operation")
                if evidence_operation not in {"acquire", "renew", "release"}:
                    raise AdmissionError("last fence evidence operation is invalid")
                position = recovery["expected_position"]
                predecessor_matches = (
                    evidence.get("epoch") == position["epoch"]
                    and self._store.proof_ref(evidence) == position["proof"]
                    and evidence.get("state") == "held"
                )
                successor_matches = (
                    evidence.get("epoch") == recovery["successor_epoch"]
                    and evidence_operation == "release"
                    and evidence.get("state") == "released"
                    and evidence.get("authorization_ref")
                    == recovery["authorization_ref"]
                )
                if not predecessor_matches and not successor_matches:
                    raise AdmissionConflict(
                        "authority position is not the exact release recovery binding"
                    )
                return {
                    "present": True,
                    "resource_ref": fence_resource_ref,
                    "receipt": self._resource_receipt(
                        str(evidence_operation),
                        binding,
                        evidence,
                        session_id,
                        resource_ref=fence_resource_ref,
                        schema=FENCE_RECEIPT_SCHEMA,
                    ),
                }
            if action == "fence-current":
                evidence = self._store.verify_current(fence_resource_ref)
                if evidence is None:
                    return {"current": False, "resource_ref": fence_resource_ref}
                if any(
                    evidence.get(field) != binding[binding_field]
                    for field, binding_field in (
                        ("body_ref", "body_ref"),
                        ("holder_embodiment_id", "embodiment_id"),
                        ("holder_incarnation_id", "incarnation_id"),
                        ("holder_key_id", "holder_key_id"),
                    )
                ):
                    return {"current": False, "resource_ref": fence_resource_ref}
                return {
                    "current": True,
                    "receipt": self._resource_receipt(
                        "current", binding, evidence, session_id,
                        resource_ref=fence_resource_ref, schema=FENCE_RECEIPT_SCHEMA,
                    ),
                }
            operation = str(action).removeprefix("fence-")
            authorization = request.get("authorization")
            expected_epoch = request.get("expected_epoch")
            expected_proof = request.get("expected_proof")
            if operation == "acquire":
                evidence = self._store.acquire(
                    fence_resource_ref,
                    str(binding["holder_pubkey"]),
                    ed25519_fingerprint(str(binding["holder_pubkey"])),
                    ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                    renewer=f"fence-session:{session_id}",
                    holder_embodiment_id=str(binding["embodiment_id"]),
                    body_ref=str(binding["body_ref"]),
                    holder_incarnation_id=str(binding["incarnation_id"]),
                    holder_key_id=str(binding["holder_key_id"]),
                    expected_epoch=expected_epoch,
                    expected_proof=expected_proof,
                    authorization=(
                        authorization if isinstance(authorization, dict) else None
                    ),
                )
            else:
                current = self._store.get(fence_resource_ref)
                if current is None or any(
                    current.get(field) != binding[binding_field]
                    for field, binding_field in (
                        ("body_ref", "body_ref"),
                        ("holder_embodiment_id", "embodiment_id"),
                        ("holder_incarnation_id", "incarnation_id"),
                        ("holder_key_id", "holder_key_id"),
                    )
                ):
                    raise AdmissionConflict("enrolled holder does not own the fence")
                if operation == "renew":
                    evidence = self._store.renew(
                        fence_resource_ref,
                        new_ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                        expected_epoch=expected_epoch,
                        expected_proof=expected_proof,
                        authorization=(
                            authorization if isinstance(authorization, dict) else None
                        ),
                    )
                else:
                    evidence = self._store.release(
                        fence_resource_ref,
                        expected_epoch=expected_epoch,
                        expected_proof=expected_proof,
                        authorization=(
                            authorization if isinstance(authorization, dict) else None
                        ),
                    )
            if evidence is None:
                raise AdmissionError("fence mutation returned no evidence")
            return self._resource_receipt(
                operation, binding, evidence, session_id,
                resource_ref=fence_resource_ref, schema=FENCE_RECEIPT_SCHEMA,
            )
        if action == "current":
            binding = self._binding(request)
            resource_ref = admission_resource_ref(
                str(binding["being_ref"]), str(binding["embodiment_id"])
            )
            evidence = self._store.verify_current(resource_ref)
            if evidence is None:
                return {"current": False, "resource_ref": resource_ref}
            if evidence.get("renewer") != f"admission-session:{session_id}":
                return {"current": False, "resource_ref": resource_ref}
            return {
                "current": True,
                "receipt": self._receipt("current", binding, evidence, session_id),
            }
        if action not in {"acquire", "renew", "release"}:
            raise AdmissionError("admission action is unsupported")
        binding = self._binding(request)
        resource_ref = admission_resource_ref(
            str(binding["being_ref"]), str(binding["embodiment_id"])
        )
        authorization = request.get("authorization")
        expected_epoch = request.get("expected_epoch")
        expected_proof = request.get("expected_proof")
        if action == "acquire":
            evidence = self._store.acquire(
                resource_ref,
                str(binding["holder_pubkey"]),
                ed25519_fingerprint(str(binding["holder_pubkey"])),
                ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                renewer=f"admission-session:{session_id}",
                holder_embodiment_id=str(binding["embodiment_id"]),
                body_ref=str(binding["body_ref"]),
                holder_incarnation_id=str(binding["incarnation_id"]),
                holder_key_id=str(binding["holder_key_id"]),
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        elif action == "renew":
            current = self._store.get(resource_ref)
            if (
                current is None
                or current.get("renewer") != f"admission-session:{session_id}"
            ):
                raise AdmissionConflict("admission session does not own the lease")
            evidence = self._store.renew(
                resource_ref,
                new_ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        else:
            current = self._store.get(resource_ref)
            if (
                current is None
                or current.get("renewer") != f"admission-session:{session_id}"
            ):
                raise AdmissionConflict("admission session does not own the lease")
            evidence = self._store.release(
                resource_ref,
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        if evidence is None:
            raise AdmissionError("admission mutation returned no evidence")
        return self._receipt(str(action), binding, evidence, session_id)


class _AdmissionRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        if not raw or len(raw) > MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
            return
        request_id: str | None = None
        try:
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise AdmissionError("admission request is malformed")
            candidate = request.get("request_id")
            request_id = candidate if isinstance(candidate, str) else None
            result = self.server.authority.dispatch(request)  # type: ignore[attr-defined]
            response = self.server.authority.sign_response({  # type: ignore[attr-defined]
                "schema": RESPONSE_SCHEMA,
                "request_id": request_id,
                "ok": True,
                "result": result,
            })
        except (AdmissionError, FenceError, KeyError, TypeError, ValueError) as exception:
            name = type(exception).__name__
            response = self.server.authority.sign_response({  # type: ignore[attr-defined]
                "schema": RESPONSE_SCHEMA,
                "request_id": request_id,
                "ok": False,
                "error": name,
                "message": str(exception),
            })
        try:
            self.wfile.write(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
        except (BrokenPipeError, ConnectionResetError):
            # The signed mutation may already be durable when a bounded client
            # abandons a slow response.  Recovery is handled by the idempotent
            # client protocol; the fixture server must not leak a thread-level
            # traceback during that normal response-loss boundary.
            return


class AdmissionServer(socketserver.ThreadingUnixStreamServer):
    """Owner-only, same-host fixture service around an admission authority."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str | Path, authority: AdmissionAuthority):
        self.socket_path = Path(os.path.abspath(socket_path))
        parent = self.socket_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise AdmissionError("admission socket directory is not owner-only")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise AdmissionError("admission socket path already exists")
        self.authority = authority
        super().__init__(str(self.socket_path), _AdmissionRequestHandler)
        self.socket_path.chmod(0o600)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        if hasattr(socket, "SO_PEERCRED"):
            import struct

            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
            if uid != os.geteuid():
                connection.close()
                raise AdmissionError("admission peer uid is unauthorized")
        return connection, address

    def server_close(self) -> None:
        super().server_close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


class AdmissionTCPServer(socketserver.ThreadingTCPServer):
    """Network-capable authority endpoint with signed application messages."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self, address: tuple[str, int], authority: AdmissionAuthority
    ) -> None:
        self.authority = authority
        super().__init__(address, _AdmissionRequestHandler)


class AdmissionClient:
    """Holder-only client; contains neither authority signing key nor database."""

    def __init__(
        self,
        endpoint: AdmissionEndpoint | str | Path,
        *,
        holder_signer: Ed25519Signer,
        authority_key_id: str,
        authority_public_key: str,
        being_ref: str,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        activation_id: str,
        credential_id: str,
        manifest_hash: str,
        timeout_s: float = 2.0,
        lease_ttl_s: int = DEFAULT_LEASE_TTL_S,
        deadline_ns: int | None = None,
    ):
        if timeout_s <= 0 or timeout_s > 30:
            raise AdmissionError("admission client timeout is invalid")
        if deadline_ns is not None and (type(deadline_ns) is not int or deadline_ns <= 0):
            raise AdmissionError("admission client deadline is invalid")
        self.deadline_ns = deadline_ns
        if (
            isinstance(lease_ttl_s, bool)
            or not isinstance(lease_ttl_s, int)
            or not 3 <= lease_ttl_s <= 300
        ):
            raise AdmissionError("admission client lease TTL is invalid")
        self.endpoint = (
            endpoint
            if isinstance(endpoint, AdmissionEndpoint)
            else AdmissionEndpoint.local_fixture(endpoint)
        )
        # A new, in-memory-only session key is created for every launch.  The
        # identifier is its fingerprint and is never accepted without proof of
        # possession, so copying holder custody plus a receipt/session id cannot
        # renew a running body's lease.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._session_private_key = Ed25519PrivateKey.generate()
        self.session_public_key = _session_public(self._session_private_key)
        self.session_id = ed25519_fingerprint(self.session_public_key)
        self.holder_signer = holder_signer
        self.authority_key_id = authority_key_id
        self.authority_public_key = authority_public_key
        self.being_ref = being_ref
        self.body_ref = body_ref
        self.embodiment_id = embodiment_id
        self.incarnation_id = incarnation_id
        self.activation_id = activation_id
        self.credential_id = credential_id
        self.manifest_hash = manifest_hash
        # Renew performs at most two authority round trips (position + CAS).
        # Bounding each round trip to one tenth of the lease makes network
        # failure observable well before the supervisor's hard kill margin.
        self.timeout_s = min(timeout_s, lease_ttl_s / 10)
        self.lease_ttl_s = lease_ttl_s

    def _coordinates(self) -> dict[str, Any]:
        return {
            "holder_key_id": self.holder_signer.key_id,
            "holder_pubkey": self.holder_signer.public_key,
            "being_ref": self.being_ref,
            "body_ref": self.body_ref,
            "embodiment_id": self.embodiment_id,
            "incarnation_id": self.incarnation_id,
            "activation_id": self.activation_id,
            "credential_id": self.credential_id,
            "manifest_hash": self.manifest_hash,
            "session_id": self.session_id,
            "session_public_key": self.session_public_key,
        }

    def _call(self, action: str, **values: Any) -> Any:
        deadline_ns = time.monotonic_ns() + int(self.timeout_s * 1_000_000_000)
        if self.deadline_ns is not None:
            deadline_ns = min(deadline_ns, self.deadline_ns)

        def remaining() -> float:
            budget = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if budget <= 0:
                raise AdmissionUnavailable("admission round-trip deadline expired")
            return budget

        request_id = str(uuid.uuid4())
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "action": action,
            **values,
        }
        if action != "enroll":
            request["session_id"] = self.session_id
            request["session_public_key"] = self.session_public_key
            request["session_signature"] = _session_signature(
                self._session_private_key, request
            )
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        ) + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise AdmissionError("admission request is too large")
        try:
            with self.endpoint.connect(remaining()) as connection:
                connection.settimeout(remaining())
                connection.sendall(encoded)
                chunks = bytearray()
                while not chunks.endswith(b"\n"):
                    connection.settimeout(remaining())
                    chunk = connection.recv(65536)
                    remaining()
                    if not chunk:
                        break
                    chunks.extend(chunk)
                    if len(chunks) > MAX_MESSAGE_BYTES:
                        raise AdmissionUnavailable("admission response is too large")
        except (OSError, TimeoutError) as exception:
            remaining()
            raise AdmissionUnavailable("admission authority is unavailable") from exception
        try:
            response = json.loads(chunks)
        except (json.JSONDecodeError, UnicodeDecodeError) as exception:
            raise AdmissionUnavailable("admission response is malformed") from exception
        if (
            not isinstance(response, dict)
            or response.get("schema") != RESPONSE_SCHEMA
            or response.get("request_id") != request_id
            or response.get("authority_key_id") != self.authority_key_id
        ):
            raise AdmissionUnavailable("admission response binding mismatch")
        signature = response.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(response), signature, self.authority_public_key
        ):
            raise AdmissionUnavailable("admission response signature is invalid")
        remaining()
        if response.get("ok") is not True:
            if response.get("error") in {"AdmissionConflict", "FenceConflict"}:
                raise AdmissionConflict(str(response.get("message")))
            raise AdmissionError(str(response.get("message", "admission refused")))
        return response.get("result")

    def enroll(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        result = self._call("enroll", enrollment=enrollment)
        if not isinstance(result, dict) or result.get("admitted") is not True:
            raise AdmissionUnavailable("admission enrollment response is invalid")
        return result

    def _position(self) -> dict[str, Any]:
        result = self._call(
            "position", being_ref=self.being_ref, embodiment_id=self.embodiment_id
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("epoch"), int)
            or not isinstance(result.get("current"), bool)
            or result.get("resource_ref")
            != admission_resource_ref(self.being_ref, self.embodiment_id)
        ):
            raise AdmissionUnavailable("admission position response is invalid")
        return result

    def position(self) -> dict[str, Any]:
        """Return the authority-signed global position for this coordinate."""

        return dict(self._position())

    def _mutation(self, action: str, *, ttl_s: int | None = None) -> dict[str, Any]:
        position = self._position()
        resource_ref = str(position["resource_ref"])
        if action != "release" and (
            isinstance(ttl_s, bool)
            or not isinstance(ttl_s, int)
            or not 1 <= ttl_s <= MAX_FENCE_TTL_S
        ):
            raise AdmissionError("admission lease TTL is out of bounds")
        authorization = create_holder_authorization(
            self.holder_signer,
            operation=action,
            body_ref=self.body_ref,
            embodiment_id=self.embodiment_id,
            incarnation_id=self.incarnation_id,
            resource_ref=resource_ref,
            expected_epoch=position["epoch"],
            expected_proof=position.get("proof"),
            expected_current=bool(position.get("current")),
            fence_ttl_s=ttl_s,
            nonce=str(uuid.uuid4()),
        )
        values = {
            **self._coordinates(),
            "expected_epoch": position["epoch"],
            "expected_proof": position.get("proof"),
            "authorization": authorization,
        }
        if ttl_s is not None:
            values["ttl_s"] = ttl_s
        result = self._call(action, **values)
        return self.verify_receipt(result, expected_action=action)

    def acquire(self, *, ttl_s: int = DEFAULT_LEASE_TTL_S) -> dict[str, Any]:
        return self._mutation("acquire", ttl_s=ttl_s)

    def renew(self, *, ttl_s: int = DEFAULT_LEASE_TTL_S) -> dict[str, Any]:
        return self._mutation("renew", ttl_s=ttl_s)

    def release(self) -> dict[str, Any]:
        return self._mutation("release")

    def current(self) -> dict[str, Any] | None:
        result = self._call("current", **self._coordinates())
        if not isinstance(result, dict) or not isinstance(result.get("current"), bool):
            raise AdmissionUnavailable("admission current response is invalid")
        if result["current"] is False:
            return None
        return self.verify_receipt(result.get("receipt"), expected_action="current")

    def verify_receipt(
        self, receipt: Any, *, expected_action: str | None = None
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
            raise AdmissionUnavailable("admission receipt is malformed")
        expected = {
            **{
                key: value
                for key, value in self._coordinates().items()
                if key not in {"holder_pubkey", "session_public_key"}
            },
            "resource_ref": admission_resource_ref(self.being_ref, self.embodiment_id),
            "authority_key_id": self.authority_key_id,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise AdmissionUnavailable("admission receipt binding mismatch")
        if expected_action is not None and receipt.get("action") != expected_action:
            raise AdmissionUnavailable("admission receipt action mismatch")
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(receipt), signature, self.authority_public_key
        ):
            raise AdmissionUnavailable("admission receipt signature is invalid")
        evidence = receipt.get("evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("resource_ref") != expected["resource_ref"]
            or evidence.get("epoch") != receipt.get("fencing_token")
            or ProductionFenceStore.proof_ref(evidence) != receipt.get("proof_ref")
            or _lease_expiry(evidence) != receipt.get("lease_expires_at_ms")
        ):
            raise AdmissionUnavailable("admission receipt evidence is inconsistent")
        return dict(receipt)


class FenceMutationClient(AdmissionClient):
    """Signed holder client for arbitrary concrete-resource fence mutation.

    Unlike :class:`ResourceFenceStore`, this object never opens an authority
    database.  A mutation is split into a durable, serializable preparation
    and an exact CAS commit.  Retrying a prepared mutation after response loss
    adopts only the authority-signed successor whose ``authorization_ref`` is
    bound to the exact prepared holder signature.
    """

    PREPARED_SCHEMA = FENCE_MUTATION_PREPARED_SCHEMA

    def embodiment_current(self) -> dict[str, Any] | None:
        return AdmissionClient.current(self)

    def position(self, resource_ref: str | None = None) -> dict[str, Any]:
        if resource_ref is None:
            return AdmissionClient.position(self)
        result = self._call(
            "fence-position", **self._coordinates(), resource_ref=resource_ref
        )
        if (
            not isinstance(result, dict)
            or result.get("resource_ref") != resource_ref
            or isinstance(result.get("epoch"), bool)
            or not isinstance(result.get("epoch"), int)
            or not isinstance(result.get("current"), bool)
        ):
            raise AdmissionUnavailable("fence position response is invalid")
        return dict(result)

    def current(self, resource_ref: str | None = None) -> dict[str, Any] | None:
        if resource_ref is None:
            return AdmissionClient.current(self)
        result = self._call(
            "fence-current", **self._coordinates(), resource_ref=resource_ref
        )
        if not isinstance(result, dict) or not isinstance(result.get("current"), bool):
            raise AdmissionUnavailable("fence current response is invalid")
        if result["current"] is False:
            return None
        return self.verify_fence_receipt(
            result.get("receipt"), resource_ref=resource_ref, expected_action="current"
        )

    def prepare(
        self, resource_ref: str, *, operation: str = "renew", ttl_s: int | None = None
    ) -> dict[str, Any]:
        if operation not in {"acquire", "renew", "release"}:
            raise AdmissionError("fence mutation operation is invalid")
        position = self.position(resource_ref)
        if ttl_s is None:
            ttl_s = self.lease_ttl_s
        mutation_ttl_s = None if operation == "release" else ttl_s
        if operation != "release" and (
            isinstance(mutation_ttl_s, bool)
            or not isinstance(mutation_ttl_s, int)
            or not 1 <= mutation_ttl_s <= MAX_FENCE_TTL_S
        ):
            raise AdmissionError("fence lease TTL is out of bounds")
        authorization = create_holder_authorization(
            self.holder_signer,
            operation=operation,
            body_ref=self.body_ref,
            embodiment_id=self.embodiment_id,
            incarnation_id=self.incarnation_id,
            resource_ref=resource_ref,
            expected_epoch=position["epoch"],
            expected_proof=position.get("proof"),
            expected_current=bool(position.get("current")),
            fence_ttl_s=mutation_ttl_s,
            nonce=str(uuid.uuid4()),
        )
        return {
            "schema": self.PREPARED_SCHEMA,
            "operation": operation,
            "resource_ref": resource_ref,
            "expected_position": position,
            "successor_epoch": position["epoch"] + 1,
            "authorization": authorization,
            "authorization_ref": ProductionFenceStore.proof_ref(authorization),
            "ttl_s": mutation_ttl_s,
        }

    def _validate_prepared(
        self,
        prepared: Mapping[str, Any],
    ) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
        if set(prepared) != {
            "schema",
            "operation",
            "resource_ref",
            "expected_position",
            "successor_epoch",
            "authorization",
            "authorization_ref",
            "ttl_s",
        } or prepared.get("schema") != self.PREPARED_SCHEMA:
            raise AdmissionError("prepared fence mutation is malformed")
        operation = prepared.get("operation")
        resource_ref = prepared.get("resource_ref")
        position = prepared.get("expected_position")
        authorization = prepared.get("authorization")
        ttl_s = prepared.get("ttl_s")
        authorization_fields = {
            "schema",
            "operation",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "resource_ref",
            "holder_key_id",
            "holder_pubkey",
            "expected_epoch",
            "expected_proof",
            "expected_current",
            "fence_ttl_s",
            "issued_ms",
            "expires_at_ms",
            "nonce",
            "signature",
        }
        if (
            operation not in {"acquire", "renew", "release"}
            or not isinstance(resource_ref, str)
            or not resource_ref
            or not isinstance(position, dict)
            or set(position) != {"resource_ref", "epoch", "proof", "current"}
            or position.get("resource_ref") != resource_ref
            or not isinstance(authorization, dict)
            or set(authorization) != authorization_fields
            or authorization.get("operation") != operation
            or authorization.get("body_ref") != self.body_ref
            or authorization.get("embodiment_id") != self.embodiment_id
            or authorization.get("incarnation_id") != self.incarnation_id
            or authorization.get("resource_ref") != resource_ref
            or authorization.get("holder_key_id") != self.holder_signer.key_id
            or authorization.get("holder_pubkey") != self.holder_signer.public_key
            or authorization.get("expected_epoch") != position.get("epoch")
            or authorization.get("expected_proof") != position.get("proof")
            or authorization.get("expected_current") != position.get("current")
            or authorization.get("fence_ttl_s") != ttl_s
            or not isinstance(authorization.get("nonce"), str)
            or not authorization.get("nonce")
            or not isinstance(authorization.get("signature"), str)
            or not self.holder_signer.verify(
                _canonical(authorization),
                str(authorization.get("signature")),
                self.holder_signer.public_key,
            )
            or prepared.get("authorization_ref")
            != ProductionFenceStore.proof_ref(authorization)
            or isinstance(position.get("epoch"), bool)
            or not isinstance(position.get("epoch"), int)
            or not isinstance(position.get("current"), bool)
            or (
                position.get("proof") is not None
                and not isinstance(position.get("proof"), str)
            )
            or isinstance(prepared.get("successor_epoch"), bool)
            or prepared.get("successor_epoch") != position.get("epoch", -2) + 1
            or (
                operation in {"renew", "release"}
                and position.get("current") is not True
            )
            or (
                operation == "release" and ttl_s is not None
            )
            or (
                operation != "release"
                and (
                    isinstance(ttl_s, bool)
                    or not isinstance(ttl_s, int)
                    or not 1 <= ttl_s <= MAX_FENCE_TTL_S
                )
            )
        ):
            raise AdmissionError("prepared fence mutation binding is invalid")
        return str(operation), resource_ref, position, authorization

    def recover(self, prepared: Mapping[str, Any]) -> dict[str, Any] | None:
        """Read-only recovery of one exact already-committed successor.

        ``None`` means the signed predecessor is still current and the caller
        may submit the CAS.  Any other position is a conflict; it is never
        repaired by sending another mutation.
        """

        operation, resource_ref, position, _authorization = self._validate_prepared(
            prepared
        )
        receipt = (
            self._last(prepared)
            if operation == "release"
            else self.current(resource_ref)
        )
        if receipt is None:
            if position.get("current") is False:
                return None
            raise AdmissionConflict("prepared fence predecessor is no longer current")
        evidence = receipt["evidence"]
        if (
            receipt.get("fencing_token") == position.get("epoch")
            and receipt.get("proof_ref") == position.get("proof")
        ):
            return None
        if (
            receipt.get("fencing_token") == prepared.get("successor_epoch")
            and evidence.get("authorization_ref") == prepared.get("authorization_ref")
            and evidence.get("operation") == operation
            and (operation != "release" or evidence.get("state") == "released")
        ):
            return receipt
        raise AdmissionConflict("authority position is not the exact prepared successor")

    def commit(self, prepared: Mapping[str, Any]) -> dict[str, Any]:
        operation, resource_ref, position, authorization = self._validate_prepared(
            prepared
        )
        recovered = self.recover(prepared)
        if recovered is not None:
            return recovered
        values: dict[str, Any] = {
            **self._coordinates(),
            "resource_ref": resource_ref,
            "expected_epoch": position["epoch"],
            "expected_proof": position.get("proof"),
            "authorization": authorization,
        }
        if operation != "release":
            values["ttl_s"] = prepared.get("ttl_s")
        receipt: dict[str, Any]
        try:
            result = self._call(f"fence-{operation}", **values)
            receipt = self.verify_fence_receipt(
                result, resource_ref=resource_ref, expected_action=str(operation)
            )
        except AdmissionError:
            # The authority may have committed and lost the response.  Query
            # through the same authenticated channel and accept only the exact
            # successor bound to these prepared authorization bytes.
            recovered = self.recover(prepared)
            if recovered is None:
                raise
            receipt = recovered
        evidence = receipt["evidence"]
        if (
            receipt.get("fencing_token") != prepared["successor_epoch"]
            or evidence.get("authorization_ref") != prepared["authorization_ref"]
            or evidence.get("operation") != operation
        ):
            raise AdmissionConflict("authority did not commit the exact fence successor")
        return receipt

    def verify_fence_receipt(
        self, receipt: Any, *, resource_ref: str, expected_action: str | None
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or receipt.get("schema") != FENCE_RECEIPT_SCHEMA:
            raise AdmissionUnavailable("fence mutation receipt is malformed")
        expected = {
            **{
                key: value
                for key, value in self._coordinates().items()
                if key not in {"holder_pubkey", "session_public_key"}
            },
            "resource_ref": resource_ref,
            "authority_key_id": self.authority_key_id,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise AdmissionUnavailable("fence mutation receipt binding mismatch")
        if expected_action is None:
            if receipt.get("action") not in {"acquire", "renew", "release"}:
                raise AdmissionUnavailable("fence mutation receipt action mismatch")
        elif receipt.get("action") != expected_action:
            raise AdmissionUnavailable("fence mutation receipt action mismatch")
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(receipt), signature, self.authority_public_key
        ):
            raise AdmissionUnavailable("fence mutation receipt signature is invalid")
        evidence = receipt.get("evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("resource_ref") != resource_ref
            or evidence.get("epoch") != receipt.get("fencing_token")
            or ProductionFenceStore.proof_ref(evidence) != receipt.get("proof_ref")
            or _lease_expiry(evidence) != receipt.get("lease_expires_at_ms")
        ):
            raise AdmissionUnavailable("fence mutation receipt evidence is inconsistent")
        return dict(receipt)

    def _last(self, prepared: Mapping[str, Any]) -> dict[str, Any] | None:
        resource_ref = str(prepared["resource_ref"])
        recovery = dict(prepared)
        challenge = self._call(
            "fence-recovery-challenge",
            **self._coordinates(),
            resource_ref=resource_ref,
            recovery=recovery,
        )
        if (
            not isinstance(challenge, dict)
            or set(challenge)
            != {
                "schema",
                "challenge_id",
                "challenge_nonce",
                "expires_at_ms",
                "session_id",
                "resource_ref",
                "successor_epoch",
                "operation",
                "authorization_ref",
            }
            or challenge.get("schema") != FENCE_RECOVERY_CHALLENGE_SCHEMA
            or challenge.get("session_id") != self.session_id
            or challenge.get("resource_ref") != resource_ref
            or challenge.get("successor_epoch") != prepared.get("successor_epoch")
            or challenge.get("operation") != "release"
            or challenge.get("authorization_ref")
            != prepared.get("authorization_ref")
            or not isinstance(challenge.get("challenge_id"), str)
            or not isinstance(challenge.get("challenge_nonce"), str)
            or isinstance(challenge.get("expires_at_ms"), bool)
            or not isinstance(challenge.get("expires_at_ms"), int)
        ):
            raise AdmissionUnavailable("fence recovery challenge is invalid")
        proof = {
            "schema": FENCE_RECOVERY_PROOF_SCHEMA,
            "challenge_id": challenge["challenge_id"],
            "challenge_nonce": challenge["challenge_nonce"],
            "session_id": self.session_id,
            "recovery": recovery,
        }
        try:
            proof["signature"] = self.holder_signer.sign(_canonical(proof))
        except Exception as exception:
            raise AdmissionError(
                "fence recovery holder proof of possession is unavailable"
            ) from exception
        result = self._call(
            "fence-last",
            **self._coordinates(),
            resource_ref=resource_ref,
            recovery_proof=proof,
        )
        if not isinstance(result, dict) or not isinstance(result.get("present"), bool):
            raise AdmissionUnavailable("fence last response is invalid")
        if result.get("resource_ref") != resource_ref:
            raise AdmissionUnavailable("fence last resource binding mismatch")
        if result["present"] is False:
            return None
        return self.verify_fence_receipt(
            result.get("receipt"), resource_ref=resource_ref, expected_action=None
        )

    # Read facade used by handoff code.  No local database is ever consulted.
    @staticmethod
    def proof_ref(value: dict[str, Any]) -> str:
        return ProductionFenceStore.proof_ref(value)

    def get(self, resource_ref: str) -> dict[str, Any] | None:
        receipt = self.current(resource_ref)
        return None if receipt is None else dict(receipt["evidence"])

    def verify_current(self, resource_ref: str) -> dict[str, Any] | None:
        return self.get(resource_ref)

    def status(self, resource_ref: str) -> dict[str, Any]:
        receipt = self.current(resource_ref)
        if receipt is None:
            position = self.position(resource_ref)
            return {
                "resource_ref": resource_ref,
                "present": False,
                "expired": False,
                "last_epoch": position["epoch"],
                "proof": position.get("proof"),
            }
        evidence = receipt["evidence"]
        return {
            "resource_ref": resource_ref,
            "present": True,
            "expired": False,
            "last_epoch": evidence["epoch"],
            "acquired_ms": evidence.get("acquired_ms"),
            "holder_embodiment_id": evidence.get("holder_embodiment_id"),
            "holder_incarnation_id": evidence.get("holder_incarnation_id"),
            "holder_key_id": evidence.get("holder_key_id"),
            "proof": receipt["proof_ref"],
        }

def serve_in_thread(
    server: AdmissionServer | AdmissionTCPServer,
) -> threading.Thread:
    """Start a disposable authority server; primarily useful to local harnesses."""

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    endpoint = parser.add_mutually_exclusive_group(required=True)
    endpoint.add_argument("--socket", type=Path)
    endpoint.add_argument("--listen-host")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--authority-key", type=Path, required=True)
    parser.add_argument("--authority-key-id", required=True)
    parser.add_argument("--registrar-key-id", required=True)
    parser.add_argument("--registrar-public-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    registrar_public_key = args.registrar_public_key_file.read_text(
        encoding="ascii"
    ).strip()
    authority = AdmissionAuthority(
        args.state_dir,
        signer=Ed25519Signer(args.authority_key, args.authority_key_id),
        holder_registrars={args.registrar_key_id: registrar_public_key},
    )
    if args.socket is not None:
        if args.listen_port is not None:
            parser.error("--listen-port requires --listen-host")
        server: AdmissionServer | AdmissionTCPServer = AdmissionServer(
            args.socket, authority
        )
    else:
        if args.listen_port is None:
            parser.error("--listen-host requires --listen-port")
        server = AdmissionTCPServer((args.listen_host, args.listen_port), authority)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_LEASE_TTL_S",
    "FENCE_RECEIPT_SCHEMA",
    "RECEIPT_SCHEMA",
    "AdmissionAuthority",
    "AdmissionClient",
    "AdmissionConflict",
    "AdmissionEndpoint",
    "AdmissionError",
    "AdmissionServer",
    "AdmissionTCPServer",
    "AdmissionUnavailable",
    "FenceMutationClient",
    "admission_resource_ref",
    "main",
    "serve_in_thread",
]
