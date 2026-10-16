"""Receiving-owned holder custody for the maintained shared admission service.

Matrix identity comes from the verified native runtime. This adapter only binds
that identity to a separate physical holder key; it never creates Matrix IDs.
The host registrar receives public proof, never the receiving private key.
"""
from __future__ import annotations

import time
import uuid
import subprocess
from collections.abc import Callable
from typing import TYPE_CHECKING

from . import being_seed
from .admission import AdmissionClient, AdmissionEndpoint
from .admission_supervisor import AdmissionSupervisor
from .fences import Ed25519Signer, _canonical
from .onboarding import OnboardingError, digest, private_directory, validate_plan
from .production_fences import (
    AUTHORIZATION_SCHEMA, _verify_ed25519, create_holder_authorization,
    create_holder_enrollment, ed25519_fingerprint,
)

if TYPE_CHECKING:
    from .onboarding_target import Target

SCHEMA = "cluster-onboarding-admission-holder/v1"
REQUEST_SCHEMA = "cluster-onboarding-admission-request/v1"
COORDINATES = {"being_ref", "body_ref", "embodiment_id", "incarnation_id",
               "activation_id", "credential_id", "manifest_hash"}


def coordinates(target: Target) -> dict:
    """Derive public enrollment coordinates from verified current authority."""
    from daimon_matrix import identity, operator_rebirth
    from .onboarding_target import document
    if target.observe()["phase"] != "v8":
        raise OnboardingError("current_onboarding_target_required")
    bundle = document(target.package / "runtime/runtime.json")
    authority = operator_rebirth.authority_from_runtime_bundle(bundle)
    origin = bundle["local_origin"]
    authority.validate_origin(origin, require_active=True)
    member = authority.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    credential = authority.credentials[member["embodiment_credential_id"]]
    authorization = authority.incarnations[member["incarnation_authorization_id"]]
    now = time.time_ns() // 1_000_000
    identity.verify_embodiment_credential(credential, authority.state, at_ms=now)
    identity.verify_incarnation_authorization(authorization, credential, authority.state, at_ms=now)
    return dict(being_ref=authority.manifest.being_ref, body_ref=origin["body_ref"],
                embodiment_id=origin["embodiment_id"], incarnation_id=origin["incarnation_id"],
                activation_id=document(target.package / "activation.json")["activation_id"],
                credential_id=credential["artifact_id"], manifest_hash=authority.manifest.digest)


class ReceivingHolder:
    def __init__(self, target: Target):
        self.target = target
        self.root = target.root / "admission"
        self.key = self.root / "holder.pem"

    def _binding(self) -> dict:
        return dict(schema=SCHEMA, plan_digest=digest(self.target.plan), coordinates=coordinates(self.target))

    def prepare(self) -> dict:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from daimon_matrix import canonical, keystore
        from .onboarding_target import document
        private_directory(self.target.root)
        with being_seed._locked(self.target.root):
            binding = self._binding()
            private_directory(self.root, create=True)
            marker = self.root / "binding.json"
            descriptor = self.root / "holder.json"
            if not marker.exists():
                if any(self.root.iterdir()):
                    raise OnboardingError("existing_onboarding_admission_preserved")
                keystore._atomic_write(marker, canonical.canonical_bytes(binding))
            if document(marker) != binding:
                raise OnboardingError("existing_onboarding_admission_preserved")
            if not self.key.exists():
                if descriptor.exists():
                    raise OnboardingError("existing_onboarding_admission_preserved")
                raw = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                keystore._atomic_write(self.key, raw)
            signer = Ed25519Signer(self.key, "onboarding-holder:" + digest(self.target.plan))
            public = dict(schema=SCHEMA, plan_digest=binding["plan_digest"], coordinates=binding["coordinates"],
                          holder_key_id=signer.key_id, holder_pubkey=signer.public_key)
            if descriptor.exists():
                if document(descriptor) != public:
                    raise OnboardingError("existing_onboarding_admission_preserved")
            else:
                keystore._atomic_write(descriptor, canonical.canonical_bytes(public))
            return public

    @staticmethod
    def _budget(deadline_ns: int | None) -> None:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')

    def request(self, *, deadline_ns: int | None = None) -> dict:
        self._budget(deadline_ns)
        public = self.prepare()
        signer = Ed25519Signer(self.key, public["holder_key_id"])
        origin = public["coordinates"]
        proof = create_holder_authorization(signer, operation="acquire",
            body_ref=origin["body_ref"], embodiment_id=origin["embodiment_id"], incarnation_id=origin["incarnation_id"],
            resource_ref="onboarding-holder:" + digest(self.target.plan), expected_epoch=-1,
            expected_proof=None, expected_current=False, fence_ttl_s=15, nonce=str(uuid.uuid4()))
        self._budget(deadline_ns)
        return dict(schema=REQUEST_SCHEMA, holder=public, proof=proof)

    def client(self, endpoint: AdmissionEndpoint, *, authority_key_id: str,
               authority_public_key: str, lease_ttl_s: int = 15,
               deadline_ns: int | None = None) -> AdmissionClient:
        public = self.prepare()
        return AdmissionClient(endpoint, holder_signer=Ed25519Signer(self.key, public["holder_key_id"]),
            authority_key_id=authority_key_id, authority_public_key=authority_public_key,
            lease_ttl_s=lease_ttl_s, deadline_ns=deadline_ns, **public["coordinates"])

    def configured_client(self, configuration: dict, *, deadline_ns: int | None = None) -> AdmissionClient:
        """Bind host public configuration to this body's existing holder."""
        fields = {'schema', 'plan_digest', 'endpoint', 'authority_key_id',
                  'authority_public_key', 'lease_ttl_s', 'enrollment'}
        if (set(configuration) != fields
                or configuration['schema'] != 'cluster-onboarding-admission-profile/v1'
                or configuration['plan_digest'] != digest(self.target.plan)
                or not isinstance(configuration['endpoint'], dict)
                or set(configuration['endpoint']) != {'transport', 'host', 'port'}
                or configuration['endpoint']['transport'] != 'tcp-authenticated'
                or not isinstance(configuration['enrollment'], dict)
                or not isinstance(configuration['authority_key_id'], str)
                or not configuration['authority_key_id']
                or type(configuration['lease_ttl_s']) is not int
                or not 3 <= configuration['lease_ttl_s'] <= 300):
            raise OnboardingError('onboarding_admission_profile_rejected')
        ed25519_fingerprint(configuration['authority_public_key'])
        public = self.prepare()
        expected = {**public['coordinates'], 'holder_key_id': public['holder_key_id'],
                    'holder_pubkey': public['holder_pubkey']}
        if any(configuration['enrollment'].get(key) != value for key, value in expected.items()):
            raise OnboardingError('onboarding_admission_profile_rejected')
        endpoint = configuration['endpoint']
        return self.client(AdmissionEndpoint.network(endpoint['host'], endpoint['port']),
            authority_key_id=configuration['authority_key_id'],
            authority_public_key=configuration['authority_public_key'],
            lease_ttl_s=configuration['lease_ttl_s'], deadline_ns=deadline_ns)

    def ensure_enrolled(self, configuration: dict, *, enroll: bool = False,
                        deadline_ns: int | None = None) -> bool:
        """Recover a lost enrollment ACK without refreshing a registered key."""
        from .admission import AdmissionError, AdmissionConflict, AdmissionUnavailable
        self._budget(deadline_ns)
        client = self.configured_client(configuration, **({} if deadline_ns is None else {'deadline_ns': deadline_ns}))
        self._budget(deadline_ns)
        try:
            client.current()
        except AdmissionUnavailable:
            raise
        except AdmissionConflict:
            # The enrolled coordinate is held by another service session.
            self._budget(deadline_ns)
            return True
        except AdmissionError:
            if not enroll:
                self._budget(deadline_ns)
                return False
            self._budget(deadline_ns)
            client.enroll(configuration['enrollment'])
        self._budget(deadline_ns)
        return True

    def launch(self, client: AdmissionClient, spawn: Callable[[], subprocess.Popen[bytes]]) -> AdmissionSupervisor:
        """Acquire/recheck shared admission before the controlled runtime spawn.

        The caller supplies a qualified native launcher, never seed commands.
        Shared supervision retains the holder session in this parent process.
        An uncertain acquisition starts no process; its lease can be observed
        by the same client or expires before another session can acquire.
        """
        from .admission import AdmissionError
        public = self.prepare()
        expected = {**public["coordinates"], "holder_key_id": public["holder_key_id"],
                    "holder_pubkey": public["holder_pubkey"]}
        if any(client._coordinates().get(key) != value for key, value in expected.items()):
            raise OnboardingError("onboarding_admission_client_rejected")
        started = time.monotonic()
        receipt = client.acquire(ttl_s=client.lease_ttl_s)
        process = None
        supervisor = None
        try:
            current = client.current()
            if (current is None or current["session_id"] != client.session_id
                    or time.monotonic() - started >= client.lease_ttl_s / 2):
                raise OnboardingError("onboarding_admission_not_current")
            process = spawn()
            supervisor = AdmissionSupervisor(process, client, receipt, client.lease_ttl_s,
                                               lease_started_monotonic=started)
            supervisor.start()
            if supervisor.verify_current(minimum_remaining_s=client.lease_ttl_s / 4) is None:
                raise OnboardingError("onboarding_admission_not_current")
            return supervisor
        except BaseException:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            if supervisor is not None and supervisor.thread.ident is not None:
                # Supervision owns final release after its thread has started.
                # Never race its current-position exchange with another release.
                supervisor.thread.join(timeout=client.timeout_s * 4 + 2)
                raise
            try:
                client.release()
            except AdmissionError:
                pass
            raise


def enrollment(plan: dict, request: dict, expected: dict, registrar: Ed25519Signer) -> dict:
    """Host registrar verifies exact approved coordinates and native holder PoP."""
    validate_plan(plan)
    try:
        if set(expected) != COORDINATES or expected["body_ref"] != "codex:daimon-cluster:" + plan["name"]:
            raise ValueError()
        if set(request) != {"schema", "holder", "proof"} or request["schema"] != REQUEST_SCHEMA:
            raise ValueError()
        holder, proof = request["holder"], request["proof"]
        if (set(holder) != {"schema", "plan_digest", "coordinates", "holder_key_id", "holder_pubkey"}
                or holder["schema"] != SCHEMA or holder["plan_digest"] != digest(plan)
                or holder["coordinates"] != expected
                or holder["holder_key_id"] != "onboarding-holder:" + digest(plan)):
            raise ValueError()
        ed25519_fingerprint(holder["holder_pubkey"])
        fixed = dict(schema=AUTHORIZATION_SCHEMA, operation="acquire", body_ref=expected["body_ref"],
            embodiment_id=expected["embodiment_id"], incarnation_id=expected["incarnation_id"],
            resource_ref="onboarding-holder:" + digest(plan), holder_key_id=holder["holder_key_id"],
            holder_pubkey=holder["holder_pubkey"], expected_epoch=-1, expected_proof=None,
            expected_current=False, fence_ttl_s=15)
        now = time.time_ns() // 1_000_000
        if (set(proof) != set(fixed) | {"issued_ms", "expires_at_ms", "nonce", "signature"}
                or any(proof[key] != value or type(proof[key]) is not type(value) for key, value in fixed.items())
                or type(proof["issued_ms"]) is not int or type(proof["expires_at_ms"]) is not int
                or not 0 <= proof["issued_ms"] <= now < proof["expires_at_ms"]
                or proof["expires_at_ms"] - proof["issued_ms"] != 60_000
                or str(uuid.UUID(proof["nonce"])) != proof["nonce"]
                or not _verify_ed25519(_canonical(proof), proof["signature"], holder["holder_pubkey"])):
            raise ValueError()
        return create_holder_enrollment(registrar, holder_key_id=holder["holder_key_id"],
            holder_pubkey=holder["holder_pubkey"], nonce=str(uuid.uuid4()), **expected)
    except Exception:
        raise OnboardingError("onboarding_admission_request_rejected") from None


def profile(plan: dict, request: dict, expected: dict, registrar: Ed25519Signer, *,
            endpoint: AdmissionEndpoint, authority_key_id: str, authority_public_key: str,
            lease_ttl_s: int = 15) -> dict:
    """Compose host-selected public service configuration after holder proof."""
    if (endpoint.transport != "tcp-authenticated" or endpoint.port is None
            or not isinstance(authority_key_id, str) or not authority_key_id
            or type(lease_ttl_s) is not int or not 3 <= lease_ttl_s <= 300):
        raise OnboardingError("onboarding_admission_profile_rejected")
    ed25519_fingerprint(authority_public_key)
    return dict(schema="cluster-onboarding-admission-profile/v1", plan_digest=digest(plan),
        endpoint=dict(transport=endpoint.transport, host=endpoint.address, port=endpoint.port),
        authority_key_id=authority_key_id, authority_public_key=authority_public_key,
        lease_ttl_s=lease_ttl_s, enrollment=enrollment(plan,request,expected,registrar))
