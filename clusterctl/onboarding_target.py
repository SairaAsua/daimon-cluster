"""Receiving-side native target custody and runtime preparation.

Root custody stays with its authorized holder. Only signed public authority,
a body-signed request and Root authorization cross this boundary. Preparation
never means admission. Existing beings use native same-Root enrollment.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import socket
import struct
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator

from . import being_seed, onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import OnboardingError, digest, private_directory, refusal_diagnostic, validate_plan


def document(path: Path) -> dict:
    raw = onboarding_release.regular(path, uid=os.geteuid(), limit=4 * 1024**2)
    if path.stat().st_mode & 0o077:
        raise OnboardingError("private_onboarding_target_required")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OnboardingError("invalid_onboarding_target_document")
    return value


def _socket_identity(path: Path, deadline_ns: int | None):
    """Await initial socket publication inside the existing observation budget.

    This is no presence or readiness proof. The actual connection, responder,
    admission parent and loaded selection are still authenticated afterwards.
    Ordinary unbounded status keeps its immediate missing-socket refusal.
    """
    while True:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        try:
            return path.lstat()
        except FileNotFoundError:
            if deadline_ns is None:
                raise
        time.sleep(min(.05, max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)))


def profile(plan: dict) -> dict:
    validate_plan(plan)
    return dict(schema="dm.operator.rebirth-target-profile/v1", label=plan["name"] + "-codex-cluster",
                body_ref="codex:daimon-cluster:" + plan["name"],
                principal_id="principal:codex:daimon-cluster:" + plan["name"],
                listen_host="127.0.0.1", listen_port=8687,
                advertised_endpoint="http://127.0.0.1:8687/dm-peer/v1", targets=[])


class Target:
    def __init__(self, home: Path, plan: dict, genesis: dict, *, code: Path | None = None,
                 code_uid: int = 0, code_digest: str | None = None,
                 qualified_startup: dict | None = None):
        self.home = private_directory(home)
        self.plan = validate_plan(plan)
        self.genesis = genesis
        self.existing = genesis.get("schema") == "cluster-onboarding-existing-base/v1"
        if self.existing:
            from .onboarding_existing import validate_base
            validate_base(genesis, self.plan)
        self.root = home / ".local/state/daimon-onboarding" / plan["name"] / "matrix"
        self.preparation = self.root / "preparation"
        self.package = self.root / "package"
        self.credential = self.root / "credential"
        self.code = code if code is not None else Path(__file__).resolve().parents[1]
        self.code_uid = code_uid
        self.code_digest = code_digest or plan['release_digest']
        self.qualified_startup = qualified_startup

    def document_bundle(self) -> dict:
        return document(self.package / "runtime/runtime.json")

    def _reader(self) -> bytearray:
        password = self.root / "body.unlock"
        raw = onboarding_release.regular(password, uid=os.geteuid())
        if password.stat().st_mode & 0o077 or len(raw) != 64:
            raise OnboardingError("private_onboarding_target_required")
        return bytearray(raw)

    def _binding(self) -> dict:
        return dict(schema="cluster-onboarding-target/v1", plan_digest=digest(self.plan),
                    genesis_digest=digest(self.genesis))

    def _base(self):
        from daimon_matrix import operator_first_embodiment as first, operator_rebirth
        if self.existing:
            from .onboarding_existing import public_base_bundle
            return operator_rebirth.authority_from_runtime_bundle(public_base_bundle(self.genesis, self.plan))
        return first._initial_base(self.genesis)

    def _profile(self) -> dict:
        if self.existing:
            from .onboarding_existing import target_profile
            return target_profile(self.genesis, self.plan)
        return profile(self.plan)

    def _activation_authority(self, request: dict, activation: dict):
        from daimon_matrix import operator_first_embodiment as first, operator_rebirth
        if self.existing:
            return operator_rebirth.validate_activation(activation, self._base(), request=request)[1]
        return first.validate_activation(self.genesis, request, activation)[1]

    @contextmanager
    def _runtime_writer(self) -> Iterator[None]:
        from daimon_matrix import daemon
        descriptor = daemon.acquire_lock(self.package / "runtime")
        try:
            yield
        finally:
            os.close(descriptor)

    def _validate(self) -> tuple[dict, dict]:
        from daimon_matrix import operator_rebirth
        if document(self.root / "plan.json") != self._binding():
            raise OnboardingError("onboarding_target_binding_conflict")
        prepared, request = document(self.preparation / "preparation.json"), document(self.preparation / "request.json")
        verified, _, _ = operator_rebirth._validated_preparation(self.preparation, prepared, request,
            self._base(), self._reader, observed_at_ms=prepared["created_at_ms"],
            expected_targets=None if self.existing else set())
        if verified["profile"] != self._profile():
            raise OnboardingError("onboarding_target_binding_conflict")
        return verified, request

    def group_relationship(self, value: dict, *, authority_closure: dict,
                           expected_context_sha256: str | None = None,
                           membership_precondition: dict | None = None,
                           deadline_ns: int | None = None) -> dict:
        """Accept/ingest through native authentication before first managed start."""
        from .onboarding_group_admission import (
            check_retained_ledger, command, load_owner_runtime, owner_authorities, relationship_request,
        )
        value = command(value)
        with being_seed._locked(self.root), self._runtime_writer():
            check_retained_ledger(self.package / 'runtime', self.root / 'group-admission', value)
            root = self.package / 'runtime'
            authorities = owner_authorities(root, self.root / 'tribe', self.root / 'group-admission',
                value['operation_id'], authority_closure, expected_context_sha256=expected_context_sha256)
            if self._observe_receiving()['phase'] != 'v8':
                raise OnboardingError('current_onboarding_target_required')
            hosted = load_owner_runtime(root, self._reader, authorities=authorities,
                                        qualified_startup=self.qualified_startup)
            return relationship_request(root, self.root / 'group-admission', value,
                offline=hosted, deadline_ns=deadline_ns, membership_precondition=membership_precondition)

    def group_publication(self, value: dict, *, authority_closure: dict,
                          expected_context_sha256: str | None = None,
                          deadline_ns: int | None = None) -> dict:
        from .onboarding_receiving_update import bootstrap_group
        from .onboarding_group_admission import (
            check_snapshot_context, load_owner_runtime, owner_authorities, preview_owner_context,
            publication_command, publication_request,
        )
        value = publication_command(value)
        root = self.package / 'runtime'
        group = self.root / 'tribe'
        journal = self.root / 'group-admission'
        if value['action'] == 'context-preview':
            result = preview_owner_context(root, group, value['operation_id'], authority_closure,
                deadline_ns=deadline_ns)
            if expected_context_sha256 is not None and result['owner_context_sha256'] != expected_context_sha256:
                raise OnboardingError('onboarding_group_owner_context_conflict')
            return result
        with being_seed._locked(self.root), self._runtime_writer():
            check_snapshot_context(journal, value)
            authorities = owner_authorities(root, group, journal, value['operation_id'], authority_closure,
                expected_context_sha256=expected_context_sha256)
            if self._observe_receiving()['phase'] != 'v8':
                raise OnboardingError('current_onboarding_target_required')
            hosted = load_owner_runtime(root, self._reader, authorities=authorities,
                                        qualified_startup=self.qualified_startup)
            return publication_request(hosted, group, journal, value, deadline_ns=deadline_ns,
                snapshot=lambda: bootstrap_group(self, self.document_bundle()))

    def prepare(self) -> dict:
        from daimon_matrix import canonical, keystore, operator_first_embodiment as first
        current = self.home
        for part in self.root.relative_to(self.home).parts:
            current /= part
            private_directory(current, create=True)
        with being_seed._locked(self.root):
            record = self.root / "plan.json"
            if not record.exists():
                # The only possible earlier effect is creation of this lock.
                if any(path.name != "lock" and not path.name.startswith(".plan.json.tmp-")
                       for path in self.root.iterdir()):
                    raise OnboardingError("existing_onboarding_target_preserved")
                keystore._atomic_write(record, canonical.canonical_bytes(self._binding()))
            if document(record) != self._binding():
                raise OnboardingError("onboarding_target_binding_conflict")
            if self.existing:
                self._recover_request_renewal()
            password = self.root / "body.unlock"
            if not password.exists():
                if self.preparation.exists() or self.package.exists():
                    raise OnboardingError("existing_onboarding_target_preserved")
                keystore._atomic_write(password, os.urandom(32).hex().encode())
            if not self.preparation.exists():
                now = time.time_ns() // 1_000_000
                if self.existing:
                    from daimon_matrix import operator_rebirth
                    operator_rebirth.create_target_preparation(self.preparation, self._base(), self._profile(),
                        self._reader, created_at_ms=now, expires_at_ms=now + 24 * 3600000)
                else:
                    first.prepare_target(self.preparation, self.genesis, profile(self.plan), self._reader,
                                         created_at_ms=now)
            prepared, request = self._validate()
            now = time.time_ns() // 1_000_000
            if self.existing and not self.package.exists() and now >= request["body"]["expires_at_ms"]:
                self._renew_request(prepared, request, now)
                return self._validate()[1]
            return request

    def _recover_request_renewal(self) -> None:
        """Publish both native public documents after a lost acknowledgement."""
        from daimon_matrix import canonical, keystore
        transaction = self.root / "request-renewal.json"
        if not transaction.exists():
            return
        value = document(transaction)
        if set(value) != {"previous", "preparation", "request"}:
            raise OnboardingError("existing_onboarding_target_preserved")
        prior = document(self.root / "expired-requests" / (value["previous"] + ".json"))
        for name, field in (("preparation.json", "preparation"), ("request.json", "request")):
            current = document(self.preparation / name)
            if current not in (prior[field], value[field]):
                raise OnboardingError("existing_onboarding_target_preserved")
        from daimon_matrix import operator_rebirth
        operator_rebirth._validated_preparation(
            self.preparation, value["preparation"], value["request"], self._base(), self._reader,
            observed_at_ms=value["preparation"]["created_at_ms"],
        )
        for name, field in (("preparation.json", "preparation"), ("request.json", "request")):
            keystore._atomic_write(self.preparation / name, canonical.canonical_bytes(value[field]))
        transaction.unlink()

    def _renew_request(self, prepared: dict, request: dict, now: int) -> None:
        """Re-sign the native request with the same Body and transport keys."""
        from daimon_matrix import canonical, keystore, operator_rebirth
        _, keys, transport = operator_rebirth._validated_preparation(
            self.preparation, prepared, request, self._base(), self._reader,
            observed_at_ms=prepared["created_at_ms"],
        )
        slots = prepared["slots"]
        successor = operator_rebirth.create_enrollment_request(
            self._base(), signing_seed=keys[slots["signing"]],
            encryption_private=keys[slots["encryption"]],
            transport_seed=transport[slots["transport"]], **prepared["origin"],
            created_at_ms=prepared["created_at_ms"], expires_at_ms=now + 24 * 3600000,
            nonce=os.urandom(32),
        )
        updated = {**prepared, "request_id": successor["request_id"],
                   "expires_at_ms": successor["body"]["expires_at_ms"]}
        operator_rebirth._validated_preparation(
            self.preparation, updated, successor, self._base(), self._reader, observed_at_ms=now,
        )
        previous = {"preparation": prepared, "request": request}
        history = private_directory(self.root / "expired-requests", create=True)
        keystore._atomic_write(history / (digest(previous) + ".json"), canonical.canonical_bytes(previous))
        keystore._atomic_write(self.root / "request-renewal.json", canonical.canonical_bytes(
            {"previous": digest(previous), "preparation": updated, "request": successor}))
        self._recover_request_renewal()

    def activate(self, activation: dict) -> dict:
        from daimon_matrix import operator_first_embodiment as first
        private_directory(self.root)
        with being_seed._locked(self.root):
            prepared, request = self._validate()
            self._activation_authority(request, activation)
            if not self.package.exists():
                if self.existing:
                    from daimon_matrix import operator_rebirth
                    from .onboarding_existing import public_base_bundle
                    operator_rebirth.activate_target_runtime(self.package, self.preparation,
                        prepared, request, activation, public_base_bundle(self.genesis, self.plan), self._reader)
                else:
                    first.activate_runtime(self.package, self.genesis, self.preparation,
                                           prepared, request, activation, self._reader)
            elif document(self.package / "activation.json") != activation:
                raise OnboardingError("existing_onboarding_target_preserved")
            return self.observe()

    def observe(self) -> dict:
        return self._observe_receiving(include_group=True)

    def _observe_receiving(self, *, include_group: bool = False) -> dict:
        """Validate receiving identity/custody independently of group selection.

        Only retained offline owner maintenance uses this narrow observation.
        Public observe() still validates the selected group's publication pins.
        """
        if not self.root.exists() or not self.preparation.exists():
            return dict(phase="absent", request=None, receipt=None)
        if self.existing and (self.root / "request-renewal.json").exists():
            with being_seed._locked(self.root):
                self._recover_request_renewal()
        _, request = self._validate()
        if not self.package.exists():
            return dict(phase="prepared", request=request, receipt=None)
        from daimon_matrix import canonical, identity, keystore
        activation = document(self.package / "activation.json")
        authority = self._activation_authority(request, activation)
        receipt = document(self.package / "receipt.json")
        bundle = document(self.package / "runtime/runtime.json")
        original = document(self.credential / "original.json") if (self.credential / "original.json").exists() else bundle
        if (receipt["origin"] != request["body"]["origin"] or bundle["local_origin"] != receipt["origin"]
                or original["manifest"] != authority.manifest.value
                or receipt["runtime_sha256"] != hashlib.sha256(canonical.canonical_bytes(original)).hexdigest()
                or (receipt.get("empty_writable_state") is not True if self.existing
                    else receipt.get("root_seeds_in_target") is not False)):
            raise OnboardingError("onboarding_target_runtime_conflict")
        store = keystore.EncryptedKeystore(self.package / "runtime/custody.json").open(
            self._reader, minimum_counter=1, required_control_head=authority.state.head)
        if store.counter != bundle['keystore']['counter']:
            raise OnboardingError('existing_onboarding_target_preserved')
        signing = store.secrets[bundle["keystore"]["signing_slot"]]
        if identity.signing_descriptor(signing) != activation["body"]["credential"]["body"]["signing_key"]:
            raise OnboardingError("onboarding_target_runtime_conflict")
        if bundle != original:
            expected = self._credential_bundle(original, document(self.credential / "response.json"))
            if document(self.credential / "candidate.json") != expected:
                raise OnboardingError("existing_onboarding_target_preserved")
            current_receipt = self._credential_receipt(original, expected)
            complete = self.credential / "receipt.json"
            if complete.exists() and document(complete) != current_receipt:
                raise OnboardingError("onboarding_target_runtime_conflict")
            comparison, controller = self._controller_comparison(expected, bundle, store,
                activation['body']['credential']['body']['signing_key'])
            if comparison != expected:
                if (not complete.exists() or not (self.root / 'peer/accepted-private.json').is_file()
                        or set(comparison) != set(expected) or any(comparison[key] != expected[key]
                            for key in expected if key not in {'sources', 'relationships'})):
                    raise OnboardingError('existing_onboarding_target_preserved')
                from .onboarding_peer import augmented
                peer_receipt, peer_complete = augmented(self, expected, comparison)
                result: dict = dict(phase='v8' if peer_complete else 'peer-published', request=request, receipt=peer_receipt)
            else:
                result = dict(phase="v8" if complete.exists() else "v8-published", request=request, receipt=current_receipt)
            if controller is not None:
                result['receiving_controller'] = {**controller, 'historical_receipt_sha256': digest(result['receipt'])}
            if include_group and result['phase'] == 'v8':
                from .onboarding_peer import observed_group
                group = observed_group(self, bundle)
                if group is not None:
                    result['group'] = group
            return result
        return dict(phase="credential-pending" if self.existing else "v7", request=request, receipt=receipt)

    def _controller_comparison(self, expected: dict, bundle: dict, store, signing_key: dict) -> tuple[dict, dict | None]:
        """Observe the native one-controller successor without changing history.

        Normalize only for the retained credential/peer comparison. Current
        group validation and loaded evidence always use the actual bundle.
        Authenticity remains inspectable after expiry; this grants no control.
        The custody counter is an antirollback revision, not a count of controller
        issuances: renewal retains one role while advancing authenticated custody.
        Its transaction lineage is retained by the native owner/update journals.
        """
        from daimon_matrix import canonical, local_api, operator_capabilities as profiles
        fields = ('capabilities', 'operator_capability_binding', 'keystore')
        if all(bundle.get(key) == expected[key] for key in fields):
            return bundle, None
        try:
            profile = profiles.host_capability_profile('receiving-controller')
            previous = expected['capabilities']
            current = bundle['capabilities']
            if (len(current) != len(previous) + 1 or current[:-1] != previous
                    or any(row['profile'] == profile for row in previous)
                    or type(bundle['keystore'].get('counter')) is not int
                    or bundle['keystore']['counter'] <= expected['keystore']['counter']
                    or bundle['keystore'] != {**expected['keystore'], 'counter': bundle['keystore']['counter']}
                    or store.counter != bundle['keystore']['counter']):
                raise ValueError
            label = expected['runtime_label']
            slot = profiles.host_capability_slot(label, 'receiving-controller')
            row = current[-1]
            key = store.secrets[slot]
            if (len(key) != 32 or any(value == key for name, value in store.secrets.items() if name != slot)
                    or row != dict(profile=profile, runtime_id=expected['runtime_id'],
                        secret_slot=slot, descriptor=row['descriptor'])):
                raise ValueError
            for capability in current:
                local_api.LocalCapability.from_value(capability['descriptor'], store.secrets[capability['secret_slot']])
            capability = local_api.LocalCapability.from_value(row['descriptor'], key)
            if (capability.client_id != f'client:host:{label}:receiving-controller'
                    or frozenset(capability.methods) != profiles.OPTIONAL_HOST_CAPABILITY_PROFILES['receiving-controller']
                    or capability.descriptor['status'] != 'active'
                    or capability.descriptor['schema'] != local_api.CAPABILITY_SCHEMA):
                raise ValueError
            profiles.verify_operator_capability_binding(bundle['operator_capability_binding'],
                runtime_id=expected['runtime_id'], runtime_label=label,
                being_ref=expected['manifest']['being_ref'], origin=expected['local_origin'],
                signing_key=signing_key, capability_rows=current)
            directory = private_directory(self.package / 'runtime' / profile['client_directory'])
            key_path = directory / profile['client_key_filename']
            if (onboarding_release.regular(key_path, uid=os.geteuid()) != key or key_path.stat().st_mode & 0o077
                    or document(directory / profile['client_config_filename']) != dict(
                        schema='dm.local.client-config/v3', capability=capability.descriptor,
                        expected_server=expected['local_origin'], runtime_id=expected['runtime_id'], runtime_label=label)):
                raise ValueError
            comparison = {**bundle, **{field: expected[field] for field in fields}}
            observation = dict(schema='cluster-receiving-controller-observation/v1',
                runtime_sha256=hashlib.sha256(canonical.canonical_bytes(bundle)).hexdigest(),
                counter=store.counter, capability_id=capability.capability_id, control_usability='unobserved')
            return comparison, observation
        except (KeyError, TypeError, ValueError, OSError):
            raise OnboardingError('existing_onboarding_target_preserved') from None

    def credential_request(self) -> dict:
        """Persist one Body-accepted native proposal before contacting Root."""
        from daimon_matrix import canonical, keystore, operator_rebirth
        from . import onboarding_credential
        private_directory(self.root)
        with being_seed._locked(self.root), self._runtime_writer():
            observed = self.observe()
            if observed["phase"] not in {"v7", "credential-pending", "v8-published", "v8"}:
                raise OnboardingError("prepared_onboarding_target_required")
            private_directory(self.credential, create=True)
            original_path = self.credential / "original.json"
            if not original_path.exists():
                keystore._atomic_write(original_path, canonical.canonical_bytes(document(self.package / "runtime/runtime.json")))
            original = document(original_path)
            previous = operator_rebirth.authority_from_runtime_bundle(original)
            request_path = self.credential / "request.json"
            if not request_path.exists():
                if any((self.credential / name).exists() for name in ("response.json", "candidate.json", "receipt.json")):
                    raise OnboardingError("existing_onboarding_target_preserved")
                store = keystore.EncryptedKeystore(self.package / "runtime/custody.json").open(
                    self._reader, minimum_counter=1, required_control_head=previous.state.head)
                signing = store.secrets[original["keystore"]["signing_slot"]]
                request = onboarding_credential.receiving_request(previous, original["local_origin"], self.plan, signing,
                    issued_at_ms=time.time_ns() // 1_000_000)
                keystore._atomic_write(request_path, canonical.canonical_bytes(request))
            request = document(request_path)
            onboarding_credential.validate_request(previous, self.plan, request, observed_at_ms=request["issued_at_ms"])
            return request

    def _credential_bundle(self, original: dict, response: dict) -> dict:
        from daimon_matrix import operator_rebirth
        from . import onboarding_credential
        previous = operator_rebirth.authority_from_runtime_bundle(original)
        request = document(self.credential / "request.json")
        successor = onboarding_credential.verify_response(previous, self.plan, request, response)
        result = copy.deepcopy(original)
        result.update(schema="dm.runtime.bundle/v8", manifest=response["manifest"],
            credentials=list(successor.credentials.values()), incarnations=list(successor.incarnations.values()),
            authority_history=[*original["authority_history"],
                               {"manifest": previous.manifest.value, "successor": response["succession"]}])
        operator_rebirth.authority_from_runtime_bundle(result)
        return result

    def _credential_receipt(self, original: dict, candidate: dict) -> dict:
        from daimon_matrix import canonical
        return dict(schema="cluster-onboarding-credential-receipt/v1", plan_digest=digest(self.plan),
            origin=candidate["local_origin"], original_runtime_sha256=hashlib.sha256(canonical.canonical_bytes(original)).hexdigest(),
            runtime_sha256=hashlib.sha256(canonical.canonical_bytes(candidate)).hexdigest(),
            response_digest=digest(document(self.credential / "response.json")))

    def apply_credential(self, response: dict) -> dict:
        """Publish only the exact native successor while the runtime is stopped."""
        from daimon_matrix import canonical, daemon, keystore, native_egress, runtime
        private_directory(self.credential)
        with being_seed._locked(self.root):
            self.observe()
            original = document(self.credential / "original.json")
            candidate = self._credential_bundle(original, response)
            descriptor = daemon.acquire_lock(self.package / "runtime")
            try:
                current = self.package / "runtime/runtime.json"
                if document(current) not in (original, candidate):
                    raise OnboardingError("existing_onboarding_target_preserved")
                for name, value in (("response.json", response), ("candidate.json", candidate)):
                    path = self.credential / name
                    if path.exists():
                        if document(path) != value:
                            raise OnboardingError("existing_onboarding_target_preserved")
                    else:
                        keystore._atomic_write(path, canonical.canonical_bytes(value))
                if document(current) == original:
                    keystore._atomic_write(current, canonical.canonical_bytes(candidate))
                receipt = self._credential_receipt(original, candidate)
                marker = self.credential / "receipt.json"
                if marker.exists():
                    if document(marker) != receipt:
                        raise OnboardingError("existing_onboarding_target_preserved")
                else:
                    def clock() -> int:
                        return time.time_ns() // 1_000_000
                    hosted = runtime.load_runtime(self.package / "runtime", "runtime.json", self._reader, clock=clock,
                        egress=native_egress.closed_visibility(clock=clock, catalog_mode="migrate"))
                    hosted.egress.migrate_registered_catalogs(version=native_egress.VISIBILITY_SCHEMA_VERSION)
                    hosted.egress.validate_registered_catalogs()
                    keystore._atomic_write(marker, canonical.canonical_bytes(receipt))
                return self.observe()
            finally:
                os.close(descriptor)

    def serve(self, *, receive_only: bool = False, visibility_installation: Path | None = None,
              ready_descriptor: int | None = None) -> int:
        """Hand this body's verified custody to the native single-writer daemon.

        Receive-only is an explicit qualification/initial-admission choice.
        A mirrored body must supply its signed native visibility installation;
        a missing or invalid installation never falls back to closed visibility.
        Process restarts retain the package, authority and native journals.
        """
        from daimon_matrix import daemon
        if receive_only == (visibility_installation is not None):
            raise OnboardingError("onboarding_visibility_selection_required")
        if self.observe()["phase"] != "v8":
            raise OnboardingError("current_onboarding_target_required")
        # Validate/read only this receiving body's existing password. A pipe
        # keeps custody unlock material out of argv, environment and logs.
        password = self._reader()
        reader, writer = os.pipe()
        pipe_identity = os.fstat(reader)
        try:
            os.write(writer, password)
        finally:
            password[:] = b"\x00" * len(password)
            os.close(writer)
        try:
            argv = ["--state-root", str(self.package / "runtime"), "--password-fd", str(reader)]
            if receive_only:
                argv.append("--closed-visibility")
            else:
                argv += ["--visibility-installation", str(visibility_installation)]
            if ready_descriptor is not None:
                argv += ["--ready-fd", str(ready_descriptor)]
            options = {} if self.qualified_startup is None else {
                'qualified_startup': self.qualified_startup}
            return daemon.main(argv, **options)
        finally:
            # Native startup consumes/closes the FD. Early refusal may not.
            try:
                remaining = os.fstat(reader)
                if (remaining.st_dev, remaining.st_ino) == (pipe_identity.st_dev, pipe_identity.st_ino):
                    os.close(reader)
            except OSError:
                pass

    def running(self, *, admitted: bool = False, require_loaded: bool = False,
                deadline_ns: int | None = None, bootstrap_base_only: bool = False) -> dict:
        """Observe a kernel-pinned daemon and authenticate its native status.

        Admitted observations also check the current native body scope. Loaded
        observations associate the selected group with that same process/base;
        candidate equality, resource fences and communication remain separate.
        First adoption may observe only the compatible base/admission route:
        the predecessor group profile does not expose authenticated status.
        That mode never establishes group load or qualified receiving readiness.
        """
        from daimon_matrix.client import ClientConfig, LocalClient
        if bootstrap_base_only and (not admitted or require_loaded):
            raise OnboardingError('invalid_receiving_bootstrap_observation')
        if deadline_ns is not None:
            if 'deadline_ns' not in getattr(LocalClient, '__dataclass_fields__', {}):
                raise OnboardingError('qualified_onboarding_deadline_client_required')
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
        root = self.package / "runtime"
        capture = {}
        if bootstrap_base_only:
            # A current read is not another birth or archived pair ceremony.
            # Freeze only protected public/client preimages; actual native
            # identity/admission below must authenticate that same selection.
            for path in (self.root/'plan.json', root/'runtime.json', root/'client.json', root/'client.key'):
                capture[path] = hashlib.sha256(onboarding_release.regular(
                    path, uid=os.geteuid())).hexdigest()
            if document(self.root/'plan.json') != self._binding():
                raise OnboardingError('onboarding_target_binding_conflict')
            bundle = self.document_bundle()
            expected = bundle['local_origin']
            group = None
            runtime_sha256 = digest(bundle)
        else:
            prepared = self.observe()
            if prepared["phase"] != "v8":
                raise OnboardingError("current_onboarding_target_required")
            expected = prepared['receipt']['origin']
            group = prepared.get('group')
            runtime_sha256 = prepared.get('receiving_controller', prepared['receipt'])['runtime_sha256']
        socket_identity = _socket_identity(root / "matrix.sock", deadline_ns)
        key = bytearray(onboarding_release.regular(root / "client.key", uid=os.geteuid()))
        try:
            config = ClientConfig.load(root / "client.json", key)
        finally:
            key[:] = b'\0' * len(key)
        public = self._bootstrap_public_identity(bundle, config) if bootstrap_base_only else None
        from .owner_process import ConnectedProcessObserver, ParentProcessPresence, ProcessPresence
        connected = 'connection_observer' in getattr(LocalClient, '__dataclass_fields__', {})
        if (require_loaded or bootstrap_base_only) and not connected:
            raise OnboardingError('qualified_onboarding_client_required')
        with ExitStack() as stack:
            presence: ConnectedProcessObserver | ProcessPresence
            if connected:
                presence = stack.enter_context(ConnectedProcessObserver())
                options: dict = {'connection_observer': presence}
            else:
                # Retained SDKs lack the actual-connection seam. Preserve their
                # original presence probe, explicitly never receiving-qualified.
                if self.qualified_startup is not None:
                    raise OnboardingError('qualified_onboarding_client_required')
                connection = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                connection.settimeout(5)
                connection.connect(str(root / 'matrix.sock'))
                pid, uid, _gid = struct.unpack('3i', connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.geteuid():
                    raise OnboardingError('onboarding_daemon_owner_conflict')
                process = dict(uid=uid, pid=pid,
                    start_ticks=int((Path('/proc') / str(pid) / 'stat').read_text().rpartition(
                        ')')[2].split()[19]),
                    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
                presence = stack.enter_context(ProcessPresence(process))
                options = {}
            # Kernel observation covers the exact connection and authenticated
            # response. A separate empty probe cannot identify this responder.
            if deadline_ns is not None:
                options['deadline_ns'] = deadline_ns
                if time.monotonic_ns() >= deadline_ns:
                    raise OnboardingError('onboarding_observation_deadline_expired')
            client = LocalClient(root / "matrix.sock", config, timeout_seconds=40,
                                 **options)
            _, status = client.runtime_status()
            if status["ok"] is not True or any(status["server"].get(field) != value for field, value in expected.items()):
                raise OnboardingError("onboarding_daemon_origin_conflict")
            loaded = status['result'].get('loaded_runtime')
            if connected and loaded is not None and (presence.process is None
                    or loaded.get('process_id') != presence.process['pid']):
                raise OnboardingError('onboarding_daemon_responder_conflict')
            if public is not None and loaded is not None and (
                    loaded.get('runtime_bundle_sha256') != runtime_sha256
                    or loaded.get('runtime_id') != bundle['runtime_id']
                    or loaded.get('local_origin') != expected):
                raise OnboardingError('onboarding_loaded_base_conflict')
            group_status = None
            if connected and group is not None and not bootstrap_base_only:
                from daimon_matrix.operator_capabilities import host_capability_profile
                role = host_capability_profile('status')
                directory = root / role['client_directory']
                group_socket = Path(group['socket'])
                before_group = group_socket.lstat()
                group_key = bytearray(onboarding_release.regular(
                    directory / role['client_key_filename'], uid=os.geteuid()))
                group_config = ClientConfig.load(directory / role['client_config_filename'], group_key)
                hosted = LocalClient(group_socket, group_config, timeout_seconds=40, **options)
                response = hosted.runtime_status()[1]
                if response.get('ok') is not True or response['server'] != status['server']:
                    raise OnboardingError('onboarding_daemon_origin_conflict')
                group_status = response['result']
                if group_status.get('loaded_runtime') != loaded:
                    raise OnboardingError('onboarding_loaded_base_conflict')
                after_group = group_socket.lstat()
                if (before_group.st_dev, before_group.st_ino) != (after_group.st_dev, after_group.st_ino):
                    raise OnboardingError('onboarding_daemon_socket_changed')
            if require_loaded:
                from daimon_matrix.canonical import canonical_bytes
                application = None if group_status is None else group_status.get('loaded_application')
                if (not isinstance(loaded, dict) or not loaded.get('qualified_startup')
                        or not isinstance(application, dict)
                        or application.get('loaded_base_sha256') != hashlib.sha256(canonical_bytes(loaded)).hexdigest()):
                    raise OnboardingError('qualified_onboarding_loaded_view_required')
            identity = None
            if admitted:
                _, observed = client.scope_me()
                scope_result = observed.get('result')
                body = scope_result.get('body') if isinstance(scope_result, dict) else None
                if (observed.get('ok') is not True or not isinstance(body, dict) or body.get('state') != 'running'
                        or any(body.get(field) != expected[field] for field in
                               ('body_ref', 'embodiment_id', 'incarnation_id'))):
                    raise OnboardingError('onboarding_admission_not_current')
                from .onboarding_receiving_update import receiving_identity
                identity = receiving_identity(observed, status['result'], status['server'])
                if public is not None and any(identity[field] != public[selected] for field, selected in (
                        ('being_ref', 'being_ref'), ('manifest_hash', 'manifest_hash'),
                        ('credential_ref', 'credential_id'),
                        ('incarnation_authorization_ref', 'incarnation_authorization_id'))):
                    raise OnboardingError('receiving_identity_public_binding_conflict')
            parent = None
            if admitted and connected:
                child_process = presence.process
                if not isinstance(child_process, dict):
                    raise OnboardingError('onboarding_daemon_responder_conflict')
                parent = stack.enter_context(ParentProcessPresence(child_process))
            current_socket = (root / "matrix.sock").lstat()
            if (socket_identity.st_dev, socket_identity.st_ino) != (current_socket.st_dev, current_socket.st_ino):
                raise OnboardingError("onboarding_daemon_socket_changed")
            presence.verify()
            if parent is not None:
                parent.verify()
            if capture and any(hashlib.sha256(onboarding_release.regular(
                    path, uid=os.geteuid())).hexdigest() != fingerprint
                    for path, fingerprint in capture.items()):
                raise OnboardingError('receiving_bootstrap_public_preimage_changed')
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            return dict(schema="cluster-onboarding-runtime-presence/v1", plan_digest=digest(self.plan),
                origin=expected, process=presence.process, runtime_id=config.runtime_id,
                admission_parent=None if parent is None else parent.process,
                runtime_sha256=runtime_sha256,
                runtime_status=status['result'], group=group, group_runtime_status=group_status,
                receiving_identity=identity,
                receiving_readiness='unobserved',
                responder_association='same-connection' if connected else 'legacy-probe')

    @staticmethod
    def _bootstrap_public_identity(bundle: dict, config) -> dict:
        """Bind a current authorized client, without custody or loaded claims."""
        from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
        from daimon_matrix.messaging_config import _public_identity
        from daimon_matrix.operator_capabilities import verify_operator_capability_binding
        try:
            authority = authority_from_runtime_bundle(bundle)
            public = _public_identity(authority, bundle['local_origin'], bundle['runtime_id'],
                bundle['runtime_label'], time.time_ns() // 1_000_000)
            verify_operator_capability_binding(bundle['operator_capability_binding'],
                runtime_id=bundle['runtime_id'], runtime_label=bundle['runtime_label'],
                being_ref=public['being_ref'], origin=bundle['local_origin'],
                signing_key=authority.credentials[public['credential_id']]['body']['signing_key'],
                capability_rows=bundle['capabilities'])
            if (config.expected_server != bundle['local_origin']
                    or config.runtime_id != bundle['runtime_id'] or config.runtime_label != bundle['runtime_label']
                    or not any(row['descriptor'] == config.capability.descriptor for row in bundle['capabilities'])):
                raise ValueError
        except (KeyError, ValueError, TypeError):
            raise OnboardingError('receiving_bootstrap_public_binding_conflict') from None
        return public

    def receiving_control(self, action: str, path: Path, *, command: dict | None = None,
                          deadline_ns: int | None = None) -> dict:
        """Use the selected admitted group; preserve exact retained controls."""
        from .onboarding_receiving_update import owner_control
        observed = self.running(admitted=True, require_loaded=True, deadline_ns=deadline_ns)
        result = owner_control(self.package / 'runtime', observed['group'], observed,
            action, path, command=command, status_key='group_runtime_status', deadline_ns=deadline_ns)
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        return result

    def qualified_receiving_identity(self, *, expires_at_ms: int, deadline_ns: int) -> dict:
        from .onboarding_receiving_update import OwnerGroupClient
        observed = self.running(admitted=True, require_loaded=True, deadline_ns=deadline_ns)
        with OwnerGroupClient(self.package / 'runtime', Path(observed['group']['socket']),
                              deadline_ns=deadline_ns) as owner:
            current = owner.qualified_identity(expires_at_ms=expires_at_ms, require_admitted=True)
            if (current['process'] != observed['process'] or current['server'] != observed['origin']
                    or any(current['runtime_status'].get(key) != observed['group_runtime_status'].get(key)
                           for key in ('loaded_runtime', 'loaded_application'))):
                raise OnboardingError('receiving_control_process_changed')
            if time.monotonic_ns() >= deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            return {**current, 'admission_parent': observed['admission_parent'],
                    'plan_digest': observed['plan_digest'], 'responder_association': 'same-connection',
                    'group': observed['group']}



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("sdk-observe", "sdk-prepare", "prepare", "activate", "observe", "credential-prepare", "credential-apply", "serve", "running", "admission-prepare", "admitted-serve", "admission-check", "admission-enroll", "admitted-running", "peer-identity", "peer-accept", "group-relationship", "group-publication", "receiving-control-prepare", "receiving-control-apply", "receiving-control-prepare-apply", "receiving-identity", "receiving-bootstrap-freeze", "receiving-bootstrap-stage", "receiving-bootstrap-publish"))
    parser.add_argument("--diagnostics", action="store_true", help="write bounded nonsecret refusal detail to stderr")
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--credential-response", type=Path)
    parser.add_argument("--admission-profile", type=Path)
    parser.add_argument("--public-profile-json")
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--runtime-code", type=Path)
    parser.add_argument("--runtime-digest")
    parser.add_argument("--peer-packet", type=Path)
    parser.add_argument("--peer-packet-sha256")
    parser.add_argument("--peer-being-ref")
    parser.add_argument("--messaging-application", type=Path)
    visibility = parser.add_mutually_exclusive_group()
    visibility.add_argument("--receive-only", action="store_true")
    visibility.add_argument("--visibility-installation", type=Path)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument('--require-loaded', action='store_true')
    parser.add_argument('--observation-timeout-seconds', type=float)
    parser.add_argument('--observation-deadline-ns', type=int)
    parser.add_argument('--authorization-expires-at-ms', type=int)
    parser.add_argument('--control-file', type=Path)
    parser.add_argument('--control-command', type=Path)
    parser.add_argument('--identity-expires-at-ms', type=int)
    parser.add_argument('--native-tooling-json')
    parser.add_argument('--bootstrap-request-json')
    parser.add_argument('--bootstrap-ready-sha256')
    parser.add_argument('--bootstrap-timeout-seconds', type=float)
    parser.add_argument('--bootstrap-initial', action='store_true')
    parser.add_argument('--bootstrap-initial-service', action='store_true')
    parser.add_argument('--initial-context-json')
    parser.add_argument('--group-request', type=Path)
    args = parser.parse_args(argv)
    stage = 'arguments'
    probe_scope = ExitStack()
    try:
        expected_initial_context = None
        if args.initial_context_json is not None:
            from .onboarding_service import initial_context
            if args.action != 'admitted-serve' or len(args.initial_context_json.encode()) > 1024:
                raise OnboardingError('receiving_initial_context_required')
            expected_initial_context = initial_context(json.loads(args.initial_context_json))
        controlling = args.action in {'receiving-control-prepare', 'receiving-control-apply', 'receiving-control-prepare-apply'}
        identity_query = args.action == 'receiving-identity'
        grouping = args.action in {'group-relationship', 'group-publication'}
        if grouping != (args.group_request is not None) or grouping and args.ready_fd is not None:
            raise OnboardingError('onboarding_group_relationship_command_required')
        if args.native_tooling_json is not None and (not identity_query
                or len(args.native_tooling_json.encode()) > 65536):
            raise OnboardingError('receiving_native_tooling_recipe_required')
        if identity_query != (args.identity_expires_at_ms is not None):
            raise OnboardingError('invalid_receiving_identity_request')
        if identity_query and not 0 < args.identity_expires_at_ms < 2**53:
            raise OnboardingError('invalid_receiving_identity_request')
        bootstrapping = args.action.startswith('receiving-bootstrap-')
        if bootstrapping:
            if (args.bootstrap_timeout_seconds is None or not math.isfinite(args.bootstrap_timeout_seconds)
                    or not 0 < args.bootstrap_timeout_seconds <= 60 or args.ready_fd is not None
                    or (args.action == 'receiving-bootstrap-freeze') != (args.bootstrap_request_json is None)
                    or (args.action == 'receiving-bootstrap-publish') != (args.bootstrap_ready_sha256 is not None)
                    or args.bootstrap_initial and args.bootstrap_initial_service
                    or (args.bootstrap_initial or args.bootstrap_initial_service) and args.action != 'receiving-bootstrap-freeze'
                    or args.bootstrap_request_json is not None and len(args.bootstrap_request_json.encode()) > 131072):
                raise OnboardingError('invalid_receiving_bootstrap_request')
        elif args.bootstrap_initial or args.bootstrap_initial_service or any(value is not None for value in (args.bootstrap_request_json,
                args.bootstrap_ready_sha256, args.bootstrap_timeout_seconds)):
            raise OnboardingError('invalid_receiving_bootstrap_request')
        timeout = args.observation_timeout_seconds
        admitting = args.action in {'admission-prepare', 'admission-check', 'admission-enroll'}
        if (args.authorization_expires_at_ms is not None and (not admitting
                    or not 0 < args.authorization_expires_at_ms < 2**53)
                or admitting and ((timeout is None) != (args.authorization_expires_at_ms is None))):
            raise OnboardingError('invalid_receiving_observation_timeout')
        if timeout is not None and (args.action not in {'observe', 'sdk-observe', 'sdk-prepare', 'running', 'admitted-running', 'receiving-identity', 'receiving-control-prepare', 'receiving-control-apply', 'receiving-control-prepare-apply', 'group-relationship', 'group-publication', 'admission-prepare', 'admission-check', 'admission-enroll'}
                or not math.isfinite(timeout) or not 0 < timeout <= 60):
            raise OnboardingError('invalid_receiving_observation_timeout')
        if bootstrapping:
            timeout = args.bootstrap_timeout_seconds
        now_ns = time.monotonic_ns()
        observation_deadline_ns = None if timeout is None else now_ns + int(timeout * 1_000_000_000)
        if args.authorization_expires_at_ms is not None:
            observation_deadline_ns = min(observation_deadline_ns, now_ns +
                (args.authorization_expires_at_ms - time.time_ns() // 1_000_000) * 1_000_000)
            if observation_deadline_ns <= now_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
        if args.observation_deadline_ns is not None:
            if (observation_deadline_ns is None or args.observation_deadline_ns <= now_ns
                    or args.observation_deadline_ns > observation_deadline_ns):
                raise OnboardingError('onboarding_observation_deadline_expired')
            observation_deadline_ns = args.observation_deadline_ns
        probe_scope.enter_context(onboarding_sdk.probe_budget(observation_deadline_ns))
        if (identity_query or grouping) and timeout is None:
            raise OnboardingError('invalid_receiving_identity_request')
        if (args.require_loaded and args.action not in {'running', 'admitted-running'}
                or controlling and (args.control_file is None
                    or (args.action != 'receiving-control-apply') != (args.control_command is not None))
                or not controlling and (args.control_file is not None or args.control_command is not None)
                or controlling and args.ready_fd is not None):
            raise OnboardingError('invalid_receiving_control_request')
        stage = 'public-release'
        plan = validate_plan(being_seed._read(args.plan))
        runtime = onboarding_code_successor.selection(args.runtime_code, args.runtime_digest,
            args.code, plan['release_digest'], uid=0)
        sdk_parameters = onboarding_code_successor.sdk_parameters(runtime)
        if (controlling or identity_query or bootstrapping or grouping or args.require_loaded
                or admitting and timeout is not None) and not sdk_parameters:
            raise OnboardingError('qualified_onboarding_target_observer_required')
        matrix_commit = sdk_parameters.get('matrix_commit', onboarding_sdk.MATRIX_COMMIT)
        if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        if args.action == 'sdk-prepare':
            stage = 'sdk-preparation'
            venv = onboarding_sdk.install(args.home, runtime, args.runtime_digest or plan['release_digest'], **sdk_parameters)
            if sdk_parameters:
                stage = 'sdk-imports'
                onboarding_sdk.runtime_imports(venv, runtime, **sdk_parameters)
            if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            print(json.dumps(dict(ready=True, matrix_commit=matrix_commit)))
            return 0
        if args.action == 'sdk-observe':
            stage = 'sdk-observation'
            try:
                onboarding_sdk.observe(args.home, runtime, **sdk_parameters)
                ready = True
            except FileNotFoundError:
                ready = False
            if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            print(json.dumps(dict(ready=ready, matrix_commit=matrix_commit)))
            return 0
        stage = 'sdk-observation'
        with ExitStack() as startup_lock:
            if sdk_parameters:
                # Selection already verified this protected V4 manifest. The
                # qualified process excludes installed site-packages; validate
                # its actual closed imports below, without scanning unused files.
                sdk = json.loads(onboarding_release.regular(runtime / 'sdk/sdk.json', uid=0))
                venv = args.home / '.local/share/daimon-matrix/sdk' / digest(sdk) / 'venv'
                private_directory(venv.parent)
                startup_lock.enter_context(being_seed._locked(venv.parent, shared=True))
                imports = private_directory(venv.parent / 'runtime-imports')
                document(venv.parent / 'runtime-imports.json')
                # Keep read ownership through qualification so a missing tree
                # or receipt never enters runtime_imports' construction branch.
            else:
                venv = onboarding_sdk.observe(args.home, runtime, **sdk_parameters)
                imports = None
            qualified_context = (imports is not None
                and onboarding_sdk.startup_context(venv, imports, runtime))
            if Path(sys.prefix) != venv or sdk_parameters and not qualified_context:
                arguments = list(argv if argv is not None else sys.argv[1:])
                if observation_deadline_ns is not None:
                    if time.monotonic_ns() >= observation_deadline_ns:
                        raise OnboardingError('onboarding_observation_deadline_expired')
                    # Same process/guest monotonic clock across exec. Import/startup
                    # time must consume this budget rather than reset its duration.
                    arguments += ['--observation-deadline-ns', str(observation_deadline_ns)]
                if sdk_parameters:
                    stage = 'sdk-imports'
                    imports = onboarding_sdk.runtime_imports(venv, runtime, **sdk_parameters)
                    command = onboarding_sdk.runtime_command(venv, imports, runtime,
                        'clusterctl.onboarding_target', arguments)
                else:
                    launcher = ("import sys; sys.path.insert(0,sys.argv.pop(1)); "
                                "from clusterctl.onboarding_target import main; raise SystemExit(main())")
                    command = [str(venv / "bin/python"), "-B", "-I", "-c", launcher,
                               str(runtime), *arguments]
                os.execv(venv / "bin/python", command)
            stage = 'sdk-startup'
            startup = (onboarding_sdk.qualified_startup(venv, runtime,
                code_digest=args.runtime_digest or plan['release_digest'], **sdk_parameters)
                if sdk_parameters else None)
        stage = 'owner-action'
        target = Target(args.home, plan, document(args.genesis), code=runtime,
            code_digest=args.runtime_digest or plan['release_digest'], qualified_startup=startup)
        if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        if bootstrapping:
            from .onboarding_receiving_update import GuestOwnerBootstrap, freeze_guest_bootstrap
            if observation_deadline_ns is None:
                raise OnboardingError('invalid_receiving_bootstrap_request')
            deadline_ns = observation_deadline_ns
            stage = args.action
            if args.action == 'receiving-bootstrap-freeze':
                result = freeze_guest_bootstrap(target, deadline_ns=deadline_ns, initial=args.bootstrap_initial,
                    initial_service=args.bootstrap_initial_service)
            else:
                owner = GuestOwnerBootstrap(target, json.loads(args.bootstrap_request_json))
                result = owner.execute(args.action.removeprefix('receiving-bootstrap-'),
                    deadline_ns=deadline_ns, ready_sha256=args.bootstrap_ready_sha256)
            print(json.dumps(result))
            return 0
        if controlling:
            if args.control_command == Path('-'):
                raw = sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1)
                if len(raw) > being_seed.MAX_SELECTION:
                    raise OnboardingError('invalid_receiving_control_request')
                control_command = json.loads(raw)
                if not isinstance(control_command, dict):
                    raise OnboardingError('invalid_receiving_control_request')
            else:
                control_command = (None if args.control_command is None
                                   else being_seed._read(args.control_command, limit=being_seed.MAX_SELECTION))
            print(json.dumps(target.receiving_control(args.action, args.control_file,
                command=control_command, deadline_ns=observation_deadline_ns)))
            return 0
        if identity_query:
            if observation_deadline_ns is None:
                raise OnboardingError('invalid_receiving_identity_request')
            result = target.qualified_receiving_identity(expires_at_ms=args.identity_expires_at_ms,
                deadline_ns=observation_deadline_ns)
            if args.native_tooling_json is not None:
                from .onboarding_owner_client import observe_selected_tooling
                if startup is None:
                    raise OnboardingError('qualified_native_peer_tool_required')
                result['native_tooling'] = observe_selected_tooling(json.loads(args.native_tooling_json),
                    code=runtime, startup=startup, code_uid=0, deadline_ns=observation_deadline_ns,
                    receiving=result)
            print(json.dumps(result))
            return 0
        if grouping:
            from .onboarding_group_admission import request_packet
            if args.group_request == Path('-'):
                raw = sys.stdin.buffer.read(being_seed.MAX_SELECTION + 1)
                if len(raw) > being_seed.MAX_SELECTION:
                    raise OnboardingError('onboarding_group_relationship_command_required')
                packet = json.loads(raw)
            else:
                packet = being_seed._read(args.group_request, limit=being_seed.MAX_SELECTION)
            packet = request_packet(packet)
            if (not packet['offline']
                    or (args.action == 'group-publication') != ('action' in packet['command'])):
                raise OnboardingError('onboarding_group_relationship_writer_required')
            method = target.group_publication if args.action == 'group-publication' else target.group_relationship
            print(json.dumps(method(packet['command'],
                authority_closure=packet['authority_closure'], deadline_ns=observation_deadline_ns,
                **({'expected_context_sha256': packet['expected_context_sha256']}
                   if 'expected_context_sha256' in packet else {}),
                **({'membership_precondition': packet['membership_precondition']}
                   if 'membership_precondition' in packet else {}))))
            return 0
        if args.action == 'peer-identity':
            from .onboarding_peer import identity
            print(json.dumps(identity(target)))
            return 0
        if args.action == 'peer-accept':
            from .onboarding_peer import accept
            if args.peer_packet is None or args.peer_packet_sha256 is None or args.peer_being_ref is None:
                raise OnboardingError('approved_onboarding_peer_required')
            raw = onboarding_release.regular(args.peer_packet, uid=os.geteuid())
            if hashlib.sha256(raw).hexdigest() != args.peer_packet_sha256:
                raise OnboardingError('approved_onboarding_peer_required')
            print(json.dumps(accept(target, json.loads(raw), expected_being=args.peer_being_ref)))
            return 0
        if args.action == "admitted-serve":
            from .onboarding_runtime import serve
            if args.admission_profile is None:
                raise OnboardingError("onboarding_admission_profile_required")
            return serve(target, document(args.admission_profile), receive_only=args.receive_only,
                visibility_installation=args.visibility_installation, messaging_application=args.messaging_application,
                ready_descriptor=args.ready_fd, expected_initial_context=expected_initial_context)
        if args.action == "serve":
            return target.serve(receive_only=args.receive_only, visibility_installation=args.visibility_installation,
                                ready_descriptor=args.ready_fd)
        if args.action in {"running", "admitted-running"}:
            stage = 'native-observation'
            print(json.dumps(target.running(admitted=args.action == 'admitted-running',
                require_loaded=args.require_loaded,
                deadline_ns=observation_deadline_ns)))
            return 0
        if args.action in {'admission-check', 'admission-enroll'}:
            from .onboarding_admission import ReceivingHolder
            if args.public_profile_json is None or len(args.public_profile_json) > 16384:
                raise OnboardingError('onboarding_admission_profile_required')
            registered = ReceivingHolder(target).ensure_enrolled(json.loads(args.public_profile_json),
                enroll=args.action == 'admission-enroll', deadline_ns=observation_deadline_ns)
            if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
                raise OnboardingError('onboarding_observation_deadline_expired')
            print(json.dumps(dict(registered=registered)))
            return 0
        if args.action == "admission-prepare":
            from .onboarding_admission import ReceivingHolder
            print(json.dumps(ReceivingHolder(target).request(deadline_ns=observation_deadline_ns)))
            return 0
        if args.action == "prepare":
            target.prepare()
        elif args.action == "activate":
            if args.activation is None:
                raise OnboardingError("onboarding_target_activation_required")
            target.activate(document(args.activation))
        elif args.action == "credential-apply":
            if args.credential_response is None:
                raise OnboardingError("onboarding_target_activation_required")
            target.apply_credential(document(args.credential_response))
        result = target.observe()
        if observation_deadline_ns is not None and time.monotonic_ns() >= observation_deadline_ns:
            raise OnboardingError('onboarding_observation_deadline_expired')
        if args.action == "credential-prepare":
            result["request"] = target.credential_request()
        print(json.dumps(result))
        return 0
    except Exception as error:
        if args.diagnostics:
            print(json.dumps(refusal_diagnostic(error, stage=stage)), file=sys.stderr)
        print(json.dumps({"error": "native_onboarding_target_refused"}))
        return 1
    finally:
        probe_scope.close()


if __name__ == "__main__":
    raise SystemExit(main())
