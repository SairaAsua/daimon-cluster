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
import os
import socket
import struct
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Iterator

from . import being_seed, onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import OnboardingError, digest, private_directory, validate_plan


def document(path: Path) -> dict:
    raw = onboarding_release.regular(path, uid=os.geteuid(), limit=4 * 1024**2)
    if path.stat().st_mode & 0o077:
        raise OnboardingError("private_onboarding_target_required")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OnboardingError("invalid_onboarding_target_document")
    return value


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
            if result['phase'] == 'v8':
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
                    or bundle['keystore'] != {**expected['keystore'], 'counter': expected['keystore']['counter'] + 1}
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

    def running(self, *, admitted: bool = False, require_loaded: bool = False) -> dict:
        """Observe a kernel-pinned daemon and authenticate its native status.

        Admitted observations also check the current native body scope. Loaded
        observations associate the selected group with that same process/base;
        candidate equality, resource fences and communication remain separate.
        """
        from daimon_matrix.client import ClientConfig, LocalClient
        prepared = self.observe()
        if prepared["phase"] != "v8":
            raise OnboardingError("current_onboarding_target_required")
        root = self.package / "runtime"
        socket_identity = (root / "matrix.sock").lstat()
        key = bytearray(onboarding_release.regular(root / "client.key", uid=os.geteuid()))
        config = ClientConfig.load(root / "client.json", key)
        from .owner_process import ConnectedProcessObserver, ParentProcessPresence, ProcessPresence
        connected = 'connection_observer' in getattr(LocalClient, '__dataclass_fields__', {})
        if require_loaded and not connected:
            raise OnboardingError('qualified_onboarding_client_required')
        with ExitStack() as stack:
            presence: ConnectedProcessObserver | ProcessPresence
            if connected:
                presence = stack.enter_context(ConnectedProcessObserver())
                options = {'connection_observer': presence}
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
            client = LocalClient(root / "matrix.sock", config, timeout_seconds=40,
                                 **options)
            _, status = client.runtime_status()
            expected = prepared["receipt"]["origin"]
            if status["ok"] is not True or any(status["server"].get(field) != value for field, value in expected.items()):
                raise OnboardingError("onboarding_daemon_origin_conflict")
            loaded = status['result'].get('loaded_runtime')
            if connected and loaded is not None and (presence.process is None
                    or loaded.get('process_id') != presence.process['pid']):
                raise OnboardingError('onboarding_daemon_responder_conflict')
            group = prepared.get('group')
            group_status = None
            if connected and group is not None:
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
            if admitted:
                _, observed = client.scope_me()
                scope_result = observed.get('result')
                body = scope_result.get('body') if isinstance(scope_result, dict) else None
                if (observed.get('ok') is not True or not isinstance(body, dict) or body.get('state') != 'running'
                        or any(body.get(field) != expected[field] for field in
                               ('body_ref', 'embodiment_id', 'incarnation_id'))):
                    raise OnboardingError('onboarding_admission_not_current')
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
            return dict(schema="cluster-onboarding-runtime-presence/v1", plan_digest=digest(self.plan),
                origin=expected, process=presence.process, runtime_id=config.runtime_id,
                admission_parent=None if parent is None else parent.process,
                runtime_sha256=prepared.get('receiving_controller', prepared['receipt'])["runtime_sha256"],
                runtime_status=status['result'], group=group, group_runtime_status=group_status,
                receiving_readiness='unobserved',
                responder_association='same-connection' if connected else 'legacy-probe')

    def receiving_control(self, action: str, path: Path, *, command: dict | None = None) -> dict:
        """Use the selected admitted group; preserve exact retained controls."""
        from .onboarding_receiving_update import owner_control
        observed = self.running(admitted=True, require_loaded=True)
        return owner_control(self.package / 'runtime', observed['group'], observed,
            action, path, command=command, status_key='group_runtime_status')



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("sdk-observe", "sdk-prepare", "prepare", "activate", "observe", "credential-prepare", "credential-apply", "serve", "running", "admission-prepare", "admitted-serve", "admission-check", "admission-enroll", "admitted-running", "peer-identity", "peer-accept", "receiving-control-prepare", "receiving-control-apply"))
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
    parser.add_argument('--control-file', type=Path)
    parser.add_argument('--control-command', type=Path)
    args = parser.parse_args(argv)
    try:
        controlling = args.action in {'receiving-control-prepare', 'receiving-control-apply'}
        if (args.require_loaded and args.action not in {'running', 'admitted-running'}
                or controlling and (args.control_file is None
                    or (args.action == 'receiving-control-prepare') != (args.control_command is not None))
                or not controlling and (args.control_file is not None or args.control_command is not None)
                or controlling and args.ready_fd is not None):
            raise OnboardingError('invalid_receiving_control_request')
        plan = validate_plan(being_seed._read(args.plan))
        runtime = onboarding_code_successor.selection(args.runtime_code, args.runtime_digest,
            args.code, plan['release_digest'], uid=0)
        sdk_parameters = onboarding_code_successor.sdk_parameters(runtime)
        if (controlling or args.require_loaded) and not sdk_parameters:
            raise OnboardingError('qualified_onboarding_target_observer_required')
        matrix_commit = sdk_parameters.get('matrix_commit', onboarding_sdk.MATRIX_COMMIT)
        if args.action == 'sdk-prepare':
            onboarding_sdk.install(args.home, runtime, args.runtime_digest or plan['release_digest'], **sdk_parameters)
            print(json.dumps(dict(ready=True, matrix_commit=matrix_commit)))
            return 0
        if args.action == 'sdk-observe':
            try:
                onboarding_sdk.observe(args.home, runtime, **sdk_parameters)
                ready = True
            except FileNotFoundError:
                ready = False
            print(json.dumps(dict(ready=ready, matrix_commit=matrix_commit)))
            return 0
        venv = onboarding_sdk.observe(args.home, runtime, **sdk_parameters)
        imports = venv.parent / 'runtime-imports' if sdk_parameters else None
        qualified_context = (imports is not None
            and onboarding_sdk.startup_context(venv, imports, runtime))
        if Path(sys.prefix) != venv or sdk_parameters and not qualified_context:
            arguments = argv if argv is not None else sys.argv[1:]
            if sdk_parameters:
                imports = onboarding_sdk.runtime_imports(venv, runtime, **sdk_parameters)
                command = onboarding_sdk.runtime_command(venv, imports, runtime,
                    'clusterctl.onboarding_target', arguments)
            else:
                launcher = ("import sys; sys.path.insert(0,sys.argv.pop(1)); "
                            "from clusterctl.onboarding_target import main; raise SystemExit(main())")
                command = [str(venv / "bin/python"), "-B", "-I", "-c", launcher,
                           str(runtime), *arguments]
            os.execv(venv / "bin/python", command)
        startup = (onboarding_sdk.qualified_startup(venv, runtime,
            code_digest=args.runtime_digest or plan['release_digest'], **sdk_parameters)
            if sdk_parameters else None)
        target = Target(args.home, plan, document(args.genesis), code=runtime,
            code_digest=args.runtime_digest or plan['release_digest'], qualified_startup=startup)
        if controlling:
            control_command = (None if args.control_command is None
                               else being_seed._read(args.control_command, limit=being_seed.MAX_SELECTION))
            print(json.dumps(target.receiving_control(args.action, args.control_file, command=control_command)))
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
                ready_descriptor=args.ready_fd)
        if args.action == "serve":
            return target.serve(receive_only=args.receive_only, visibility_installation=args.visibility_installation,
                                ready_descriptor=args.ready_fd)
        if args.action in {"running", "admitted-running"}:
            print(json.dumps(target.running(admitted=args.action == 'admitted-running',
                                            require_loaded=args.require_loaded)))
            return 0
        if args.action in {'admission-check', 'admission-enroll'}:
            from .onboarding_admission import ReceivingHolder
            if args.public_profile_json is None or len(args.public_profile_json) > 16384:
                raise OnboardingError('onboarding_admission_profile_required')
            registered = ReceivingHolder(target).ensure_enrolled(json.loads(args.public_profile_json),
                enroll=args.action == 'admission-enroll')
            print(json.dumps(dict(registered=registered)))
            return 0
        if args.action == "admission-prepare":
            from .onboarding_admission import ReceivingHolder
            print(json.dumps(ReceivingHolder(target).request()))
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
        if args.action == "credential-prepare":
            result["request"] = target.credential_request()
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({"error": "native_onboarding_target_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
