"""Qualified preparation and owner-controlled receiving update effects.

Inputs come from protected approved selections, never participant uploads.
Preparation, sender revocation and selector CAS have separate retained evidence;
none alone establishes receiving readiness or completed adoption.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import uuid
from collections.abc import Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import being_seed, onboarding_release, onboarding_sdk
from .onboarding import JobStore, OnboardingError, digest, private_directory
from .owner_process import ConnectedProcessObserver


def receiving_identity(response: dict, runtime_status: dict, server: dict,
                       *, require_admitted: bool = True) -> dict:
    """Keep only the authenticated current identity/admission subset of scope.me.

    Both responses must belong to the caller's same observed connection. This
    contains no ledger projection, inbox, capabilities or readiness inference.
    """
    scope = response.get('result')
    body = scope.get('body') if isinstance(scope, dict) else None
    if (response.get('ok') is not True or response.get('server') != server
            or not isinstance(scope, dict) or scope.get('schema') != 'dm.scope.me/v1'
            or scope.get('origin') != server or runtime_status.get('local_origin') != server
            or scope.get('being_ref') != runtime_status.get('being_ref')
            or scope.get('manifest_hash') != runtime_status.get('manifest_hash')
            or type(scope.get('evaluated_at_ms')) is not int or scope['evaluated_at_ms'] < 0
            or any(not isinstance(scope.get(key), str) or not scope[key]
                   for key in ('being_ref', 'manifest_hash', 'credential_ref', 'incarnation_authorization_ref'))
            or require_admitted and (not isinstance(body, dict) or body.get('state') != 'running'
                or any(body.get(key) != server.get(key)
                       for key in ('body_ref', 'embodiment_id', 'incarnation_id')))):
        raise OnboardingError('receiving_identity_admission_conflict')
    return {**{key: scope[key] for key in ('schema', 'being_ref', 'manifest_hash', 'evaluated_at_ms',
                                         'credential_ref', 'incarnation_authorization_ref')},
            'origin': dict(server)}


def verify_receiving_identity(bundle: dict, observed: dict, *, expires_at_ms: int) -> dict:
    """Verify current public credential validity in the authenticated loaded bundle.

    The selected horizon stays finite even for until-revoked credentials. This
    derives evidence only; it never unlocks custody or loads another runtime.
    """
    from daimon_matrix.messaging_config import _public_identity
    from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
    from daimon_matrix.canonical import canonical_bytes
    now = time.time_ns() // 1_000_000
    if type(expires_at_ms) is not int or not now < expires_at_ms < 2**53:
        raise OnboardingError('receiving_identity_horizon_expired')
    loaded = observed['runtime_status'].get('loaded_runtime')
    identity = observed.get('identity')
    if (not isinstance(loaded, dict) or not isinstance(identity, dict)
            or hashlib.sha256(canonical_bytes(bundle)).hexdigest() != loaded.get('runtime_bundle_sha256')
            or loaded.get('process_id') != observed['process']['pid']
            or loaded.get('local_origin') != observed['server']
            or observed['runtime_status'].get('local_origin') != observed['server']
            or identity.get('origin') != observed['server']
            or observed['runtime_status'].get('being_ref') != identity.get('being_ref')
            or observed['runtime_status'].get('manifest_hash') != identity.get('manifest_hash')
            or bundle.get('local_origin') != observed['server']
            or bundle.get('runtime_id') != loaded.get('runtime_id')):
        raise OnboardingError('receiving_identity_loaded_bundle_conflict')
    try:
        authority = authority_from_runtime_bundle(bundle)
        public = _public_identity(authority, observed['server'], bundle['runtime_id'],
                                  bundle['runtime_label'], now)
        if (public['being_ref'] != identity['being_ref']
                or public['manifest_hash'] != identity['manifest_hash']
                or public['credential_id'] != identity['credential_ref']
                or public['incarnation_authorization_id'] != identity['incarnation_authorization_ref']):
            raise OnboardingError('receiving_identity_public_binding_conflict')
        credential = authority.credentials[public['credential_id']]['body']
        if 'validity' in credential:
            validity = dict(credential['validity'])
            if validity['mode'] == 'finite':
                expires_at_ms = min(expires_at_ms, validity['not_after_ms'])
        else:
            validity = dict(valid_from_ms=credential['valid_from_ms'],
                            valid_until_ms=credential['valid_until_ms'])
            expires_at_ms = min(expires_at_ms, validity['valid_until_ms'])
    except (ValueError, KeyError, TypeError):
        raise OnboardingError('receiving_identity_public_verification_failed') from None
    if expires_at_ms <= time.time_ns() // 1_000_000:
        raise OnboardingError('receiving_identity_horizon_expired')
    return dict(schema='cluster-receiving-verified-identity/v1', identity=identity,
        authority_control_head=public['control_head'],
        runtime_bundle_sha256=loaded['runtime_bundle_sha256'], credential_validity=validity,
        verified_at_ms=now, expires_at_ms=expires_at_ms)


class OwnerGroupClient:
    """Finite owner-local control of the actual selected group daemon.

    Call from its receiving owner, not a model tool. Prepared authenticated
    requests stay in owner-private files; outputs contain only their digests and
    verified observations. Reading/control never claims candidate readiness.
    """

    def __init__(self, root: Path, socket_path: Path, *, deadline_ns: int | None = None):
        self.root = private_directory(root)
        self.socket = socket_path
        self.deadline_ns = deadline_ns
        self._observer: ConnectedProcessObserver | None = None

    def __enter__(self) -> OwnerGroupClient:
        if self._observer is not None:
            raise OnboardingError('receiving_owner_scope_required')
        self._observer = ConnectedProcessObserver()
        self._observer.__enter__()
        return self

    def __exit__(self, *args):
        if self._observer is not None:
            self._observer.__exit__(*args)
            self._observer = None

    def _accept_deadline(self) -> None:
        if self.deadline_ns is not None and time.monotonic_ns() >= self.deadline_ns:
            raise OnboardingError('receiving_owner_deadline_expired')

    def _client(self, role: str):
        from daimon_matrix.client import ClientConfig, LocalClient
        from daimon_matrix.operator_capabilities import host_capability_profile
        if self._observer is None or 'connection_observer' not in LocalClient.__dataclass_fields__:
            raise OnboardingError('qualified_receiving_owner_client_required')
        profile = host_capability_profile(role)
        directory = self.root / profile['client_directory']
        key = bytearray(onboarding_release.regular(directory / profile['client_key_filename'], uid=os.geteuid()))
        config = ClientConfig.load(directory / profile['client_config_filename'], key)
        options = {'connection_observer': self._observer, 'timeout_seconds': 40}
        if self.deadline_ns is not None:
            if ('deadline_ns' not in LocalClient.__dataclass_fields__
                    or time.monotonic_ns() >= self.deadline_ns):
                raise OnboardingError('qualified_receiving_deadline_client_required')
            options['deadline_ns'] = self.deadline_ns
        return LocalClient(self.socket, config, **options)

    def _observe_status(self) -> dict:
        before = self.socket.lstat()
        client = self._client('status')
        response = client.runtime_status()[1]
        if response.get('ok') is not True:
            raise OnboardingError('receiving_group_status_unavailable')
        after = self.socket.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OnboardingError('receiving_group_socket_changed')
        if self._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        self._observer.verify()
        process = self._observer.process
        if process is None:
            raise OnboardingError('receiving_group_responder_conflict')
        status = response['result']
        loaded = status.get('loaded_runtime')
        if loaded is not None and loaded.get('process_id') != process['pid']:
            raise OnboardingError('receiving_group_responder_conflict')
        self._accept_deadline()
        return dict(process=process, server=response['server'], runtime_status=status,
                    receiving_readiness='unobserved')

    def base_status(self) -> dict:
        """Pin an authenticated predecessor without claiming loaded readiness.

        The client-side observer also works with the unchanged predecessor API.
        No reader gate, selected group or candidate load is inferred from this.
        """
        if self.socket != self.root / 'matrix.sock':
            raise OnboardingError('receiving_base_socket_required')
        observed = self._observe_status()
        return dict(schema='cluster-receiving-base-observation/v1', **observed)

    def wait_for_exit(self, timeout_seconds: float) -> bool:
        """Observe the already-authenticated peer; lifecycle ownership is separate."""
        if self._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        return self._observer.wait_for_exit(timeout_seconds)

    def status(self) -> dict:
        observed = self._observe_status()
        gate = observed['runtime_status'].get('receiving', {}).get('channels', {}).get('tribe')
        if (not isinstance(gate, dict) or gate.get('controlled') is not True
                or gate.get('process_id') != observed['process']['pid']):
            raise OnboardingError('receiving_group_control_required')
        return dict(schema='cluster-receiving-owner-observation/v1', gate=gate, **observed)

    def identity(self, *, require_admitted: bool = False) -> dict:
        """Use the status grant; require admission only for the guest profile.

        Current credential expiry still requires public-bundle verification;
        neither this query nor Source's user-service proves Cluster admission.
        """
        observed = self.status()
        before = self.socket.lstat()
        response = self._client('status').scope_me()[1]
        after = self.socket.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OnboardingError('receiving_group_socket_changed')
        if self._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        self._observer.verify()
        identity = receiving_identity(response, observed['runtime_status'], observed['server'],
                                      require_admitted=require_admitted)
        return {**observed, 'identity': identity}

    def qualified_identity(self, *, expires_at_ms: int, require_admitted: bool = False,
                           native_tooling: dict | None = None) -> dict:
        if native_tooling is not None:
            raise OnboardingError('qualified_native_peer_tool_required')
        observed = self.identity(require_admitted=require_admitted)
        bundle = being_seed._read(self.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        verified = verify_receiving_identity(bundle, observed, expires_at_ms=expires_at_ms)
        if self._observer is None:
            raise OnboardingError('receiving_owner_scope_required')
        self._observer.verify()
        if verified['expires_at_ms'] <= time.time_ns() // 1_000_000:
            raise OnboardingError('receiving_identity_horizon_expired')
        return {**observed, 'verified_identity': verified}

    def prepare_control(self, command: dict, path: Path) -> dict:
        """Persist one exact native request before attempting its effect."""
        parent = self._control_directory(path)
        with being_seed._locked(parent):
            result = self._prepare_control(command, path)
            self._accept_deadline()
            return result

    def _control_directory(self, path: Path) -> Path:
        parent = private_directory(self.root / 'receiving-control', create=True)
        if path.parent != parent or not re.fullmatch(r'[a-z0-9-]{1,128}\.json', path.name):
            raise OnboardingError('receiving_control_path_required')
        return parent

    def _durable_control(self, path: Path) -> None:
        """Complete a failed publication without rewriting its exact request.

        Called under the control-directory lock, including retained-file retries
        and direct apply. A readable file after rename may still need its file,
        directory and newly-created directory's parent made durable.
        """
        self._control_directory(path)
        descriptor = os.open(being_seed._path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077
                    or info.st_size > being_seed.MAX_SELECTION):
                raise OnboardingError('receiving_control_private_file_required')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for directory in (path.parent, self.root):
            private_directory(directory)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _prepare_control(self, command: dict, path: Path) -> dict:
        from daimon_matrix.local_api import request_hash
        if path.exists():
            retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
            if retained.get('command') != command:
                raise OnboardingError('receiving_control_binding_conflict')
            self._durable_control(path)
            return dict(request_id=retained['request']['request_id'],
                request_sha256=request_hash(retained['request']), command_sha256=digest(command))
        observed = self.status()
        gate = observed['gate']
        if (command.get('channel_id') != 'tribe'
                or command.get('process_instance_id') != gate['process_instance_id']
                or command.get('expected_head') != gate['head']):
            raise OnboardingError('receiving_control_binding_conflict')
        client = self._client('receiving-controller')
        request = client.prepare('runtime.reader-selection', command)
        being_seed._write(path, dict(schema='cluster-receiving-owner-control/v1',
            command=command, request=request, process=observed['process'], server=observed['server']),
            limit=being_seed.MAX_SELECTION)
        self._durable_control(path)
        return dict(request_id=request['request_id'], request_sha256=request_hash(request),
                    command_sha256=digest(command))

    def apply_control(self, path: Path) -> dict:
        """Exact retry or observed same-process completion; never re-author."""
        with being_seed._locked(self._control_directory(path)):
            result = self._apply_control(path)
            self._accept_deadline()
            return result

    def prepare_apply_control(self, command: dict, path: Path) -> dict:
        """Retain and apply the same request in one bounded owner invocation."""
        with being_seed._locked(self._control_directory(path)):
            self._accept_deadline()
            self._prepare_control(command, path)
            self._accept_deadline()
            result = self._apply_control(path)
            self._accept_deadline()
            return result

    def _apply_control(self, path: Path) -> dict:
        from daimon_matrix.local_api import request_hash
        retained = being_seed._read(path, limit=being_seed.MAX_SELECTION)
        if set(retained) != {'schema', 'command', 'request', 'process', 'server'} or retained['schema'] != 'cluster-receiving-owner-control/v1':
            raise OnboardingError('receiving_control_binding_conflict')
        command, request = retained['command'], retained['request']
        if request.get('method') != 'runtime.reader-selection' or request.get('params') != command:
            raise OnboardingError('receiving_control_binding_conflict')
        self._durable_control(path)
        observed = self.status()
        if observed['process'] != retained['process'] or observed['server'] != retained['server']:
            raise OnboardingError('receiving_control_process_changed')
        expected_hash = request_hash(request)
        gate = observed['gate']
        if gate.get('request_sha256') != expected_hash:
            if (gate['process_instance_id'] != command['process_instance_id']
                    or gate['head'] != command['expected_head']):
                raise OnboardingError('receiving_control_superseded')
            response = self._client('receiving-controller').send(request)
            if response.get('ok') is not True:
                raise OnboardingError('receiving_control_not_accepted')
            observed = self.status()
            gate = observed['gate']
        if (gate.get('request_sha256') != expected_hash
                or gate.get('phase') != command['phase']
                or gate.get('operation_id') != command['operation_id']
                or gate.get('release_digest') != command['release_digest']
                or gate.get('readers') != command['readers']):
            raise OnboardingError('receiving_control_completion_uncertain')
        return {**observed, 'schema': 'cluster-receiving-owner-control-observation/v1',
            'request_id': request['request_id'], 'request_sha256': expected_hash,
            'command_sha256': digest(command)}


class GuestGroupClient:
    """Host adapter to receiving-owner controls without opening guest custody.

    Private request files remain inside the guest. Only its closed qualified
    owner CLI observes or writes them; the host retains public observations.
    """

    def __init__(self, backend, plan: dict, candidate: tuple[Path, str],
                 *, root: Path, timeout_seconds: float = 30):
        if (not root.is_absolute() or '..' in root.parts or not 0 < timeout_seconds <= 60):
            raise OnboardingError('receiving_guest_owner_locator_required')
        self.backend, self.plan, self.candidate = backend, dict(plan), candidate
        self.root, self.socket = root, root / 'tribe.sock'
        self.timeout_seconds = timeout_seconds
        self.deadline_ns: int | None = None

    def _call(self, action: str, **arguments) -> dict:
        timeout = self.timeout_seconds
        if self.deadline_ns is not None:
            timeout = min(timeout, (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000)
            if timeout <= 0:
                raise OnboardingError('receiving_owner_deadline_expired')
        result = self.backend._target_call(self.plan, action, candidate=self.candidate,
            observation_timeout_seconds=timeout, **arguments)
        if self.deadline_ns is not None and time.monotonic_ns() >= self.deadline_ns:
            raise OnboardingError('receiving_owner_deadline_expired')
        return result

    def status(self) -> dict:
        value = self._call('admitted-running', require_loaded=True)
        status = value.get('group_runtime_status')
        gate = None if not isinstance(status, dict) else status.get('receiving', {}).get('channels', {}).get('tribe')
        if (value.get('responder_association') != 'same-connection'
                or not isinstance(status, dict)
                or not isinstance(value.get('admission_parent'), dict)
                or value.get('group', {}).get('socket') != str(self.socket)
                or not isinstance(gate, dict) or gate.get('controlled') is not True
                or not isinstance(status.get('loaded_runtime'), dict)
                or not isinstance(status.get('loaded_application'), dict)
                or gate.get('process_id') != value['process']['pid']
                or status.get('local_origin') != value['origin']
                or status.get('loaded_runtime') != value['runtime_status'].get('loaded_runtime')):
            raise OnboardingError('receiving_guest_owner_observation_conflict')
        return dict(schema='cluster-receiving-owner-observation/v1', process=value['process'],
            server=value['origin'], gate=gate, runtime_status=status,
            admission_parent=value['admission_parent'], identity=value.get('receiving_identity'),
            receiving_readiness='unobserved')

    def qualified_identity(self, *, expires_at_ms: int, require_admitted: bool = True,
                           native_tooling: dict | None = None) -> dict:
        value = self._call('receiving-identity', identity_expires_at_ms=expires_at_ms,
            **({'native_tooling': native_tooling} if native_tooling is not None else {}))
        if (value.get('responder_association') != 'same-connection'
                or value.get('plan_digest') != digest(self.plan)
                or not isinstance(value.get('admission_parent'), dict)
                or value.get('runtime_status', {}).get('local_origin') != value.get('server')
                or not isinstance(value.get('verified_identity'), dict)
                or value['verified_identity'].get('expires_at_ms', 0) > expires_at_ms
                or value['verified_identity'].get('expires_at_ms', 0) <= time.time_ns() // 1_000_000):
            raise OnboardingError('receiving_guest_owner_observation_conflict')
        return value

    def prepare_control(self, command: dict, path: Path) -> dict:
        return self._call('receiving-control-prepare', control_file=path, control_value=command)

    def group_relationship(self, command: dict, *, authority_closure: dict,
                           expected_context_sha256: str | None = None,
                           membership_precondition: dict | None = None) -> dict:
        return self._call('group-relationship', group_request=dict(command=command,
            offline=True, authority_closure=authority_closure,
            **({'expected_context_sha256': expected_context_sha256} if expected_context_sha256 is not None else {}),
            **({'membership_precondition': membership_precondition} if membership_precondition is not None else {})))

    def group_publication(self, command: dict, *, authority_closure: dict,
                          expected_context_sha256: str | None = None) -> dict:
        return self._call('group-publication', group_request=dict(command=command,
            offline=True, authority_closure=authority_closure,
            **({'expected_context_sha256': expected_context_sha256} if expected_context_sha256 is not None else {})))

    def apply_control(self, path: Path) -> dict:
        return self._call('receiving-control-apply', control_file=path)

    def prepare_apply_control(self, command: dict, path: Path) -> dict:
        return self._call('receiving-control-prepare-apply', control_file=path, control_value=command)

    def reconcile_tooling(self, operation_id: str, *, attachment: Path,
                         codex_home: Path, connections: tuple[Path, ...] = (),
                         native_endpoint: Path | None = None, native_threads: tuple[str, ...] = (),
                         binding_filename: str = 'binding.json') -> dict:
        from .onboarding_owner_client import OwnerClient
        return OwnerClient(self.backend).reconcile(self.plan, operation_id,
            candidate=self.candidate, attachment=attachment, codex_home=codex_home, connections=connections,
            native_endpoint=native_endpoint, native_threads=native_threads, binding_filename=binding_filename,
            timeout_seconds=self.timeout_seconds, deadline_ns=self.deadline_ns)

    def preflight_native(self, endpoint: Path) -> dict:
        from .onboarding_owner_client import OwnerClient
        return OwnerClient(self.backend).preflight_native(self.plan, candidate=self.candidate,
            endpoint=endpoint, timeout_seconds=self.timeout_seconds, deadline_ns=self.deadline_ns)


def _run_owner(argv: list[str], **options):
    """Bound and reap one technical owner CLI and its probe descendants."""
    payload, timeout = options.pop('input', None), options.pop('timeout')
    options.pop('capture_output', None)
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, **options) as process:
        try:
            stdout, stderr = process.communicate(payload, timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


class SourceGroupClient:
    """Host coordination through the approved receiving owner's closed CLI.

    Private SDK/config/control files are never opened by the root coordinator.
    subprocess drops all supplementary groups and the selected UID/GID before
    executing the private interpreter. Locators/selection come from the protected
    operation, not model or peer content. A timeout retains uncertain effects.
    """

    def __init__(self, *, config: Path, config_sha256: str, owner_uid: int, owner_gid: int,
                 code: Path, code_digest: str, code_uid: int, venv: Path, imports: Path,
                 root: Path, socket_path: Path, timeout_seconds: float = 30,
                 lifecycle_journal: Path | None = None):
        if (os.geteuid() != 0 or any(type(item) is not int or item <= 0 for item in (owner_uid, owner_gid))
                or type(code_uid) is not int or code_uid < 0
                or type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60
                or any(not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None
                       for value in (config_sha256, code_digest))
                or lifecycle_journal is not None and (
                    not lifecycle_journal.is_absolute() or '..' in lifecycle_journal.parts)
                or any(not path.is_absolute() or '..' in path.parts
                       for path in (config, code, venv, imports, root, socket_path))):
            raise OnboardingError('receiving_source_owner_binding_required')
        self.config, self.config_sha256 = config, config_sha256
        self.owner_uid, self.owner_gid = owner_uid, owner_gid
        self.code, self.code_digest, self.code_uid = code, code_digest, code_uid
        self.venv, self.imports = venv, imports
        self.root, self.socket = root, socket_path
        self.timeout_seconds = timeout_seconds
        self.lifecycle_journal = lifecycle_journal
        self.deadline_ns: int | None = None

    def _call(self, arguments: list[str], *, command: dict | None = None,
              module: str = 'clusterctl.onboarding_source') -> dict:
        deadline = time.monotonic_ns() + int(self.timeout_seconds * 1_000_000_000)
        if self.deadline_ns is not None:
            deadline = min(deadline, self.deadline_ns)
        if deadline <= time.monotonic_ns():
            raise OnboardingError('receiving_owner_deadline_expired')
        info = self.config.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or (info.st_uid, info.st_gid) != (self.owner_uid, self.owner_gid)):
            raise OnboardingError('receiving_source_owner_binding_required')
        payload = None if command is None else json.dumps(command, separators=(',', ':'))
        if payload is not None and len(payload.encode()) > being_seed.MAX_SELECTION:
            raise OnboardingError('invalid_receiving_control_request')
        if module not in {'clusterctl.onboarding_source', 'clusterctl.onboarding_owner_client'}:
            raise OnboardingError('receiving_source_owner_binding_required')
        argv = onboarding_sdk.runtime_command(self.venv, self.imports, self.code, module, [
            '--config', str(self.config), '--expected-config-sha256', self.config_sha256,
            '--code-owner', str(self.code_uid), '--code-digest', self.code_digest,
            '--observation-deadline-ns', str(deadline), *arguments])
        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise OnboardingError('receiving_owner_deadline_expired')
        try:
            # user/group/extra_groups are applied by subprocess BEFORE exec.
            # Do not stat, prepare or import this private interpreter as root.
            result = _run_owner(argv, input=payload, text=True, capture_output=True,
                timeout=remaining,
                user=self.owner_uid, group=self.owner_gid, extra_groups=(),
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
            if time.monotonic_ns() >= deadline:
                raise OnboardingError('receiving_owner_deadline_expired')
            if result.returncode or len(result.stdout.encode()) > being_seed.MAX_SELECTION:
                raise OnboardingError('receiving_source_owner_unavailable')
            value = json.loads(result.stdout)
            if not isinstance(value, dict) or 'error' in value:
                raise OnboardingError('receiving_source_owner_unavailable')
            after = self.config.lstat()
            if (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode) != (
                    info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode):
                raise OnboardingError('receiving_source_configuration_changed')
            if time.monotonic_ns() >= deadline:
                raise OnboardingError('receiving_owner_deadline_expired')
            return value
        except OnboardingError:
            raise
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise OnboardingError('receiving_source_owner_unavailable') from None

    def _observation(self, value: dict) -> dict:
        gate, status, group = value.get('gate'), value.get('runtime_status'), value.get('group')
        if (not isinstance(gate, dict) or gate.get('controlled') is not True
                or not isinstance(status, dict) or not isinstance(value.get('process'), dict)
                or type(value['process'].get('pid')) is not int or value['process']['pid'] <= 0
                or not isinstance(value.get('server'), dict) or not value['server']
                or not isinstance(group, dict) or group.get('socket') != str(self.socket)
                or gate.get('process_id') != value['process'].get('pid')
                or status.get('local_origin') != value.get('server')
                or not isinstance(status.get('loaded_runtime'), dict)
                or status['loaded_runtime'].get('process_id') != value['process'].get('pid')
                or not isinstance(status.get('loaded_application'), dict)):
            raise OnboardingError('receiving_source_owner_observation_conflict')
        return value

    def status(self) -> dict:
        return self._observation(self._call(['--owner-status']))

    def qualified_identity(self, *, expires_at_ms: int, require_admitted: bool = False,
                           native_tooling: dict | None = None) -> dict:
        if require_admitted:
            raise OnboardingError('receiving_source_guest_admission_unsupported')
        if type(expires_at_ms) is not int or not time.time_ns() // 1_000_000 < expires_at_ms < 2**53:
            raise OnboardingError('receiving_identity_horizon_expired')
        arguments = ['--qualified-identity', '--identity-expires-at-ms', str(expires_at_ms)]
        if native_tooling is not None:
            arguments += ['--native-tooling-json', json.dumps(native_tooling, separators=(',', ':'))]
        value = self._observation(self._call(arguments))
        verified = value.get('verified_identity')
        if (not isinstance(verified, dict) or type(verified.get('expires_at_ms')) is not int
                or verified['expires_at_ms'] <= time.time_ns() // 1_000_000
                or verified['expires_at_ms'] > expires_at_ms):
            raise OnboardingError('receiving_source_owner_observation_conflict')
        return value

    def prepare_control(self, command: dict, path: Path) -> dict:
        return self._call(['--prepare-control', str(path), '--control-command', '-'], command=command)

    def group_relationship(self, command: dict, *, offline: bool = False,
                           authority_closure: dict | None = None,
                           expected_context_sha256: str | None = None,
                           membership_precondition: dict | None = None) -> dict:
        return self._call(['--group-request', '-'], command=dict(command=command,
            offline=offline, authority_closure={} if authority_closure is None else authority_closure,
            **({'expected_context_sha256': expected_context_sha256} if expected_context_sha256 is not None else {}),
            **({'membership_precondition': membership_precondition} if membership_precondition is not None else {})))

    def group_publication(self, command: dict, *, authority_closure: dict,
                          expected_context_sha256: str | None = None) -> dict:
        return self._call(['--group-request', '-'], command=dict(command=command,
            offline=True, authority_closure=authority_closure,
            **({'expected_context_sha256': expected_context_sha256} if expected_context_sha256 is not None else {})))

    def apply_control(self, path: Path) -> dict:
        return self._call(['--apply-control', str(path)])

    def prepare_apply_control(self, command: dict, path: Path) -> dict:
        return self._call(['--prepare-apply-control', str(path), '--control-command', '-'], command=command)

    def reconcile_tooling(self, operation_id: str, *, attachment: Path,
                         codex_home: Path, connections: tuple[Path, ...] = (),
                         native_endpoint: Path | None = None, native_threads: tuple[str, ...] = (),
                         binding_filename: str = 'binding.json') -> dict:
        result = self._call(['--binding', str(attachment / binding_filename),
            '--reconcile-tooling', operation_id,
            '--codex-home', str(codex_home),
            *[part for path in connections for part in ('--connection-mirror', str(path))],
            *(['--native-endpoint', str(native_endpoint)] if native_endpoint is not None else []),
            *[part for thread in native_threads for part in ('--native-thread', thread)]],
            module='clusterctl.onboarding_owner_client')
        if (result.get('schema') != 'cluster-native-chat-tooling/v1'
                or result.get('operation_id') != operation_id or result.get('code_digest') != self.code_digest):
            raise OnboardingError('receiving_source_owner_observation_conflict')
        return result

    def preflight_native(self, endpoint: Path) -> dict:
        result = self._call(['--native-preflight', '--native-endpoint', str(endpoint)],
            module='clusterctl.onboarding_owner_client')
        if (result.get('schema') != 'cluster-native-endpoint-readiness/v1'
                or result.get('acceptance') != 'native-endpoint-only'
                or result.get('model_turns_started') != 0 or result.get('messages_sent') != 0
                or result.get('qualification', {}).get('code_digest') != self.code_digest):
            raise OnboardingError('receiving_source_owner_observation_conflict')
        return result

    def lifecycle_operation(self, operation_id: str) -> dict:
        """Read the retained owner journal under that owner, never as root."""
        if self.lifecycle_journal is None:
            raise OnboardingError('receiving_source_lifecycle_binding_required')
        value = self._call(['--receiving-lifecycle', operation_id,
            '--operation-journal', str(self.lifecycle_journal)])
        row = value.get('lifecycle')
        if (set(value) != {'schema', 'source_config_sha256', 'lifecycle'}
                or value['schema'] != 'cluster-receiving-source-lifecycle/v1'
                or value['source_config_sha256'] != self.config_sha256
                or not isinstance(row, dict) or row.get('operation_id') != operation_id
                or row.get('operation') != 'receiving-update'):
            raise OnboardingError('receiving_source_lifecycle_conflict')
        return row

    def prepare_admission_lifecycle(self, request: dict) -> dict:
        """Create/recover this owner's local child; return public pins only."""
        if self.lifecycle_journal is None:
            raise OnboardingError('receiving_source_lifecycle_binding_required')
        result = self._call(['--prepare-admission-lifecycle', '-',
            '--operation-journal', str(self.lifecycle_journal)], command=request)
        if (set(result) != {'schema', 'operation_id', 'source_config_sha256', 'code_digest', 'request_sha256',
                'cohort_operation_id', 'cohort_intent_sha256', 'link_sha256', 'owner_context_sha256', 'receiving_readiness'}
                or result.get('schema') != 'cluster-source-admission-prepared/v1'
                or result.get('source_config_sha256') != self.config_sha256
                or result.get('code_digest') != self.code_digest
                or result.get('request_sha256') != digest(request)
                or any(result.get(key) != request.get(key) for key in (
                    'cohort_operation_id', 'cohort_intent_sha256', 'owner_context_sha256'))
                or not isinstance(result.get('operation_id'), str) or not result['operation_id']
                or not isinstance(result.get('link_sha256'), str)
                or re.fullmatch('[0-9a-f]{64}', result['link_sha256']) is None
                or result.get('receiving_readiness') != 'unobserved'):
            raise OnboardingError('receiving_source_lifecycle_conflict')
        return result

    def lifecycle_action(self, operation_id: str, action: str) -> dict:
        """Use the same qualified owner for the frozen Matrix-only lifecycle."""
        if self.lifecycle_journal is None or action not in {'quiesce', 'preserve', 'derive', 'start', 'quiescence'}:
            raise OnboardingError('receiving_source_lifecycle_binding_required')
        value = self._call(['--receiving-lifecycle', operation_id,
            '--operation-journal', str(self.lifecycle_journal), '--lifecycle-action', action])
        if (set(value) != {'schema', 'source_config_sha256', 'operation_id', 'action', 'result'}
                or value['schema'] != 'cluster-receiving-source-lifecycle-effect/v1'
                or value['source_config_sha256'] != self.config_sha256
                or value['operation_id'] != operation_id or value['action'] != action
                or not isinstance(value['result'], dict)):
            raise OnboardingError('receiving_source_lifecycle_conflict')
        return value['result']


def owner_control(root: Path, group: dict, observed: dict, action: str, path: Path,
                  *, command: dict | None = None, status_key: str = 'runtime_status',
                  deadline_ns: int | None = None) -> dict:
    """Reuse qualified Source/guest observation for the same finite owner RPC.

    The prepared request stays on its receiving owner. Only observation and
    request hashes cross the controller boundary; no capability key is returned.
    """
    if (action not in {'receiving-control-prepare', 'receiving-control-apply', 'receiving-control-prepare-apply'}
            or (action != 'receiving-control-apply') != (command is not None)
            or not isinstance(group, dict) or group.get('channel_id') != 'tribe'
            or observed.get('responder_association') != 'same-connection'):
        raise OnboardingError('invalid_receiving_control_request')
    options = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
    with OwnerGroupClient(root, Path(group['socket']), **options) as owner:
        current = owner.status()
        previous = observed[status_key]
        if (current['process'] != observed['process']
                or any(current['runtime_status'].get(key) != previous.get(key)
                       for key in ('loaded_runtime', 'loaded_application'))
                or current['gate'] != previous.get('receiving', {}).get('channels', {}).get('tribe')):
            raise OnboardingError('receiving_control_process_changed')
        if action == 'receiving-control-prepare-apply':
            assert command is not None
            return owner.prepare_apply_control(command, path)
        return (owner.prepare_control(command, path) if command is not None
                else owner.apply_control(path))


def _owner_identity(observed: dict) -> tuple[str, str]:
    """Root identity is in authenticated status; server identifies its Body."""
    server, status = observed.get('server', {}), observed.get('runtime_status', {})
    being, body = status.get('being_ref'), server.get('embodiment_id')
    if (not isinstance(being, str) or not being or not isinstance(body, str) or not body
            or status.get('local_origin') != server):
        raise OnboardingError('receiving_owner_identity_conflict')
    return being, body


def freeze_senders(owners: Mapping[str, OwnerGroupClient | GuestGroupClient | SourceGroupClient], *, tribe_ref: str) -> list[dict]:
    """Observe the required sender vector before planning the update intent."""
    senders = []
    identities = set()
    for name, owner in sorted(owners.items()):
        observed = owner.status()
        application = observed['runtime_status'].get('loaded_application')
        if (not isinstance(application, dict)
                or application.get('tribe', {}).get('policy', {}).get('tribe_ref') != tribe_ref):
            raise OnboardingError('receiving_sender_group_required')
        identity = _owner_identity(observed)
        if identity in identities:
            raise OnboardingError('receiving_sender_vector_invalid')
        identities.add(identity)
        senders.append(dict(name=name, root=str(owner.root), socket=str(owner.socket),
            being_ref=identity[0],
            server=observed['server'], process=observed['process'], gate=observed['gate']))
    if not 1 <= len(senders) <= 256:
        raise OnboardingError('receiving_sender_vector_invalid')
    return senders



def controller_preservation(root: Path, bundle: dict) -> dict | None:
    """Pin immutable owner inputs without traversing live databases/sockets.

    Native runtime validation under writer ownership separately establishes the
    signed bundle/custody binding. No credential material leaves this function.
    """
    from daimon_matrix.client import ClientConfig
    from daimon_matrix.operator_capabilities import host_capability_profile, operator_capability_profile
    rows = bundle.get('capabilities', [])
    if not any(row.get('profile', {}).get('role') == 'receiving-controller' for row in rows):
        return None
    controller_profile = host_capability_profile('receiving-controller')
    controllers = [row for row in rows if row.get('profile') == controller_profile]
    if len(controllers) != 1:
        raise OnboardingError('receiving_controller_binding_conflict')
    hashes = {}
    for name in ('runtime.json', 'custody.json'):
        hashes[name] = hashlib.sha256(onboarding_release.regular(root / name, uid=os.geteuid())).hexdigest()
    for row in rows:
        profile = row['profile']
        role = profile['role']
        maintained = (host_capability_profile(role) if profile['schema'] == controller_profile['schema']
                      else operator_capability_profile(role))
        if profile != maintained:
            raise OnboardingError('receiving_controller_binding_conflict')
        directory = root / maintained['client_directory']
        key_path = directory / maintained['client_key_filename']
        config_path = directory / maintained['client_config_filename']
        key = bytearray(onboarding_release.regular(key_path, uid=os.geteuid()))
        key_sha256 = hashlib.sha256(key).hexdigest()
        try:
            config = ClientConfig.load(config_path, key)
            if (config.capability.descriptor != row['descriptor']
                    or config.expected_server != bundle['local_origin']
                    or config.runtime_id != bundle['runtime_id'] or config.runtime_label != bundle['runtime_label']):
                raise OnboardingError('receiving_controller_binding_conflict')
            hashes[str(key_path.relative_to(root))] = key_sha256
        finally:
            key[:] = b'\0' * len(key)
        hashes[str(config_path.relative_to(root))] = hashlib.sha256(
            onboarding_release.regular(config_path, uid=os.geteuid())).hexdigest()
    return dict(schema='cluster-receiving-controller-preservation/v1',
        immutable_sha256=digest(hashes), runtime_sha256=digest(bundle),
        runtime_bytes_sha256=hashes['runtime.json'], counter=bundle['keystore']['counter'],
        controller_id=controllers[0]['descriptor']['capability_id'], origin=bundle['local_origin'],
        not_before_ms=max(row['descriptor']['not_before_ms'] for row in rows),
        not_after_ms=min(row['descriptor']['not_after_ms'] for row in rows),
        active=all(row['descriptor']['status'] == 'active' for row in rows))



def preservation_authorization(expected: dict, expires_at_ms: int) -> None:
    now = time.time_ns() // 1_000_000
    if (not expected['active'] or type(expires_at_ms) is not int or not expected['not_before_ms'] <= now < expires_at_ms
            or expires_at_ms > expected['not_after_ms']):
        raise OnboardingError('receiving_preservation_authorization_expired')


def controller_bootstrap_mode(bundle: dict, preservation: dict | None) -> str:
    """Recover only an expired optional role through the selected native SDK.

    The original owner roles still authorize recovery. Freeze this decision
    before stopping anything; publication revalidates custody and all grants.
    """
    if preservation is None:
        return 'issue'
    from daimon_matrix import operator_runtime_upgrade as upgrade
    from daimon_matrix.operator_capabilities import host_capability_profile
    profile = host_capability_profile('receiving-controller')
    row, = [row for row in bundle['capabilities'] if row['profile'] == profile]
    now = time.time_ns() // 1_000_000
    if row['descriptor']['not_after_ms'] > now:
        return 'preserve'
    import inspect
    if 'renew_receiving_controller' not in inspect.signature(upgrade.stage_capabilities).parameters:
        raise OnboardingError('qualified_controller_renewal_sdk_required')
    upgrade._forward_authorization(bundle, now + 60000, renew_receiving_controller=True)
    if bundle['schema'] != 'dm.runtime.bundle/v8':
        raise OnboardingError('receiving_controller_renewal_v8_required')
    return 'renew'


def renewal_authorization(bundle: dict, expires_at_ms: int) -> None:
    from daimon_matrix import operator_runtime_upgrade as upgrade
    now = upgrade._forward_authorization(bundle, expires_at_ms, renew_receiving_controller=True)
    if expires_at_ms > upgrade._controller_grant_expiry(bundle, now):
        raise OnboardingError('receiving_controller_renewal_authorization_expired')


def controller_stage_options(mode: str) -> dict:
    # Do not send the new keyword to a retained legacy SDK on ordinary issuance.
    return ({'renew_receiving_controller': True} if mode == 'renew'
            else {'provision_receiving_controller': True})


def controller_stage_matches(receipt: dict, mode: str) -> bool:
    return (receipt.get('renew_receiving_controller', False) is (mode == 'renew')
            and receipt.get('provision_receiving_controller', False) is (mode != 'renew'))


def preservation_result(upgrade, root: Path, expected: dict, *, password: bytearray,
                        operation_id: str, request_sha256: str, expires_at_ms: int, retained: dict | None = None) -> dict:
    """Verify unchanged native authority while the caller owns native locks."""
    try:
        if retained is None:
            preservation_authorization(expected, expires_at_ms)
        bundle = being_seed._read(root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        if controller_preservation(root, bundle) != expected:
            raise OnboardingError('receiving_controller_preservation_changed')
        if retained is None:
            upgrade._forward_authorization(bundle, expires_at_ms)
        from daimon_matrix.keystore import EncryptedKeystore
        custody = EncryptedKeystore(root / 'custody.json').open(lambda: bytearray(password),
            minimum_counter=expected['counter'], required_control_head=bundle['control_head'])
        if custody.counter != expected['counter']:
            raise OnboardingError('receiving_controller_counter_conflict')
        before = upgrade.inventory_digest(root)
        if retained is None:
            upgrade._validate(root, Path(upgrade.__file__).resolve().parent.parent, bytes(password))
        if (upgrade.inventory_digest(root) != before
                or controller_preservation(root, bundle) != expected):
            raise OnboardingError('receiving_controller_preservation_changed')
        result = dict(schema='cluster-receiving-owner-preserved/v1', operation_id=operation_id,
            request_sha256=request_sha256, mode='preserve', preservation=expected, inventory_sha256=before,
            runtime_sha256=expected['runtime_sha256'], runtime_bytes_sha256=expected['runtime_bytes_sha256'],
            counter_after=expected['counter'], receiving_readiness='unobserved')
        if retained is None:
            preservation_authorization(expected, expires_at_ms)
        elif any(retained.get(key) != value for key, value in result.items()):
            raise OnboardingError('receiving_controller_preservation_changed')
        return result
    finally:
        password[:] = b'\0' * len(password)


def bootstrap_effects(observations: dict, *, source: bool, mode: str) -> tuple[str, str | None]:
    """Resolve exactly one genuine publication or preservation branch."""
    preserved = observations.get('owner_preserved')
    published = observations.get('capability_published' if source else 'owner_published')
    visibility = observations.get('visibility_published')
    if (mode == 'preserve') != (preserved is not None):
        raise OnboardingError('receiving_bootstrap_effect_conflict')
    if preserved is not None:
        if published is not None or source and visibility is not None:
            raise OnboardingError('receiving_bootstrap_effect_conflict')
        return (preserved['runtime_bytes_sha256'] if source else preserved['runtime_sha256'],
                preserved.get('visibility_sha256'))
    if published is None or source and visibility is None:
        raise OnboardingError('receiving_bootstrap_publication_required')
    if source:
        if not isinstance(visibility, dict):
            raise OnboardingError('receiving_bootstrap_publication_required')
        return published['runtime_sha256'], visibility['installation_sha256']
    return published['runtime_sha256'], None


def admission_lifecycle_link(value: dict, *, being_ref: str, embodiment_id: str) -> dict:
    """Validate the protected association frozen before any lifecycle effect."""
    from .onboarding_group_admission import publication_command
    try:
        if (not isinstance(value, dict) or set(value) != {'schema', 'cohort_operation_id',
                'cohort_intent_sha256', 'tribe_ref', 'owner', 'snapshot_request'}
                or value['schema'] != 'cluster-admission-lifecycle-link/v1'
                or not isinstance(value['cohort_operation_id'], str) or not value['cohort_operation_id']
                or len(value['cohort_operation_id']) > 240
                or not isinstance(value['cohort_intent_sha256'], str)
                or re.fullmatch('[0-9a-f]{64}', value['cohort_intent_sha256']) is None
                or not isinstance(value['tribe_ref'], str) or not value['tribe_ref']
                or value['owner'] != dict(being_ref=being_ref, embodiment_id=embodiment_id)):
            raise ValueError
        command = publication_command(value['snapshot_request'])
        if (command['action'] != 'snapshot' or not isinstance(command['params'].get('expected_preservation'), dict)
                or not isinstance(command['params'].get('expected_stores'), dict)
                or 'ledger' not in command['params']['expected_stores']):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise OnboardingError('receiving_admission_lifecycle_link_required') from None
    return json.loads(json.dumps(value))


def admission_group_derivation(link: dict, snapshot: dict, *, previous: dict, stores: dict) -> dict:
    """Bind the owner's observed after-group to the original admission intent.

    Call only with the actual qualified owner's snapshot result. The native
    route authenticates publications; this layer preserves the frozen physical
    association and original store identities, never a replacement host pin.
    """
    command = link['snapshot_request']
    if (not isinstance(snapshot, dict) or snapshot.get('schema') != 'cluster-group-publication-result/v1'
            or any(snapshot.get(key) != command[key] for key in ('operation_id', 'step', 'action'))
            or snapshot.get('status') != 'recorded' or snapshot.get('receiving_readiness') != 'unobserved'
            or snapshot.get('owner_context_sha256') != command['params']['owner_context_sha256']
            or not isinstance(stores, dict) or 'ledger' not in stores or not stores
            or snapshot.get('stores') != stores
            or not isinstance(snapshot.get('group'), dict)
            or snapshot['group'].get('selected') != previous['selected']
            or snapshot['group']['selected'].get('tribe_ref') != link['tribe_ref']):
        raise OnboardingError('receiving_admission_group_changed')
    return dict(schema='cluster-admission-group-derivation/v1', link_sha256=digest(link),
        cohort_operation_id=link['cohort_operation_id'], cohort_intent_sha256=link['cohort_intent_sha256'],
        snapshot=snapshot, receiving_readiness='unobserved')


def derived_lifecycle_group(candidate: dict, effects: dict, previous: dict, *, required: bool = False) -> dict:
    """Ordinary updates keep the original group; admissions need retained proof."""
    link = candidate.get('admission_link')
    retained = effects.get('admission_group')
    if link is None:
        if retained is not None:
            raise OnboardingError('receiving_admission_lifecycle_link_required')
        return previous
    if retained is None:
        if required:
            raise OnboardingError('receiving_admission_group_unobserved')
        return previous
    if (retained.get('schema') != 'cluster-admission-group-derivation/v1'
            or retained.get('link_sha256') != digest(link)
            or retained.get('cohort_operation_id') != link['cohort_operation_id']
            or retained.get('cohort_intent_sha256') != link['cohort_intent_sha256']
            or retained.get('receiving_readiness') != 'unobserved'):
        raise OnboardingError('receiving_admission_group_changed')
    return retained['snapshot']['group']


def admission_store_bindings(root: Path, bundle: dict, original: dict | None) -> dict:
    """Verify original physical stores read-only, before any runtime can open them."""
    from daimon_matrix.service import LoadedStoreBinding
    if not isinstance(original, dict) or 'ledger' not in original or set(original) - {'ledger', 'relationships'}:
        raise OnboardingError('receiving_admission_store_binding_required')
    current = {}
    for role in original:
        name = bundle['ledger'] if role == 'ledger' else bundle['relationships']['store_filename']
        if not isinstance(name, str) or name in {'', '.', '..'} or Path(name).name != name:
            raise OnboardingError('receiving_admission_store_binding_changed')
        metadata = ({'ledger': 'metadata', 'communication': 'communication_meta'} if role == 'ledger'
                    else {'relationships': 'metadata'})
        try:
            binding = LoadedStoreBinding.capture(root / name, metadata=metadata)
            binding.verify()
        except (ValueError, OSError):
            raise OnboardingError('receiving_admission_store_binding_changed') from None
        current[role] = json.loads(binding.observation)
    if current != original:
        raise OnboardingError('receiving_admission_store_binding_changed')
    return current


def preserved_admission_stores(root: Path, bundle: dict, preservation: dict, original: dict | None) -> dict:
    if controller_preservation(root, bundle) != preservation:
        raise OnboardingError('receiving_controller_preservation_changed')
    return admission_store_bindings(root, bundle, original)


def admission_lifecycle_projection(row: dict, *, profile: str, name: str | None = None) -> dict | None:
    """Export only the retained admission association and public effect hashes.

    The owner validates its full local journal before projecting it. Private
    snapshot inputs, preservation vectors and custody/client locations stay
    local. The cohort must still match this association to its own intent.
    """
    try:
        before, after = row['expected_precondition'], row['intended_transition']
        call = row['intent']['runtime_call']
        if (row['operation'] != 'receiving-update' or row['intent_hash'] != digest(row['intent'])
                or call['precondition_digest'] != digest(before)
                or call['transition_digest'] != digest(after)
                or re.fullmatch('[0-9a-f]{64}', call['manifest_digest']) is None):
            raise ValueError
        if profile == 'source':
            frozen, candidate = before['source_bootstrap'], after['source_bootstrap']
            effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
        elif profile == 'guest' and name is not None:
            frozen, candidate = before['guest_bootstraps'][name]['owner'], after['guest_bootstraps'][name]
            effects = (row['runtime_observation'] or {}).get('guest_bootstraps', {}).get(name, {})
        else:
            raise ValueError
        if 'admission_link' not in candidate:
            if 'admission_group' in effects:
                raise ValueError
            return None
        if profile == 'source':
            owner = dict(zip(('being_ref', 'embodiment_id'), _owner_identity(frozen['predecessor'])))
            group = candidate.get('qualification', {}).get('group')
            stores = frozen['predecessor']['runtime_status']['loaded_runtime']['stores']
        else:
            owner = dict(being_ref=frozen['being_ref'], embodiment_id=frozen['origin']['embodiment_id'])
            group, stores = frozen.get('group'), frozen.get('store_bindings')
        link = admission_lifecycle_link(candidate['admission_link'], **owner)
        if (frozen.get('mode') != 'preserve' or not isinstance(group, dict)
                or group['selected']['tribe_ref'] != link['tribe_ref']
                or stores != link['snapshot_request']['params']['expected_stores']
                or frozen['preservation'] != link['snapshot_request']['params']['expected_preservation']):
            raise ValueError
        retained = effects.get('admission_group')
        derived = None
        if retained is not None:
            snapshot = retained['snapshot']
            if admission_group_derivation(link, snapshot, previous=group, stores=stores) != retained:
                raise ValueError
            publications = snapshot['publications']
            if set(publications) != {'application', 'visibility-publish', 'selection'}:
                raise ValueError
            for action, step_key in (('application', 'application_step'), ('visibility-publish', 'visibility_step'),
                                     ('selection', 'selection_step')):
                result = publications[action]['result']
                if (result.get('schema') != 'cluster-group-publication-result/v1'
                        or result['operation_id'] != snapshot['operation_id'] or result['action'] != action
                        or result['step'] != link['snapshot_request']['params'][step_key]
                        or result['status'] != 'recorded' or result['receiving_readiness'] != 'unobserved'
                        or re.fullmatch('[0-9a-f]{64}', publications[action]['command_sha256']) is None):
                    raise ValueError
            derived = dict(derivation_sha256=digest(retained),
                group={key: snapshot['group'][key] for key in (
                    'application_sha256', 'publication_sha256', 'installation_sha256')},
                selection_sha256=snapshot['selection_sha256'],
                publications={action: dict(command_sha256=receipt['command_sha256'],
                    result_sha256=digest(receipt['result'])) for action, receipt in publications.items()})
        return dict(schema='cluster-admission-lifecycle-projection/v1',
            **{key: link[key] for key in ('cohort_operation_id', 'cohort_intent_sha256', 'tribe_ref', 'owner')},
            link_sha256=digest(link), manifest_digest=call['manifest_digest'],
            snapshot_request_sha256=digest(link['snapshot_request']),
            owner_context_sha256=link['snapshot_request']['params']['owner_context_sha256'],
            publication_operation_id=link['snapshot_request']['operation_id'], derived=derived)
    except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
        raise OnboardingError('receiving_admission_lifecycle_unobserved') from None


def freeze_source_bootstrap(source, manager, *, deadline_ns: int | None = None) -> dict:
    """Freeze the Source's existing identity and actual Matrix manager scope."""
    options = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
    with OwnerGroupClient(source.root, source.root / 'matrix.sock', **options) as owner:
        predecessor = owner.base_status()
        service = manager.inspect(**options)
        scope = manager.bind_process(predecessor['process'], service)
        bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        if (bundle['local_origin'] != predecessor['runtime_status']['local_origin']
                or _owner_identity(predecessor) != (
                    bundle['manifest']['being_ref'], bundle['local_origin']['embodiment_id'])):
            raise OnboardingError('receiving_bootstrap_identity_conflict')
        visibility = onboarding_release.regular(source.visibility, uid=os.geteuid())
        preservation = controller_preservation(source.root, bundle)
        if preservation is not None and (predecessor['runtime_status'].get('loaded_runtime') or {}).get(
                'runtime_bundle_sha256') != preservation['runtime_bytes_sha256']:
            raise OnboardingError('receiving_controller_loaded_bundle_conflict')
        return dict(mode=controller_bootstrap_mode(bundle, preservation), preservation=preservation, settings_sha256=digest(source.settings), unit=str(manager.unit),
            service=service, scope=scope, predecessor=predecessor,
            bundle_sha256=digest(bundle), visibility_sha256=hashlib.sha256(visibility).hexdigest(),
            visibility_envelope=json.loads(visibility))


def prepare_source_bootstrap(source, *, home: Path, code: Path, code_digest: str,
                             config: Path, manifest_path: Path, manifest_digest: str,
                             transaction: Path, expires_at_ms: int, code_uid: int = 0,
                             manifest_uid: int = 0, admission_link: dict | None = None,
                             installed_only: bool = False) -> dict:
    """Prepare the exact supported Source command before managed interruption.

    Only owner-protected release/configuration inputs select executable code.
    This installs an immutable SDK, not custody, authority or a running service.
    """
    from .onboarding_code_successor import sdk_parameters
    for path in (home, code, config, manifest_path, transaction):
        if not path.is_absolute() or '..' in path.parts:
            raise OnboardingError('receiving_bootstrap_binding_conflict')
    if being_seed._read(config) != source.settings:
        raise OnboardingError('receiving_bootstrap_binding_conflict')
    onboarding_release.regular(code / 'clusterctl/onboarding_source.py', uid=code_uid)
    bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
    group = source_bootstrap_group(source, bundle)
    checked = prepare_sdk(home, code, code_digest, manifest_path, manifest_digest,
        being_ref=bundle['manifest']['being_ref'], embodiment_id=bundle['local_origin']['embodiment_id'],
        code_uid=code_uid, manifest_uid=manifest_uid,
        **({'installed_only': True} if installed_only else {}))
    parameters = sdk_parameters(code, uid=code_uid)
    if parameters != dict(matrix_commit=checked['matrix_revision'], matrix_wheel_sha256=checked['matrix_wheel_sha256']):
        raise OnboardingError('qualified_onboarding_source_runtime_required')
    venv = onboarding_sdk.observe(home, code, code_uid=code_uid, **parameters)
    with ExitStack() as read_scope:
        if installed_only:
            read_scope.enter_context(being_seed._locked(venv.parent, shared=True))
            private_directory(venv.parent / 'runtime-imports')
            being_seed._read(venv.parent / 'runtime-imports.json')
        imports = onboarding_sdk.runtime_imports(venv, code, code_uid=code_uid, **parameters)
        argv = onboarding_sdk.runtime_command(venv, imports, code, 'clusterctl.onboarding_source',
            ['--config', str(config), '--code-digest', code_digest, '--code-owner', str(code_uid)])
    association = ({} if admission_link is None else dict(admission_link=admission_lifecycle_link(
        admission_link, being_ref=bundle['manifest']['being_ref'],
        embodiment_id=bundle['local_origin']['embodiment_id'])))
    return dict(transaction=str(transaction), expires_at_ms=expires_at_ms, argv=argv, **association,
        qualification=dict(home=str(home), code=str(code), code_digest=code_digest, code_uid=code_uid, group=group,
            config=str(config), manifest_path=str(manifest_path), manifest_uid=manifest_uid, prepared=checked))


def prepare_source_admission(source, journal_path: Path, request: dict, *, config: Path,
                             deadline_ns: int) -> dict:
    """Plan the existing Source's local admission lifecycle without stopping it.

    The qualified owner supplies code/configuration. The protected coordinator
    supplies the closed preparation recipe; only the resulting public binding
    leaves this owner's journal. Exact retries never freeze a later process.
    """
    from .onboarding_code_successor import plan_update
    from .onboarding_group_admission import preview_owner_context
    from .onboarding_service import MatrixUserService
    from .operation_journal import JournalConflict, OperationJournal
    fields = {'schema', 'operation_id', 'cohort_operation_id', 'cohort_intent_sha256',
        'tribe_ref', 'owner', 'predecessor', 'unit', 'home', 'manifest_path', 'manifest_uid',
        'manifest_digest', 'expires_at_ms', 'authority_closure', 'owner_context_sha256', 'steps'}
    try:
        if (not isinstance(request, dict) or set(request) != fields
                or request['schema'] != 'cluster-source-admission-preparation/v1'
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or any(not isinstance(request[key], str) or not 1 <= len(request[key]) <= 240
                    for key in ('cohort_operation_id', 'tribe_ref'))
                or any(not isinstance(request[key], str) or re.fullmatch('[0-9a-f]{64}', request[key]) is None
                    for key in ('cohort_intent_sha256', 'manifest_digest', 'owner_context_sha256'))
                or any(not isinstance(request[key], str) or not Path(request[key]).is_absolute()
                    or '..' in Path(request[key]).parts for key in ('unit', 'home', 'manifest_path'))
                or type(request['manifest_uid']) is not int or request['manifest_uid'] < 0
                or type(request['expires_at_ms']) is not int or not 0 < request['expires_at_ms'] < 2**53
                or not isinstance(request['owner'], dict) or set(request['owner']) != {'being_ref', 'embodiment_id'}
                or any(not isinstance(value, str) or not value for value in request['owner'].values())
                or not isinstance(request['predecessor'], dict) or set(request['predecessor']) != {'process', 'server'}
                or not all(isinstance(value, dict) for value in request['predecessor'].values())
                or not isinstance(request['authority_closure'], dict)
                or not isinstance(request['steps'], dict)
                or set(request['steps']) != {'application', 'visibility', 'selection', 'snapshot'}
                or any(not isinstance(step, str) or re.fullmatch('[a-z][a-z0-9-]{0,79}', step) is None
                    for step in request['steps'].values()) or len(set(request['steps'].values())) != 4
                or not isinstance(source.qualified_startup, dict)
                or not isinstance(source.code_digest, str) or re.fullmatch('[0-9a-f]{64}', source.code_digest) is None):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('receiving_source_admission_preparation_required') from None
    def budget(*, fresh: bool = False):
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_owner_deadline_expired')
        if fresh and time.time_ns() // 1_000_000 >= request['expires_at_ms']:
            raise OnboardingError('receiving_preservation_authorization_expired')
    budget()
    target = 'source-admission:' + request['operation_id']
    journal = OperationJournal.existing(journal_path)
    row = None if journal is None else journal.latest_for_target(target)
    if row is None:
        budget(fresh=True)
        preview = preview_owner_context(source.root, source.outputs / 'tribe', request['operation_id'],
            request['authority_closure'], deadline_ns=deadline_ns)
        if preview['owner_context_sha256'] != request['owner_context_sha256']:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        manager = MatrixUserService(Path(request['unit']))
        frozen = freeze_source_bootstrap(source, manager, deadline_ns=deadline_ns)
        if (frozen['mode'] != 'preserve' or frozen['bundle_sha256'] != preview['runtime_bundle_sha256']
                or request['predecessor'] != {key: frozen['predecessor'][key] for key in ('process', 'server')}
                or _owner_identity(frozen['predecessor']) != (
                    request['owner']['being_ref'], request['owner']['embodiment_id'])):
            raise OnboardingError('receiving_source_admission_predecessor_changed')
        preservation_authorization(frozen['preservation'], request['expires_at_ms'])
        stores = (frozen['predecessor']['runtime_status'].get('loaded_runtime') or {}).get('stores')
        bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        preserved_admission_stores(source.root, bundle, frozen['preservation'], stores)
        steps = request['steps']
        snapshot = dict(operation_id=request['operation_id'], step=steps['snapshot'], action='snapshot', params=dict(
            application_step=steps['application'], visibility_step=steps['visibility'], selection_step=steps['selection'],
            owner_context_sha256=request['owner_context_sha256'], expected_stores=stores,
            expected_preservation=frozen['preservation']))
        link = admission_lifecycle_link(dict(schema='cluster-admission-lifecycle-link/v1',
            cohort_operation_id=request['cohort_operation_id'], cohort_intent_sha256=request['cohort_intent_sha256'],
            tribe_ref=request['tribe_ref'], owner=request['owner'], snapshot_request=snapshot), **request['owner'])
        with onboarding_sdk.probe_budget(deadline_ns):
            candidate = prepare_source_bootstrap(source, home=Path(request['home']), code=source.code,
                code_digest=source.code_digest, config=config, manifest_path=Path(request['manifest_path']),
                manifest_digest=request['manifest_digest'],
                transaction=source.root.parent / ('.admission-controller-' + request['operation_id']),
                expires_at_ms=request['expires_at_ms'], code_uid=source.code_uid, manifest_uid=request['manifest_uid'],
                admission_link=link, installed_only=True)
        if candidate['qualification']['group']['selected']['tribe_ref'] != request['tribe_ref']:
            raise OnboardingError('receiving_admission_tribe_changed')
        budget(fresh=True)
        journal = OperationJournal(journal_path)
        row = plan_update(journal, manifest_digest=request['manifest_digest'], target=target,
            expected_precondition=dict(source_bootstrap=frozen, source_admission_preparation=request),
            intended_transition=dict(source_bootstrap=candidate),
            audit_identity={'actor': 'qualified-source-admission-owner'})
    if (row['expected_precondition'].get('source_admission_preparation') != request
            or row['state'] in {'degraded', 'compensated'}
            or row['intended_transition']['source_bootstrap']['qualification']['code'] != str(source.code)
            or row['intended_transition']['source_bootstrap']['qualification']['code_digest'] != source.code_digest):
        raise JournalConflict('source admission preparation changed')
    # Reuse the supported owner projection for journal/config/intent integrity;
    # this is historical preparation, never authorization to stop or load.
    projected = source.receiving_lifecycle(journal_path, row['operation_id'])
    link = row['intended_transition']['source_bootstrap']['admission_link']
    if projected['lifecycle'].get('admission', {}).get('link_sha256') != digest(link):
        raise OnboardingError('receiving_source_lifecycle_conflict')
    budget()
    return dict(schema='cluster-source-admission-prepared/v1', operation_id=row['operation_id'],
        source_config_sha256=digest(source.settings), code_digest=source.code_digest, request_sha256=digest(request),
        cohort_operation_id=request['cohort_operation_id'], cohort_intent_sha256=request['cohort_intent_sha256'],
        link_sha256=digest(link), owner_context_sha256=request['owner_context_sha256'], receiving_readiness='unobserved')


def source_bootstrap_group(source, bundle: dict) -> dict:
    """Freeze the existing signed group selector and external publications."""
    from types import SimpleNamespace
    return bootstrap_group(SimpleNamespace(root=source.outputs, package=source.outputs),
        bundle, socket_root=source.outputs)


def bootstrap_group(target, bundle: dict, *, socket_root: Path | None = None) -> dict:
    """Freeze one signed receiving group without changing its publication."""
    from .onboarding_peer import observed_group
    from daimon_matrix.canonical import unb64url
    from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
    from daimon_matrix.messaging_config import config_digest, _public_identity, verify_public_binding, _read_verified_publication
    group = observed_group(target, bundle, socket_root=socket_root)
    if group is None:
        raise OnboardingError('qualified_onboarding_group_required')
    authority = authority_from_runtime_bundle(bundle)
    identity = _public_identity(authority, bundle['local_origin'], bundle['runtime_id'],
        bundle['runtime_label'], time.time_ns() // 1000000)
    key = unb64url(authority.credentials[identity['credential_id']]['body']['signing_key']['public'])
    application, metadata, publication = _read_verified_publication(Path(group['application']),
        lambda value, binding: verify_public_binding(identity, key, value, binding))
    paths = dict(selection=target.root / 'tribe/selection.json',
        publication=Path(group['application']) / 'publication.json',
        application=metadata / 'application.json', binding=metadata / 'binding.json', visibility=Path(group['visibility']))
    visibility = being_seed._read(Path(group['visibility']), limit=being_seed.MAX_SELECTION)
    return dict(selected=group, application_sha256=config_digest(application), publication_sha256=config_digest(publication),
        installation_sha256=config_digest(visibility['document']),
        hashes={key: hashlib.sha256(onboarding_release.regular(
        path, uid=os.geteuid())).hexdigest() for key, path in paths.items()})


def recover_capability_stage(upgrade, *, runtime_root: Path, transaction: Path,
                             source_sha256: str, operation_id: str, observe, record, quiescence) -> None:
    """Reuse retained unpublished-stage recovery under the native source locks.

    The operation must own the transaction before calling this helper. Archive
    intent precedes rename; all bytes and durability survive a lost reply.
    Active publication is never rewound or relabelled as an incomplete stage.
    """
    with upgrade._locks(runtime_root):
        quiescence()
        if upgrade.inventory_digest(runtime_root) != source_sha256:
            raise OnboardingError('receiving_bootstrap_source_changed')
        observations = observe()
        for attempt in range(8):
            key = 'capability_archive_' + str(attempt)
            done = key + '_retained'
            archived = observations.get(key)
            if done in observations:
                continue
            if archived is None:
                if not transaction.exists():
                    return
                archive = transaction.parent / ('.bootstrap-' + operation_id + '-' + str(attempt) + '.incomplete')
                if archive.exists() or archive.is_symlink():
                    raise OnboardingError('receiving_bootstrap_archive_conflict')
                archived = dict(path=str(archive), sha256=upgrade.inventory_digest(transaction))
                record(key, archived)
            archive = Path(archived['path'])
            if archive.exists():
                if transaction.exists() or upgrade.inventory_digest(archive) != archived['sha256']:
                    raise OnboardingError('receiving_bootstrap_archive_conflict')
            else:
                if upgrade.inventory_digest(transaction) != archived['sha256']:
                    raise OnboardingError('receiving_bootstrap_archive_conflict')
                os.rename(transaction, archive)
            # A failed file fsync may be the reason this tree is partial.
            # Preserve its bytes, not just the rename's directory entry.
            snapshot = upgrade._snapshot(archive)
            if upgrade._inventory(snapshot) != archived['sha256']:
                raise OnboardingError('receiving_bootstrap_archive_conflict')
            for name in snapshot:
                if name.endswith('/'):
                    continue
                descriptor = os.open(archive / name, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            for name in sorted((key for key in snapshot if key.endswith('/')), key=len, reverse=True):
                upgrade._sync(archive / name)
            upgrade._sync(archive)
            if upgrade.inventory_digest(archive) != archived['sha256']:
                raise OnboardingError('receiving_bootstrap_archive_conflict')
            upgrade._sync(transaction.parent)
            record(done, archived)
            return
        raise OnboardingError('receiving_bootstrap_attempt_limit')


def _freeze_initial_guest_owner(target, *, deadline_ns: int, initial_service: bool) -> dict:
    """Read initial context while the caller holds the actual native writer.

    Both offline freeze and the initial child's under-lock pre-load assertion
    use this same validation. Never acquire the daemon lock recursively here.
    """
    from .onboarding_service import GuestServiceBootstrap
    prepared = target.observe()
    if (prepared['phase'] != 'v8'
            or (prepared.get('group') is not None) != initial_service):
        raise OnboardingError('receiving_guest_bootstrap_initial_required')
    bundle = target.document_bundle()
    preservation = controller_preservation(target.package / 'runtime', bundle)
    mode = controller_bootstrap_mode(bundle, preservation)
    group = None
    if initial_service:
        # First service start uses the already published optional
        # controller and signed group. It must not issue/renew authority
        # after the group's owner context has been frozen.
        if preservation is None or mode != 'preserve':
            raise OnboardingError('receiving_initial_controller_required')
        now = time.time_ns() // 1_000_000
        if (not preservation['active']
                or not preservation['not_before_ms'] <= now < preservation['not_after_ms']):
            raise OnboardingError('receiving_initial_controller_required')
        group = bootstrap_group(target, bundle)
        if group['selected'] != prepared['group']:
            raise OnboardingError('receiving_guest_bootstrap_group_changed')
    renewal = {}
    if mode == 'renew':
        from daimon_matrix import operator_runtime_upgrade as upgrade
        renewal['renewal_not_after_ms'] = upgrade._controller_grant_expiry(
            bundle, time.time_ns() // 1_000_000)
    GuestServiceBootstrap._budget(deadline_ns)
    return dict(plan_digest=digest(target.plan), genesis_digest=digest(target.genesis),
        code_digest=target.code_digest, runtime_sha256=digest(bundle),
        group_sha256=digest({'group': None} if group is None else group),
        mode=mode, preservation=preservation, **renewal,
        being_ref=bundle['manifest']['being_ref'], origin=bundle['local_origin'], group=group,
        observer_startup=target.qualified_startup, predecessor=None)


def freeze_guest_bootstrap(target, *, deadline_ns: int, initial: bool = False,
                           initial_service: bool = False) -> dict:
    """Freeze a predecessor, initial controller or first selected group load."""
    from .onboarding_service import GuestServiceBootstrap
    if (type(initial) is not bool or type(initial_service) is not bool
            or initial and initial_service):
        raise OnboardingError('invalid_receiving_bootstrap_request')
    GuestServiceBootstrap._budget(deadline_ns)
    if initial or initial_service:
        with being_seed._locked(target.root), target._runtime_writer():
            return _freeze_initial_guest_owner(target, deadline_ns=deadline_ns, initial_service=initial_service)
    observed = target.running(admitted=True, deadline_ns=deadline_ns, bootstrap_base_only=True)
    bundle = target.document_bundle()
    if (observed['responder_association'] != 'same-connection'
            or observed['runtime_sha256'] != digest(bundle)
            or observed['origin'] != bundle['local_origin']
            or observed['runtime_status'].get('being_ref') != bundle['manifest']['being_ref']
            or observed['runtime_status'].get('local_origin') != bundle['local_origin']
            or not isinstance(observed['admission_parent'], dict)):
        raise OnboardingError('receiving_guest_bootstrap_identity_required')
    group = bootstrap_group(target, bundle)
    GuestServiceBootstrap._budget(deadline_ns)
    preservation = controller_preservation(target.package / 'runtime', bundle)
    if preservation is not None and (observed['runtime_status'].get('loaded_runtime') or {}).get(
            'runtime_bundle_sha256') != preservation['runtime_bytes_sha256']:
        raise OnboardingError('receiving_controller_loaded_bundle_conflict')
    mode = controller_bootstrap_mode(bundle, preservation)
    renewal = {}
    if mode == 'renew':
        from daimon_matrix import operator_runtime_upgrade as upgrade
        renewal['renewal_not_after_ms'] = upgrade._controller_grant_expiry(bundle, time.time_ns() // 1_000_000)
    return dict(plan_digest=digest(target.plan), genesis_digest=digest(target.genesis),
        code_digest=target.code_digest, runtime_sha256=digest(bundle), group_sha256=digest(group),
        mode=mode, preservation=preservation, **renewal,
        being_ref=bundle['manifest']['being_ref'], origin=bundle['local_origin'], group=group,
        store_bindings=(observed['runtime_status'].get('loaded_runtime') or {}).get('stores'),
        observer_startup=target.qualified_startup,
        predecessor=dict(process=observed['process'], admission_parent=observed['admission_parent']))


class GuestOwnerBootstrap:
    """Owner-side native capability publication for a host-owned operation.

    The host keeps journal/job ownership and current stopped-unit verification
    across root and owner calls. These protected local files retain only their
    exact publication effects; they are not another authority or readiness.
    This adapter never stops/starts a service or changes the signed group.
    """

    def __init__(self, target, request: dict):
        from .owner_process import validate_process
        initial = request.get('schema') == 'cluster-guest-owner-initial/v1'
        predecessor = request.get('predecessor')
        valid_predecessor = (predecessor is None and request.get('group_sha256') == digest({'group': None})
            if initial else isinstance(predecessor, dict) and set(predecessor) == {'process', 'admission_parent'})
        fields = {'schema', 'operation_id', 'plan_digest', 'genesis_digest', 'code_digest',
                  'runtime_sha256', 'group_sha256', 'predecessor', 'expires_at_ms'}
        if (os.geteuid() != 1000 or set(request) not in (fields, fields | {'mode', 'preservation'})
                or request.get('mode', 'issue') not in {'issue', 'preserve', 'renew'}
                or (request.get('mode', 'issue') in {'preserve', 'renew'}) != isinstance(request.get('preservation'), dict)
                or request.get('mode') in {'preserve', 'renew'} and (
                    request['runtime_sha256'] != request['preservation'].get('runtime_sha256')
                    or request['preservation'].get('origin') != target.document_bundle()['local_origin'])
                or request['schema'] not in {'cluster-guest-owner-bootstrap/v1', 'cluster-guest-owner-initial/v1'}
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or any(not isinstance(request[key], str) or re.fullmatch('[0-9a-f]{64}', request[key]) is None
                       for key in fields - {'schema', 'operation_id', 'predecessor', 'expires_at_ms'})
                or type(request['expires_at_ms']) is not int or request['expires_at_ms'] <= 0
                or request['plan_digest'] != digest(target.plan)
                or request['genesis_digest'] != digest(target.genesis)
                or request['code_digest'] != target.code_digest
                or not valid_predecessor):
            raise OnboardingError('receiving_guest_bootstrap_request_required')
        if not initial:
            child = validate_process(request['predecessor']['process'])
            parent = validate_process(request['predecessor']['admission_parent'])
            if (child['uid'] != 1000 or parent['uid'] != 1000 or child['pid'] == parent['pid']
                    or child['boot_id'] != parent['boot_id']):
                raise OnboardingError('receiving_guest_bootstrap_request_required')
        self.target, self.request = target, request
        self.initial = initial
        self.runtime = target.package / 'runtime'
        self.operation_id = request['operation_id']
        records_parent = private_directory(target.root / 'receiving-bootstrap', create=True)
        self.records = private_directory(records_parent / self.operation_id, create=True)
        self.transaction = self.runtime.parent / ('.receiving-bootstrap-' + self.operation_id)

    def _record(self, name: str, value: dict) -> dict:
        from .onboarding_service import GuestServiceBootstrap
        return GuestServiceBootstrap._record(self.records / (name + '.json'), value)

    def _observations(self) -> dict:
        return {path.stem: json.loads(onboarding_release.regular(path, uid=1000))
                for path in self.records.glob('*.json')}

    def _exits(self) -> None:
        if self.initial:
            # No predecessor exists. Cleanup and native stage/publication own
            # the actual writer; recovery already holds it around this callback.
            # Never recursively acquire that lock or invent an exit receipt.
            return
        from .owner_process import observe_process_exit
        retained = self._observations()
        for name, process in self.request['predecessor'].items():
            proof = dict(process=process, exited=True)
            if name + '_exited' in retained:
                if retained[name + '_exited'] != proof:
                    raise OnboardingError('receiving_guest_bootstrap_request_conflict')
            else:
                if not observe_process_exit(process):
                    raise OnboardingError('receiving_guest_bootstrap_exit_required')
                self._record(name + '_exited', proof)

    def _group(self) -> dict | None:
        if self.initial:
            from .onboarding_peer import observed_group
            if observed_group(self.target, self.target.document_bundle()) is not None:
                raise OnboardingError('receiving_guest_bootstrap_group_changed')
            return None
        group = bootstrap_group(self.target, self.target.document_bundle())
        if (digest(group) != self.request['group_sha256']
                or Path(group['selected']['socket']) != self.runtime / 'tribe.sock'):
            raise OnboardingError('receiving_guest_bootstrap_group_changed')
        return group

    def _ready(self, upgrade, *, deadline_ns: int) -> tuple[dict, str]:
        from .onboarding_service import GuestServiceBootstrap
        ready_path = self.transaction / 'ready.json'
        observations = self._observations()
        intent = observations.get('capability_intent')
        try:
            receipt = json.loads(onboarding_release.regular(ready_path, uid=1000))
            complete = isinstance(receipt, dict) and receipt.get('schema') == 'dm.operator.capability-upgrade/v1'
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            complete = False
        if not complete:
            bundle = self.target.document_bundle()
            if digest(bundle) != self.request['runtime_sha256']:
                raise OnboardingError('receiving_guest_bootstrap_source_changed')
            current = dict(source_sha256=upgrade.inventory_digest(self.runtime), counter=bundle['keystore']['counter'],
                control_head=bundle['control_head'], being_ref=bundle['manifest']['being_ref'], origin=bundle['local_origin'])
            if intent is not None and current != intent:
                raise OnboardingError('receiving_guest_bootstrap_source_changed')
            if self.request.get('mode') == 'renew':
                if controller_preservation(self.runtime, bundle) != self.request['preservation']:
                    raise OnboardingError('receiving_controller_preservation_changed')
                renewal_authorization(bundle, self.request['expires_at_ms'])
            intent = self._record('capability_intent', current)
            stage = dict(transaction=str(self.transaction))
            if 'capability_stage_intent' not in observations:
                if self.transaction.exists() or self.transaction.is_symlink():
                    raise OnboardingError('receiving_guest_bootstrap_unowned_stage')
                self._record('capability_stage_intent', stage)
            elif observations['capability_stage_intent'] != stage:
                raise OnboardingError('receiving_guest_bootstrap_request_conflict')
            recover_capability_stage(upgrade, runtime_root=self.runtime, transaction=self.transaction,
                source_sha256=intent['source_sha256'], operation_id=self.operation_id,
                observe=self._observations, record=self._record, quiescence=self._exits)
            GuestServiceBootstrap._budget(deadline_ns)
            password = self.target._reader()
            try:
                upgrade.stage_capabilities(source=self.runtime, transaction=self.transaction,
                    expected_source_sha256=intent['source_sha256'], expected_counter=intent['counter'],
                    expected_control_head=intent['control_head'], expected_being_ref=intent['being_ref'],
                    expected_origin=intent['origin'], add_methods={},
                    **controller_stage_options(self.request.get('mode', 'issue')), expires_at_ms=self.request['expires_at_ms'], password=bytes(password), externally_quiesced=True)
            finally:
                password[:] = b'\0' * len(password)
            receipt = json.loads(onboarding_release.regular(ready_path, uid=1000))
        if (intent is None or receipt.get('source') != str(self.runtime)
                or receipt.get('transaction') != str(self.transaction)
                or receipt.get('source_sha256') != intent['source_sha256']
                or receipt.get('counter_before') != intent['counter']
                or receipt.get('counter_after') != intent['counter'] + 1
                or receipt.get('control_head') != intent['control_head']
                or receipt.get('being_ref') != intent['being_ref'] or receipt.get('origin') != intent['origin']
                or not controller_stage_matches(receipt, self.request.get('mode', 'issue'))
                or receipt.get('add_methods') != {} or receipt.get('expires_at_ms') != self.request['expires_at_ms']):
            raise OnboardingError('receiving_guest_bootstrap_request_conflict')
        raw = onboarding_release.regular(ready_path, uid=1000)
        ready_sha256 = hashlib.sha256(raw).hexdigest()
        descriptor = os.open(ready_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        upgrade._sync(self.transaction)
        self._record('capability_ready', dict(ready_sha256=ready_sha256))
        GuestServiceBootstrap._budget(deadline_ns)
        return receipt, ready_sha256

    def execute(self, action: str, *, deadline_ns: int, ready_sha256: str | None = None) -> dict:
        from daimon_matrix import operator_runtime_upgrade as upgrade
        from daimon_matrix.daemon import _prepare_socket
        from .onboarding_service import GuestServiceBootstrap
        if (action not in {'stage', 'publish'} or (action == 'publish') != (ready_sha256 is not None)
                or ready_sha256 is not None and re.fullmatch('[0-9a-f]{64}', ready_sha256) is None):
            raise OnboardingError('receiving_guest_bootstrap_request_required')
        GuestServiceBootstrap._budget(deadline_ns)
        with being_seed._locked(self.target.root), being_seed._locked(self.records):
            self._record('request', self.request)
            self._exits()
            self._group()
            if self.request.get('mode', 'issue') == 'preserve':
                if action != 'stage':
                    raise OnboardingError('receiving_preservation_has_no_publication')
                with upgrade._locks(self.runtime):
                    for name in ('matrix.sock', 'tribe.sock', 'peer.sock'):
                        _prepare_socket(self.runtime / name)
                    self.target.observe()
                    result = preservation_result(upgrade, self.runtime, self.request['preservation'],
                        password=self.target._reader(), operation_id=self.operation_id,
                        request_sha256=digest(self.request), expires_at_ms=self.request['expires_at_ms'],
                        retained=self._observations().get('owner_preserved'))
                    self._group()
                    if 'owner_preserved' not in self._observations():
                        preservation_authorization(self.request['preservation'], self.request['expires_at_ms'])
                    self._record('owner_preserved', result)
                    GuestServiceBootstrap._budget(deadline_ns)
                    return result
            with self.target._runtime_writer():
                # The exact parent/child exits and native writer establish safe
                # cleanup of ephemeral runtime sockets, never private history.
                for name in ('matrix.sock', 'tribe.sock', 'peer.sock'):
                    _prepare_socket(self.runtime / name)
            self.target.observe()
            GuestServiceBootstrap._budget(deadline_ns)
            if action == 'stage':
                _, pin = self._ready(upgrade, deadline_ns=deadline_ns)
                return dict(schema='cluster-guest-owner-bootstrap-ready/v1', operation_id=self.operation_id,
                    ready_sha256=pin, receiving_readiness='unobserved')
            retained = self._observations().get('capability_ready')
            if retained != dict(ready_sha256=ready_sha256):
                raise OnboardingError('receiving_guest_bootstrap_ready_required')
            password = self.target._reader()
            try:
                publication = upgrade.publish(source=self.runtime, transaction=self.transaction,
                    expected_receipt_sha256=ready_sha256, password=bytes(password), externally_quiesced=True,
                    capability_upgrade=True)
            finally:
                password[:] = b'\0' * len(password)
            self.target.observe()
            self._group()
            result = dict(schema='cluster-guest-owner-bootstrap-publication/v1', operation_id=self.operation_id,
                ready_sha256=ready_sha256, runtime_sha256=digest(self.target.document_bundle()),
                counter_after=publication['counter_after'], receiving_readiness='unobserved')
            self._record('capability_published', result)
            GuestServiceBootstrap._budget(deadline_ns)
            return result


class SourceBootstrapController:
    """Journaled first controlled adoption through the existing Source owner.

    A live caller needs the approved exact code/SDK and scoped interruption
    consent before invoking this effect adapter. No global Stop is performed.
    The guest's admitted-parent lifecycle is a separate receiving adapter.
    """

    def __init__(self, journal, operation_id: str, source, manager):
        self.journal, self.operation_id = journal, operation_id
        self.source, self.manager = source, manager

    @staticmethod
    def _budget(deadline_ns: int | None) -> None:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_owner_deadline_expired')

    def _remaining(self, timeout_seconds: float, deadline_ns: int | None) -> float:
        self._budget(deadline_ns)
        return timeout_seconds if deadline_ns is None else min(
            timeout_seconds, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)

    def _row(self):
        row = self.journal.get(self.operation_id)
        if (row is None or row['operation'] != 'receiving-update'
                or row['state'] in {'degraded', 'compensated', 'completed'}):
            raise OnboardingError('receiving_bootstrap_operation_required')
        before, after = row['expected_precondition'], row['intended_transition']
        call = row['intent'].get('runtime_call', {})
        if (call.get('precondition_digest') != digest(before)
                or call.get('transition_digest') != digest(after)
                or not re.fullmatch(r'[0-9a-f]{64}', call.get('manifest_digest', ''))):
            raise OnboardingError('receiving_bootstrap_operation_required')
        frozen, candidate = before.get('source_bootstrap'), after.get('source_bootstrap')
        if (not isinstance(frozen, dict) or not isinstance(candidate, dict)
                or frozen.get('settings_sha256') != digest(self.source.settings)
                or frozen.get('unit') != str(self.manager.unit)
                or frozen.get('mode', 'issue') not in {'issue', 'preserve', 'renew'}
                or (frozen.get('mode', 'issue') in {'preserve', 'renew'}) != isinstance(frozen.get('preservation'), dict)
                or frozen.get('mode') in {'preserve', 'renew'} and (
                    'qualification' not in candidate
                    or frozen['preservation'].get('runtime_sha256') != frozen.get('bundle_sha256')
                    or frozen['preservation'].get('origin') != frozen['predecessor'].get('server'))
                or set(candidate) - {'admission_link'} not in ({'transaction', 'expires_at_ms', 'argv'},
                    {'transaction', 'expires_at_ms', 'argv', 'qualification'})):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        if 'admission_link' in candidate:
            if frozen.get('mode') != 'preserve' or 'qualification' not in candidate:
                raise OnboardingError('receiving_admission_prepared_controller_required')
            being_ref, embodiment_id = _owner_identity(frozen['predecessor'])
            link = admission_lifecycle_link(candidate['admission_link'], being_ref=being_ref, embodiment_id=embodiment_id)
            group = candidate['qualification'].get('group') if isinstance(candidate['qualification'], dict) else None
            if (not isinstance(group, dict) or not isinstance(group.get('selected'), dict)
                    or link['tribe_ref'] != group['selected'].get('tribe_ref')):
                raise OnboardingError('receiving_admission_tribe_changed')
            stores = (frozen['predecessor']['runtime_status'].get('loaded_runtime') or {}).get('stores')
            if (not isinstance(stores, dict) or stores != link['snapshot_request']['params']['expected_stores']
                    or frozen['preservation'] != link['snapshot_request']['params']['expected_preservation']):
                raise OnboardingError('receiving_admission_store_binding_required')
        transaction = Path(candidate['transaction'])
        if (not transaction.is_absolute() or '..' in transaction.parts
                or transaction.parent != self.source.root.parent or transaction == self.source.root):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        return row, frozen, candidate

    def _qualify_candidate(self, row: dict, candidate: dict, *, check_group: bool = True) -> dict:
        from .onboarding_code_successor import sdk_parameters
        qualification = candidate['qualification']
        if (not isinstance(qualification, dict) or set(qualification) != {
                'home', 'code', 'code_digest', 'code_uid', 'config', 'manifest_path', 'manifest_uid', 'prepared', 'group'}
                or any(type(qualification[key]) is not int or qualification[key] < 0
                       for key in ('code_uid', 'manifest_uid'))
                or being_seed._read(Path(qualification['config'])) != self.source.settings):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        if any(not Path(qualification[key]).is_absolute() or '..' in Path(qualification[key]).parts
               for key in ('home', 'code', 'config', 'manifest_path')):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        code = Path(qualification['code'])
        onboarding_release.regular(code / 'clusterctl/onboarding_source.py', uid=qualification['code_uid'])
        bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
        if check_group and source_bootstrap_group(self.source, bundle) != derived_lifecycle_group(
                candidate, effects, qualification['group']):
            raise OnboardingError('receiving_bootstrap_group_changed')
        prepared = qualification['prepared']
        predecessor = row['expected_precondition']['source_bootstrap']['predecessor']
        if (prepared.get('being_ref'), prepared.get('embodiment_id')) != _owner_identity(predecessor):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        checked = preflight(code, qualification['code_digest'], Path(qualification['manifest_path']),
            row['intent']['runtime_call']['manifest_digest'], being_ref=prepared['being_ref'],
            embodiment_id=prepared['embodiment_id'], code_uid=qualification['code_uid'],
            manifest_uid=qualification['manifest_uid'])
        if any(prepared.get(key) != value for key, value in checked.items()):
            raise OnboardingError('receiving_bootstrap_candidate_changed')
        parameters = sdk_parameters(code, uid=qualification['code_uid'])
        if parameters != dict(matrix_commit=checked['matrix_revision'], matrix_wheel_sha256=checked['matrix_wheel_sha256']):
            raise OnboardingError('qualified_onboarding_source_runtime_required')
        venv = onboarding_sdk.observe(Path(qualification['home']), code, code_uid=qualification['code_uid'], **parameters)
        if onboarding_sdk.interpreter(venv) != checked['reader']['contract']['interpreter']:
            raise OnboardingError('incompatible_receiving_interpreter')
        imports = onboarding_sdk.runtime_imports(venv, code, code_uid=qualification['code_uid'], **parameters)
        argv = onboarding_sdk.runtime_command(venv, imports, code, 'clusterctl.onboarding_source',
            ['--config', qualification['config'], '--code-digest', qualification['code_digest'],
             '--code-owner', str(qualification['code_uid'])])
        if argv != candidate['argv'] or prepared.get('prepared') is not True:
            raise OnboardingError('receiving_bootstrap_candidate_changed')
        from .onboarding_service import entrypoint
        entrypoint(onboarding_release.regular(self.manager.unit, uid=os.geteuid()), argv)
        return checked

    def _record(self, key: str, value: dict):
        row, _, _ = self._row()
        observations = dict(row['runtime_observation'] or {})
        bootstrap = dict(observations.get('source_bootstrap', {}))
        if key in bootstrap and bootstrap[key] != value:
            raise OnboardingError('receiving_bootstrap_observation_conflict')
        bootstrap[key] = value
        observations['source_bootstrap'] = bootstrap
        self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                             expected_runtime_observation=row['runtime_observation'])

    def _admission_preserved(self, frozen: dict) -> dict:
        """Check immutable owner/store bindings under the native writer.

        The original loaded store observations bind physical identity and
        schema, not mutable ledger contents. Only the frozen admission branch
        uses this instead of ordinary full-inventory equality.
        """
        bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        original = (frozen['predecessor']['runtime_status'].get('loaded_runtime') or {}).get('stores')
        return preserved_admission_stores(self.source.root, bundle, frozen['preservation'], original)

    def retain_admission_group(self, *, timeout_seconds: float = 30, deadline_ns: int | None = None) -> dict:
        """Derive the after-group only from this pre-approved owner's effects."""
        from .onboarding_service import selection_lock
        from .owner_process import observe_process_exit
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_bootstrap_invalid_wait')
        self._budget(deadline_ns)
        options = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            link = candidate.get('admission_link')
            if link is None:
                raise OnboardingError('receiving_admission_lifecycle_link_required')
            self._qualify_candidate(row, candidate, check_group=False)
            self._budget(deadline_ns)
            effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
            if ('owner_preserved' not in effects or 'controlled_loaded' in effects
                    or effects.get('quiesced', {}).get('exit_observed') is not True
                    or not observe_process_exit(frozen['predecessor']['process'])):
                raise OnboardingError('receiving_admission_preservation_required')
            self._stopped(frozen, candidate, **options)
            with self.source.writer():
                stores = self._admission_preserved(frozen)
            request = link['snapshot_request']
            context = being_seed._read(self.source.outputs / 'group-admission' /
                request['operation_id'] / 'owner/context.json', limit=being_seed.MAX_SELECTION)
            if digest(context) != request['params']['owner_context_sha256']:
                raise OnboardingError('receiving_admission_group_changed')
            self._budget(deadline_ns)
            snapshot = self.source.group_publication(request, authority_closure=context['authority_closure'],
                deadline_ns=min(time.monotonic_ns() + int(timeout_seconds * 1_000_000_000),
                    2**63 - 1 if deadline_ns is None else deadline_ns))
            derived = admission_group_derivation(link, snapshot,
                previous=candidate['qualification']['group'], stores=stores)
            self._stopped(frozen, candidate, **options)
            with self.source.writer():
                if self._admission_preserved(frozen) != stores:
                    raise OnboardingError('receiving_admission_store_binding_changed')
                if source_bootstrap_group(self.source, being_seed._read(
                        self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)) != snapshot['group']:
                    raise OnboardingError('receiving_admission_group_changed')
                if hashlib.sha256(self._visibility_current(frozen, {})).hexdigest() != frozen['visibility_sha256']:
                    raise OnboardingError('receiving_bootstrap_visibility_changed')
            self._budget(deadline_ns)
            self._record('admission_group', derived)
            return derived

    def _stopped(self, frozen: dict, candidate: dict, *, deadline_ns: int | None = None):
        from .onboarding_service import entrypoint
        inspected = self.manager.inspect() if deadline_ns is None else self.manager.inspect(deadline_ns=deadline_ns)
        values = inspected['manager']
        original = frozen['service']['unit_sha256']
        current = onboarding_release.regular(self.manager.unit, uid=os.geteuid())
        retained = self.manager.unit.with_name(self.manager.unit.name + '.' + original + '.previous')
        prior = current if hashlib.sha256(current).hexdigest() == original else onboarding_release.regular(retained, uid=os.geteuid())
        if (hashlib.sha256(prior).hexdigest() != original or current not in (prior, entrypoint(prior, candidate['argv']))
                or values['ActiveState'] != 'inactive' or values['SubState'] != 'dead'
                or values['MainPID'] != '0'
                or values['InvocationID'] not in {'', frozen['scope']['invocation_id']}):
            raise OnboardingError('receiving_bootstrap_quiescence_required')
        return inspected

    def _writer_quiesced(self, *, deadline_ns: int | None = None) -> None:
        from daimon_matrix.daemon import _prepare_socket
        with self.source.writer():
            self._budget(deadline_ns)
            # Supported stale-socket checks are safe only after exact process
            # exit and stopped-manager proof. A forced exit may leave this
            # ephemeral socket, which cannot be copied as a runtime artifact.
            _prepare_socket(self.source.root / 'matrix.sock')

    def observe_quiescence(self, *, timeout_seconds: float = 30, deadline_ns: int | None = None) -> dict:
        """Fresh stopped-unit and exact-exit evidence; never dispatch StopUnit."""
        from .onboarding_service import selection_lock
        from .owner_process import observe_process_exit
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_bootstrap_invalid_wait')
        deadline = min(time.monotonic_ns() + int(timeout_seconds * 1_000_000_000),
            2**63 - 1 if deadline_ns is None else deadline_ns)
        self._budget(deadline)
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            retained = (row['runtime_observation'] or {}).get('source_bootstrap', {}).get('quiesced')
            if (not isinstance(retained, dict) or retained.get('process') != frozen['predecessor']['process']
                    or retained.get('exit_observed') is not True or retained.get('writer_available') is not True
                    or not observe_process_exit(frozen['predecessor']['process'])):
                raise OnboardingError('receiving_bootstrap_exit_unobserved')
            inspected = self._stopped(frozen, candidate, deadline_ns=deadline)
            with self.source.writer():
                if time.monotonic_ns() >= deadline:
                    raise OnboardingError('receiving_owner_deadline_expired')
                # Acquire only the native writer: observation must not unlink
                # sockets, load custody or replay a retained stop operation.
                return dict(schema='cluster-source-bootstrap-quiescence/v1', operation_id=self.operation_id,
                    process=frozen['predecessor']['process'], server=frozen['predecessor']['server'],
                    exit_sha256=digest(retained), service=inspected, observed_at_ns=time.monotonic_ns(),
                    receiving_readiness='unobserved')

    def _visibility_current(self, frozen: dict, observations: dict) -> bytes:
        raw = onboarding_release.regular(self.source.visibility, uid=os.geteuid())
        actual = hashlib.sha256(raw).hexdigest()
        intended = observations.get('visibility_intent', {}).get('installation_sha256')
        if actual not in {frozen['visibility_sha256'], intended}:
            raise OnboardingError('receiving_bootstrap_visibility_changed')
        return raw

    def _recover_stage(self, upgrade, transaction: Path, intent: dict, frozen: dict, candidate: dict) -> None:
        recover_capability_stage(upgrade, runtime_root=self.source.root, transaction=transaction,
            source_sha256=intent['source_sha256'], operation_id=self.operation_id,
            observe=lambda: (self._row()[0]['runtime_observation'] or {}).get('source_bootstrap', {}),
            record=self._record, quiescence=lambda: self._stopped(frozen, candidate))

    def _publish_visibility(self, upgrade, frozen: dict, transaction: Path) -> dict:
        """Derive through the owning signer, then journal an exact envelope CAS."""
        from daimon_matrix.canonical import canonical_bytes
        from daimon_matrix.operator_messaging import _reissue_installation
        from .onboarding_service import publish
        observations = (self._row()[0]['runtime_observation'] or {}).get('source_bootstrap', {})
        with self.source.writer():
            self._visibility_current(frozen, observations)
            intended = observations.get('visibility_intent')
            if intended is None:
                current = self.source._load(signed=False)
                bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
                # Only an isolated unpublished copy is passed to the existing
                # reissue helper. Its source is the exact frozen envelope; all
                # local/foreign attestation rules remain owned by Matrix.
                with tempfile.TemporaryDirectory(prefix='.visibility-', dir=transaction) as scratch:
                    copy = Path(scratch) / 'installation.json'
                    publish(copy, canonical_bytes(frozen['visibility_envelope']))
                    _reissue_installation(current, copy, application_sha256=digest(bundle))
                    envelope = being_seed._read(copy, limit=being_seed.MAX_SELECTION)
                raw = canonical_bytes(envelope)
                intended = dict(envelope=envelope, installation_sha256=hashlib.sha256(raw).hexdigest(),
                    runtime_sha256=hashlib.sha256(canonical_bytes(bundle)).hexdigest())
                self._record('visibility_intent', intended)
            raw = canonical_bytes(intended['envelope'])
            if hashlib.sha256(raw).hexdigest() != intended['installation_sha256']:
                raise OnboardingError('receiving_bootstrap_binding_conflict')
            observations = (self._row()[0]['runtime_observation'] or {})['source_bootstrap']
            actual = self._visibility_current(frozen, observations)
            if actual != raw:
                previous = self.source.visibility.with_name(self.source.visibility.name + '.' + frozen['visibility_sha256'] + '.previous')
                publish(previous, actual)
                temporary = self.source.visibility.with_name('.bootstrap-' + self.operation_id + '.json')
                publish(temporary, raw)
                if self._visibility_current(frozen, observations) != actual:
                    raise OnboardingError('receiving_bootstrap_visibility_changed')
                os.replace(temporary, self.source.visibility)
            descriptor = os.open(self.source.visibility, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            upgrade._sync(self.source.visibility.parent)
            self.source._load(signed=True).egress.validate_registered_catalogs()
        return {key: intended[key] for key in ('installation_sha256', 'runtime_sha256')}

    def quiesce(self, *, timeout_seconds: float = 30, deadline_ns: int | None = None) -> dict:
        """Retain exact process exit separately from graceful delivery/drain."""
        from .onboarding_service import selection_lock
        from .owner_process import observe_process_exit
        if type(timeout_seconds) not in {int, float} or not 0 <= timeout_seconds <= 60:
            raise OnboardingError('receiving_bootstrap_invalid_wait')
        self._budget(deadline_ns)
        options = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if 'qualification' in candidate:
                effects = (row['runtime_observation'] or {}).get('source_bootstrap', {})
                if ('admission_link' in candidate and 'owner_preserved' in effects
                        and effects.get('quiesced', {}).get('exit_observed') is True):
                    self._qualify_candidate(row, candidate, check_group=False)
                else:
                    self._qualify_candidate(row, candidate)
            self._budget(deadline_ns)
            if row['state'] == 'planned':
                self.journal.advance(self.operation_id, 'runtime-dispatching')
            if frozen.get('mode', 'issue') in {'preserve', 'renew'}:
                bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
                if controller_preservation(self.source.root, bundle) != frozen['preservation']:
                    raise OnboardingError('receiving_controller_preservation_changed')
            previous = (row['runtime_observation'] or {}).get('source_bootstrap', {}).get('quiesced')
            if previous is not None:
                self._stopped(frozen, candidate, **options)
                if not observe_process_exit(frozen['predecessor']['process']):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                # The operation retains exit proof, but a new/foreign writer
                # still prevents another publication or selection effect.
                self._writer_quiesced(**options)
                return previous
            if (frozen.get('mode') in {'preserve', 'renew'}
                    and self.manager.inspect(**options)['manager']['ActiveState'] == 'inactive'):
                # The frozen, authenticated predecessor can have been stopped
                # after preparation. Observe its actual exit/current unit and
                # writer fence; never restart it just to request another stop.
                stopped = self._stopped(frozen, candidate, **options)
                if not observe_process_exit(frozen['predecessor']['process']):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                self._writer_quiesced(**options)
                result = dict(process=frozen['predecessor']['process'], manager=stopped,
                    exit_observed=True, writer_available=True, graceful_delivery='unobserved')
                self._record('quiesced', result)
                return result
            stop_intent = (row['runtime_observation'] or {}).get('source_bootstrap', {}).get('stop_intent')
            if stop_intent is not None:
                if stop_intent != dict(scope=frozen['scope'], unit_sha256=frozen['service']['unit_sha256']):
                    raise OnboardingError('receiving_bootstrap_binding_conflict')
                if not observe_process_exit(frozen['predecessor']['process']):
                    from .owner_process import ProcessPresence
                    current_manager = self.manager.inspect(**options)
                    values = current_manager['manager']
                    if (current_manager['unit_sha256'] != frozen['service']['unit_sha256']
                            or values['ActiveState'] not in {'active', 'deactivating'}
                            or values['MainPID'] != str(frozen['predecessor']['process']['pid'])
                            or values['InvocationID'] != frozen['scope']['invocation_id']):
                        raise OnboardingError('receiving_bootstrap_predecessor_changed')
                    with ProcessPresence(frozen['predecessor']['process']) as process:
                        # A durable intent does not prove dispatch. Resume only
                        # this unchanged active unit; deactivating means await.
                        if values['ActiveState'] == 'active':
                            if frozen.get('mode') == 'preserve':
                                preservation_authorization(frozen['preservation'], candidate['expires_at_ms'])
                            elif frozen.get('mode') == 'renew':
                                renewal_authorization(bundle, candidate['expires_at_ms'])
                            self._budget(deadline_ns)
                            try:
                                self.manager.stop(**options)
                            except (OnboardingError, OSError):
                                if not process.wait_for_exit(0):
                                    raise
                        if not process.wait_for_exit(self._remaining(timeout_seconds, deadline_ns)):
                            raise OnboardingError('receiving_bootstrap_exit_unobserved')
                stopped = self._stopped(frozen, candidate, **options)
                self._writer_quiesced(**options)
                result = dict(process=frozen['predecessor']['process'], manager=stopped,
                    exit_observed=True, writer_available=True, graceful_delivery='unobserved')
                self._record('quiesced', result)
                return result
            with OwnerGroupClient(self.source.root, self.source.root / 'matrix.sock', **options) as owner:
                observed = owner.base_status()
                inspected = self.manager.inspect(**options)
                scope = self.manager.bind_process(observed['process'], inspected)
                if (observed['process'] != frozen['predecessor']['process']
                        or observed['server'] != frozen['predecessor']['server']
                        or inspected != frozen['service'] or scope != frozen['scope']):
                    raise OnboardingError('receiving_bootstrap_predecessor_changed')
                # Intent precedes stop; a lost CLI reply is not proof of failure.
                self._record('stop_intent', dict(scope=scope, unit_sha256=inspected['unit_sha256']))
                if frozen.get('mode') == 'preserve':
                    preservation_authorization(frozen['preservation'], candidate['expires_at_ms'])
                elif frozen.get('mode') == 'renew':
                    renewal_authorization(bundle, candidate['expires_at_ms'])
                self._budget(deadline_ns)
                try:
                    self.manager.stop(**options)
                except (OnboardingError, OSError):
                    if not owner.wait_for_exit(0):
                        raise
                if not owner.wait_for_exit(self._remaining(timeout_seconds, deadline_ns)):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                stopped = self._stopped(frozen, candidate, **options)
                self._writer_quiesced(**options)
                result = dict(process=observed['process'], manager=stopped,
                    exit_observed=True, writer_available=True, graceful_delivery='unobserved')
                self._record('quiesced', result)
                return result

    def publish(self, *, deadline_ns: int | None = None) -> dict:
        """Recover exact capability/visibility/unit publications while stopped."""
        from daimon_matrix import operator_runtime_upgrade as upgrade
        from .onboarding_service import select_entrypoint, selection_lock
        self._budget(deadline_ns)
        options = {} if deadline_ns is None else {'deadline_ns': deadline_ns}
        selection_options = {} if deadline_ns is None else {'pre_replace': lambda: self._budget(deadline_ns)}
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if deadline_ns is not None and frozen.get('mode') != 'preserve':
                raise OnboardingError('receiving_admission_prepared_controller_required')
            if 'qualification' in candidate:
                self._qualify_candidate(row, candidate)
            self._budget(deadline_ns)
            observations = (row['runtime_observation'] or {}).get('source_bootstrap', {})
            if observations.get('quiesced', {}).get('exit_observed') is not True:
                raise OnboardingError('receiving_bootstrap_quiescence_required')
            from .owner_process import observe_process_exit
            if not observe_process_exit(frozen['predecessor']['process']):
                raise OnboardingError('receiving_bootstrap_exit_unobserved')
            self._stopped(frozen, candidate, **options)
            self._visibility_current(frozen, observations)
            if frozen.get('mode', 'issue') == 'preserve':
                from daimon_matrix.daemon import _prepare_socket
                with upgrade._locks(self.source.root):
                    self._budget(deadline_ns)
                    _prepare_socket(self.source.root / 'matrix.sock')
                    current_visibility = self._visibility_current(frozen, {})
                    if hashlib.sha256(current_visibility).hexdigest() != frozen['visibility_sha256']:
                        raise OnboardingError('receiving_bootstrap_visibility_changed')
                    if 'admission_link' in candidate and 'owner_preserved' in observations:
                        self._admission_preserved(frozen)
                        result = observations['owner_preserved']
                    else:
                        result = preservation_result(upgrade, self.source.root, frozen['preservation'],
                            password=self.source._reader(), operation_id=self.operation_id,
                            request_sha256=digest(dict(frozen=frozen, candidate=candidate)),
                            expires_at_ms=candidate['expires_at_ms'], retained=observations.get('owner_preserved'))
                    if source_bootstrap_group(self.source, being_seed._read(
                            self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)) != derived_lifecycle_group(
                                candidate, observations, candidate['qualification']['group']):
                        raise OnboardingError('receiving_bootstrap_group_changed')
                    if hashlib.sha256(self._visibility_current(frozen, {})).hexdigest() != frozen['visibility_sha256']:
                        raise OnboardingError('receiving_bootstrap_visibility_changed')
                    result['visibility_sha256'] = frozen['visibility_sha256']
                    if 'owner_preserved' not in observations:
                        preservation_authorization(frozen['preservation'], candidate['expires_at_ms'])
                    self._record('owner_preserved', result)
                    stopped = self._stopped(frozen, candidate, **options)
                    if stopped['unit_sha256'] == frozen['service']['unit_sha256']:
                        preservation_authorization(frozen['preservation'], candidate['expires_at_ms'])
                    selected = select_entrypoint(self.manager.unit, candidate['argv'],
                        previous_sha256=frozen['service']['unit_sha256'], **selection_options)
                    self._record('unit_selected', selected)
                return dict(schema='cluster-source-bootstrap-preservation/v1', operation_id=self.operation_id,
                    preserved=True, loaded_readiness='unobserved')
            password = bytes(self.source._reader())
            transaction = Path(candidate['transaction'])
            ready_path = transaction / 'ready.json'
            try:
                ready_document = json.loads(onboarding_release.regular(ready_path, uid=os.geteuid()))
                complete = isinstance(ready_document, dict) and ready_document.get('schema') == 'dm.operator.capability-upgrade/v1'
            except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
                complete = False
            if not complete:
                bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
                if digest(bundle) != frozen['bundle_sha256']:
                    raise OnboardingError('receiving_bootstrap_identity_conflict')
                intent = dict(source_sha256=upgrade.inventory_digest(self.source.root),
                    counter=bundle['keystore']['counter'], control_head=bundle['control_head'],
                    being_ref=bundle['manifest']['being_ref'], origin=bundle['local_origin'])
                if frozen.get('mode') == 'renew':
                    if controller_preservation(self.source.root, bundle) != frozen['preservation']:
                        raise OnboardingError('receiving_controller_preservation_changed')
                    renewal_authorization(bundle, candidate['expires_at_ms'])
                retained_intent = observations.get('capability_intent', intent)
                if retained_intent != intent:
                    raise OnboardingError('receiving_bootstrap_source_changed')
                self._record('capability_intent', intent)
                stage_intent = observations.get('capability_stage_intent')
                if stage_intent is None:
                    if transaction.exists() or transaction.is_symlink():
                        raise OnboardingError('receiving_bootstrap_unowned_stage')
                    self._record('capability_stage_intent', dict(transaction=str(transaction)))
                elif stage_intent != dict(transaction=str(transaction)):
                    raise OnboardingError('receiving_bootstrap_binding_conflict')
                self._recover_stage(upgrade, transaction, intent, frozen, candidate)
                self._stopped(frozen, candidate, **options)
                upgrade.stage_capabilities(source=self.source.root, transaction=transaction,
                    expected_source_sha256=intent['source_sha256'], expected_counter=intent['counter'],
                    expected_control_head=intent['control_head'], expected_being_ref=intent['being_ref'],
                    expected_origin=intent['origin'], add_methods={},
                    **controller_stage_options(frozen.get('mode', 'issue')), expires_at_ms=candidate['expires_at_ms'], password=password, externally_quiesced=True)
            ready = onboarding_release.regular(ready_path, uid=os.geteuid())
            receipt = json.loads(ready)
            intent = (self._row()[0]['runtime_observation'] or {})['source_bootstrap']['capability_intent']
            if (receipt.get('source_sha256') != intent['source_sha256']
                    or receipt.get('origin') != intent['origin'] or receipt.get('control_head') != intent['control_head']
                    or not controller_stage_matches(receipt, frozen.get('mode', 'issue'))
                    or receipt.get('add_methods') != {} or receipt.get('expires_at_ms') != candidate['expires_at_ms']):
                raise OnboardingError('receiving_bootstrap_binding_conflict')
            ready_hash = hashlib.sha256(ready).hexdigest()
            descriptor = os.open(ready_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            upgrade._sync(transaction)
            self._record('capability_ready', dict(ready_sha256=ready_hash))
            self._stopped(frozen, candidate, **options)
            # After a lost publication ACK the native helper resolves the same
            # atomic exchange. Never restage or restore its old checkpoint.
            published = observations.get('capability_published')
            if published is None:
                publication = upgrade.publish(source=self.source.root, transaction=transaction,
                    expected_receipt_sha256=ready_hash, password=password, externally_quiesced=True,
                    capability_upgrade=True)
                published = dict(publication=publication, runtime_sha256=hashlib.sha256(
                    onboarding_release.regular(self.source.root / 'runtime.json', uid=os.geteuid())).hexdigest())
                self._record('capability_published', published)
            if hashlib.sha256(onboarding_release.regular(self.source.root / 'runtime.json', uid=os.geteuid())).hexdigest() != published['runtime_sha256']:
                raise OnboardingError('receiving_bootstrap_source_changed')
            self._stopped(frozen, candidate, **options)
            self._record('visibility_published', self._publish_visibility(upgrade, frozen, transaction))
            self._stopped(frozen, candidate, **options)
            selected = select_entrypoint(self.manager.unit, candidate['argv'],
                previous_sha256=frozen['service']['unit_sha256'], **selection_options)
            self._record('unit_selected', selected)
            return dict(schema='cluster-source-bootstrap-publication/v1', operation_id=self.operation_id,
                        published=True, loaded_readiness='unobserved')

    def start(self, *, timeout_seconds: float = 30, deadline_ns: int | None = None) -> dict:
        """Start the selected exact command and retain actual controlled load.

        Older publication-only operations cannot use this method. The supported
        prepared candidate is requalified before the first lifecycle effect.
        A retained load never authorizes replacing/restarting a later process.
        """
        from daimon_matrix.client import ClientError
        from .onboarding_service import selection_lock
        from .owner_process import observe_process_exit
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_bootstrap_invalid_wait')
        self._budget(deadline_ns)
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if 'qualification' not in candidate:
                raise OnboardingError('qualified_bootstrap_candidate_required')
            checked = self._qualify_candidate(row, candidate)
            self._budget(deadline_ns)
            observations = (row['runtime_observation'] or {}).get('source_bootstrap', {})
            expected_group = derived_lifecycle_group(candidate, observations, candidate['qualification']['group'],
                required='admission_link' in candidate)
            selected = observations.get('unit_selected')
            if not isinstance(selected, dict) or selected.get('selected') is not True:
                raise OnboardingError('receiving_bootstrap_publication_required')
            expected_runtime, expected_visibility = bootstrap_effects(observations, source=True, mode=frozen.get('mode', 'issue'))
            # Artifact verification precedes the lifecycle budget. Local file
            # hashing/fsync scheduling is not a hard realtime guarantee; check
            # the shared monotonic deadline before dispatch and acceptance.
            if deadline_ns is None:
                deadline_ns = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
            inspected = self.manager.inspect(deadline_ns=deadline_ns)
            if inspected['unit_sha256'] != selected['selected_sha256']:
                raise OnboardingError('receiving_bootstrap_candidate_changed')
            retained = observations.get('controlled_loaded')
            if retained is None:
                if not observe_process_exit(frozen['predecessor']['process']):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                intent = dict(unit_sha256=selected['selected_sha256'], candidate_sha256=digest(candidate))
                self._record('start_intent', intent)
                if inspected['manager']['ActiveState'] == 'inactive':
                    self._stopped(frozen, candidate, deadline_ns=deadline_ns)
                    with self.source.writer():
                        if frozen.get('mode', 'issue') == 'preserve':
                            from daimon_matrix import operator_runtime_upgrade as upgrade
                            preservation_authorization(frozen['preservation'], candidate['expires_at_ms'])
                            bundle = being_seed._read(self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
                            if 'admission_link' in candidate:
                                self._admission_preserved(frozen)
                            elif (controller_preservation(self.source.root, bundle) != frozen['preservation']
                                      or upgrade.inventory_digest(self.source.root) != observations['owner_preserved']['inventory_sha256']):
                                raise OnboardingError('receiving_controller_preservation_changed')
                        actual_bundle = hashlib.sha256(onboarding_release.regular(
                            self.source.root / 'runtime.json', uid=os.geteuid())).hexdigest()
                        actual_visibility = hashlib.sha256(onboarding_release.regular(
                            self.source.visibility, uid=os.geteuid())).hexdigest()
                        if (actual_bundle != expected_runtime
                                or actual_visibility != expected_visibility
                                or source_bootstrap_group(self.source, being_seed._read(
                                    self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION))
                                   != expected_group):
                            raise OnboardingError('receiving_bootstrap_publication_changed')
                    # Named-unit scope, including recovery after lost dispatch
                    # confirmation. An active candidate is only observed.
                    try:
                        self.manager.start(deadline_ns=deadline_ns)
                    except (OnboardingError, OSError):
                        if self.manager.inspect(deadline_ns=deadline_ns)['manager']['ActiveState'] not in {'active', 'activating'}:
                            raise
            while True:
                if time.monotonic_ns() >= deadline_ns:
                    raise OnboardingError('receiving_bootstrap_start_unobserved')
                inspected = self.manager.inspect(deadline_ns=deadline_ns)
                if inspected['unit_sha256'] != selected['selected_sha256']:
                    raise OnboardingError('receiving_bootstrap_candidate_changed')
                if inspected['manager']['ActiveState'] == 'active':
                    try:
                        actual = self.source.observe(require_loaded=True, deadline_ns=deadline_ns)
                    except (ClientError, OSError):
                        if retained is not None:
                            raise OnboardingError('receiving_bootstrap_loaded_process_changed') from None
                    else:
                        if time.monotonic_ns() >= deadline_ns:
                            raise OnboardingError('receiving_bootstrap_start_unobserved')
                        scope = self.manager.bind_process(actual['process'], inspected)
                        base = actual['base_runtime_status']['loaded_runtime']
                        application = actual['runtime_status']['loaded_application']
                        startup = base['qualified_startup']
                        gate = actual['runtime_status'].get('receiving', {}).get('channels', {}).get('tribe')
                        expected = dict(code_digest=checked['code_digest'], matrix_commit=checked['matrix_revision'],
                            sdk_digest=checked['sdk_digest'], matrix_wheel_sha256=checked['matrix_wheel_sha256'],
                            reader=checked['reader'])
                        group = expected_group
                        if (any(startup.get(key) != value for key, value in expected.items())
                                or startup.get('process_id') != actual['process']['pid']
                                or base.get('runtime_bundle_sha256') != expected_runtime
                                or actual.get('responder_association') != 'same-connection'
                                or not isinstance(gate, dict) or gate.get('controlled') is not True
                                or gate.get('process_id') != actual['process']['pid']):
                            raise OnboardingError('receiving_bootstrap_loaded_candidate_conflict')
                        if ('admission_link' in candidate and base.get('stores') !=
                                (frozen['predecessor']['runtime_status'].get('loaded_runtime') or {}).get('stores')):
                            raise OnboardingError('receiving_bootstrap_loaded_store_conflict')
                        if (actual.get('group') != group['selected']
                                or any(application.get(key) != group[key]
                                       for key in ('application_sha256', 'publication_sha256'))
                                or application.get('visibility', {}).get('installation_sha256') != group['installation_sha256']):
                            raise OnboardingError('receiving_bootstrap_loaded_group_conflict')
                        normalized = dict(process=actual['process'], manager=scope, loaded_runtime=base,
                            loaded_application={key: value for key, value in application.items() if key != 'reader_gates'})
                        if retained is not None:
                            if any(retained.get(key) != value for key, value in normalized.items()):
                                raise OnboardingError('receiving_bootstrap_loaded_process_changed')
                            return retained
                        if gate.get('phase') != 'unselected' or gate.get('readers') != []:
                            raise OnboardingError('receiving_bootstrap_initial_gate_conflict')
                        result = dict(schema='cluster-source-bootstrap-controlled-load/v1', **normalized,
                            initial_gate=gate, receiving_readiness='unobserved')
                        self._record('controlled_loaded', result)
                        return result
                elif retained is not None:
                    raise OnboardingError('receiving_bootstrap_loaded_process_changed')
                if time.monotonic_ns() >= deadline_ns:
                    raise OnboardingError('receiving_bootstrap_start_unobserved')
                time.sleep(min(0.1, max(0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)))


def prepare_guest_bootstrap(backend, plan: dict, *, candidate: tuple[Path, str],
                            manifest_path: Path, manifest_digest: str, expires_at_ms: int,
                            timeout_seconds: float = 30, manifest_uid: int = 0,
                            admission_link: dict | None = None, installed_only: bool = False,
                            deadline_ns: int | None = None) -> tuple[dict, dict]:
    """Prepare one guest without selecting code or interrupting its service.

    A receiving operation freezes these vectors before any lifecycle effect.
    Read-only candidate mounts must already be installed by supported preparation.
    """
    from .onboarding_service import command
    def remaining():
        if deadline_ns is None:
            return timeout_seconds
        if type(deadline_ns) is not int:
            raise OnboardingError('receiving_owner_deadline_expired')
        value = min(timeout_seconds, (deadline_ns-time.monotonic_ns())/1_000_000_000)
        if value <= 0:
            raise OnboardingError('receiving_owner_deadline_expired')
        return value
    remaining()
    if type(expires_at_ms) is not int or expires_at_ms <= time.time_ns() // 1_000_000:
        raise OnboardingError('receiving_guest_bootstrap_authorization_expired')
    manifest = _manifest(manifest_path, manifest_digest, uid=manifest_uid)
    onboarding_release.verify(candidate[0], candidate[1], uid=os.geteuid())
    onboarding_sdk.verify(candidate[0], uid=os.geteuid(),
        matrix_commit=manifest['provenance']['matrix_revision'],
        matrix_wheel_sha256=manifest['artifacts']['matrix_sdk'])
    if not any({**manifest['artifacts'], **receiver.get('artifacts', {})}.get('receiving_code') == candidate[1]
            for receiver in manifest['required_receivers']):
        raise OnboardingError('receiving_artifact_selection_mismatch')
    installed = backend._target_call(plan, 'sdk-observe' if installed_only else 'sdk-prepare', candidate=candidate,
        **({'observation_timeout_seconds': remaining()} if deadline_ns is not None else {}))
    if installed.get('ready') is not True:
        raise OnboardingError('qualified_guest_bootstrap_candidate_required')
    owner = backend._target_call(plan, 'receiving-bootstrap-freeze', candidate=candidate,
        bootstrap_timeout_seconds=remaining())
    remaining()
    with onboarding_sdk.probe_budget(deadline_ns):
        checked = preflight(candidate[0], candidate[1], manifest_path, manifest_digest,
            being_ref=owner['being_ref'], embodiment_id=owner['origin']['embodiment_id'],
            code_uid=os.geteuid(), manifest_uid=manifest_uid)
    if installed.get('matrix_commit') != checked['matrix_revision']:
        raise OnboardingError('qualified_guest_bootstrap_candidate_required')
    startup = owner.get('observer_startup')
    if (not isinstance(startup, dict) or any(startup.get(key) != value for key, value in dict(
            code_digest=checked['code_digest'], matrix_commit=checked['matrix_revision'],
            matrix_wheel_sha256=checked['matrix_wheel_sha256'], sdk_digest=checked['sdk_digest'],
            reader=checked['reader']).items()) or not isinstance(startup.get('interpreter'), dict)
            or any(startup['interpreter'].get(key) != value
                   for key, value in checked['reader']['contract']['interpreter'].items())
            or not isinstance(startup['interpreter'].get('executable_sha256'), str)
            or re.fullmatch('[0-9a-f]{64}', startup['interpreter']['executable_sha256']) is None):
        raise OnboardingError('qualified_guest_bootstrap_candidate_required')
    root = backend._guest_service_call(plan, 'bootstrap-inspect', candidate=candidate,
        timeout_seconds=remaining(), owner_observation=owner['predecessor'])
    if (root.get('scope') is None or root['scope']['process'] != owner['predecessor']['process']
            or root['scope']['admission_parent'] != owner['predecessor']['admission_parent']):
        raise OnboardingError('receiving_guest_bootstrap_identity_required')
    base = backend._receiving_base(plan)
    selected, _, _ = backend._runtime_paths(plan, base, candidate=candidate)
    argv = command(base, receive_only=False, visibility=Path(owner['group']['selected']['visibility']),
        runtime_code=selected, runtime_digest=candidate[1])
    # Validate the maintained unit encoding locally before interruption. Root
    # subsequently validates against its actual preserved disk unit too.
    from .onboarding_service import entrypoint
    entrypoint(b'[Service]\nExecStart=/prepared\n', argv)
    association = ({} if admission_link is None else dict(admission_link=admission_lifecycle_link(
        admission_link, being_ref=owner['being_ref'], embodiment_id=owner['origin']['embodiment_id'])))
    remaining()
    return dict(plan=plan, owner=owner, root=root), dict(
        runtime_code=str(candidate[0]), runtime_digest=candidate[1], manifest_path=str(manifest_path),
        manifest_uid=manifest_uid, code_uid=os.geteuid(), prepared=checked,
        argv=argv, expires_at_ms=expires_at_ms, **association)


def prepare_guest_admission(backend, plan: dict, journal, request: dict, *, config: Path,
                            candidate: tuple[Path, str], deadline_ns: int) -> dict:
    """Plan an old guest's existing lifecycle before group admission effects.

    Reconcile the stable retained target before observing a later process. The
    host retains public owner/root preparations, never opens guest custody and
    never installs SDKs, selects a unit or changes the signed group here.
    """
    from .onboarding_code_successor import plan_update
    from .onboarding_group_admission import publication_command
    from .onboarding_host import HostConfig
    from .operation_journal import JournalConflict
    fields = {'schema', 'operation_id', 'cohort_operation_id', 'cohort_intent_sha256',
        'tribe_ref', 'owner', 'predecessor', 'root', 'manifest_path', 'manifest_uid',
        'manifest_digest', 'expires_at_ms', 'authority_closure', 'owner_context_sha256', 'steps'}
    try:
        if (not isinstance(request, dict) or set(request) != fields
                or request['schema'] != 'cluster-guest-admission-preparation/v1'
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or any(not isinstance(request[key], str) or not 1 <= len(request[key]) <= 240
                       for key in ('cohort_operation_id', 'tribe_ref'))
                or any(not isinstance(request[key], str) or re.fullmatch('[0-9a-f]{64}', request[key]) is None
                       for key in ('cohort_intent_sha256', 'manifest_digest', 'owner_context_sha256'))
                or any(not isinstance(request[key], str) or not Path(request[key]).is_absolute()
                       or '..' in Path(request[key]).parts for key in ('root', 'manifest_path'))
                or type(request['manifest_uid']) is not int or request['manifest_uid'] < 0
                or type(request['expires_at_ms']) is not int or not 0 < request['expires_at_ms'] < 2**53
                or not isinstance(request['owner'], dict) or set(request['owner']) != {'being_ref', 'embodiment_id'}
                or any(not isinstance(value, str) or not value for value in request['owner'].values())
                or not isinstance(request['predecessor'], dict) or set(request['predecessor']) != {'process', 'server'}
                or any(not isinstance(value, dict) for value in request['predecessor'].values())
                or not isinstance(request['authority_closure'], dict) or not isinstance(request['steps'], dict)
                or set(request['steps']) != {'application', 'visibility', 'selection', 'snapshot'}
                or len(set(request['steps'].values())) != 4):
            raise ValueError
        steps = request['steps']
        snapshot = publication_command(dict(operation_id=request['operation_id'], step=steps['snapshot'], action='snapshot',
            params=dict(application_step=steps['application'], visibility_step=steps['visibility'],
                selection_step=steps['selection'], owner_context_sha256=request['owner_context_sha256'])))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise OnboardingError('receiving_guest_admission_preparation_required') from None

    def budget(*, fresh: bool = False):
        if type(deadline_ns) is not int or time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_owner_deadline_expired')
        if fresh and time.time_ns()//1_000_000 >= request['expires_at_ms']:
            raise OnboardingError('receiving_preservation_authorization_expired')
    budget()
    if backend.config != HostConfig.load(config):
        raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
    target = 'guest-admission:' + plan['name'] + ':' + request['operation_id']
    row = journal.latest_for_target(target)
    if row is None:
        budget(fresh=True)
        owner = GuestGroupClient(backend, plan, candidate, root=Path(request['root']))
        owner.deadline_ns = deadline_ns
        preview = owner.group_publication(dict(operation_id=request['operation_id'],
            step='context', action='context-preview', params={}), authority_closure=request['authority_closure'])
        if preview.get('owner_context_sha256') != request['owner_context_sha256']:
            raise OnboardingError('onboarding_group_owner_context_conflict')
        before, prepared = prepare_guest_bootstrap(backend, plan, candidate=candidate,
            manifest_path=Path(request['manifest_path']), manifest_digest=request['manifest_digest'],
            expires_at_ms=request['expires_at_ms'], manifest_uid=request['manifest_uid'],
            installed_only=True, deadline_ns=deadline_ns)
        frozen = before['owner']
        if (frozen.get('mode') != 'preserve' or frozen['runtime_sha256'] != preview.get('runtime_bundle_sha256')
                or request['owner'] != dict(being_ref=frozen['being_ref'], embodiment_id=frozen['origin']['embodiment_id'])
                or request['predecessor'] != dict(process=frozen['predecessor']['process'], server=frozen['origin'])
                or frozen['group']['selected']['tribe_ref'] != request['tribe_ref']
                or frozen['group']['selected']['socket'] != str(owner.socket)
                or not isinstance(frozen.get('store_bindings'), dict) or 'ledger' not in frozen['store_bindings']):
            raise OnboardingError('receiving_guest_admission_predecessor_changed')
        preservation_authorization(frozen['preservation'], request['expires_at_ms'])
        snapshot['params'].update(expected_stores=frozen['store_bindings'], expected_preservation=frozen['preservation'])
        link = admission_lifecycle_link(dict(schema='cluster-admission-lifecycle-link/v1',
            cohort_operation_id=request['cohort_operation_id'], cohort_intent_sha256=request['cohort_intent_sha256'],
            tribe_ref=request['tribe_ref'], owner=request['owner'], snapshot_request=snapshot), **request['owner'])
        prepared['admission_link'] = link
        host = being_seed._read(config)
        if backend.config != HostConfig.load(config, expected_value=host):
            raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
        budget(fresh=True)
        row = plan_update(journal, manifest_digest=request['manifest_digest'], target=target,
            expected_precondition=dict(host_config=str(config), host_configuration=host, host_config_sha256=digest(host),
                guest_bootstraps={plan['name']: before}, guest_admission_preparation=request),
            intended_transition=dict(guest_bootstraps={plan['name']: prepared}),
            audit_identity={'actor': 'qualified-guest-admission-owner'})
    if (row['expected_precondition'].get('guest_admission_preparation') != request
            or row['expected_precondition'].get('host_config') != str(config)
            or row['expected_precondition']['guest_bootstraps'][plan['name']]['plan'] != plan
            or row['state'] in {'degraded', 'compensated'}
            or row['intended_transition']['guest_bootstraps'][plan['name']]['runtime_code'] != str(candidate[0])
            or row['intended_transition']['guest_bootstraps'][plan['name']]['runtime_digest'] != candidate[1]):
        raise JournalConflict('guest admission preparation changed')
    checked, _before, prepared = GuestBootstrapController(journal, row['operation_id'], backend, plan['name'])._row()
    link = prepared['admission_link']
    budget()
    return dict(schema='cluster-guest-admission-prepared/v1', operation_id=checked['operation_id'],
        host_config_sha256=checked['expected_precondition']['host_config_sha256'], code_digest=candidate[1],
        request_sha256=digest(request), cohort_operation_id=request['cohort_operation_id'],
        cohort_intent_sha256=request['cohort_intent_sha256'], link_sha256=digest(link),
        owner_context_sha256=request['owner_context_sha256'], receiving_readiness='unobserved')


def guest_bootstrap_operation_id(operation_id: str) -> str:
    """Preserve canonical UUIDs; retain the existing namespaced journal route."""
    try:
        if str(uuid.UUID(operation_id)) == operation_id:
            return operation_id
    except ValueError:
        pass
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'cluster-guest-bootstrap:' + operation_id))


class GuestBootstrapController:
    """One journal/job-owned operation spans public root and private owner calls.

    Call only after exact candidate/readiness/recovery preparation and scoped
    human interruption consent for live receivers. No global Stop is performed.
    This controller retains bootstrap/load evidence, not cohort readiness.
    """

    def __init__(self, journal, operation_id: str, backend, name: str):
        self.journal, self.operation_id, self.backend, self.name = journal, operation_id, backend, name

    def _native_operation_id(self) -> str:
        return guest_bootstrap_operation_id(self.operation_id)

    def _row(self) -> tuple[dict, dict, dict]:
        row = self.journal.get(self.operation_id)
        if (row is None or row['operation'] != 'receiving-update'
                or row['state'] in {'degraded', 'compensated', 'completed'}):
            raise OnboardingError('receiving_guest_bootstrap_operation_required')
        before, after = row['expected_precondition'], row['intended_transition']
        call = row['intent'].get('runtime_call', {})
        if (call.get('precondition_digest') != digest(before) or call.get('transition_digest') != digest(after)
                or not re.fullmatch('[0-9a-f]{64}', call.get('manifest_digest', ''))
                or before.get('host_config_sha256') != digest(before.get('host_configuration'))
                or being_seed._read(Path(before['host_config'])) != before['host_configuration']
                or Path(before['host_configuration']['jobs']) != self.backend.config.jobs):
            raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
        frozen = before['guest_bootstraps'][self.name]
        candidate = after['guest_bootstraps'][self.name]
        if (set(frozen) != {'plan', 'owner', 'root'} or frozen['plan']['name'] != self.name
                or type(candidate['expires_at_ms']) is not int or candidate['expires_at_ms'] <= 0
                or frozen['owner'].get('mode', 'issue') not in {'issue', 'preserve', 'renew'}
                or (frozen['owner'].get('mode', 'issue') in {'preserve', 'renew'}) != isinstance(frozen['owner'].get('preservation'), dict)
                or frozen['owner']['plan_digest'] != digest(frozen['plan'])
                or frozen['owner'].get('mode') in {'preserve', 'renew'} and (
                    frozen['owner']['preservation'].get('runtime_sha256') != frozen['owner']['runtime_sha256']
                    or frozen['owner']['preservation'].get('origin') != frozen['owner']['origin'])
                or candidate['runtime_digest'] != frozen['owner']['code_digest']
                or (candidate['prepared']['being_ref'], candidate['prepared']['embodiment_id']) != (
                    frozen['owner']['being_ref'], frozen['owner']['origin']['embodiment_id'])
                or candidate['prepared']['release_digest'] != call['manifest_digest']):
            raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
        from .onboarding_service import command
        base = Path('/opt/daimon-onboarding') / frozen['plan']['release_digest']
        selected = Path('/opt/daimon-onboarding-runtime') / candidate['runtime_digest']
        if candidate['argv'] != command(base, receive_only=False,
                visibility=Path(frozen['owner']['group']['selected']['visibility']),
                runtime_code=selected, runtime_digest=candidate['runtime_digest']):
            raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
        if 'admission_link' in candidate:
            owner = frozen['owner']
            if owner.get('mode') != 'preserve':
                raise OnboardingError('receiving_admission_prepared_controller_required')
            link = admission_lifecycle_link(candidate['admission_link'], being_ref=owner['being_ref'],
                embodiment_id=owner['origin']['embodiment_id'])
            if link['tribe_ref'] != owner['group']['selected']['tribe_ref']:
                raise OnboardingError('receiving_admission_tribe_changed')
            if (owner.get('store_bindings') != link['snapshot_request']['params']['expected_stores']
                    or owner['preservation'] != link['snapshot_request']['params']['expected_preservation']):
                raise OnboardingError('receiving_admission_store_binding_required')
        return row, frozen, candidate

    def _record(self, name: str, value: dict) -> None:
        from .operation_journal import JournalConflict
        row, _, _ = self._row()
        observations = dict(row['runtime_observation'] or {})
        guests = dict(observations.get('guest_bootstraps', {}))
        effects = dict(guests.get(self.name, {}))
        if name in effects and effects[name] != value:
            raise JournalConflict('receiving guest effect changed')
        effects[name] = value
        guests[self.name] = effects
        observations['guest_bootstraps'] = guests
        self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
            expected_runtime_observation=row['runtime_observation'])

    def execute(self, *, timeout_seconds: float = 30, authority_closure: dict | None = None) -> dict:
        """Resume exact local effects; never blindly stop a replacement process."""
        return self._advance(timeout_seconds=timeout_seconds, phase='load', authority_closure=authority_closure)

    def quiesce(self, *, timeout_seconds: float = 30) -> dict:
        """Retain and recheck predecessor exit without publishing or starting.

        Group admission needs the existing native writer while the predecessor
        is stopped. This is the same bounded lifecycle operation as execute,
        not permission to stop a replacement or report receiving readiness.
        """
        return self._advance(timeout_seconds=timeout_seconds, phase='quiesce')

    def preserve(self, *, timeout_seconds: float = 30) -> dict:
        """Finish existing-owner preservation before admission writes."""
        return self._advance(timeout_seconds=timeout_seconds, phase='preserve')

    def retain_admission_group(self, *, authority_closure: dict, timeout_seconds: float = 30) -> dict:
        return self._advance(timeout_seconds=timeout_seconds, phase='derive', authority_closure=authority_closure)

    def observe_quiescence(self, *, timeout_seconds: float = 30) -> dict:
        """Read the exact root evidence without reacquiring caller-owned job locks."""
        from .onboarding_host import HostConfig
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60:
            raise OnboardingError('receiving_host_deadline_required')
        deadline = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        row, frozen, candidate = self._row()
        if self.backend.config != HostConfig.load(Path(row['expected_precondition']['host_config'])):
            raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
        retained = (row['runtime_observation'] or {}).get('guest_bootstraps', {}).get(self.name, {}).get('quiesced')
        if not isinstance(retained, dict):
            raise OnboardingError('receiving_guest_bootstrap_quiescence_required')
        request = self._service_request(frozen, candidate)
        remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise OnboardingError('receiving_owner_deadline_expired')
        result = self.backend._guest_service_call(frozen['plan'], 'bootstrap-quiescence',
            candidate=(Path(candidate['runtime_code']), candidate['runtime_digest']),
            timeout_seconds=remaining, request=request)
        if (result.get('schema') != 'cluster-guest-service-quiescence-observation/v1'
                or result.get('request_sha256') != digest(request) or result.get('exit_sha256') != digest(retained)
                or time.monotonic_ns() >= deadline):
            raise OnboardingError('receiving_guest_bootstrap_quiescence_required')
        return result

    def _service_request(self, frozen: dict, candidate: dict) -> dict:
        previous = {**frozen['owner']['predecessor'], 'service': frozen['root']['service'], 'scope': frozen['root']['scope']}
        return dict(schema='cluster-guest-service-bootstrap/v1', operation_id=self._native_operation_id(),
            plan_digest=digest(frozen['plan']), predecessor=previous, argv=candidate['argv'])

    def _advance(self, *, timeout_seconds: float, phase: str,
                 authority_closure: dict | None = None) -> dict:
        from .onboarding_host import HostConfig
        with ExitStack() as locks:
            locks.enter_context(self.journal.mutation_lock(self.operation_id))
            row, frozen, candidate = self._row()
            jobs = private_directory(self.backend.config.jobs)
            locks.enter_context(being_seed._locked(jobs))
            store = JobStore(jobs)
            for name in store.names():
                locks.enter_context(being_seed._locked(private_directory(store.directory(name))))
            row, frozen, candidate = self._row()
            if self.backend.config != HostConfig.load(Path(row['expected_precondition']['host_config'])):
                raise OnboardingError('receiving_guest_bootstrap_binding_conflict')
            if phase not in {'load', 'quiesce', 'preserve', 'derive'}:
                raise OnboardingError('receiving_guest_bootstrap_phase_required')
            if phase == 'preserve' and frozen['owner'].get('mode') != 'preserve':
                raise OnboardingError('receiving_admission_prepared_controller_required')
            vector = (Path(candidate['runtime_code']), candidate['runtime_digest'])
            checked = preflight(vector[0], vector[1], Path(candidate['manifest_path']),
                row['intent']['runtime_call']['manifest_digest'], being_ref=frozen['owner']['being_ref'],
                embodiment_id=frozen['owner']['origin']['embodiment_id'],
                code_uid=candidate['code_uid'], manifest_uid=candidate['manifest_uid'])
            if checked != candidate['prepared']:
                raise OnboardingError('receiving_guest_bootstrap_candidate_changed')
            # OperationJournal normally uses operation:UUID identifiers, while
            # both receiving CLIs require canonical UUIDs. Preserve previously
            # accepted UUID requests; derive one stable UUID for journal refs.
            request_id = self._native_operation_id()
            root_request = self._service_request(frozen, candidate)
            owner_request = {key: frozen['owner'][key] for key in (
                'plan_digest', 'genesis_digest', 'code_digest', 'runtime_sha256', 'group_sha256', 'predecessor')}
            owner_request.update(schema='cluster-guest-owner-bootstrap/v1', operation_id=request_id,
                expires_at_ms=candidate['expires_at_ms'])
            if 'mode' in frozen['owner']:
                owner_request.update(mode=frozen['owner']['mode'], preservation=frozen['owner']['preservation'])
            effects = (row['runtime_observation'] or {}).get('guest_bootstraps', {}).get(self.name, {})
            link = candidate.get('admission_link')
            if phase == 'derive' and (link is None or 'owner_preserved' not in effects or 'quiesced' not in effects):
                raise OnboardingError('receiving_admission_preservation_required')
            if phase == 'load' and link is not None:
                derived_lifecycle_group(candidate, effects, frozen['owner']['group'], required=True)
            if phase != 'load' and ('started' in effects or 'controlled_loaded' in effects):
                raise OnboardingError('receiving_guest_bootstrap_already_started')
            if row['state'] == 'planned':
                self.journal.advance(self.operation_id, 'runtime-dispatching')
            def root_call(action):
                return self.backend._guest_service_call(frozen['plan'], action, candidate=vector,
                    timeout_seconds=timeout_seconds, request=root_request)
            def owner_call(action, **kwargs):
                return self.backend._target_call(frozen['plan'], action, candidate=vector,
                    bootstrap_timeout_seconds=timeout_seconds, bootstrap_request=owner_request, **kwargs)
            if 'candidate_validated' not in effects:
                self._record('candidate_validated', root_call('bootstrap-validate'))
            if 'controlled_loaded' in effects:
                return self._loaded(frozen, candidate, vector, timeout_seconds)
            if 'quiesced' not in effects:
                current = self.backend._guest_service_call(frozen['plan'], 'bootstrap-inspect', candidate=vector,
                    timeout_seconds=timeout_seconds)
                if current['service']['manager']['ActiveState'] == 'active':
                    if frozen['owner'].get('mode', 'issue') == 'preserve':
                        preservation_authorization(frozen['owner']['preservation'], candidate['expires_at_ms'])
                    if (current['service'] != frozen['root']['service']
                            or candidate['expires_at_ms'] <= time.time_ns() // 1_000_000):
                        raise OnboardingError('receiving_guest_bootstrap_predecessor_or_expiry_changed')
                    fresh = self.backend._target_call(frozen['plan'], 'receiving-bootstrap-freeze', candidate=vector,
                        bootstrap_timeout_seconds=timeout_seconds)
                    if any(fresh.get(key) != value for key, value in frozen['owner'].items()
                           if key != 'observer_startup'):
                        raise OnboardingError('receiving_guest_bootstrap_predecessor_changed')
                    if frozen['owner'].get('mode') == 'renew' and (
                            type(fresh.get('renewal_not_after_ms')) is not int
                            or candidate['expires_at_ms'] > fresh['renewal_not_after_ms']):
                        raise OnboardingError('receiving_controller_renewal_authorization_expired')
                    expected_startup = dict(code_digest=candidate['prepared']['code_digest'],
                        matrix_commit=candidate['prepared']['matrix_revision'],
                        matrix_wheel_sha256=candidate['prepared']['matrix_wheel_sha256'],
                        sdk_digest=candidate['prepared']['sdk_digest'], reader=candidate['prepared']['reader'],
                        interpreter=frozen['owner']['observer_startup']['interpreter'])
                    if any(fresh.get('observer_startup', {}).get(key) != value
                           for key, value in expected_startup.items()):
                        raise OnboardingError('qualified_guest_bootstrap_candidate_required')
                    if candidate['expires_at_ms'] <= time.time_ns() // 1_000_000:
                        raise OnboardingError('receiving_guest_bootstrap_authorization_expired')
                self._record('quiesced', root_call('bootstrap-quiesce'))
            if phase == 'quiesce':
                # A retained exit is historical evidence. The owning root
                # route rechecks the current unit and exact predecessor exits
                # before returning, and refuses to stop a replacement.
                if 'quiesced' in effects:
                    result = root_call('bootstrap-quiesce')
                    self._record('quiesced', result)
                    return result
                return self._row()[0]['runtime_observation']['guest_bootstraps'][self.name]['quiesced']
            # Root rechecks current quiescence before every owner mutation; its
            # retained independent exits do not imply the unit stayed stopped.
            if owner_request.get('mode', 'issue') == 'preserve':
                current = self.backend._guest_service_call(frozen['plan'], 'bootstrap-inspect', candidate=vector,
                    timeout_seconds=timeout_seconds)
                if ('owner_preserved' not in effects or link is None
                        and current['service']['manager']['ActiveState'] == 'inactive'):
                    root_call('bootstrap-quiesce')
                    preserved = owner_call('receiving-bootstrap-stage')
                    if (preserved.get('mode') != 'preserve'
                            or preserved.get('preservation') != owner_request['preservation']
                            or preserved.get('request_sha256') != digest(owner_request)):
                        raise OnboardingError('receiving_controller_preservation_changed')
                    self._record('owner_preserved', preserved)
            else:
                if 'owner_ready' not in effects:
                    root_call('bootstrap-quiesce')
                    ready = owner_call('receiving-bootstrap-stage')
                    self._record('owner_ready', ready)
                else:
                    ready = effects['owner_ready']
                if 'owner_published' not in effects:
                    root_call('bootstrap-quiesce')
                    published = owner_call('receiving-bootstrap-publish', bootstrap_ready_sha256=ready['ready_sha256'])
                    self._record('owner_published', published)
            if phase == 'preserve':
                root_call('bootstrap-quiesce')
                return self._row()[0]['runtime_observation']['guest_bootstraps'][self.name]['owner_preserved']
            if phase == 'derive' and current['service']['manager']['ActiveState'] != 'inactive':
                raise OnboardingError('receiving_guest_bootstrap_quiescence_required')
            if link is not None and current['service']['manager']['ActiveState'] == 'inactive':
                if not isinstance(authority_closure, dict):
                    raise OnboardingError('receiving_admission_owner_context_required')
                root_call('bootstrap-quiesce')
                snapshot = self.backend._target_call(frozen['plan'], 'group-publication', candidate=vector,
                    observation_timeout_seconds=timeout_seconds, group_request=dict(
                        command=link['snapshot_request'], offline=True, authority_closure=authority_closure))
                derived = admission_group_derivation(link, snapshot,
                    previous=frozen['owner']['group'], stores=frozen['owner']['store_bindings'])
                self._record('admission_group', derived)
                if phase == 'derive':
                    return derived
            if 'unit_selected' not in effects:
                if owner_request.get('mode') == 'preserve' and current['service']['unit_sha256'] == frozen['root']['service']['unit_sha256']:
                    preservation_authorization(owner_request['preservation'], candidate['expires_at_ms'])
                self._record('unit_selected', root_call('bootstrap-select'))
            # Reconcile the retained start, rather than reissuing it after a
            # lost ACK. Actual owner load/admission is checked independently.
            if owner_request.get('mode') == 'preserve' and current['service']['manager']['ActiveState'] == 'inactive':
                preservation_authorization(owner_request['preservation'], candidate['expires_at_ms'])
            self._record('started', root_call('bootstrap-start'))
            loaded = self._loaded(frozen, candidate, vector, timeout_seconds)
            self._record('controlled_loaded', loaded)
            return loaded

    def _loaded(self, frozen: dict, candidate: dict, vector: tuple[Path, str], timeout_seconds: float) -> dict:
        observed = self.backend._target_call(frozen['plan'], 'admitted-running', candidate=vector,
            observation_timeout_seconds=timeout_seconds, require_loaded=True)
        root = self.backend._guest_service_call(frozen['plan'], 'bootstrap-inspect', candidate=vector,
            timeout_seconds=timeout_seconds, owner_observation={key: observed[key]
                for key in ('process', 'admission_parent')})
        effects = self._row()[0]['runtime_observation']['guest_bootstraps'][self.name]
        expected_runtime, _ = bootstrap_effects(effects, source=False, mode=frozen['owner'].get('mode', 'issue'))
        owner = frozen['owner']
        if 'admission_link' in candidate:
            group = derived_lifecycle_group(candidate, effects, owner['group'], required=True)
            if observed['runtime_status']['loaded_runtime'].get('stores') != owner['store_bindings']:
                raise OnboardingError('receiving_bootstrap_loaded_store_conflict')
            owner = {**owner, 'group': group, 'group_sha256': digest(group)}
        result = dict(schema='cluster-guest-bootstrap-loaded/v1', **guest_loaded_observation(
            observed, root, owner, candidate, expected_runtime=expected_runtime,
            unit_sha256=effects['unit_selected']['selected_sha256'],
            manager=effects['started']['manager'], dropins=frozen['root']['service'].get('dropins', {}),
            initial_observation='controlled_loaded' not in effects))
        if effects.get('controlled_loaded', result) != result:
            raise OnboardingError('receiving_guest_bootstrap_loaded_conflict')
        return result


def guest_loaded_observation(observed: dict, root: dict, owner: dict, candidate: dict, *,
                             expected_runtime: str, unit_sha256: str, manager: dict,
                             dropins: dict, initial_observation: bool) -> dict:
    """Bind the qualified native child/load to its independent manager observation."""
    loaded = observed['runtime_status']['loaded_runtime']
    startup = loaded['qualified_startup']
    application = observed['group_runtime_status']['loaded_application']
    gate = observed['group_runtime_status']['receiving']['channels']['tribe']
    if (root['scope']['process'] != observed['process']
            or root['scope']['admission_parent'] != observed['admission_parent']
            or root['service']['unit_sha256'] != unit_sha256
            or root['service'].get('dropins', {}) != dropins
            or root['service']['manager'] != manager
            or any(startup.get(key) != value for key, value in dict(
                code_digest=candidate['runtime_digest'], matrix_commit=candidate['prepared']['matrix_revision'],
                sdk_digest=candidate['prepared']['sdk_digest'], reader=candidate['prepared']['reader'],
                matrix_wheel_sha256=candidate['prepared']['matrix_wheel_sha256']).items())
            or startup['process_id'] != observed['process']['pid']
            or loaded['runtime_bundle_sha256'] != expected_runtime
            or observed['runtime_sha256'] != expected_runtime
            or observed.get('responder_association') != 'same-connection'
            or observed['origin'] != owner['origin']
            or observed['group'] != owner['group']['selected']
            or application['application_sha256'] != owner['group']['application_sha256']
            or application['publication_sha256'] != owner['group']['publication_sha256']
            or application['visibility']['installation_sha256'] != owner['group']['installation_sha256']
            or gate['controlled'] is not True or gate['process_id'] != observed['process']['pid']
            or initial_observation and (gate['phase'] != 'unselected' or gate['readers'])):
        raise OnboardingError('receiving_guest_bootstrap_loaded_conflict')
    result = dict(process=observed['process'],
        admission_parent=observed['admission_parent'], runtime_sha256=observed['runtime_sha256'],
        code_digest=startup['code_digest'], matrix_revision=startup['matrix_commit'],
        startup_instance_id=startup['startup_instance_id'],
        loaded_runtime=loaded, loaded_application={key: value for key, value in application.items() if key != 'reader_gates'},
        group_sha256=owner['group_sha256'], receiving_readiness='unobserved')
    return result


class CohortController:
    """Fence updates and qualify one fixed all-required reader projection.

    Uses maintained preflight, owner RPC, lifecycle records and the existing
    journal. Native selections attest local projection readiness; actual
    communication acceptance remains independently observed evidence.
    """

    def __init__(self, journal, operation_id: str,
                 owners: Mapping[str, OwnerGroupClient | GuestGroupClient | SourceGroupClient]):
        self.journal = journal
        self.operation_id = operation_id
        self.owners = dict(owners)
        self._preflights: dict[str, dict] = {}
        self._lifecycle_projections: dict[tuple[int, str, str], dict | None] | None = None

    @contextmanager
    def _observation_scope(self):
        """Reuse immutable owner lifecycle proof only within this invocation.

        Current identity, process, admission, gate and credential horizons are
        always queried afresh. The next invocation reads owner proof again.
        """
        previous = self._lifecycle_projections
        if previous is None:
            self._lifecycle_projections = {}
        try:
            yield
        finally:
            self._lifecycle_projections = previous

    def _row(self) -> dict:
        row = self.journal.get(self.operation_id)
        if (row is None or row['operation'] != 'receiving-update'
                or row['state'] in {'degraded', 'compensated', 'completed'}):
            raise OnboardingError('receiving_cohort_operation_required')
        before, after = row['expected_precondition'], row['intended_transition']
        call = row['intent'].get('runtime_call', {})
        if (call.get('precondition_digest') != digest(before)
                or call.get('transition_digest') != digest(after)
                or not re.fullmatch(r'[0-9a-f]{64}', call.get('manifest_digest', ''))):
            raise OnboardingError('receiving_cohort_operation_required')
        senders = before.get('senders')
        if (not isinstance(senders, list) or not 1 <= len(senders) <= 256
                or any(not isinstance(item, dict) for item in senders)
                or any(not isinstance(item.get('name'), str) for item in senders)
                or [item['name'] for item in senders] != sorted({item['name'] for item in senders})
                or not {item['name'] for item in senders} <= set(self.owners)):
            raise OnboardingError('receiving_sender_vector_invalid')
        for item in senders:
            if set(item) - {'being_ref'} != {'name', 'root', 'socket', 'server', 'process', 'gate'}:
                raise OnboardingError('receiving_sender_vector_invalid')
            owner = self.owners[item['name']]
            if (str(owner.root), str(owner.socket)) != (item['root'], item['socket']):
                raise OnboardingError('receiving_sender_vector_invalid')
        admission = self._admission(row)
        if admission is None and [item['name'] for item in senders] != sorted(self.owners):
            raise OnboardingError('receiving_sender_vector_invalid')
        return row

    def _admission(self, row: dict) -> dict | None:
        """Validate the frozen physical after-set, independently of late effects."""
        transition = row['intended_transition']
        if 'cohort_admission' not in transition:
            return None
        value = transition['cohort_admission']
        if (not isinstance(value, dict) or set(value) != {'schema', 'tribe_ref', 'entrant', 'receivers', 'activation'}
                or value['schema'] != 'cluster-receiving-admission/v1' or 'cohort_activation' in transition
                or not isinstance(value['tribe_ref'], str) or not value['tribe_ref']
                or row['target'] != 'receiving:' + value['tribe_ref']
                or row['expected_precondition'].get('tribe_ref') != value['tribe_ref']
                or not isinstance(value['receivers'], dict) or not 1 <= len(value['receivers']) <= 256
                or sorted(value['receivers']) != sorted(self.owners)):
            raise OnboardingError('receiving_cohort_admission_required')
        before = {item['name']: item for item in row['expected_precondition']['senders']}
        added = set(self.owners) - set(before)
        if (not added or not isinstance(row['expected_precondition'].get('receiver_selections'), dict)
                or sorted(row['expected_precondition']['receiver_selections']) != sorted(self.owners)):
            raise OnboardingError('receiving_cohort_admission_required')
        identities = set()
        for name, receiver in value['receivers'].items():
            if (not isinstance(receiver, dict) or set(receiver) != {
                    'being_ref', 'embodiment_id', 'root', 'socket', 'candidate', 'recipe'}
                    or any(not isinstance(receiver[key], str) or not receiver[key]
                           for key in ('being_ref', 'embodiment_id', 'root', 'socket'))
                    or (receiver['root'], receiver['socket']) != (str(self.owners[name].root), str(self.owners[name].socket))):
                raise OnboardingError('receiving_cohort_admission_receiver_changed')
            identity = receiver['being_ref'], receiver['embodiment_id']
            if identity in identities:
                raise OnboardingError('receiving_cohort_admission_receiver_changed')
            identities.add(identity)
            if name in before and (before[name].get('being_ref'), before[name]['server'].get('embodiment_id')) != identity:
                raise OnboardingError('receiving_cohort_admission_receiver_changed')
            candidate, recipe = receiver['candidate'], receiver['recipe']
            if (not isinstance(candidate, dict) or set(candidate) != {'code', 'code_uid'}
                    or not isinstance(candidate['code'], str) or not Path(candidate['code']).is_absolute()
                    or '..' in Path(candidate['code']).parts
                    or type(candidate['code_uid']) is not int or candidate['code_uid'] < 0
                    or not isinstance(recipe, dict) or set(recipe) != {'profile', 'prepared', 'tooling'}
                    or recipe['profile'] not in {'source', 'guest'} or name in added and recipe['profile'] != 'guest'
                    or not isinstance(recipe['prepared'], dict)
                    or any(recipe['prepared'].get(key) != receiver[key] for key in ('being_ref', 'embodiment_id'))
                    or any(not isinstance(recipe['prepared'].get(key), str)
                        or re.fullmatch('[0-9a-f]{64}', recipe['prepared'][key]) is None
                        for key in ('code_digest', 'matrix_wheel_sha256'))):
                raise OnboardingError('receiving_cohort_admission_candidate_changed')
            from .onboarding_owner_client import validate_tooling_recipe
            validate_tooling_recipe(recipe['tooling'])
        entrant = value['entrant']
        if (not isinstance(entrant, dict) or set(entrant) != {'being_ref', 'embodiment_ids'}
                or not isinstance(entrant['being_ref'], str) or not entrant['being_ref']
                or not isinstance(entrant['embodiment_ids'], list)
                or any(not isinstance(body, str) or not body for body in entrant['embodiment_ids'])
                or entrant['embodiment_ids'] != sorted(set(entrant['embodiment_ids']))
                or {(value['receivers'][name]['being_ref'], value['receivers'][name]['embodiment_id']) for name in added}
                    != {(entrant['being_ref'], body) for body in entrant['embodiment_ids']}):
            raise OnboardingError('receiving_cohort_admission_entrant_changed')
        bounds = value['activation']
        if (not isinstance(bounds, dict) or set(bounds) != {
                'manifest_path', 'manifest_uid', 'expires_at_ms', 'observation_window_ms'}
                or not isinstance(bounds['manifest_path'], str) or not Path(bounds['manifest_path']).is_absolute()
                or '..' in Path(bounds['manifest_path']).parts
                or type(bounds['manifest_uid']) is not int or bounds['manifest_uid'] < 0
                or type(bounds['expires_at_ms']) is not int or not 0 < bounds['expires_at_ms'] < 2**53
                or type(bounds['observation_window_ms']) is not int or not 0 < bounds['observation_window_ms'] <= 60000):
            raise OnboardingError('receiving_cohort_admission_required')
        return value

    def _record(self, row: dict, key: str, value: dict) -> dict:
        from .operation_journal import JournalConflict
        observations = dict(row['runtime_observation'] or {})
        revocations = dict(observations.get('sender_revocations', {}))
        if key in revocations and revocations[key] != value:
            raise JournalConflict('receiving sender revocation changed')
        revocations[key] = value
        observations['sender_revocations'] = revocations
        return self.journal.advance(self.operation_id, row['state'],
            runtime_observation=observations,
            expected_runtime_observation=row['runtime_observation'])

    def revoke_senders(self) -> dict:
        """Resume only retained exact controls and persist each actual ACK."""
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            if row['state'] == 'planned':
                row = self.journal.advance(self.operation_id, 'runtime-dispatching')
            release = row['intent']['runtime_call']['manifest_digest']
            control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
            for sender in row['expected_precondition']['senders']:
                name = sender['name']
                if name in (row['runtime_observation'] or {}).get('sender_revocations', {}):
                    continue
                owner = self.owners[name]
                observed = owner.status()
                if observed['process'] != sender['process'] or observed['server'] != sender['server']:
                    raise OnboardingError('receiving_sender_precondition_changed')
                # The receiving owner reconciles its retained private file. A
                # host must not inspect that path in its own filesystem; a
                # changed gate without the exact retained request is refused
                # by prepare_control before any new native request is authored.
                gate = sender['gate']
                command = dict(process_instance_id=gate['process_instance_id'], channel_id='tribe',
                    expected_head=gate['head'], operation_id=control_id, release_digest=release,
                    phase='revoke', readers=[])
                path = owner.root / 'receiving-control' / (control_id + '-revoke.json')
                result = owner.prepare_apply_control(command, path)
                row = self._record(row, name, result)
            return self.require_revocation_barrier()

    def require_revocation_barrier(self) -> dict:
        """A durable old ACK alone cannot authorize a current receiver effect."""
        row = self._row()
        if self._admission(row) is not None:
            with self.journal.mutation_lock(self.operation_id):
                return self._admission_revocation_barrier(self._row())
        revocations = (row['runtime_observation'] or {}).get('sender_revocations', {})
        for sender in row['expected_precondition']['senders']:
            retained = revocations.get(sender['name'])
            if not isinstance(retained, dict):
                raise OnboardingError('receiving_sender_barrier_incomplete')
            control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
            if (retained.get('server') != sender['server']
                    or retained.get('process') != sender['process']
                    or retained.get('gate', {}).get('operation_id') != control_id
                    or retained.get('gate', {}).get('release_digest') != row['intent']['runtime_call']['manifest_digest']):
                raise OnboardingError('receiving_sender_barrier_changed')
            current = self.owners[sender['name']].status()
            if (current['process'] != retained['process'] or current['server'] != retained['server']
                    or current['gate'] != retained['gate']
                    or current['gate'].get('phase') != 'revoke'
                    or current['gate'].get('readers') != []
                    or current['gate'].get('request_sha256') != retained['request_sha256']):
                raise OnboardingError('receiving_sender_barrier_changed')
        return dict(schema='cluster-receiving-sender-barrier/v1', operation_id=self.operation_id,
            manifest_digest=row['intent']['runtime_call']['manifest_digest'],
            sender_revocations=revocations, receiving_readiness='unobserved')

    def apply_host_selection(self, config_path: Path) -> dict:
        """Gate the maintained real selector effect, not a test callback."""
        with self.journal.mutation_lock(self.operation_id):
            return apply_host_selection(self.journal, self.operation_id, config_path,
                                        _cohort_control=self)

    def admit_membership(self, *, deadline_ns: int) -> dict:
        """Run the approved native social phase with all original bodies stopped."""
        from .onboarding_group_admission import admit_membership
        return admit_membership(self, deadline_ns=deadline_ns)

    def publish_admission_group(self, *, deadline_ns: int) -> dict:
        """Publish only the protected post-membership offline group phase."""
        from .onboarding_group_admission import publish_admission_group
        return publish_admission_group(self, deadline_ns=deadline_ns)

    def _activation(self, row: dict) -> tuple[dict, dict]:
        """Resolve fixed activation or the admission's retained late derivation."""
        admission = self._admission(row)
        if admission is None:
            value = row['intended_transition'].get('cohort_activation')
        else:
            retained = (row['runtime_observation'] or {}).get('admission_activation_plan')
            if (not isinstance(retained, dict) or set(retained) != {
                    'schema', 'admission_sha256', 'plan_sha256', 'plan', 'receiving_readiness'}
                    or retained['schema'] != 'cluster-admission-activation-plan/v1'
                    or retained['admission_sha256'] != digest(admission)
                    or not isinstance(retained['plan'], dict)
                    or retained['plan_sha256'] != digest(retained['plan'])
                    or retained['receiving_readiness'] != 'unobserved'):
                raise OnboardingError('receiving_admission_activation_unobserved')
            value = retained['plan']
            if any(value.get(key) != item for key, item in admission['activation'].items()):
                raise OnboardingError('receiving_admission_activation_changed')
        if (not isinstance(value, dict) or set(value) != {'manifest_path', 'manifest_uid',
                'roster_sha256', 'expires_at_ms', 'observation_window_ms', 'receivers'}
                or not isinstance(value['receivers'], dict)
                or sorted(value['receivers']) != sorted(self.owners)
                or type(value['expires_at_ms']) is not int or not 0 < value['expires_at_ms'] < 2**53
                or type(value['observation_window_ms']) is not int or not 0 < value['observation_window_ms'] <= 60000
                or re.fullmatch('[0-9a-f]{64}', value['roster_sha256']) is None):
            raise OnboardingError('receiving_cohort_activation_required')
        manifest = _manifest(Path(value['manifest_path']),
            row['intent']['runtime_call']['manifest_digest'], uid=value['manifest_uid'])
        frozen = row['expected_precondition'].get('receiver_selections')
        if not isinstance(frozen, dict) or sorted(frozen) != sorted(self.owners):
            raise OnboardingError('receiving_cohort_predecessor_required')
        senders = row['expected_precondition']['senders']
        if any(not isinstance(item.get('being_ref'), str) for item in senders):
            raise OnboardingError('receiving_cohort_predecessor_required')
        expected = ({(item['being_ref'], item['server']['embodiment_id']) for item in senders}
            if admission is None else {(item['being_ref'], item['embodiment_id']) for item in admission['receivers'].values()})
        if {(item['being_ref'], item['embodiment_id']) for item in manifest['required_receivers']} != expected:
            raise OnboardingError('receiving_required_cohort_changed')
        if admission is not None:
            for name, approved in admission['receivers'].items():
                recipe = value['receivers'][name]
                if (not isinstance(recipe, dict) or set(recipe) != {
                        'profile', 'prepared', 'tooling', 'selection', 'lifecycle_operation_id'}
                        or any(recipe.get(key) != item for key, item in approved['recipe'].items())
                        or not isinstance(recipe['lifecycle_operation_id'], str) or not recipe['lifecycle_operation_id']
                        or not isinstance(recipe['selection'], dict)
                        or recipe['selection'].get('receiving_code') != approved['recipe']['prepared']['code_digest']
                        or recipe['selection'].get('matrix_sdk') != approved['recipe']['prepared']['matrix_wheel_sha256']):
                    raise OnboardingError('receiving_admission_activation_changed')
                required = next(item for item in manifest['required_receivers'] if
                    (item['being_ref'], item['embodiment_id']) == (approved['being_ref'], approved['embodiment_id']))
                if required['expected_selection_sha256'] != digest(frozen[name]):
                    raise OnboardingError('receiving_cohort_predecessor_required')
        return value, manifest

    def retain_admission_activation(self, plan: dict) -> dict:
        """Bind later publication/lifecycle selections without rewriting intent.

        This is not adoption or permission to enable a sender. Actual native
        observation and lifecycle qualification remain the activation path.
        """
        from .operation_journal import JournalConflict
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            admission = self._admission(row)
            if admission is None or row['state'] == 'planned' or not isinstance(plan, dict):
                raise OnboardingError('receiving_cohort_admission_required')
            value = dict(schema='cluster-admission-activation-plan/v1', admission_sha256=digest(admission),
                plan_sha256=digest(plan), plan=plan, receiving_readiness='unobserved')
            observations = dict(row['runtime_observation'] or {})
            retained = observations.get('admission_activation_plan')
            if retained is not None and retained != value:
                raise JournalConflict('admission activation derivation changed')
            observations['admission_activation_plan'] = value
            self._activation({**row, 'runtime_observation': observations})
            if retained is None:
                self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                    expected_runtime_observation=row['runtime_observation'])
            return value

    def _adoption_context(self, name: str, plan: dict, manifest: dict) -> tuple[dict, dict, dict | None, dict]:
        """Resolve immutable inputs and caches on the coordinator thread."""
        recipe = plan['receivers'][name]
        if (not isinstance(recipe, dict)
                or set(recipe) != {'profile', 'selection', 'prepared', 'lifecycle_operation_id', 'tooling'}
                or recipe['profile'] not in {'source', 'guest'}
                or not isinstance(recipe['prepared'], dict)
                or not isinstance(recipe['selection'], dict)
                or not isinstance(recipe['lifecycle_operation_id'], str)):
            raise OnboardingError('receiving_cohort_profile_required')
        from .onboarding_owner_client import validate_tooling_recipe
        tooling = validate_tooling_recipe(recipe['tooling'])
        native_options = {}
        if tooling['profile'] == 'codex':
            accepted = (self._row()['runtime_observation'] or {}).get('native_tooling', {}).get(name)
            if not isinstance(accepted, dict):
                raise OnboardingError('receiving_native_tooling_unobserved')
            native_options['native_tooling'] = {'recipe': tooling, 'accepted': accepted}
        lifecycle_row = self._lifecycle(name, recipe)
        prepared = self._qualified_preflight(name, recipe, plan, manifest, lifecycle_row)
        return tooling, native_options, lifecycle_row, prepared

    def _observe_adoption(self, name: str, plan: dict, *,
                          context: tuple[dict, dict, dict | None, dict],
                          deadline_ns: int | None = None) -> tuple[dict, int, int]:
        """Query one distinct owner; no journal/cache writes or validation."""
        observed_at_ms = time.time_ns() // 1_000_000
        observed_at_ns = time.monotonic_ns()
        observation_deadline = observed_at_ns + min(plan['observation_window_ms'],
            plan['expires_at_ms'] - observed_at_ms) * 1_000_000
        if deadline_ns is not None:
            observation_deadline = min(observation_deadline, deadline_ns)
        with self._owner_deadline(self.owners[name], observation_deadline):
            current = self.owners[name].qualified_identity(expires_at_ms=plan['expires_at_ms'],
                require_admitted=plan['receivers'][name]['profile'] == 'guest', **context[1])
        return current, observed_at_ms, observed_at_ns

    def _adoption(self, name: str, plan: dict, manifest: dict,
                  *, observations: dict | None = None,
                  context: tuple[dict, dict, dict | None, dict] | None = None,
                  observed: tuple[dict, int, int] | None = None) -> dict:
        """Qualify actual owner observations against the selected receiver vector."""
        recipe = plan['receivers'][name]
        tooling, native_options, lifecycle_row, prepared = (
            self._adoption_context(name, plan, manifest) if context is None else context)
        accepted = native_options.get('native_tooling', {}).get('accepted', {})
        current, observed_at_ms, observed_at_ns = (
            self._observe_adoption(name, plan, context=(tooling, native_options, lifecycle_row, prepared))
            if observed is None else observed)
        native = current.get('native_tooling')
        if tooling['profile'] == 'codex' and (not isinstance(native, dict)
                or native.get('schema') != 'cluster-native-tool-catalog/v1'
                or native.get('acceptance') != ('selected-existing-contexts' if tooling['native_threads'] else 'server-catalog-only')
                or [item.get('thread_id') for item in native.get('contexts', [])] != (tooling['native_threads'] or [None])):
            raise OnboardingError('receiving_native_tooling_unobserved')
        status, identity = current['runtime_status'], current['identity']
        loaded, application = status.get('loaded_runtime'), status.get('loaded_application')
        if not isinstance(loaded, dict) or not isinstance(application, dict):
            raise OnboardingError('receiving_cohort_loaded_required')
        cohort_row = self._row()
        admission = self._admission(cohort_row)
        if admission is not None and application.get('tribe', {}).get('policy', {}).get('tribe_ref') != admission['tribe_ref']:
            raise OnboardingError('receiving_cohort_admission_group_changed')
        startup = loaded.get('qualified_startup')
        if (not isinstance(startup, dict) or any(startup.get(key) != prepared.get(field) for key, field in (
                ('code_digest', 'code_digest'), ('matrix_commit', 'matrix_revision'),
                ('matrix_wheel_sha256', 'matrix_wheel_sha256'), ('sdk_digest', 'sdk_digest'), ('reader', 'reader')))
                or prepared.get('release_digest') != digest(manifest)
                or prepared.get('assessment', {}).get('compatible') is not True
                or (prepared.get('being_ref'), prepared.get('embodiment_id')) !=
                   (identity['being_ref'], current['server']['embodiment_id'])
                or loaded.get('process_id') != current['process']['pid']
                or 'signed-roster-cas/v1' not in startup['reader']['contract']['capabilities']):
            raise OnboardingError('receiving_cohort_startup_mismatch')
        if startup['matrix_commit'] != manifest['provenance']['matrix_revision']:
            raise OnboardingError('receiving_cohort_startup_mismatch')
        if tooling['profile'] == 'codex' and any(accepted.get(key) != startup.get(key) for key in (
                'code_digest', 'sdk_digest', 'matrix_commit', 'matrix_wheel_sha256')):
            raise OnboardingError('receiving_native_tooling_changed')
        if tooling['profile'] == 'codex':
            assert isinstance(native, dict)
        if tooling['profile'] == 'codex' and isinstance(native, dict) and (native.get('runtime_id') != loaded.get('runtime_id')
                or native.get('server') != current['server'] or accepted.get('server') != current['server']
                or accepted.get('runtime_id') != loaded.get('runtime_id')
                or native.get('tribe_channel') != tooling['tribe_channel']
                or native.get('group_socket_sha256') != digest({'socket': str(self.owners[name].socket)})):
            raise OnboardingError('receiving_native_tooling_identity_changed')
        receiving = status.get('receiving', {})
        roster = receiving.get('rosters', {}).get('tribe')
        if (not isinstance(roster, dict) or roster.get('schema') != 'dm.runtime.tribe-roster/v1'
                or roster.get('roster_sha256') != plan['roster_sha256']
                or 'signed-roster-cas/v1' not in receiving.get('features', [])
                or current['gate'].get('controlled') is not True):
            raise OnboardingError('receiving_cohort_roster_unready')
        visibility = application.get('visibility', {})
        store_versions = startup['reader']['contract']['store_versions']
        if (visibility.get('catalog_mode') != 'validate'
                or visibility.get('catalog_validation') != 'validated'
                or visibility.get('release_enabled') is not True
                or application.get('shared_relationships') is not True
                or application.get('communication_store_role') != 'ledger'
                or application.get('shared_stores', {}).get('ledger', {}).get('schema_versions', {}).get('communication')
                    not in store_versions.get('communication', [])
                or visibility.get('catalog_schema_version') not in store_versions.get('visibility_catalog', [])):
            raise OnboardingError('receiving_cohort_store_unready')
        selection = dict(receiving_code=startup['code_digest'], matrix_sdk=startup['matrix_wheel_sha256'],
            runtime_bundle_sha256=loaded['runtime_bundle_sha256'], application_sha256=application['application_sha256'],
            publication_sha256=application['publication_sha256'], visibility_installation_sha256=visibility['installation_sha256'])
        if selection != recipe['selection']:
            raise OnboardingError('receiving_cohort_selection_changed')
        receiver = next((item for item in manifest['required_receivers'] if
            (item['being_ref'], item['embodiment_id']) == (identity['being_ref'], current['server']['embodiment_id'])), None)
        if receiver is None:
            raise OnboardingError('receiving_required_cohort_changed')
        expected_artifacts = {**manifest['artifacts'], **receiver.get('artifacts', {})}
        if set(expected_artifacts) - {'receiving_code', 'matrix_sdk'}:
            raise OnboardingError('receiving_cohort_artifact_unobserved')
        if any(selection[key] != fingerprint for key, fingerprint in expected_artifacts.items()):
            raise OnboardingError('receiving_cohort_artifact_changed')
        epochs = set(loaded['authority_epoch']['accepted_manifest_hashes'])
        for authority in application['authorities'].values():
            epochs.update(authority['accepted_manifest_hashes'])
        if not set(roster['required_authority_epochs']) <= epochs or len(epochs) > 256:
            raise OnboardingError('receiving_cohort_authority_unready')
        verified = current['verified_identity']
        if (verified['runtime_bundle_sha256'] != loaded['runtime_bundle_sha256']
                or verified['identity'] != identity or verified['expires_at_ms'] > plan['expires_at_ms']):
            raise OnboardingError('receiving_cohort_identity_changed')
        for required_authority in manifest['authorities']['candidate']:
            being = required_authority['being_ref']
            actual = (dict(active_manifest_hash=identity['manifest_hash'],
                           active_control_head=verified['authority_control_head'])
                      if being == identity['being_ref'] else application['authorities'].get(being))
            if (not isinstance(actual, dict) or
                    (actual.get('active_manifest_hash'), actual.get('active_control_head')) !=
                    (required_authority['manifest_hash'], required_authority['control_head'])):
                raise OnboardingError('receiving_cohort_authority_unready')
        if recipe['profile'] == 'guest' and not isinstance(current.get('admission_parent'), dict):
            raise OnboardingError('receiving_cohort_admission_required')
        effects = {} if lifecycle_row is None else lifecycle_row['runtime_observation'] or {}
        if (admission is not None and lifecycle_row is not None
                and name not in {item['name'] for item in cohort_row['expected_precondition']['senders']}):
            lifecycle = self._initial_lifecycle(lifecycle_row, name, recipe)['controlled_loaded']
        else:
            lifecycle = (effects.get('source_bootstrap', {}) if recipe['profile'] == 'source'
                else effects.get('guest_bootstraps', {}).get(name, {})).get('controlled_loaded')
        if (not isinstance(lifecycle, dict) or lifecycle.get('process') != current['process']
                or lifecycle.get('loaded_runtime') != loaded
                or lifecycle.get('loaded_application') != {key: val for key, val in application.items() if key != 'reader_gates'}
                or recipe['profile'] == 'guest' and lifecycle.get('admission_parent') != current.get('admission_parent')):
            raise OnboardingError('receiving_cohort_lifecycle_unobserved')
        reader = dict(being_ref=identity['being_ref'], embodiment_id=current['server']['embodiment_id'],
            incarnation_id=current['server']['incarnation_id'], credential_id=identity['credential_ref'],
            authority_manifest_hash=identity['manifest_hash'], receiving_selection_sha256=digest(selection),
            loaded_view_sha256=application['loaded_view_sha256'], expires_at_ms=verified['expires_at_ms'],
            wire_read=sorted(set(startup['reader']['contract']['wire_read']) &
                {'dm.tribe.conversation/v1', 'dm.tribe.direct-conversation/v1'}), authority_epochs=sorted(epochs))
        if observations is not None:
            observations[name] = {key: current[key] for key in ('server', 'process', 'gate')}
        return dict(process=current['process'], server=current['server'],
            loaded_runtime=loaded, loaded_application={key: val for key, val in application.items() if key != 'reader_gates'},
            admission_parent=current.get('admission_parent'), selection=selection,
            roster_sha256=roster['roster_sha256'], reader=reader,
            **({'native_tooling': native} if tooling['profile'] == 'codex' else {}),
            observed_at_ms=observed_at_ms, observed_at_ns=observed_at_ns)

    def _adoption_round(self, plan: dict, manifest: dict, *, observations: dict) -> dict:
        """Overlap independent queries, then validate every result serially."""
        names = sorted(self.owners)
        if len({id(owner) for owner in self.owners.values()}) != len(names):
            raise OnboardingError('receiving_sender_vector_invalid')
        contexts = {name: self._adoption_context(name, plan, manifest) for name in names}
        queried = {}
        deadline = time.monotonic_ns() + min(plan['observation_window_ms'],
            plan['expires_at_ms'] - time.time_ns() // 1_000_000) * 1_000_000
        self._accept_activation_deadline(deadline)
        # Bound submitted work as well as worker count. Joining the executor
        # precedes validation, journal writes, controls and failure fencing.
        with ThreadPoolExecutor(max_workers=min(3, len(names))) as executor:
            remaining = iter(names)
            pending: dict[Future[tuple[dict, int, int]], str] = {}
            while True:
                while len(pending) < 3:
                    name = next(remaining, None)
                    if name is None:
                        break
                    self._accept_activation_deadline(deadline)
                    future = executor.submit(self._observe_adoption, name, plan,
                        context=contexts[name], deadline_ns=deadline)
                    pending[future] = name
                if not pending:
                    break
                finished, _ = wait(pending, return_when=FIRST_COMPLETED)
                # Inspect all completed results before submitting more. Any
                # refusal stops refill; executor exit still joins other queries.
                queried.update({pending[future]: future.result() for future in finished})
                for future in finished:
                    del pending[future]
        self._accept_activation_deadline(deadline)
        return {name: self._adoption(name, plan, manifest, observations=observations,
            context=contexts[name], observed=queried[name]) for name in names}

    def _lifecycle(self, name: str, recipe: dict, *, require_group: bool = True) -> dict | None:
        cohort = self._row()
        admission = self._admission(cohort)
        if admission is not None and name not in {item['name'] for item in cohort['expected_precondition']['senders']}:
            self._initial_lifecycle(cohort, name, recipe)
            return cohort
        owner = self.owners[name]
        inspect = getattr(owner, 'lifecycle_operation', None)
        if recipe['profile'] == 'source' and inspect is not None:
            key = (id(owner), name, digest(recipe))
            retained = self._lifecycle_projections
            if retained is not None and key in retained:
                row = retained[key]
            else:
                row = inspect(recipe['lifecycle_operation_id'])
                if retained is not None:
                    # The CLI result is data, not a mutable proxy owned by an
                    # adapter. Reuse no host-side copy across invocations.
                    retained[key] = json.loads(json.dumps(row))
        else:
            row = self.journal.get(recipe['lifecycle_operation_id'])
        if row is not None and row.get('operation_id') != recipe['lifecycle_operation_id']:
            raise OnboardingError('receiving_cohort_lifecycle_unobserved')
        if admission is not None and row is not None:
            proof = (row.get('admission') if recipe['profile'] == 'source' and inspect is not None
                else admission_lifecycle_projection(row, profile=recipe['profile'], name=name))
            self._admission_lifecycle_association(cohort, admission, name, recipe, row, proof,
                require_group=require_group)
        return row

    def _admission_lifecycle_association(self, cohort: dict, admission: dict, name: str,
                                         recipe: dict, lifecycle: dict, proof: dict | None,
                                         *, require_group: bool = True) -> None:
        """A valid local load cannot stand in for a different admission intent."""
        try:
            approved = admission['receivers'][name]
            sender = next(item for item in cohort['expected_precondition']['senders'] if item['name'] == name)
            if recipe['profile'] == 'source':
                previous = lifecycle['expected_precondition']['source_bootstrap']['predecessor']
                server = previous['server']
            else:
                frozen = lifecycle['expected_precondition']['guest_bootstraps'][name]['owner']
                previous, server = frozen['predecessor'], frozen['origin']
            if (not isinstance(proof, dict) or set(proof) != {'schema', 'cohort_operation_id',
                    'cohort_intent_sha256', 'tribe_ref', 'owner', 'link_sha256', 'manifest_digest',
                    'snapshot_request_sha256', 'owner_context_sha256', 'publication_operation_id', 'derived'}
                    or proof['schema'] != 'cluster-admission-lifecycle-projection/v1'
                    or proof['cohort_operation_id'] != self.operation_id
                    or proof['cohort_intent_sha256'] != digest(cohort['intent'])
                    or proof['tribe_ref'] != admission['tribe_ref']
                    or proof['owner'] != {key: approved[key] for key in ('being_ref', 'embodiment_id')}
                    or proof['manifest_digest'] != cohort['intent']['runtime_call']['manifest_digest']
                    or any(recipe.get(key) != value for key, value in approved['recipe'].items())
                    or previous['process'] != sender['process'] or server != sender['server']
                    or any(not isinstance(proof[key], str) or re.fullmatch('[0-9a-f]{64}', proof[key]) is None
                           for key in ('link_sha256', 'snapshot_request_sha256', 'owner_context_sha256'))
                    or not isinstance(proof['publication_operation_id'], str) or not proof['publication_operation_id']
                    or require_group and (not isinstance(proof['derived'], dict)
                    or proof['derived']['group'] != dict(application_sha256=recipe['selection']['application_sha256'],
                        publication_sha256=recipe['selection']['publication_sha256'],
                        installation_sha256=recipe['selection']['visibility_installation_sha256']))):
                raise ValueError
        except (KeyError, TypeError, ValueError, StopIteration):
            raise OnboardingError('receiving_admission_lifecycle_association_changed') from None

    def bind_admission_lifecycle(self, name: str, operation_id: str) -> dict:
        """Retain an approved child's association before it can stop a sender."""
        from .operation_journal import JournalConflict
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            admission = self._admission(row)
            if (admission is None or name not in {item['name'] for item in row['expected_precondition']['senders']}
                    or not isinstance(operation_id, str) or not operation_id):
                raise OnboardingError('receiving_admission_lifecycle_binding_required')
            recipe = {**admission['receivers'][name]['recipe'], 'lifecycle_operation_id': operation_id}
            lifecycle = self._lifecycle(name, recipe, require_group=False)
            if lifecycle is None:
                raise OnboardingError('receiving_cohort_lifecycle_unobserved')
            proof = (lifecycle.get('admission') if recipe['profile'] == 'source'
                and hasattr(self.owners[name], 'lifecycle_operation') else admission_lifecycle_projection(
                    lifecycle, profile=recipe['profile'], name=name))
            if not isinstance(proof, dict):
                raise OnboardingError('receiving_admission_lifecycle_association_changed')
            value = dict(lifecycle_operation_id=operation_id, link_sha256=proof['link_sha256'])
            observations = dict(row['runtime_observation'] or {})
            bindings = dict(observations.get('admission_lifecycles', {}))
            if name in bindings:
                if bindings[name] != value:
                    raise JournalConflict('admission lifecycle binding changed')
                return value
            effects = ((lifecycle['runtime_observation'] or {}).get('source_bootstrap', {})
                if recipe['profile'] == 'source' else
                (lifecycle['runtime_observation'] or {}).get('guest_bootstraps', {}).get(name, {}))
            if any(key in effects for key in ('quiesced', 'controlled_loaded')):
                raise OnboardingError('receiving_admission_lifecycle_binding_too_late')
            bindings[name] = value
            observations['admission_lifecycles'] = bindings
            self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
            return value

    def _bound_admission_lifecycle(self, row: dict, name: str) -> tuple[dict, dict]:
        admission = self._admission(row)
        binding = (row['runtime_observation'] or {}).get('admission_lifecycles', {}).get(name)
        if (admission is None or not isinstance(binding, dict)
                or set(binding) != {'lifecycle_operation_id', 'link_sha256'}):
            raise OnboardingError('receiving_admission_lifecycle_binding_required')
        recipe = {**admission['receivers'][name]['recipe'], 'lifecycle_operation_id': binding['lifecycle_operation_id']}
        lifecycle = self._lifecycle(name, recipe, require_group=False)
        if lifecycle is None:
            raise OnboardingError('receiving_cohort_lifecycle_unobserved')
        proof = (lifecycle.get('admission') if recipe['profile'] == 'source'
            and hasattr(self.owners[name], 'lifecycle_operation') else admission_lifecycle_projection(
                lifecycle, profile=recipe['profile'], name=name))
        if not isinstance(proof, dict) or proof['link_sha256'] != binding['link_sha256']:
            raise OnboardingError('receiving_admission_lifecycle_association_changed')
        return recipe, lifecycle

    def _admission_revocation_barrier(self, row: dict) -> dict:
        """Observe revoked originals, stopped units, or freshly fenced loads."""
        deadline = min([time.monotonic_ns() + 30_000_000_000, *[
            getattr(owner, 'deadline_ns', None) or 2**63 - 1 for owner in self.owners.values()]])
        control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
        revocations = (row['runtime_observation'] or {}).get('sender_revocations', {})
        proofs = {}
        for sender in row['expected_precondition']['senders']:
            name, owner = sender['name'], self.owners[sender['name']]
            old = revocations.get(name)
            if not isinstance(old, dict):
                raise OnboardingError('receiving_sender_barrier_incomplete')
            if (old.get('process') != sender['process'] or old.get('server') != sender['server']
                    or old.get('gate', {}).get('phase') != 'revoke' or old['gate'].get('readers') != []
                    or old['gate'].get('operation_id') != control_id
                    or old['gate'].get('release_digest') != row['intent']['runtime_call']['manifest_digest']
                    or old['gate'].get('request_sha256') != old.get('request_sha256')):
                raise OnboardingError('receiving_sender_barrier_changed')
            with self._owner_deadline(owner, deadline):
                try:
                    current = owner.status()
                except (OnboardingError, OSError):
                    current = None
                if current is not None and current['process'] == old['process'] and current['server'] == old['server']:
                    if current['gate'] != old['gate']:
                        raise OnboardingError('receiving_sender_barrier_changed')
                    proofs[name] = dict(state='revoked-original', process=current['process'])
                    continue
                recipe, lifecycle = self._bound_admission_lifecycle(row, name)
                exited = self._replacement_exit(sender, recipe, lifecycle)
                if current is None:
                    begun = time.monotonic_ns()
                    if recipe['profile'] == 'source':
                        action = getattr(owner, 'lifecycle_action', None)
                        if not callable(action):
                            raise OnboardingError('receiving_source_lifecycle_binding_required')
                        observed = action(recipe['lifecycle_operation_id'], 'quiescence')
                        schema = 'cluster-source-bootstrap-quiescence/v1'
                    else:
                        backend = getattr(owner, 'backend', None)
                        if backend is None:
                            raise OnboardingError('receiving_guest_owner_locator_required')
                        observed = GuestBootstrapController(self.journal, recipe['lifecycle_operation_id'],
                            backend, name).observe_quiescence(timeout_seconds=(deadline - begun) / 1_000_000_000)
                        schema = 'cluster-guest-service-quiescence-observation/v1'
                    service = observed.get('service', {}).get('manager', {})
                    if (observed.get('schema') != schema or observed.get('process') != sender['process']
                            or observed.get('exit_sha256') != digest(exited)
                            or service.get('ActiveState') != 'inactive' or service.get('SubState') != 'dead'
                            or service.get('MainPID') != '0'):
                        raise OnboardingError('receiving_sender_quiescence_unobserved')
                    proofs[name] = dict(state='stopped', observation=observed)
                else:
                    effects = lifecycle['runtime_observation'] or {}
                    loaded = ((effects.get('source_bootstrap', {}) if recipe['profile'] == 'source'
                        else effects.get('guest_bootstraps', {}).get(name, {}))).get('controlled_loaded')
                    status = current['runtime_status']
                    application = {key: value for key, value in status['loaded_application'].items() if key != 'reader_gates'}
                    if (not isinstance(loaded, dict) or loaded.get('process') != current['process']
                            or loaded.get('loaded_runtime') != status.get('loaded_runtime')
                            or loaded.get('loaded_application') != application
                            or recipe['profile'] == 'guest' and loaded.get('admission_parent') != current.get('admission_parent')):
                        raise OnboardingError('receiving_sender_replacement_unobserved')
                    row = self._revoke_replacement(row, sender, current, recipe, exited)
                    proofs[name] = dict(state='revoked-replacement',
                        accepted=row['runtime_observation']['sender_replacements'][name]['accepted'])
        self._accept_activation_deadline(deadline)
        return dict(schema='cluster-receiving-admission-barrier/v1', operation_id=self.operation_id,
            manifest_digest=row['intent']['runtime_call']['manifest_digest'], sender_revocations=revocations,
            current_senders=proofs, receiving_readiness='unobserved')

    def _initial_lifecycle(self, row: dict, name: str, recipe: dict) -> dict:
        """Consume the actual first-load producer, never replacement markers."""
        from .onboarding_service import initial_context, unit_content
        try:
            admission = self._admission(row)
            if (admission is None or name in {item['name'] for item in row['expected_precondition']['senders']}
                    or recipe['profile'] != 'guest' or recipe['lifecycle_operation_id'] != self.operation_id):
                raise ValueError
            effect = row['runtime_observation']['initial_managed'][name]
            if set(effect) != {'intent', 'validated', 'selected', 'started', 'controlled_loaded'}:
                raise ValueError
            intent, prepared, selected, started, loaded = (effect[key] for key in (
                'intent', 'validated', 'selected', 'started', 'controlled_loaded'))
            binding, owner, request = intent['binding'], intent['owner'], intent['request']
            receiver = admission['receivers'][name]
            group = owner['group']
            expected_origin = {key: binding['origin'][key] for key in ('body_ref', 'embodiment_id', 'incarnation_id')}
            context = initial_context(json.loads(request['argv'][request['argv'].index('--initial-context-json') + 1]))
            fingerprint = hashlib.sha256(unit_content(request['argv'])).hexdigest()
            if (set(intent) != {'binding', 'owner', 'request', 'unit_sha256'}
                    or set(binding) != {'schema', 'plan_digest', 'admission_sha256', 'profile_sha256', 'receiver', 'origin'}
                    or binding['schema'] != 'cluster-managed-initial-binding/v1'
                    or binding['admission_sha256'] != digest(admission) or binding['receiver'] != receiver
                    or any(re.fullmatch('[0-9a-f]{64}', binding[key]) is None for key in ('profile_sha256', 'plan_digest'))
                    or owner['plan_digest'] != binding['plan_digest'] or owner['predecessor'] is not None
                    or owner['being_ref'] != receiver['being_ref'] or owner['origin'] != expected_origin
                    or owner['origin']['embodiment_id'] != receiver['embodiment_id']
                    or owner['mode'] != 'preserve' or owner['group_sha256'] != digest(group)
                    or owner['preservation']['schema'] != 'cluster-receiving-controller-preservation/v1'
                    or owner['preservation']['active'] is not True
                    or owner['preservation']['runtime_sha256'] != owner['runtime_sha256']
                    or owner['preservation']['origin'] != owner['origin']
                    or group['selected']['tribe_ref'] != admission['tribe_ref']
                    or group['selected']['socket'] != receiver['socket']
                    or request['schema'] != 'cluster-guest-service-initial/v1' or request['predecessor'] is not None
                    or request['operation_id'] != guest_bootstrap_operation_id(self.operation_id)
                    or request['plan_digest'] != binding['plan_digest']
                    or request['not_after_ms'] != admission['activation']['expires_at_ms']
                    or request['argv'].count('--initial-context-json') != 1
                    or context != dict(schema='cluster-initial-start-context/v1', owner_sha256=digest(owner),
                        profile_sha256=binding['profile_sha256'], not_after_ms=request['not_after_ms'])
                    or intent['unit_sha256'] != fingerprint or selected['selected_sha256'] != fingerprint
                    or prepared['schema'] != 'cluster-guest-service-initial-candidate/v1'
                    or prepared['candidate_sha256'] != fingerprint
                    or started['schema'] != 'cluster-guest-service-initial-start/v1'
                    or started['initial_service'] != prepared['initial_service']
                    or started['service']['unit_sha256'] != fingerprint
                    or started['service']['manager']['MainPID'] != str(started['admission_parent']['pid'])
                    or loaded['schema'] != 'cluster-guest-initial-loaded/v1'
                    or loaded['admission_parent'] != started['admission_parent']
                    or loaded['runtime_sha256'] != owner['runtime_sha256']
                    or loaded['loaded_runtime']['runtime_bundle_sha256'] != owner['runtime_sha256']
                    or loaded['group_sha256'] != owner['group_sha256']
                    or loaded['loaded_application']['application_sha256'] != group['application_sha256']
                    or loaded['loaded_application']['publication_sha256'] != group['publication_sha256']
                    or loaded['loaded_application']['visibility']['installation_sha256'] != group['installation_sha256']
                    or loaded['receiving_readiness'] != 'unobserved'):
                raise ValueError
            return effect
        except (KeyError, TypeError, ValueError, AttributeError, IndexError, OnboardingError):
            raise OnboardingError('receiving_initial_managed_lifecycle_unobserved') from None

    def _qualified_preflight(self, name: str, recipe: dict, plan: dict, manifest: dict, lifecycle: dict | None) -> dict:
        """Reuse the maintained isolated reader against this exact release.

        Boot provenance supplies the protected public candidate location. The
        release assessment is current and separate; identical software may be
        reassessed without gratuitously repeating a lifecycle effect.
        """
        if lifecycle is None or lifecycle['operation'] != 'receiving-update':
            raise OnboardingError('receiving_cohort_lifecycle_unobserved')
        admission = self._admission(lifecycle)
        if admission is not None and name not in {item['name'] for item in lifecycle['expected_precondition']['senders']}:
            self._initial_lifecycle(lifecycle, name, recipe)
            candidate = admission['receivers'][name]['candidate']
            code, uid = candidate['code'], candidate['code_uid']
        else:
            candidate = (lifecycle['intended_transition'].get('source_bootstrap', {}).get('qualification', {})
            if recipe['profile'] == 'source' else lifecycle['intended_transition'].get('guest_bootstraps', {}).get(name, {}))
            code = candidate.get('code' if recipe['profile'] == 'source' else 'runtime_code')
            uid = candidate.get('code_uid')
        if not isinstance(code, str) or not Path(code).is_absolute() or '..' in Path(code).parts or type(uid) is not int or uid < 0:
            raise OnboardingError('receiving_cohort_preflight_unobserved')
        cache_key = digest(dict(code=code, uid=uid, prepared=recipe['prepared'], manifest=manifest))
        if cache_key not in self._preflights:
            prepared = recipe['prepared']
            checked = preflight(Path(code), prepared['code_digest'], Path(plan['manifest_path']), digest(manifest),
                being_ref=prepared['being_ref'], embodiment_id=prepared['embodiment_id'],
                code_uid=uid, manifest_uid=plan['manifest_uid'])
            if any(prepared.get(key) != value for key, value in checked.items()):
                raise OnboardingError('receiving_cohort_preflight_changed')
            self._preflights[cache_key] = checked
        return self._preflights[cache_key]

    def prepare_activation(self) -> dict:
        """Persist all required adoption before any positive sender request."""
        with self.journal.mutation_lock(self.operation_id), self._observation_scope():
            return self._prepare_activation()

    def _prepare_activation(self) -> dict:
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            plan, manifest = self._activation(row)
            # Configure/discover before the finite all-reader observation round.
            # Subsequent identity calls reuse their qualified owner process to
            # inspect native state, never start another cold helper per reader.
            self.reconcile_tooling()
            row = self._row()
            observations: dict = {}
            records = self._adoption_round(plan, manifest, observations=observations)
            now = time.time_ns() // 1_000_000
            if any(now - item['observed_at_ms'] > plan['observation_window_ms']
                   or item['reader']['expires_at_ms'] <= now for item in records.values()):
                raise OnboardingError('receiving_cohort_observation_expired')
            frozen = row['expected_precondition']['receiver_selections']
            for name, record in records.items():
                receiver = next(item for item in manifest['required_receivers'] if
                    (item['being_ref'], item['embodiment_id']) == (record['reader']['being_ref'], record['reader']['embodiment_id']))
                if receiver['expected_selection_sha256'] != digest(frozen[name]):
                    raise OnboardingError('receiving_cohort_predecessor_changed')
            row = self._activation_barrier(row, plan, records, observations)
            now = time.time_ns() // 1_000_000
            if any(now - item['observed_at_ms'] > plan['observation_window_ms']
                   or item['reader']['expires_at_ms'] <= now for item in records.values()):
                raise OnboardingError('receiving_cohort_observation_expired')
            readers = sorted([item['reader'] for item in records.values()], key=lambda item: (item['being_ref'], item['embodiment_id']))
            observations = dict(row['runtime_observation'] or {})
            if 'cohort_activation' in observations:
                retained = observations['cohort_activation']
                if retained['readers'] != readers:
                    raise OnboardingError('receiving_cohort_activation_changed')
                return retained
            activation = dict(schema='cluster-receiving-cohort-activation/v1', records=records, readers=readers,
                roster_sha256=plan['roster_sha256'], evidence_sha256=digest(records), prepared_at_ms=now)
            observations['cohort_activation'] = activation
            self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
            return activation

    def reconcile_tooling(self) -> dict:
        from .onboarding_owner_client import validate_tooling_recipe
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            plan, _manifest_value = self._activation(row)
            for name in sorted(self.owners):
                recipe = validate_tooling_recipe(plan['receivers'][name].get('tooling'))
                if recipe['profile'] == 'matrix-only':
                    continue
                observations = dict(row['runtime_observation'] or {})
                retained = dict(observations.get('native_tooling', {}))
                if name in retained:
                    continue
                operation = str(uuid.uuid5(uuid.NAMESPACE_URL, 'native-tooling:' + self.operation_id + ':' + name))
                owner = self.owners[name]
                if not hasattr(owner, 'reconcile_tooling'):
                    raise OnboardingError('receiving_native_tooling_unobserved')
                result = owner.reconcile_tooling(operation, attachment=Path(recipe['attachment']),
                    codex_home=Path(recipe['codex_home']), connections=tuple(map(Path, recipe['connections'])),
                    native_endpoint=Path(recipe['native_endpoint']), native_threads=tuple(recipe['native_threads']),
                    **({'binding_filename': recipe['binding_filename']} if 'binding_filename' in recipe else {}))
                if (result.get('schema') != 'cluster-native-chat-tooling/v1' or result.get('operation_id') != operation
                        or result.get('status') != 'configured' or not isinstance(result.get('native_catalog'), dict)):
                    raise OnboardingError('receiving_native_tooling_unobserved')
                retained[name] = result
                observations['native_tooling'] = retained
                row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                    expected_runtime_observation=row['runtime_observation'])
            return (row['runtime_observation'] or {}).get('native_tooling', {})

    @staticmethod
    def _replacement_exit(sender: dict, recipe: dict, lifecycle: dict) -> dict:
        effects = lifecycle['runtime_observation'] or {}
        name = sender['name']
        if recipe['profile'] == 'source':
            previous = lifecycle['expected_precondition'].get('source_bootstrap', {}).get('predecessor', {})
            previous_server = previous.get('server')
            exited = effects.get('source_bootstrap', {}).get('quiesced', {})
            closed = exited.get('exit_observed') is True and exited.get('writer_available') is True
        else:
            frozen_owner = lifecycle['expected_precondition'].get('guest_bootstraps', {}).get(name, {}).get('owner', {})
            previous = frozen_owner.get('predecessor', {})
            previous_server = frozen_owner.get('origin')
            exited = effects.get('guest_bootstraps', {}).get(name, {}).get('quiesced', {})
            closed = (exited.get('schema') == 'cluster-guest-service-quiescence/v1'
                and exited.get('exits') == {'process': True, 'admission_parent': True}
                and exited.get('admission_parent') == previous.get('admission_parent'))
        if (not closed or previous.get('process') != sender['process']
                or previous_server != sender['server'] or exited.get('process') != sender['process']):
            raise OnboardingError('receiving_sender_replacement_unobserved')
        return exited

    def _revoke_replacement(self, row: dict, sender: dict, current: dict, recipe: dict, exited: dict) -> dict:
        """Retain a replacement's own exact revoke, shared by both barriers."""
        name = sender['name']
        owner = self.owners[name]
        release = row['intent']['runtime_call']['manifest_digest']
        control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
        observations = dict(row['runtime_observation'] or {})
        replacements = dict(observations.get('sender_replacements', {}))
        if current['process'] == sender['process']:
            raise OnboardingError('receiving_sender_replacement_unobserved')
        if name not in replacements:
            gate = current['gate']
            if gate.get('phase') != 'unselected' or gate.get('readers') != []:
                raise OnboardingError('receiving_sender_replacement_unfenced')
            command = dict(process_instance_id=gate['process_instance_id'], channel_id='tribe',
                expected_head=gate['head'], operation_id=control_id, release_digest=release, phase='revoke', readers=[])
            replacements[name] = dict(process=current['process'], server=current['server'], command=command,
                lifecycle_operation_id=recipe['lifecycle_operation_id'], exit_sha256=digest(exited))
            observations['sender_replacements'] = replacements
            row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
        replacement = replacements[name]
        if (replacement['process'] != current['process'] or replacement['server'] != current['server']
                or replacement['lifecycle_operation_id'] != recipe['lifecycle_operation_id']
                or replacement['exit_sha256'] != digest(exited)):
            raise OnboardingError('receiving_sender_replacement_changed')
        path = owner.root / 'receiving-control' / (control_id + '-replacement-revoke.json')
        result = owner.prepare_apply_control(replacement['command'], path)
        accepted = {key: result[key] for key in ('server', 'process', 'gate', 'request_sha256', 'command_sha256')}
        if (accepted['process'] != replacement['process'] or accepted['server'] != replacement['server']
                or accepted['gate'].get('phase') != 'revoke' or accepted['gate'].get('readers') != []
                or accepted['gate'].get('operation_id') != control_id or accepted['gate'].get('release_digest') != release
                or accepted['gate'].get('request_sha256') != accepted['request_sha256']):
            raise OnboardingError('receiving_sender_replacement_uncertain')
        if replacement.get('accepted', accepted) != accepted:
            raise OnboardingError('receiving_sender_replacement_changed')
        replacements[name] = {**replacement, 'accepted': accepted}
        observations['sender_replacements'] = replacements
        return self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
            expected_runtime_observation=row['runtime_observation'])

    def _activation_barrier(self, row: dict, plan: dict, records: dict, current_observations: dict) -> dict:
        """Preserve old revocations and qualify an explicitly replaced sender.

        A lifecycle exit/load record is required before a new process may be
        fenced. Its fresh revoke is retained separately, never substituted for
        the original precondition or treated as an ACK from the old process.
        """
        release = row['intent']['runtime_call']['manifest_digest']
        control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
        for sender in row['expected_precondition']['senders']:
            name = sender['name']
            observations = dict(row['runtime_observation'] or {})
            old = observations.get('sender_revocations', {}).get(name)
            if (not isinstance(old, dict) or old.get('process') != sender['process']
                    or old.get('server') != sender['server'] or old.get('gate', {}).get('phase') != 'revoke'
                    or old['gate'].get('readers') != [] or old['gate'].get('operation_id') != control_id
                    or old['gate'].get('release_digest') != release
                    or old['gate'].get('request_sha256') != old.get('request_sha256')):
                raise OnboardingError('receiving_sender_barrier_changed')
            # Adoption already authenticated this exact process/gate in the
            # current bounded round. Another cold owner CLI spends freshness
            # without adding proof; native preparation/selection still CASes
            # the actual process/head and refuses intervening change.
            current = current_observations[name]
            record = records[name]
            if current['process'] != record['process'] or current['server'] != record['server']:
                raise OnboardingError('receiving_sender_barrier_changed')
            if current['process'] == old['process'] and current['server'] == old['server']:
                if current['gate'] != old['gate']:
                    raise OnboardingError('receiving_sender_barrier_changed')
                continue
            recipe = plan['receivers'][name]
            lifecycle = self._lifecycle(name, recipe)
            if lifecycle is None:
                raise OnboardingError('receiving_cohort_lifecycle_unobserved')
            exited = self._replacement_exit(sender, recipe, lifecycle)
            row = self._revoke_replacement(row, sender, current, recipe, exited)
        admission = self._admission(row)
        if admission is not None:
            before = {item['name'] for item in row['expected_precondition']['senders']}
            for name in sorted(set(self.owners) - before):
                recipe = plan['receivers'][name]
                initial = self._initial_lifecycle(row, name, recipe)
                current, proof = current_observations[name], records[name]
                if (current['process'] != proof['process'] or current['server'] != proof['server']
                        or proof['process'] != initial['controlled_loaded']['process']):
                    raise OnboardingError('receiving_initial_sender_changed')
                observations = dict(row['runtime_observation'] or {})
                senders = dict(observations.get('sender_initials', {}))
                if name not in senders:
                    gate = current['gate']
                    if gate.get('phase') != 'unselected' or gate.get('readers') != []:
                        raise OnboardingError('receiving_initial_sender_unfenced')
                    command = dict(process_instance_id=gate['process_instance_id'], channel_id='tribe',
                        expected_head=gate['head'], operation_id=control_id, release_digest=release,
                        phase='revoke', readers=[])
                    senders[name] = dict(process=current['process'], server=current['server'], command=command,
                        lifecycle_operation_id=self.operation_id, initial_sha256=digest(initial['controlled_loaded']))
                    observations['sender_initials'] = senders
                    row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                        expected_runtime_observation=row['runtime_observation'])
                sender = senders[name]
                if (sender['process'] != current['process'] or sender['server'] != current['server']
                        or sender['lifecycle_operation_id'] != self.operation_id
                        or sender['initial_sha256'] != digest(initial['controlled_loaded'])):
                    raise OnboardingError('receiving_initial_sender_changed')
                now = time.time_ns() // 1_000_000
                deadline = min(proof['observed_at_ns'] + plan['observation_window_ms'] * 1_000_000,
                    time.monotonic_ns() + (min(plan['expires_at_ms'], proof['reader']['expires_at_ms']) - now) * 1_000_000)
                with self._owner_deadline(self.owners[name], deadline):
                    result = self.owners[name].prepare_apply_control(sender['command'],
                        self.owners[name].root / 'receiving-control' / (control_id + '-initial-revoke.json'))
                accepted = {key: result[key] for key in ('server', 'process', 'gate', 'request_sha256', 'command_sha256')}
                if (accepted['process'] != sender['process'] or accepted['server'] != sender['server']
                        or accepted['gate'].get('phase') != 'revoke' or accepted['gate'].get('readers') != []
                        or accepted['gate'].get('operation_id') != control_id
                        or accepted['gate'].get('release_digest') != release
                        or accepted['gate'].get('request_sha256') != accepted['request_sha256']):
                    raise OnboardingError('receiving_initial_sender_uncertain')
                if sender.get('accepted', accepted) != accepted:
                    raise OnboardingError('receiving_initial_sender_changed')
                senders[name] = {**sender, 'accepted': accepted}
                observations['sender_initials'] = senders
                row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                    expected_runtime_observation=row['runtime_observation'])
        return row

    def _current_activation(self, row: dict, plan: dict, manifest: dict, activation: dict,
                            *, observations: dict | None = None) -> int:
        records = self._adoption_round(plan, manifest,
            observations={} if observations is None else observations)
        for name, current in records.items():
            retained = activation['records'][name]
            if ({key: val for key, val in current.items() if key not in {'observed_at_ms', 'observed_at_ns'}} !=
                    {key: val for key, val in retained.items() if key not in {'observed_at_ms', 'observed_at_ns'}}):
                raise OnboardingError('receiving_cohort_activation_changed')
        now = time.time_ns() // 1_000_000
        if any(now - item['observed_at_ms'] > plan['observation_window_ms']
               or item['reader']['expires_at_ms'] <= now for item in records.values()):
            raise OnboardingError('receiving_cohort_activation_changed')
        deadline = min(item['observed_at_ns'] + plan['observation_window_ms'] * 1_000_000
            for item in records.values())
        deadline = min(deadline, time.monotonic_ns() + min(
            item['reader']['expires_at_ms'] - now for item in records.values()) * 1_000_000)
        self._accept_activation_deadline(deadline)
        return deadline

    @staticmethod
    def _accept_activation_deadline(deadline: int) -> None:
        if time.monotonic_ns() >= deadline:
            raise OnboardingError('receiving_cohort_observation_expired')

    @contextmanager
    def _owner_deadline(self, owner, deadline: int):
        previous = getattr(owner, 'deadline_ns', None)
        owner.deadline_ns = deadline if previous is None else min(previous, deadline)
        try:
            self._accept_activation_deadline(owner.deadline_ns)
            yield
            self._accept_activation_deadline(owner.deadline_ns)
        finally:
            owner.deadline_ns = previous

    def _sender_revocation(self, row: dict, name: str) -> dict | None:
        observations = row['runtime_observation'] or {}
        before = {item['name'] for item in row['expected_precondition']['senders']}
        if name not in before:
            if name in observations.get('sender_replacements', {}) or name in observations.get('sender_revocations', {}):
                raise OnboardingError('receiving_initial_sender_changed')
            return observations.get('sender_initials', {}).get(name, {}).get('accepted')
        if name in observations.get('sender_initials', {}):
            raise OnboardingError('receiving_sender_barrier_changed')
        replacement = observations.get('sender_replacements', {}).get(name)
        return (replacement.get('accepted') if replacement is not None else
            observations.get('sender_revocations', {}).get(name))

    def _require_all_revocations(self, row: dict, activation: dict) -> None:
        control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
        release = row['intent']['runtime_call']['manifest_digest']
        for name in self.owners:
            revoked = self._sender_revocation(row, name)
            if (not isinstance(revoked, dict) or revoked['process'] != activation['records'][name]['process']
                    or revoked['server'] != activation['records'][name]['server']
                    or revoked['gate'].get('phase') != 'revoke' or revoked['gate'].get('readers') != []
                    or revoked['gate'].get('operation_id') != control_id
                    or revoked['gate'].get('release_digest') != release
                    or revoked['gate'].get('request_sha256') != revoked.get('request_sha256')):
                raise OnboardingError('receiving_sender_barrier_changed')

    def _fence_partial_activation(self, activation: dict) -> None:
        """Retain a finite forward repair before revoking known positive grants."""
        row = self._row()
        observations = dict(row['runtime_observation'] or {})
        repairs = dict(observations.get('cohort_reassessment', {}))
        release = row['intent']['runtime_call']['manifest_digest']
        old_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
        repair_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-reassessment:' + self.operation_id))
        if 'cohort_reassessment' not in observations:
            observations['cohort_reassessment'] = repairs
            row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
        for name, owner in sorted(self.owners.items()):
            if name not in repairs or repairs[name]['state'] == 'uncertain':
                try:
                    current = owner.status()
                except (OnboardingError, OSError):
                    # Observation failure never proves a previous grant absent.
                    repairs[name] = {'state': 'uncertain'}
                    continue
                gate = current['gate']
                if (gate.get('phase') not in {'revoke', 'select'}
                        or (gate.get('operation_id'), gate.get('release_digest')) != (old_id, release)):
                    if name in repairs and gate.get('readers') == []:
                        repairs[name] = {'state': 'observed-disabled'}
                    continue
                record = activation['records'].get(name)
                if (not isinstance(record, dict) or current['process'] != record['process']
                        or current['server'] != record['server']):
                    repairs[name] = {'state': 'uncertain'}
                    continue
                command = dict(process_instance_id=gate['process_instance_id'], channel_id='tribe',
                    expected_head=gate['head'], operation_id=repair_id, release_digest=release, phase='revoke', readers=[])
                if gate['phase'] == 'revoke':
                    try:
                        original = self._sender_revocation(row, name)
                    except OnboardingError:
                        repairs[name] = {'state': 'uncertain'}
                        continue
                    pending = observations.get('sender_initials', {}).get(name)
                    if original is None and pending is not None:
                        try:
                            original = owner.prepare_apply_control(pending['command'], owner.root /
                                'receiving-control' / (old_id + '-initial-revoke.json'))
                        except (OnboardingError, OSError):
                            repairs[name] = {'state': 'uncertain'}
                            continue
                    if (not isinstance(original, dict) or any(current[key] != original[key]
                            for key in ('process', 'server', 'gate'))):
                        repairs[name] = {'state': 'uncertain'}
                        continue
                    # A revoke reserves its operation. Release that existing
                    # reservation with zero readers under the original ID;
                    # a new repair revoke would itself be rejected.
                    command['operation_id'] = old_id
                    repairs[name] = dict(state='clearing', command=command, revoke_gate=gate,
                        request_sha256=original['request_sha256'], process=current['process'], server=current['server'])
                else:
                    repairs[name] = dict(state='prepared', command=command,
                        process=current['process'], server=current['server'])
            observations['cohort_reassessment'] = repairs
            row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
            repair = repairs[name]
            if repair['state'] not in {'prepared', 'clearing'}:
                continue
            try:
                if repair['state'] == 'prepared':
                    path = owner.root / 'receiving-control' / (repair_id + '-revoke.json')
                    result = owner.prepare_apply_control(repair['command'], path)
                    if (result['process'] != repair['process'] or result['server'] != repair['server']
                            or result['gate'].get('phase') != 'revoke' or result['gate'].get('readers') != []
                            or result['gate'].get('operation_id') != repair_id
                            or result['gate'].get('release_digest') != release
                            or result['gate'].get('request_sha256') != result['request_sha256']):
                        raise OnboardingError('receiving_reassessment_uncertain')
                    repair = {**repair, 'state': 'clearing', 'revoke_gate': result['gate'],
                              'request_sha256': result['request_sha256']}
                    repairs[name] = repair
                    observations['cohort_reassessment'] = repairs
                    row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                        expected_runtime_observation=row['runtime_observation'])
                # An empty selection grants no reader. It releases the native
                # revoke reservation so a new authorized operation can recover
                # forward instead of being trapped behind this failed one.
                clear = {**repair['command'], 'expected_head': repair['revoke_gate']['head'], 'phase': 'select'}
                path = owner.root / 'receiving-control' / (repair_id + '-clear.json')
                result = owner.prepare_apply_control(clear, path)
                if (result['process'] != repair['process'] or result['server'] != repair['server']
                        or result['gate'].get('phase') != 'select' or result['gate'].get('readers') != []
                        or result['gate'].get('operation_id') != repair['command']['operation_id']
                        or result['gate'].get('release_digest') != release
                        or result['gate'].get('request_sha256') != result['request_sha256']):
                    raise OnboardingError('receiving_reassessment_uncertain')
                repairs[name] = {**repair, 'state': 'disabled', 'clear_request_sha256': result['request_sha256']}
            except (OnboardingError, OSError):
                # Keep the exact prepared request to reconcile lost replies.
                pass
            observations['cohort_reassessment'] = repairs
            row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])
        if repairs:
            observations['cohort_reassessment'] = repairs
            self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                expected_runtime_observation=row['runtime_observation'])

    def reconcile_reassessment(self) -> dict:
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            activation = (row['runtime_observation'] or {}).get('cohort_activation')
            if activation is None:
                records = dict((row['runtime_observation'] or {}).get('sender_revocations', {}))
                for name, value in (row['runtime_observation'] or {}).get('sender_replacements', {}).items():
                    # An unacknowledged replacement remains uncertain. It must
                    # never inherit the old process's observation.
                    records[name] = value.get('accepted', value)
                for name, value in (row['runtime_observation'] or {}).get('sender_initials', {}).items():
                    records[name] = value.get('accepted', value)
                activation = {'records': records}
            elif 'cohort_reassessment' not in row['runtime_observation']:
                raise OnboardingError('receiving_cohort_reassessment_required')
            self._fence_partial_activation(activation)
            return self._row()['runtime_observation']['cohort_reassessment']

    def _confirmed_selection(self, row: dict, plan: dict, manifest: dict, activation: dict) -> dict:
        """Reconcile a fully retained selection using fresh all-required proof.

        No controls are prepared/applied. The original reader/expiry vector stays
        fixed; changed proof/gate or expired observation uses the existing repair.
        """
        release = row['intent']['runtime_call']['manifest_digest']
        try:
            observations: dict = {}
            deadline = self._current_activation(row, plan, manifest, activation,
                observations=observations)
            for name, accepted in row['runtime_observation']['sender_selections'].items():
                # Qualified identity already observed this gate in the same
                # all-required round; another cold status process adds no proof.
                current = observations[name]
                if any(current[key] != accepted[key] for key in ('server', 'process', 'gate')):
                    raise OnboardingError('receiving_cohort_selection_changed')
            self._accept_activation_deadline(deadline)
            if any(item['expires_at_ms'] <= time.time_ns() // 1_000_000 for item in activation['readers']):
                raise OnboardingError('receiving_cohort_observation_expired')
        except (OnboardingError, OSError):
            self._fence_partial_activation(activation)
            raise
        return dict(schema='cluster-receiving-cohort-selection/v1', operation_id=self.operation_id,
            manifest_digest=release, evidence_sha256=activation['evidence_sha256'],
            readers=activation['readers'], sender_selections=row['runtime_observation']['sender_selections'],
            receiving_readiness='qualified-local-projection', communication_acceptance='unobserved')

    def activate(self) -> dict:
        """Resume one fixed all-required vector through exact native selections.

        Each sender's partial result is retained. Cached success is reconciled
        against its current process/gate; no request or expiry is renewed.
        """
        with self.journal.mutation_lock(self.operation_id), self._observation_scope():
            return self._activate()

    def _activate(self) -> dict:
        row = self._row()
        if 'cohort_activation' not in (row['runtime_observation'] or {}):
            self.prepare_activation()
        with self.journal.mutation_lock(self.operation_id):
            row = self._row()
            plan, manifest = self._activation(row)
            activation = (row['runtime_observation'] or {})['cohort_activation']
            if 'cohort_reassessment' in row['runtime_observation']:
                raise OnboardingError('receiving_cohort_reassessment_required')
            release = row['intent']['runtime_call']['manifest_digest']
            if set(row['runtime_observation'].get('sender_selections', {})) == set(self.owners):
                return self._confirmed_selection(row, plan, manifest, activation)
            control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'receiving-control:' + self.operation_id))
            try:
                self._require_all_revocations(row, activation)
            except (OnboardingError, OSError):
                self._fence_partial_activation(activation)
                raise
            for name in sorted(self.owners):
                # Refresh all required observers before each positive step. A
                # local roster CAS remains enforced by each actual sender.
                try:
                    deadline = self._current_activation(row, plan, manifest, activation)
                except (OnboardingError, OSError):
                    self._fence_partial_activation(activation)
                    raise
                revoked = self._sender_revocation(row, name)
                if (not isinstance(revoked, dict) or revoked['process'] != activation['records'][name]['process']
                        or revoked['server'] != activation['records'][name]['server']
                        or revoked['gate'].get('phase') != 'revoke'
                        or revoked['gate'].get('operation_id') != control_id
                        or revoked['gate'].get('release_digest') != release):
                    raise OnboardingError('receiving_sender_barrier_changed')
                command = dict(process_instance_id=revoked['gate']['process_instance_id'], channel_id='tribe',
                    expected_head=revoked['gate']['head'], operation_id=control_id, release_digest=release,
                    phase='select', readers=activation['readers'], expected_roster_sha256=activation['roster_sha256'])
                owner = self.owners[name]
                path = owner.root / 'receiving-control' / (control_id + '-select.json')
                try:
                    with self._owner_deadline(owner, deadline):
                        result = owner.prepare_apply_control(command, path)
                        self._accept_activation_deadline(deadline)
                    if (not isinstance(result, dict)
                            or not {'process', 'server', 'gate', 'request_sha256', 'command_sha256'} <= set(result)
                            or not isinstance(result['gate'], dict)
                            or any(not isinstance(result[key], str) or re.fullmatch('[0-9a-f]{64}', result[key]) is None
                                   for key in ('request_sha256', 'command_sha256'))
                            or result['process'] != revoked['process'] or result['server'] != revoked['server']
                            or result['gate'].get('phase') != 'select'
                            or result['gate'].get('readers') != activation['readers']
                            or result['gate'].get('operation_id') != control_id
                            or result['gate'].get('release_digest') != release
                            or result['gate'].get('request_sha256') != result['request_sha256']):
                        raise OnboardingError('receiving_cohort_selection_uncertain')
                    accepted = {key: result[key] for key in ('server', 'process', 'gate', 'request_sha256', 'command_sha256')}
                except (OnboardingError, OSError) as error:
                    if isinstance(error, OnboardingError) and str(error) == 'receiving_cohort_selection_uncertain':
                        self._fence_partial_activation(activation)
                        raise
                    # A valid lost ACK remains exactly resumable. A newly
                    # invalid proof or expired query window fences forward.
                    try:
                        self._accept_activation_deadline(deadline)
                        self._current_activation(row, plan, manifest, activation)
                    except (OnboardingError, OSError):
                        self._fence_partial_activation(activation)
                    raise
                observations = dict(row['runtime_observation'] or {})
                selections = dict(observations.get('sender_selections', {}))
                if name in selections and selections[name] != accepted:
                    raise OnboardingError('receiving_cohort_selection_changed')
                if name not in selections:
                    selections[name] = accepted
                    observations['sender_selections'] = selections
                    row = self.journal.advance(self.operation_id, row['state'], runtime_observation=observations,
                        expected_runtime_observation=row['runtime_observation'])
            return self._confirmed_selection(row, plan, manifest, activation)


def _manifest(path: Path, expected: str, *, uid: int) -> dict:
    value = json.loads(onboarding_release.regular(path, uid=uid, limit=2 * 1024**2))
    # The closed release contract uses ASCII identifiers/digests and integers.
    # Validate this subset before using any manifest field to select executable
    # code. Its sorted compact encoding is the Matrix canonical encoding here.
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int and -(2**53) + 1 <= item <= 2**53 - 1:
            return
        if isinstance(item, str) and item.isascii():
            return
        if isinstance(item, list):
            for entry in item:
                check(entry)
            return
        if isinstance(item, dict) and all(isinstance(key, str) and key.isascii() for key in item):
            for entry in item.values():
                check(entry)
            return
        raise OnboardingError('invalid_receiving_manifest')
    check(value)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if (not isinstance(value, dict) or not isinstance(expected, str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected)
            or hashlib.sha256(raw).hexdigest() != expected):
        raise OnboardingError('receiving_manifest_digest_mismatch')
    return value


def _reader(wheel: Path, wheel_sha256: str, manifest: dict, manifest_digest: str,
            being_ref: str, embodiment_id: str, *, uid: int) -> dict:
    raw = onboarding_release.regular(wheel, uid=uid)
    if hashlib.sha256(raw).hexdigest() != wheel_sha256:
        raise OnboardingError('onboarding_sdk_digest_mismatch')
    # Only the qualified pure-stdlib contract modules execute. Do not execute the
    # candidate's package __init__, installed dependencies, .pth or startup hooks.
    launcher = '''import json, sys, types
root = sys.argv[1]
package = types.ModuleType('daimon_matrix')
package.__path__ = [root]
sys.modules['daimon_matrix'] = package
from daimon_matrix.release_compatibility import validate_release, describe_reader, assess_reader, selected_artifacts
request = json.load(sys.stdin)
release = validate_release(request['manifest'], expected_digest=request['digest'])
reader = describe_reader()
assessment = assess_reader(release, reader, expected_digest=request['digest'])
artifacts = selected_artifacts(release, being_ref=request['being_ref'],
    embodiment_id=request['embodiment_id'], expected_digest=request['digest'])
print(json.dumps(dict(reader=reader, assessment=assessment, artifacts=artifacts)))
'''
    with tempfile.TemporaryDirectory(prefix='cluster-qualified-reader-') as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in ('canonical.py', 'release_compatibility.py'):
                member = archive.getinfo('daimon_matrix/' + name)
                if member.file_size > 1024**2:
                    raise OnboardingError('qualified_receiving_reader_required')
                (root / name).write_bytes(archive.read(member))
        try:
            process = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', launcher, str(root)],
                input=json.dumps(dict(manifest=manifest, digest=manifest_digest,
                    being_ref=being_ref, embodiment_id=embodiment_id)).encode(),
                capture_output=True, timeout=onboarding_sdk.probe_timeout(30), check=False, umask=0o077,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                     'LD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib')})
            onboarding_sdk.probe_timeout(30)
            if process.returncode or len(process.stdout) > 2 * 1024**2:
                raise OnboardingError('qualified_receiving_reader_required')
            result = json.loads(process.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise OnboardingError('qualified_receiving_reader_required') from None
    if (not isinstance(result, dict) or set(result) != {'reader', 'assessment', 'artifacts'}
            or not isinstance(result['assessment'], dict)
            or result['assessment'].get('release_digest') != manifest_digest
            or result['assessment'].get('compatible') is not True
            or result['assessment'].get('receiving_readiness') != 'unobserved'):
        raise OnboardingError('incompatible_receiving_reader')
    return result


def preflight(code: Path, code_digest: str, manifest_path: Path, manifest_digest: str,
              *, being_ref: str, embodiment_id: str, code_uid: int = 0,
              manifest_uid: int = 0) -> dict:
    """Check code/SDK bytes and candidate support before any receiving effect.

    The approved manifest is external to the content-addressed receiving code;
    neither embeds the other's digest, avoiding circular artifact identity.
    Actual authority/application/store and running readiness remain separate.
    """
    manifest = _manifest(manifest_path, manifest_digest, uid=manifest_uid)
    onboarding_release.verify(code, code_digest, uid=code_uid)
    try:
        revision = manifest['provenance']['matrix_revision']
        wheel_sha256 = manifest['artifacts']['matrix_sdk']
        sdk = onboarding_sdk.verify(code, uid=code_uid, matrix_commit=revision,
                                   matrix_wheel_sha256=wheel_sha256)
        wheel = next(row for row in sdk['wheels'] if row['distribution'] == 'daimon-matrix')
        result = _reader(code / 'sdk/wheels' / wheel['filename'], wheel_sha256,
                         manifest, manifest_digest, being_ref, embodiment_id, uid=code_uid)
        # Verify the child output against the already frozen per-receiver row.
        receiver = next(row for row in manifest['required_receivers']
                        if (row['being_ref'], row['embodiment_id']) == (being_ref, embodiment_id))
        expected_artifacts = {**manifest['artifacts'], **receiver.get('artifacts', {})}
        if (result['artifacts'] != expected_artifacts
                or expected_artifacts.get('receiving_code', code_digest) != code_digest):
            raise OnboardingError('receiving_artifact_selection_mismatch')
    except (KeyError, StopIteration, TypeError, zipfile.BadZipFile):
        raise OnboardingError('qualified_receiving_reader_required') from None
    return dict(schema='cluster-receiving-preflight/v1', release_digest=manifest_digest,
        being_ref=being_ref, embodiment_id=embodiment_id, code_digest=code_digest,
        sdk_digest=digest(sdk), matrix_revision=revision, matrix_wheel_sha256=wheel_sha256,
        **result, checked_artifacts={'receiving_code': code_digest, 'matrix_sdk': wheel_sha256},
        unverified_artifacts=sorted(set(expected_artifacts) - {'receiving_code', 'matrix_sdk'}),
        receiving_readiness='unobserved')


def prepare_sdk(home: Path, code: Path, code_digest: str, manifest_path: Path,
                manifest_digest: str, *, being_ref: str, embodiment_id: str,
                code_uid: int = 0, manifest_uid: int = 0, installed_only: bool = False) -> dict:
    """Install/observe the approved offline SDK without selecting a live runtime."""
    checked = preflight(code, code_digest, manifest_path, manifest_digest,
        being_ref=being_ref, embodiment_id=embodiment_id, code_uid=code_uid, manifest_uid=manifest_uid)
    options = dict(code_uid=code_uid, matrix_commit=checked['matrix_revision'],
        matrix_wheel_sha256=checked['matrix_wheel_sha256'])
    venv = (onboarding_sdk.observe(home, code, **options) if installed_only else
        onboarding_sdk.install(home, code, code_digest, **options))
    interpreter = onboarding_sdk.interpreter(venv)
    if interpreter != checked['reader']['contract']['interpreter']:
        raise OnboardingError('incompatible_receiving_interpreter')
    # Retain the installer's actual observation. Neither an installation receipt
    # nor this pure-reader probe proves adoption, live load or new-epoch egress.
    receipt = json.loads(onboarding_release.regular(venv.parent / 'installation.json', uid=os.geteuid()))
    if receipt.get('sdk_digest') != checked['sdk_digest']:
        raise OnboardingError('installed_onboarding_sdk_changed')
    return {**checked, 'installation': receipt, 'interpreter': interpreter, 'prepared': True}


def apply_host_selection(journal, operation_id: str, config_path: Path,
                         *, _cohort_control: CohortController | None = None) -> dict:
    """Apply/reconcile the retained host-runtime projection under real job locks.

    This is one controller effect, not completed receiving adoption. Only runtime
    selectors change; the frozen complete predecessor prevents an update from
    replacing concurrently added receivers or moving the worker's private roots.
    No service, identity, provider, native input or authority effect is performed.
    """
    from .onboarding_host import HostConfig, RUNTIME_SELECTION_KEYS
    from .operation_journal import JournalConflict
    row = journal.get(operation_id)
    if row is None or row['operation'] != 'receiving-update' or row['state'] in {'degraded', 'compensated'}:
        raise OnboardingError('receiving_update_selection_required')
    before = row['expected_precondition']
    after = row['intended_transition']
    call = row['intent'].get('runtime_call', {})
    if (call.get('precondition_digest') != digest(before)
            or call.get('transition_digest') != digest(after)
            or not isinstance(before.get('host_configuration'), dict)
            or not isinstance(after.get('host_runtime'), dict)
            or not set(after['host_runtime']) <= RUNTIME_SELECTION_KEYS
            or before.get('host_config_sha256') != digest(before['host_configuration'])):
        raise OnboardingError('receiving_update_selection_required')
    original = before['host_configuration']
    if 'senders' in before and (
            not isinstance(_cohort_control, CohortController) or _cohort_control.journal is not journal
            or _cohort_control.operation_id != operation_id):
        raise OnboardingError('receiving_sender_barrier_required')
    candidate = {**{key: value for key, value in original.items() if key not in RUNTIME_SELECTION_KEYS},
                 **after['host_runtime']}
    # Configuration path is part of the frozen operation, never a fresh target.
    if before.get('host_config') != str(config_path):
        raise OnboardingError('receiving_update_selection_required')
    jobs = private_directory(Path(original['jobs']))
    store = JobStore(jobs)
    with ExitStack() as ownership:
        ownership.enter_context(journal.mutation_lock(operation_id))
        ownership.enter_context(being_seed._locked(jobs))
        # Parent ownership excludes new submissions. Existing ticks hold exactly
        # these kernel locks, and resolve their backend only after taking one.
        for name in store.names():
            ownership.enter_context(being_seed._locked(private_directory(store.directory(name))))
        row = journal.get(operation_id)
        if row is None or row['state'] in {'degraded', 'compensated'}:
            raise JournalConflict('receiving operation requires explicit repair')
        if _cohort_control is not None:
            _cohort_control.require_revocation_barrier()
        current = being_seed._read(config_path)
        if current not in (original, candidate):
            raise JournalConflict('receiving host selection has advanced beyond the frozen predecessor')
        temporary = config_path.with_name('.receiving-selection-' + uuid.uuid4().hex + '.json')
        try:
            being_seed._write(temporary, candidate)
            HostConfig.load(temporary)
            if being_seed._read(config_path) != current:
                raise JournalConflict('receiving host selection changed during validation')
            if current != candidate and row['state'] not in {'planned', 'runtime-dispatching'}:
                raise JournalConflict('later receiving stage cannot reapply an absent host selection')
            if row['state'] == 'planned':
                row = journal.advance(operation_id, 'runtime-dispatching')
            if current != candidate:
                os.replace(temporary, config_path)
            # A prior replace-before-ACK is an observed effect. Complete its
            # directory durability before recording success, without rewriting.
            descriptor = os.open(config_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            result = dict(schema='cluster-receiving-host-selection/v1',
                operation_id=operation_id, previous_sha256=digest(original),
                selected_sha256=digest(candidate), selected=True, receiving_readiness='unobserved')
            observed = dict(row['runtime_observation'] or {})
            observed['host_selection'] = result
            # Concurrent stage evidence must not be overwritten. A conflict is
            # recoverable by rereading the retained operation and exact file;
            # the atomic selector effect is not repeated on that retry.
            journal.advance(operation_id, row['state'], runtime_observation=observed,
                            expected_runtime_observation=row['runtime_observation'])
            return result
        finally:
            temporary.unlink(missing_ok=True)
