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
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import uuid
from contextlib import ExitStack
from pathlib import Path

from . import being_seed, onboarding_release, onboarding_sdk
from .onboarding import JobStore, OnboardingError, digest, private_directory
from .owner_process import ConnectedProcessObserver


class OwnerGroupClient:
    """Finite owner-local control of the actual selected group daemon.

    Call from its receiving owner, not a model tool. Prepared authenticated
    requests stay in owner-private files; outputs contain only their digests and
    verified observations. Reading/control never claims candidate readiness.
    """

    def __init__(self, root: Path, socket_path: Path):
        self.root = private_directory(root)
        self.socket = socket_path
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

    def prepare_control(self, command: dict, path: Path) -> dict:
        """Persist one exact native request before attempting its effect."""
        parent = self._control_directory(path)
        with being_seed._locked(parent):
            return self._prepare_control(command, path)

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
            return self._apply_control(path)

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


def owner_control(root: Path, group: dict, observed: dict, action: str, path: Path,
                  *, command: dict | None = None, status_key: str = 'runtime_status') -> dict:
    """Reuse qualified Source/guest observation for the same finite owner RPC.

    The prepared request stays on its receiving owner. Only observation and
    request hashes cross the controller boundary; no capability key is returned.
    """
    if (action not in {'receiving-control-prepare', 'receiving-control-apply'}
            or (action == 'receiving-control-prepare') != (command is not None)
            or not isinstance(group, dict) or group.get('channel_id') != 'tribe'
            or observed.get('responder_association') != 'same-connection'):
        raise OnboardingError('invalid_receiving_control_request')
    with OwnerGroupClient(root, Path(group['socket'])) as owner:
        current = owner.status()
        previous = observed[status_key]
        if (current['process'] != observed['process']
                or any(current['runtime_status'].get(key) != previous.get(key)
                       for key in ('loaded_runtime', 'loaded_application'))
                or current['gate'] != previous.get('receiving', {}).get('channels', {}).get('tribe')):
            raise OnboardingError('receiving_control_process_changed')
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


def freeze_senders(owners: dict[str, OwnerGroupClient], *, tribe_ref: str) -> list[dict]:
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
            server=observed['server'], process=observed['process'], gate=observed['gate']))
    if not 1 <= len(senders) <= 256:
        raise OnboardingError('receiving_sender_vector_invalid')
    return senders


def freeze_source_bootstrap(source, manager) -> dict:
    """Freeze the Source's existing identity and actual Matrix manager scope."""
    with OwnerGroupClient(source.root, source.root / 'matrix.sock') as owner:
        predecessor = owner.base_status()
        service = manager.inspect()
        scope = manager.bind_process(predecessor['process'], service)
        bundle = being_seed._read(source.root / 'runtime.json', limit=being_seed.MAX_SELECTION)
        if (bundle['local_origin'] != predecessor['runtime_status']['local_origin']
                or _owner_identity(predecessor) != (
                    bundle['manifest']['being_ref'], bundle['local_origin']['embodiment_id'])):
            raise OnboardingError('receiving_bootstrap_identity_conflict')
        visibility = onboarding_release.regular(source.visibility, uid=os.geteuid())
        return dict(settings_sha256=digest(source.settings), unit=str(manager.unit),
            service=service, scope=scope, predecessor=predecessor,
            bundle_sha256=digest(bundle), visibility_sha256=hashlib.sha256(visibility).hexdigest(),
            visibility_envelope=json.loads(visibility))


def prepare_source_bootstrap(source, *, home: Path, code: Path, code_digest: str,
                             config: Path, manifest_path: Path, manifest_digest: str,
                             transaction: Path, expires_at_ms: int, code_uid: int = 0,
                             manifest_uid: int = 0) -> dict:
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
        code_uid=code_uid, manifest_uid=manifest_uid)
    parameters = sdk_parameters(code, uid=code_uid)
    if parameters != dict(matrix_commit=checked['matrix_revision'], matrix_wheel_sha256=checked['matrix_wheel_sha256']):
        raise OnboardingError('qualified_onboarding_source_runtime_required')
    venv = onboarding_sdk.observe(home, code, code_uid=code_uid, **parameters)
    imports = onboarding_sdk.runtime_imports(venv, code, code_uid=code_uid, **parameters)
    argv = onboarding_sdk.runtime_command(venv, imports, code, 'clusterctl.onboarding_source',
        ['--config', str(config), '--code-digest', code_digest, '--code-owner', str(code_uid)])
    return dict(transaction=str(transaction), expires_at_ms=expires_at_ms, argv=argv,
        qualification=dict(home=str(home), code=str(code), code_digest=code_digest, code_uid=code_uid, group=group,
            config=str(config), manifest_path=str(manifest_path), manifest_uid=manifest_uid, prepared=checked))


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
    from daimon_matrix.messaging_config import _public_identity, verify_public_binding, _read_verified_publication
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
    return dict(selected=group, application_sha256=digest(application), publication_sha256=digest(publication),
        installation_sha256=digest(visibility['document']),
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


def freeze_guest_bootstrap(target, *, deadline_ns: int) -> dict:
    """Observe the receiving body before its separately owned unit is stopped."""
    from .onboarding_service import GuestServiceBootstrap
    GuestServiceBootstrap._budget(deadline_ns)
    observed = target.running(admitted=True, deadline_ns=deadline_ns, bootstrap_base_only=True)
    bundle = target.document_bundle()
    if (observed['responder_association'] != 'same-connection'
            or observed['origin'] != bundle['local_origin']
            or observed['runtime_status'].get('being_ref') != bundle['manifest']['being_ref']
            or observed['runtime_status'].get('local_origin') != bundle['local_origin']
            or not isinstance(observed['admission_parent'], dict)):
        raise OnboardingError('receiving_guest_bootstrap_identity_required')
    group = bootstrap_group(target, bundle)
    GuestServiceBootstrap._budget(deadline_ns)
    return dict(plan_digest=digest(target.plan), genesis_digest=digest(target.genesis),
        code_digest=target.code_digest, runtime_sha256=digest(bundle), group_sha256=digest(group),
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
        fields = {'schema', 'operation_id', 'plan_digest', 'genesis_digest', 'code_digest',
                  'runtime_sha256', 'group_sha256', 'predecessor', 'expires_at_ms'}
        if (os.geteuid() != 1000 or set(request) != fields
                or request['schema'] != 'cluster-guest-owner-bootstrap/v1'
                or str(uuid.UUID(request['operation_id'])) != request['operation_id']
                or any(not isinstance(request[key], str) or re.fullmatch('[0-9a-f]{64}', request[key]) is None
                       for key in fields - {'schema', 'operation_id', 'predecessor', 'expires_at_ms'})
                or type(request['expires_at_ms']) is not int or request['expires_at_ms'] <= 0
                or request['plan_digest'] != digest(target.plan)
                or request['genesis_digest'] != digest(target.genesis)
                or request['code_digest'] != target.code_digest
                or set(request['predecessor']) != {'process', 'admission_parent'}):
            raise OnboardingError('receiving_guest_bootstrap_request_required')
        child = validate_process(request['predecessor']['process'])
        parent = validate_process(request['predecessor']['admission_parent'])
        if (child['uid'] != 1000 or parent['uid'] != 1000 or child['pid'] == parent['pid']
                or child['boot_id'] != parent['boot_id']):
            raise OnboardingError('receiving_guest_bootstrap_request_required')
        self.target, self.request = target, request
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

    def _group(self) -> dict:
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
                    expected_origin=intent['origin'], add_methods={}, provision_receiving_controller=True,
                    expires_at_ms=self.request['expires_at_ms'], password=bytes(password), externally_quiesced=True)
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
                or receipt.get('provision_receiving_controller') is not True
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
                or set(candidate) not in ({'transaction', 'expires_at_ms', 'argv'},
                    {'transaction', 'expires_at_ms', 'argv', 'qualification'})):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        transaction = Path(candidate['transaction'])
        if (not transaction.is_absolute() or '..' in transaction.parts
                or transaction.parent != self.source.root.parent or transaction == self.source.root):
            raise OnboardingError('receiving_bootstrap_binding_conflict')
        return row, frozen, candidate

    def _qualify_candidate(self, row: dict, candidate: dict) -> dict:
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
        if source_bootstrap_group(self.source, bundle) != qualification['group']:
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

    def _writer_quiesced(self) -> None:
        from daimon_matrix.daemon import _prepare_socket
        with self.source.writer():
            # Supported stale-socket checks are safe only after exact process
            # exit and stopped-manager proof. A forced exit may leave this
            # ephemeral socket, which cannot be copied as a runtime artifact.
            _prepare_socket(self.source.root / 'matrix.sock')

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

    def quiesce(self, *, timeout_seconds: float = 30) -> dict:
        """Retain exact process exit separately from graceful delivery/drain."""
        from .onboarding_service import selection_lock
        from .owner_process import observe_process_exit
        if type(timeout_seconds) not in {int, float} or not 0 <= timeout_seconds <= 60:
            raise OnboardingError('receiving_bootstrap_invalid_wait')
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if 'qualification' in candidate:
                self._qualify_candidate(row, candidate)
            if row['state'] == 'planned':
                self.journal.advance(self.operation_id, 'runtime-dispatching')
            previous = (row['runtime_observation'] or {}).get('source_bootstrap', {}).get('quiesced')
            if previous is not None:
                self._stopped(frozen, candidate)
                if not observe_process_exit(frozen['predecessor']['process']):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                # The operation retains exit proof, but a new/foreign writer
                # still prevents another publication or selection effect.
                self._writer_quiesced()
                return previous
            stop_intent = (row['runtime_observation'] or {}).get('source_bootstrap', {}).get('stop_intent')
            if stop_intent is not None:
                if stop_intent != dict(scope=frozen['scope'], unit_sha256=frozen['service']['unit_sha256']):
                    raise OnboardingError('receiving_bootstrap_binding_conflict')
                if not observe_process_exit(frozen['predecessor']['process']):
                    from .owner_process import ProcessPresence
                    current_manager = self.manager.inspect()
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
                            try:
                                self.manager.stop()
                            except (OnboardingError, OSError):
                                if not process.wait_for_exit(0):
                                    raise
                        if not process.wait_for_exit(timeout_seconds):
                            raise OnboardingError('receiving_bootstrap_exit_unobserved')
                stopped = self._stopped(frozen, candidate)
                self._writer_quiesced()
                result = dict(process=frozen['predecessor']['process'], manager=stopped,
                    exit_observed=True, writer_available=True, graceful_delivery='unobserved')
                self._record('quiesced', result)
                return result
            with OwnerGroupClient(self.source.root, self.source.root / 'matrix.sock') as owner:
                observed = owner.base_status()
                inspected = self.manager.inspect()
                scope = self.manager.bind_process(observed['process'], inspected)
                if (observed['process'] != frozen['predecessor']['process']
                        or observed['server'] != frozen['predecessor']['server']
                        or inspected != frozen['service'] or scope != frozen['scope']):
                    raise OnboardingError('receiving_bootstrap_predecessor_changed')
                # Intent precedes stop; a lost CLI reply is not proof of failure.
                self._record('stop_intent', dict(scope=scope, unit_sha256=inspected['unit_sha256']))
                try:
                    self.manager.stop()
                except (OnboardingError, OSError):
                    if not owner.wait_for_exit(0):
                        raise
                if not owner.wait_for_exit(timeout_seconds):
                    raise OnboardingError('receiving_bootstrap_exit_unobserved')
                stopped = self._stopped(frozen, candidate)
                self._writer_quiesced()
                result = dict(process=observed['process'], manager=stopped,
                    exit_observed=True, writer_available=True, graceful_delivery='unobserved')
                self._record('quiesced', result)
                return result

    def publish(self) -> dict:
        """Recover exact capability/visibility/unit publications while stopped."""
        from daimon_matrix import operator_runtime_upgrade as upgrade
        from .onboarding_service import select_entrypoint, selection_lock
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if 'qualification' in candidate:
                self._qualify_candidate(row, candidate)
            observations = (row['runtime_observation'] or {}).get('source_bootstrap', {})
            if observations.get('quiesced', {}).get('exit_observed') is not True:
                raise OnboardingError('receiving_bootstrap_quiescence_required')
            from .owner_process import observe_process_exit
            if not observe_process_exit(frozen['predecessor']['process']):
                raise OnboardingError('receiving_bootstrap_exit_unobserved')
            self._stopped(frozen, candidate)
            self._visibility_current(frozen, observations)
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
                self._stopped(frozen, candidate)
                upgrade.stage_capabilities(source=self.source.root, transaction=transaction,
                    expected_source_sha256=intent['source_sha256'], expected_counter=intent['counter'],
                    expected_control_head=intent['control_head'], expected_being_ref=intent['being_ref'],
                    expected_origin=intent['origin'], add_methods={}, provision_receiving_controller=True,
                    expires_at_ms=candidate['expires_at_ms'], password=password, externally_quiesced=True)
            ready = onboarding_release.regular(ready_path, uid=os.geteuid())
            receipt = json.loads(ready)
            intent = (self._row()[0]['runtime_observation'] or {})['source_bootstrap']['capability_intent']
            if (receipt.get('source_sha256') != intent['source_sha256']
                    or receipt.get('origin') != intent['origin'] or receipt.get('control_head') != intent['control_head']
                    or receipt.get('provision_receiving_controller') is not True
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
            self._stopped(frozen, candidate)
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
            self._stopped(frozen, candidate)
            self._record('visibility_published', self._publish_visibility(upgrade, frozen, transaction))
            self._stopped(frozen, candidate)
            selected = select_entrypoint(self.manager.unit, candidate['argv'],
                previous_sha256=frozen['service']['unit_sha256'])
            self._record('unit_selected', selected)
            return dict(schema='cluster-source-bootstrap-publication/v1', operation_id=self.operation_id,
                        published=True, loaded_readiness='unobserved')

    def start(self, *, timeout_seconds: float = 30) -> dict:
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
        with self.journal.mutation_lock(self.operation_id), selection_lock(self.manager.unit):
            row, frozen, candidate = self._row()
            if 'qualification' not in candidate:
                raise OnboardingError('qualified_bootstrap_candidate_required')
            checked = self._qualify_candidate(row, candidate)
            observations = (row['runtime_observation'] or {}).get('source_bootstrap', {})
            selected = observations.get('unit_selected')
            if (not isinstance(selected, dict) or selected.get('selected') is not True
                    or observations.get('capability_published') is None
                    or observations.get('visibility_published') is None):
                raise OnboardingError('receiving_bootstrap_publication_required')
            # Artifact verification precedes the lifecycle budget. Local file
            # hashing/fsync scheduling is not a hard realtime guarantee; check
            # the shared monotonic deadline before dispatch and acceptance.
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
                        actual_bundle = hashlib.sha256(onboarding_release.regular(
                            self.source.root / 'runtime.json', uid=os.geteuid())).hexdigest()
                        actual_visibility = hashlib.sha256(onboarding_release.regular(
                            self.source.visibility, uid=os.geteuid())).hexdigest()
                        if (actual_bundle != observations['capability_published']['runtime_sha256']
                                or actual_visibility != observations['visibility_published']['installation_sha256']
                                or source_bootstrap_group(self.source, being_seed._read(
                                    self.source.root / 'runtime.json', limit=being_seed.MAX_SELECTION))
                                   != candidate['qualification']['group']):
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
                        group = candidate['qualification']['group']
                        if (any(startup.get(key) != value for key, value in expected.items())
                                or startup.get('process_id') != actual['process']['pid']
                                or base.get('runtime_bundle_sha256') != observations['capability_published']['runtime_sha256']
                                or actual.get('responder_association') != 'same-connection'
                                or not isinstance(gate, dict) or gate.get('controlled') is not True
                                or gate.get('process_id') != actual['process']['pid']):
                            raise OnboardingError('receiving_bootstrap_loaded_candidate_conflict')
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


class CohortController:
    """Durably fence the frozen senders before an existing selector effect.

    Uses the actual owner RPC clients and operation journal. Receiver preparation,
    authority/application adoption, process admission and positive projection
    require their own later evidence; this barrier does not report them ready.
    """

    def __init__(self, journal, operation_id: str, owners: dict[str, OwnerGroupClient]):
        self.journal = journal
        self.operation_id = operation_id
        self.owners = dict(owners)

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
                or [item.get('name') for item in senders] != sorted(self.owners)):
            raise OnboardingError('receiving_sender_vector_invalid')
        for item in senders:
            if set(item) != {'name', 'root', 'socket', 'server', 'process', 'gate'}:
                raise OnboardingError('receiving_sender_vector_invalid')
            owner = self.owners[item['name']]
            if (str(owner.root), str(owner.socket)) != (item['root'], item['socket']):
                raise OnboardingError('receiving_sender_vector_invalid')
        return row

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
                if (observed['process'] != sender['process'] or observed['server'] != sender['server']
                        or observed['gate'] != sender['gate']):
                    # A prepare-before-reply retry may already have effected the
                    # exact retained control. The owner helper resolves it; a
                    # fresh command is never rebound to this changed gate.
                    path = owner.root / 'receiving-control' / (control_id + '-revoke.json')
                    if not path.exists():
                        raise OnboardingError('receiving_sender_precondition_changed')
                gate = sender['gate']
                command = dict(process_instance_id=gate['process_instance_id'], channel_id='tribe',
                    expected_head=gate['head'], operation_id=control_id, release_digest=release,
                    phase='revoke', readers=[])
                path = owner.root / 'receiving-control' / (control_id + '-revoke.json')
                owner.prepare_control(command, path)
                result = owner.apply_control(path)
                row = self._record(row, name, result)
            return self.require_revocation_barrier()

    def require_revocation_barrier(self) -> dict:
        """A durable old ACK alone cannot authorize a current receiver effect."""
        row = self._row()
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
                capture_output=True, timeout=30, check=False, umask=0o077,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8',
                     'LD_LIBRARY_PATH': str(Path(sys.base_prefix) / 'lib')})
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
                code_uid: int = 0, manifest_uid: int = 0) -> dict:
    """Install/observe the approved offline SDK without selecting a live runtime."""
    checked = preflight(code, code_digest, manifest_path, manifest_digest,
        being_ref=being_ref, embodiment_id=embodiment_id, code_uid=code_uid, manifest_uid=manifest_uid)
    venv = onboarding_sdk.install(home, code, code_digest, code_uid=code_uid,
        matrix_commit=checked['matrix_revision'], matrix_wheel_sha256=checked['matrix_wheel_sha256'])
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
