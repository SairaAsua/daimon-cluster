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

    def status(self) -> dict:
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
        gate = status.get('receiving', {}).get('channels', {}).get('tribe')
        if (not isinstance(gate, dict) or gate.get('controlled') is not True
                or gate.get('process_id') != process['pid']):
            raise OnboardingError('receiving_group_control_required')
        return dict(schema='cluster-receiving-owner-observation/v1', process=process,
            server=response['server'], runtime_status=status, gate=gate,
            receiving_readiness='unobserved')

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
        identity = (observed['server']['being_ref'], observed['server']['embodiment_id'])
        if identity in identities:
            raise OnboardingError('receiving_sender_vector_invalid')
        identities.add(identity)
        senders.append(dict(name=name, root=str(owner.root), socket=str(owner.socket),
            server=observed['server'], process=observed['process'], gate=observed['gate']))
    if not 1 <= len(senders) <= 256:
        raise OnboardingError('receiving_sender_vector_invalid')
    return senders


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
