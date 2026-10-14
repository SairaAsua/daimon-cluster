"""Qualified candidate preparation for the existing receiving update operation.

Inputs come from its protected approved selection, never a participant upload.
This prepares immutable SDK generations; it does not select code, stop a service,
adopt authority, open native state, or claim that a receiver has loaded it.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
import uuid
from contextlib import ExitStack
from pathlib import Path

from . import being_seed, onboarding_release, onboarding_sdk
from .onboarding import JobStore, OnboardingError, digest, private_directory


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


def apply_host_selection(journal, operation_id: str, config_path: Path) -> dict:
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
