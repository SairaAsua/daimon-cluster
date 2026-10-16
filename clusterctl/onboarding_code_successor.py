"""Qualify runtime-only code updates without rebinding a receiving seed or plan.

The original context, skills, HMK tools and provider binary remain pinned.
Ordinary successors change maintained Cluster modules only. An explicit V2
successor additionally pins the previous and qualified replacement SDK digests;
dependency generations never overwrite an existing receiving environment.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import onboarding_release
from .onboarding import OnboardingError, digest

SCHEMA = 'cluster-onboarding-runtime-successor/v1'
SDK_SCHEMA = 'cluster-onboarding-runtime-successor/v2'
TELEGRAM_SCHEMA = 'cluster-onboarding-runtime-successor/v3'
QUALIFIED_SDK_SCHEMA = 'cluster-onboarding-runtime-successor/v4'
MARKER = 'runtime-successor.json'
TRANSFER_TOOL = 'support/being-seed-tools/tools/protected_being.py'


def sdk_parameters(code: Path, *, uid: int = 0) -> dict:
    """Resolve the SDK already pinned by a verified receiving-code selection.

    Call selection/verify first. This marker is inside that approved code digest,
    not a standalone approval or a participant-supplied release manifest.
    Legacy code keeps its original fixed-pin behavior.
    """
    if not (code / MARKER).exists():
        return {}
    marker = json.loads(onboarding_release.regular(code / MARKER, uid=uid))
    if marker.get('schema') != QUALIFIED_SDK_SCHEMA:
        return {}
    if (not isinstance(marker.get('matrix_commit'), str)
            or not re.fullmatch(r'[0-9a-f]{40}', marker['matrix_commit'])
            or not isinstance(marker.get('matrix_wheel_sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', marker['matrix_wheel_sha256'])):
        raise OnboardingError('qualified_onboarding_sdk_selection_required')
    return dict(matrix_commit=marker['matrix_commit'],
                matrix_wheel_sha256=marker['matrix_wheel_sha256'])


def plan_update(journal, *, manifest_digest: str, target: str,
                expected_precondition: dict, intended_transition: dict,
                audit_identity: dict) -> dict:
    """Freeze receiving update vectors in the maintained operation journal.

    The owning controller supplies its already qualified, approved manifest and
    resolved selection vectors. This records intent only: no selection, authority
    acceptance, receiver load, egress enablement or service operation occurs.
    Apply/resume must consume the returned retained vectors under actual locks.
    """
    from .operation_journal import INTENT_SCHEMA, JournalConflict
    if (not isinstance(manifest_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', manifest_digest)
            or not isinstance(target, str) or not re.fullmatch(r'[A-Za-z0-9:._/-]{1,240}', target)
            or not isinstance(expected_precondition, dict) or not isinstance(intended_transition, dict)
            or not isinstance(audit_identity, dict)):
        raise OnboardingError('invalid_receiving_update_intent')
    operation = 'receiving-update'
    # OperationJournal hashes intent, not its separate vector arguments. Bind
    # both vectors here so an exact operation cannot acquire fresh state bytes.
    intent = dict(operation=operation, target=target, runtime_call=dict(
        manifest_digest=manifest_digest, precondition_digest=digest(expected_precondition),
        transition_digest=digest(intended_transition)))
    key = operation + ':' + target + ':' + manifest_digest
    retained = journal.latest_for_idempotency_key(key)
    if retained is None:
        try:
            retained = journal.plan(operation=operation, target=target, idempotency_key=key,
                intent=intent, expected_precondition=expected_precondition,
                intended_transition=intended_transition, audit_identity=audit_identity)
        except JournalConflict:
            # Another caller can complete this exact operation after our lookup.
            # Inspect its retained row once; the full validation below still
            # rejects different vectors and operations needing explicit repair.
            retained = journal.latest_for_idempotency_key(key)
            if retained is None:
                raise
    if (retained['operation'] != operation or retained['target'] != target
            or retained['intent'] != {'schema': INTENT_SCHEMA, **intent}
            or retained['expected_precondition'] != expected_precondition
            or retained['intended_transition'] != intended_transition):
        raise JournalConflict('receiving update is bound to different exact selection vectors')
    if retained['state'] in {'degraded', 'compensated'}:
        raise JournalConflict('receiving update requires explicit repair or a new authorized operation')
    return retained


def verify(code: Path, fingerprint: str, base: Path, base_fingerprint: str, *, uid: int) -> dict:
    original = onboarding_release.verify(base, base_fingerprint, uid=uid)
    successor = onboarding_release.verify(code, fingerprint, uid=uid)
    marker = json.loads(onboarding_release.regular(code / MARKER, uid=uid))
    ordinary = dict(schema=SCHEMA, base_release_digest=base_fingerprint)
    qualified_sdk = marker.get('schema') == QUALIFIED_SDK_SCHEMA
    telegram_change = (marker.get('schema') == TELEGRAM_SCHEMA
                      or qualified_sdk and 'telegram_digest' in marker)
    sdk_change = qualified_sdk or marker.get('schema') == SDK_SCHEMA or telegram_change and 'sdk_digest' in marker
    if sdk_change:
        from . import onboarding_sdk
        previous = onboarding_sdk.verify(base, uid=uid,
            matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
        parameters = sdk_parameters(code, uid=uid)
        if not qualified_sdk:
            # An approved V2/V3 generation pins its complete SDK manifest.
            # Reading that retained selection must not substitute today's SDK
            # default. This is public-code verification, not promotion of a
            # legacy process into qualified V4 startup or a relaxed install pin.
            value = json.loads(onboarding_release.regular(code / 'sdk/sdk.json', uid=uid))
            if not isinstance(value, dict) or digest(value) != marker.get('sdk_digest'):
                raise OnboardingError('onboarding_sdk_digest_mismatch')
            wheels = value.get('wheels')
            matrix = ([row for row in wheels if isinstance(row, dict)
                and row.get('distribution') == 'daimon-matrix'] if isinstance(wheels, list) else [])
            if (len(matrix) != 1
                    or not isinstance(value.get('matrix_commit'), str)
                    or not re.fullmatch(r'[0-9a-f]{40}', value['matrix_commit'])
                    or not isinstance(matrix[0].get('sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', matrix[0]['sha256'])):
                raise OnboardingError('invalid_onboarding_sdk')
            parameters = dict(matrix_commit=value.get('matrix_commit'),
                matrix_wheel_sha256=matrix[0].get('sha256'))
        current = onboarding_sdk.verify(code, uid=uid, **parameters)
        expected = dict(schema=SDK_SCHEMA, base_release_digest=base_fingerprint,
            previous_sdk_digest=digest(previous), sdk_digest=digest(current))
        if qualified_sdk:
            expected.update(schema=QUALIFIED_SDK_SCHEMA, **sdk_parameters(code, uid=uid))
    else:
        expected = ordinary
    if telegram_change:
        from . import onboarding_telegram
        previous_telegram = onboarding_telegram.artifact(base, uid=uid)
        current_telegram = onboarding_telegram.artifact(code, uid=uid)
        if current_telegram['commit'] not in {onboarding_telegram.COMMIT,
                onboarding_telegram.RETAINED_CURRENT_COMMIT} or previous_telegram == current_telegram:
            raise OnboardingError('qualified_telegram_successor_required')
        expected.update(schema=QUALIFIED_SDK_SCHEMA if qualified_sdk else TELEGRAM_SCHEMA,
            previous_telegram_digest=digest(previous_telegram), telegram_digest=digest(current_telegram))
    if (code.absolute() == base.absolute() or fingerprint == base_fingerprint
            or marker != expected or original['profile'] != successor['profile']):
        raise OnboardingError('compatible_onboarding_runtime_successor_required')
    before = {row['path']: row['sha256'] for row in original['files']}
    after = {row['path']: row['sha256'] for row in successor['files']}
    def module(name: str) -> bool:
        return re.fullmatch(r'clusterctl/(?:__init__|[a-z][a-z0-9_]*)\.py', name) is not None
    def sdk(name: str) -> bool:
        return sdk_change and (name in {'sdk/sdk.json', 'sdk/requirements.txt'}
            or re.fullmatch(r'sdk/wheels/[A-Za-z0-9_.+-]+\.whl', name) is not None)
    def telegram(name: str) -> bool:
        return telegram_change and name in {'telegram/telecodex', 'telegram/artifact.json'}
    def added_transfer_tool(name: str) -> bool:
        # Older public contexts predate protected transfer. Introducing its
        # runtime module must capture its pinned code helper too. Existing
        # helpers and all other context remain immutable below.
        return (name == TRANSFER_TOOL and name not in before
                and 'clusterctl/onboarding_transfer.py' in after)
    if (not {name for name in before if not sdk(name)} <= set(after)
            or any(after.get(name) != checksum for name, checksum in before.items()
                   if not module(name) and not sdk(name) and not telegram(name))
            or any(name not in before and name != MARKER and not module(name)
                   and not sdk(name) and not telegram(name) and not added_transfer_tool(name) for name in after)):
        raise OnboardingError('original_onboarding_context_preserved')
    return successor


def selected(code: Path, fingerprint: str | None, base: Path, base_fingerprint: str,
             *, uid: int = 0) -> Path:
    """Both launch paths validate their declared code before loading private state."""
    if fingerprint is None:
        if code != base:
            raise OnboardingError('qualified_onboarding_runtime_required')
        onboarding_release.verify(base, base_fingerprint, uid=uid)
    else:
        verify(code, fingerprint, base, base_fingerprint, uid=uid)
    return code


def selection(code: Path | None, fingerprint: str | None, base: Path, base_fingerprint: str,
              *, uid: int = 0) -> Path:
    if (code is None) != (fingerprint is None):
        raise OnboardingError('qualified_onboarding_runtime_required')
    return selected(base if code is None else code, fingerprint, base, base_fingerprint, uid=uid)


def build(base: Path, base_fingerprint: str, source: Path, modules: tuple[str, ...], output: Path,
          *, sdk: Path | None = None, telegram: Path | None = None,
          matrix_commit: str | None = None, matrix_wheel_sha256: str | None = None) -> dict:
    """Capture a code-only successor; never read receiving home or custody."""
    from . import being_seed
    from tools.build_onboarding_code import copy_code, capture_peer_tool, capture_chat_tool
    original = onboarding_release.verify(base, base_fingerprint, uid=os.geteuid())
    qualified_sdk = matrix_commit is not None or matrix_wheel_sha256 is not None
    if qualified_sdk and (sdk is None or matrix_commit is None
                          or matrix_wheel_sha256 is None):
        raise OnboardingError('qualified_onboarding_sdk_selection_required')
    marker = dict(schema=SCHEMA, base_release_digest=base_fingerprint)
    if sdk is not None:
        from . import onboarding_sdk
        if sdk.name != 'sdk':
            raise OnboardingError('onboarding_sdk_directory_required')
        previous = onboarding_sdk.verify(base, uid=os.geteuid(),
            matrix_commit=onboarding_sdk.PREVIOUS_MATRIX_COMMIT)
        if qualified_sdk:
            assert matrix_commit is not None and matrix_wheel_sha256 is not None
            parameters = dict(matrix_commit=matrix_commit, matrix_wheel_sha256=matrix_wheel_sha256)
        else:
            parameters = {}
        current = onboarding_sdk.verify(sdk.parent, uid=os.geteuid(), **parameters)
        marker = dict(schema=SDK_SCHEMA, base_release_digest=base_fingerprint,
            previous_sdk_digest=digest(previous), sdk_digest=digest(current))
        if qualified_sdk:
            marker.update(schema=QUALIFIED_SDK_SCHEMA, **parameters)
    if telegram is not None:
        from . import onboarding_telegram
        # Validate before creating output; no receiving home or token is read.
        previous_telegram = onboarding_telegram.artifact(base, uid=os.geteuid())
        current_telegram = onboarding_telegram.artifact_directory(telegram, uid=os.geteuid())
        if current_telegram['commit'] not in {onboarding_telegram.COMMIT,
                onboarding_telegram.RETAINED_CURRENT_COMMIT} or current_telegram == previous_telegram:
            raise OnboardingError('qualified_telegram_successor_required')
        marker.update(schema=QUALIFIED_SDK_SCHEMA if qualified_sdk else TELEGRAM_SCHEMA,
                      previous_telegram_digest=digest(previous_telegram),
                      telegram_digest=digest(current_telegram))
    being_seed._path(output)
    if (output.exists() or output.is_symlink() or output.is_relative_to(base)
            or base.is_relative_to(output)):
        raise OnboardingError('receiving_code_destination_exists')
    if (not modules or len(set(modules)) != len(modules)
            or any(re.fullmatch(r'(?:__init__|[a-z][a-z0-9_]*)\.py', name) is None for name in modules)):
        raise OnboardingError('qualified_onboarding_runtime_required')
    output.mkdir(mode=0o755)
    replaced = {'clusterctl/' + name for name in modules}
    if telegram is not None:
        replaced.update({'telegram/telecodex', 'telegram/artifact.json'})
    if 'onboarding_peer.py' in modules:
        replaced.add('clusterctl/onboarding_peer_native.py')
    if 'onboarding_owner_client.py' in modules:
        replaced.add('clusterctl/onboarding_chat_native.py')
    for row in original['files']:
        if (row['path'] not in replaced and row['path'] != MARKER
                and not (sdk is not None and row['path'].startswith('sdk/'))):
            copy_code(base / row['path'], output / row['path'])
    for name in modules:
        copy_code(source / name, output / 'clusterctl' / name)
    if 'onboarding_peer.py' in modules:
        capture_peer_tool(output)
    if 'onboarding_owner_client.py' in modules:
        capture_chat_tool(output)
    if ('onboarding_transfer.py' in modules
            and TRANSFER_TOOL not in {row['path'] for row in original['files']}):
        tools = being_seed.verified_tools()
        copy_code(tools / 'tools/protected_being.py', output / TRANSFER_TOOL)
    if sdk is not None:
        for path in sorted(sdk.rglob('*')):
            if path.is_file():
                copy_code(path, output / 'sdk' / path.relative_to(sdk))
    if telegram is not None:
        for name in ('telecodex', 'artifact.json'):
            copy_code(telegram / name, output / 'telegram' / name)
    (output / MARKER).write_text(json.dumps(marker, sort_keys=True))
    (output / MARKER).chmod(0o644)
    for directory in output.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    fingerprint = onboarding_release.seal(output, original['profile'])
    verify(output, fingerprint, base, base_fingerprint, uid=os.geteuid())
    return dict(runtime_digest=fingerprint, base_release_digest=base_fingerprint)
