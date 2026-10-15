"""CI selection preserves shared-change and onboarding regression coverage."""
from pathlib import Path

from tools.ci_scope import ONBOARDING_CONTRACTS, select

ROOT = Path(__file__).resolve().parents[1]


def test_owner_attachment_and_receiving_changes_compose_covered_profiles(tmp_path):
    from tools.ci_scope import (
        LOADED_STARTUP_FILES, LOADED_STARTUP_TESTS,
        OWNER_CLIENT_FILES, OWNER_CLIENT_TESTS,
    )
    host_files = {'clusterctl/onboarding_host.py', 'tests/test_onboarding_host.py'}
    changed = sorted(LOADED_STARTUP_FILES | (OWNER_CLIENT_FILES - host_files))
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert set(LOADED_STARTUP_TESTS) | set(OWNER_CLIENT_TESTS) == set(tests)
    assert len(tests) == len(set(tests))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for extra in ('requirements-weave.txt', 'clusterctl/onboarding_custody.py',
                  'unknown.py', 'support/matrix-agent-chat/other.py'):
        assert select([*changed, extra], ROOT) == ('full', ['tests'])


def test_receiving_metadata_scope_requires_exact_host_content_and_keeps_all_receiving_tests(monkeypatch):
    import subprocess
    from tools.ci_scope import LOADED_STARTUP_FILES, LOADED_STARTUP_TESTS
    name='clusterctl/onboarding_host.py'
    current=(ROOT/name).read_text()
    addition="set(value) - {'group', 'receiving_controller'} != {\"phase\", \"request\", \"receipt\"}"
    original=current.replace(addition,'set(value) != {"phase", "request", "receipt"}')
    assert original!=current
    monkeypatch.setattr('tools.ci_scope.subprocess.run',lambda *_args,**_kwargs:
        subprocess.CompletedProcess([],0,original.encode()))
    changed=sorted(LOADED_STARTUP_FILES | {'tools/ci_scope.py','tests/test_ci_scope.py',name,'tests/test_onboarding_host.py'})
    profile,tests=select(changed,ROOT,base='a'*40)
    assert profile=='peer' and set(LOADED_STARTUP_TESTS)<=set(tests)
    assert {'tests/test_onboarding_host.py','tests/test_onboarding_host_ownership.py',
            'tests/test_onboarding_managed.py'}<=set(tests)
    assert select(changed,ROOT)!=('peer',tests)
    for extra in ('requirements-weave.txt','clusterctl/onboarding_custody.py','unknown.py'):
        assert select([*changed,extra],ROOT,base='a'*40)!=('peer',tests)
    read_bytes=Path.read_bytes
    with monkeypatch.context() as newline:
        newline.setattr(Path,'read_bytes',lambda path:
            current.replace('\n','\r\n').encode() if path==ROOT/name else read_bytes(path))
        assert select(changed,ROOT,base='a'*40)!=('peer',tests)
    monkeypatch.setattr('tools.ci_scope.subprocess.run',lambda *_args,**_kwargs:
        subprocess.CompletedProcess([],0,('unrelated source change\n'+original).encode()))
    assert select(changed,ROOT,base='a'*40)!=('peer',tests)


def test_loaded_startup_covers_actual_processes_and_preserves_broader_boundaries(tmp_path):
    from tools.ci_scope import LOADED_STARTUP_FILES, LOADED_STARTUP_TESTS
    changed = sorted(LOADED_STARTUP_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(['clusterctl/onboarding_service.py', 'tests/test_source_bootstrap.py'], ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert select(['clusterctl/onboarding_target.py', 'tests/test_source_bootstrap.py',
        'tests/test_onboarding_code_successor.py'], ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert select(['clusterctl/onboarding_service.py', 'tests/test_onboarding_service.py',
        'clusterctl/owner_process.py', 'tests/test_receiving_process_observation.py'], ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert select(['clusterctl/onboarding_peer.py', 'tests/test_onboarding_peer.py',
        'tests/test_source_bootstrap.py'], ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    native_only_profile, native_only_tests = select(
        ['clusterctl/onboarding_peer.py', 'tests/test_onboarding_peer.py'], ROOT)
    assert native_only_profile == 'peer' and 'tests/test_onboarding_peer.py' in native_only_tests
    assert 'tests/test_onboarding_peer.py' in LOADED_STARTUP_TESTS
    assert select(['clusterctl/onboarding_service.py', 'tests/test_source_bootstrap.py',
        'tests/test_receiving_update_selection.py'], ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert {'tests/test_receiving_process_observation.py', 'tests/test_onboarding_sdk.py',
            'tests/test_onboarding_runtime.py', 'tests/test_onboarding_source.py',
            'tests/test_matrix_host_process.py'} <= set(LOADED_STARTUP_TESTS)
    for other in ('requirements-weave.txt', 'clusterctl/onboarding_admission.py',
                  'clusterctl/onboarding_custody.py', 'clusterctl/onboarding_host.py',
                  'clusterctl/production_fences.py', 'unknown.py'):
        assert select([*changed, other], ROOT) != ('peer', list(LOADED_STARTUP_TESTS))


def test_launcher_keeps_the_existing_home_authority_and_browser_boundary():
    from tools.ci_scope import HOME_TESTS
    changed=['clusterctl/homes/service.py','clusterctl/homes/homemaker.py',
             'clusterctl/homes/launcher.py','clusterctl/homes/launcher/index.html',
             'clusterctl/homes/launcher/launcher.css','clusterctl/homes/launcher/launcher.js',
             'tests/test_home_launcher.py','docs/design/miniapps-launcher.md',
             'tools/ci_scope.py','tests/test_ci_scope.py']
    assert select(changed,ROOT)==('homes',list(HOME_TESTS))
    assert select([*changed,'clusterctl/operation_journal.py'],ROOT)==('full',['tests'])


def test_host_selection_covers_job_fences_and_shared_journal_consumers(tmp_path):
    from tools.ci_scope import HOST_SELECTION_FILES, HOST_SELECTION_TESTS
    changed = sorted(HOST_SELECTION_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('host-selection', list(HOST_SELECTION_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for other in ('clusterctl/onboarding_sdk.py', 'clusterctl/onboarding_source.py',
                  'clusterctl/onboarding_admission.py', 'clusterctl/onboarding_runtime.py',
                  'clusterctl/onboarding_custody.py', 'clusterctl/rebirth.py',
                  'requirements-weave.txt', 'unknown.py'):
        assert select([*changed, other], ROOT)[0] != 'host-selection'


def test_receiving_preflight_keeps_sdk_startup_and_retained_successor_qualification(tmp_path):
    from tools.ci_scope import UPDATE_PREFLIGHT_FILES, UPDATE_PREFLIGHT_TESTS
    changed = sorted(UPDATE_PREFLIGHT_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('update-preflight', list(UPDATE_PREFLIGHT_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for other in ('clusterctl/onboarding_host.py', 'clusterctl/onboarding_target.py',
                  'clusterctl/onboarding_runtime.py', 'clusterctl/onboarding_custody.py',
                  'requirements-weave.txt', 'clusterctl/operation_journal.py', 'unknown.py'):
        assert select([*changed, other], ROOT)[0] != 'update-preflight'


def test_receiving_selection_keeps_actual_native_startup_and_unit_recovery(tmp_path):
    from tools.ci_scope import UPDATE_SELECTION_FILES, UPDATE_SELECTION_TESTS
    changed = sorted(UPDATE_SELECTION_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('update-selection', list(UPDATE_SELECTION_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for other in ('clusterctl/onboarding_admission.py', 'clusterctl/onboarding_custody.py',
                  'clusterctl/operation_journal.py', 'clusterctl/onboarding_enrollment.py',
                  'requirements-weave.txt', 'unknown.py'):
        assert select([*changed, other], ROOT)[0] != 'update-selection'


def test_sdk_bootstrap_keeps_exact_install_and_successor_contracts(tmp_path):
    from tools.ci_scope import SDK_BOOTSTRAP_FILES, SDK_BOOTSTRAP_TESTS
    changed = sorted(SDK_BOOTSTRAP_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('sdk-bootstrap', list(SDK_BOOTSTRAP_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for other in ('clusterctl/onboarding_custody.py', 'clusterctl/onboarding_runtime.py',
                  'clusterctl/onboarding_host.py', 'clusterctl/matrix_host.py',
                  'requirements-weave.txt', 'unknown.py'):
        assert select([*changed, other], ROOT)[0] != 'sdk-bootstrap'


def test_receiving_update_intent_keeps_durable_journal_and_successor_contracts(tmp_path):
    from tools.ci_scope import UPDATE_INTENT_FILES, UPDATE_INTENT_TESTS
    changed = sorted(UPDATE_INTENT_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('update-intent', list(UPDATE_INTENT_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for other in ('clusterctl/operation_journal.py', 'clusterctl/onboarding_host.py',
                  'clusterctl/onboarding_runtime.py', 'clusterctl/onboarding_custody.py',
                  'requirements-weave.txt', 'unknown.py'):
        assert select([*changed, other], ROOT)[0] != 'update-intent'


def test_scope_uses_only_the_verified_pr_merge_parent(monkeypatch):
    import subprocess
    from tools.ci_scope import scope_base
    old_base, current_base, head, merge = (c * 40 for c in ('a', 'b', 'c', 'd'))
    monkeypatch.setattr('tools.ci_scope.subprocess.run', lambda *a, **k:
        subprocess.CompletedProcess(a, 0, f'{merge} {current_base} {head}\n'.encode()))
    assert scope_base(ROOT, old_base, head) == current_base
    assert scope_base(ROOT, old_base, 'e' * 40) == old_base
    assert scope_base(ROOT, old_base, '') == old_base


def test_pin_only_qualification_checks_code_content(monkeypatch, tmp_path):
    import subprocess
    from tools.ci_scope import sdk_pin_only, SDK_PIN_TESTS
    originals = {
        'requirements-weave.txt': 'daimon-matrix @ git+https://github.com/AlterMundi/daimon-matrix.git@' + 'a' * 40 + '\n',
        'clusterctl/onboarding_sdk.py': 'MATRIX_COMMIT = "' + 'a' * 40 + '"\n\ndef validate():\n    return True\n',
        'clusterctl/matrix_host.py': 'MATRIX_CONTRACT_COMMIT = "' + 'a' * 40 + '"\n',
    }
    for name, text in originals.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text.replace('a' * 40, 'b' * 40))
    for name in SDK_PIN_TESTS:
        path = tmp_path / name.split('::', 1)[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    def show(argv, **kwargs):
        name = argv[2].split(':', 1)[1]
        return subprocess.CompletedProcess(argv, 0, originals[name].encode())
    monkeypatch.setattr('tools.ci_scope.subprocess.run', show)
    changed = list(originals)
    assert sdk_pin_only(tmp_path, 'a' * 40, changed)
    path = tmp_path / 'clusterctl/onboarding_sdk.py'
    path.write_text(path.read_text().replace('return True', 'return False'))
    assert not sdk_pin_only(tmp_path, 'a' * 40, changed)
    assert not sdk_pin_only(tmp_path, 'a' * 40, changed + ['clusterctl/onboarding_custody.py'])


def test_literal_sdk_successor_composes_receiving_tests_without_unrelated_full_jobs(monkeypatch, tmp_path):
    import subprocess
    import json
    from clusterctl.onboarding_sdk import MATRIX_COMMIT
    from tools.ci_scope import LOADED_STARTUP_TESTS, SDK_TESTS
    pins = {'requirements-weave.txt', 'clusterctl/onboarding_sdk.py', 'clusterctl/matrix_host.py'}
    metadata = 'support/matrix-onboarding/PROVENANCE.json'
    changes = sorted(pins | {'clusterctl/onboarding_receiving_update.py', 'clusterctl/onboarding_target.py',
        'tests/test_guest_owner_bootstrap.py', 'tests/test_guest_bootstrap_controller.py',
        'tests/test_source_bootstrap.py', 'docs/runbooks/tribu-sdk-successor.md'})
    def show(argv, **_kwargs):
        path = argv[2].split(':', 1)[1]
        assert path in pins | {metadata}
        return subprocess.CompletedProcess(argv, 0, (ROOT / path).read_bytes().replace(MATRIX_COMMIT.encode(), b'a' * 40))
    monkeypatch.setattr('tools.ci_scope.subprocess.run', show)
    profile, tests = select(changes, ROOT, base='a' * 40)
    assert profile == 'sdk' and set(tests) == set(LOADED_STARTUP_TESTS) | set(SDK_TESTS)
    assert len(tests) == len(set(tests))
    assert select([*changes, metadata], ROOT, base='a' * 40) == (profile, tests)
    def changed_tool(argv, **kwargs):
        result = show(argv, **kwargs)
        if argv[2].endswith(metadata):
            value = json.loads(result.stdout)
            value['sha256'] = 'f' * 64
            return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode())
        return result
    with monkeypatch.context() as altered:
        altered.setattr('tools.ci_scope.subprocess.run', changed_tool)
        assert select([*changes, metadata], ROOT, base='a' * 40) == ('full', ['tests'])
    for extra in ('clusterctl/onboarding_custody.py', 'unknown.py', 'constraints.txt'):
        assert select([*changes, extra], ROOT, base='a' * 40) == ('full', ['tests'])
    assert select(changes, tmp_path, base='a' * 40) == ('full', ['tests'])
    def changed_code(argv, **kwargs):
        result = show(argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, result.stdout + b'\n# executable drift\n')
    monkeypatch.setattr('tools.ci_scope.subprocess.run', changed_code)
    assert select(changes, ROOT, base='a' * 40) == ('full', ['tests'])


def test_receiving_presentation_and_readiness_keep_native_admission_without_archive_jobs(tmp_path):
    from tools.ci_scope import RECEIVING_RUNTIME_FILES, SDK_TESTS
    changed = sorted(RECEIVING_RUNTIME_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py',
        '.github/workflows/tests.yml'})
    assert select(changed, ROOT) == ('peer', list(SDK_TESTS))
    assert {'tests/test_onboarding_peer.py', 'tests/test_onboarding_runtime.py',
        'tests/test_onboarding_target.py', 'tests/test_onboarding_custody.py',
        'tests/test_onboarding_admission.py', 'tests/test_admission.py',
        'tests/test_onboarding_source.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_onboarding_sdk.py', 'tests/test_production_fences.py'} <= set(SDK_TESTS)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for path in ('requirements-weave.txt', 'clusterctl/production_fences.py',
                 'tools/export_local_matrix_identity.py', 'clusterctl/onboarding_mounts.py',
                 'clusterctl/onboarding_custody.py', 'unknown.py'):
        assert select([*changed, path], ROOT)[0] != 'peer'


def test_exact_sdk_successor_keeps_native_authority_and_receiving_generations(tmp_path):
    from tools.ci_scope import SDK_FILES, SDK_TESTS
    changed = sorted(SDK_FILES)
    assert select(changed, ROOT) == ('sdk', list(SDK_TESTS))
    assert {'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_onboarding_source.py', 'tests/test_onboarding_target.py',
        'tests/test_onboarding_peer.py', 'tests/test_onboarding_custody.py',
        'tests/test_onboarding_credential.py', 'tests/test_admission.py',
        'tests/test_production_fences.py', 'tests/test_matrix_host.py',
        'tests/test_clusterd.py'} <= set(SDK_TESTS)
    assert 'tests/test_offline_qualifier.py' not in SDK_TESTS
    assert select(changed, tmp_path) == ('full', ['tests'])
    for boundary in ('constraints.txt', 'clusterctl/production_fences.py',
                     'clusterctl/onboarding_target.py', 'requirements.txt'):
        assert select(changed + [boundary], ROOT) == ('full', ['tests'])


def test_input_cache_scope_keeps_drift_owner_context_and_worker_recovery():
    from tools.ci_scope import INPUT_CACHE_FILES, INPUT_CACHE_TESTS
    changed = sorted(INPUT_CACHE_FILES)
    assert select(changed, ROOT) == ('portal', list(INPUT_CACHE_TESTS))
    profile, tests = select(changed + ['clusterctl/onboarding_custody.py'], ROOT)
    assert profile == 'onboarding' and 'tests/test_onboarding_custody.py' in tests
    assert select(changed + ['requirements.txt'], ROOT) == ('full', ['tests'])


def test_receiving_browser_keeps_context_retry_sdk_and_owner_acceptance(tmp_path):
    from tools.ci_scope import BROWSER_FILES
    changed = sorted(BROWSER_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_browser.py', 'tests/test_being_seed.py',
        'tests/test_onboarding_guest.py', 'tests/test_onboarding_host.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_onboarding_sdk.py',
        'tests/test_onboarding.py', 'tests/test_onboarding_host_ownership.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/production_fences.py',
                   'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_public_identity_export_and_reuse_keep_native_and_private_owner_contracts(tmp_path):
    from tools.ci_scope import IDENTITY_EXPORT_FILES
    changed = sorted(IDENTITY_EXPORT_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_local_body.py', 'tests/test_onboarding_existing.py',
        'tests/test_onboarding_peer.py', 'tests/test_onboarding_target.py',
        'tests/test_auth.py', 'tests/test_clusterd.py', 'tests/test_human_approvals.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_enrollment_root.py'], ROOT)[0] != 'portal'


def test_context_copy_keeps_receiving_crash_retry_sdk_and_job_owner_contracts(tmp_path):
    from tools.ci_scope import CONTEXT_COPY_FILES
    changed = sorted(CONTEXT_COPY_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_guest.py', 'tests/test_onboarding_input.py',
        'tests/test_onboarding_sdk.py', 'tests/test_onboarding_worker_install.py',
        'tests/test_onboarding_host_ownership.py', 'tests/test_onboarding_consent.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/production_fences.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_custody.py'], ROOT)[0] == 'onboarding'


def test_participant_continuation_keeps_native_signing_receiving_and_owner_boundaries(tmp_path):
    from tools.ci_scope import CONTINUATION_FILES
    changed = sorted(CONTINUATION_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_continuation.py', 'tests/test_onboarding_existing.py',
        'tests/test_onboarding_intake.py', 'tests/test_being_seed.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/onboarding_enrollment_root.py',
                   'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_existing_root_enrollment_keeps_native_authority_custody_and_admission(tmp_path):
    from tools.ci_scope import ENROLLMENT_FILES
    changed = sorted(ENROLLMENT_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'onboarding'
    assert {'tests/test_onboarding_existing.py',
        'tests/test_onboarding_managed.py',
        'tests/test_admission.py', 'tests/test_production_fences.py',
        'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_local_body.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert any('test_receiving_credential_upgrade' in path for path in tests)
    assert any('test_existing_identity_and_wrong_or_missing_grant' in path for path in tests)
    assert any('test_response_cannot_change_history' in path for path in tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/matrix_host.py', 'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_hosted_witness_keeps_native_prerequisite_job_retry_and_owner_http_scope(tmp_path):
    changed = ['clusterctl/onboarding_acceptance.py', 'clusterctl/onboarding_host.py',
        'clusterctl/onboarding.py', 'clusterctl/cli.py', 'clusterd/routes.py',
        'clusterd/seed_handlers.py', 'clusterd/handlers.py', 'clusterd/seed_ui.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_being_seed.py', 'tools/check_rc_types.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding.py', 'tests/test_onboarding_acceptance.py',
        'tests/test_onboarding_worker_install.py', 'tests/test_onboarding_progress.py',
        'tests/test_onboarding_owner_client.py', 'tests/test_auth.py',
        'tests/test_clusterd.py', 'tests/test_human_approvals.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_new_seed_keeps_native_memory_context_custody_job_and_http_boundaries(tmp_path):
    from tools.ci_scope import NEW_SEED_FILES
    changed = sorted(NEW_SEED_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_new.py', 'tests/test_onboarding_guest.py',
        'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_onboarding_custody.py', 'tests/test_onboarding_intake.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_custody.py'], ROOT)[0] != 'portal'


def test_protected_transfer_keeps_auth_actual_crypto_receiving_and_host_retry_scope(tmp_path):
    from tools.ci_scope import TRANSFER_FILES
    changed = sorted(TRANSFER_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_transfer.py', 'tests/test_being_seed.py',
        'tests/test_onboarding_input.py', 'tests/test_onboarding_intake.py',
        'tests/test_onboarding_release.py', 'tests/test_onboarding_guest.py',
        'tests/test_auth.py', 'tests/test_clusterd.py',
        'tests/test_onboarding_owner_client.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_owner_client_keeps_native_authority_and_context_without_unchanged_sdk_rebuild(tmp_path):
    changed = ['clusterctl/onboarding_owner_client.py', 'clusterctl/onboarding_host.py',
               'tests/test_onboarding_owner_client.py', 'tools/check_rc_types.py', 'tools/ci_scope.py',
               'support/matrix-agent-chat/install_agent_chat.py',
               'support/matrix-agent-chat/PROVENANCE.json']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_target.py',
            'tests/test_onboarding_runtime.py', 'tests/test_onboarding_sdk.py',
            'tests/test_onboarding_welcome.py', 'tests/test_onboarding_host_ownership.py',
            'tests/test_onboarding_peer.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT)[0] == 'full'


def test_portable_exporter_pin_keeps_http_context_and_original_archives(tmp_path):
    changed = ['support/being-seed-tools/tools/export_being.py',
               'support/being-seed-tools/PROVENANCE.json', 'clusterctl/being_seed.py',
               'clusterd/seed_ui.py', 'tests/test_being_seed.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_being_seed.py', 'tests/test_onboarding_input.py',
            'tests/test_onboarding_release.py', 'tests/test_onboarding_guest.py',
            'tests/test_auth.py', 'tests/test_onboarding_consent.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['support/being-seed-tools/tools/receive_being.py'], ROOT) == ('full', ['tests'])


def test_welcome_keeps_owner_retry_and_telegram_contracts_without_dependency_rehearsals(tmp_path):
    changed = ['clusterctl/onboarding_welcome.py', 'clusterctl/onboarding_host.py',
               'tests/test_onboarding_welcome.py', 'tools/check_rc_types.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'welcome'
    assert {'tests/test_onboarding.py', 'tests/test_onboarding_telegram.py',
            'tests/test_onboarding_consent.py', 'tests/test_onboarding_host_ownership.py',
            'tests/test_onboarding_guest.py', 'tests/test_onboarding_code_successor.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_provider.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_onboarding_keeps_all_journey_tests_and_existing_authority_contracts():
    profile, tests = select(['clusterctl/onboarding_accounts.py',
                            'tests/test_onboarding_shared_login.py'], ROOT)
    assert profile == 'onboarding'
    assert set(ONBOARDING_CONTRACTS) <= set(tests)
    assert {p.relative_to(ROOT).as_posix() for p in (ROOT / 'tests').glob('test_onboarding*.py')} <= set(tests)
    assert 'tests/test_offline_qualifier.py' not in tests
    assert 'tests/test_rc_manifest.py' not in tests


def test_shared_unknown_deleted_coverage_and_unavailable_diff_require_full(tmp_path):
    for changed in [[], ['clusterctl/production_fences.py'], ['requirements-weave.txt'],
                    ['new-component.py'], ['tests/test_offline_qualifier.py']]:
        assert select(changed, ROOT) == ('full', ['tests'])
    assert select(['clusterctl/onboarding_accounts.py'], tmp_path) == ('full', ['tests'])


def test_workflow_only_changes_test_workflow_without_repeating_runtime_rehearsals():
    profile, tests = select(['.github/workflows/tests.yml', 'README.md', 'tools/ci_scope.py'], ROOT)
    assert profile == 'ci'
    assert set(tests) == {'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}


def test_approval_reconciliation_covers_receiving_and_host_without_native_rehearsals():
    profile, tests = select(['clusterctl/onboarding_approvals.py',
        'tests/test_onboarding_approvals.py', 'tools/ci_scope.py', '.github/workflows/tests.yml'], ROOT)
    assert profile == 'approval'
    assert set(tests) == {'tests/test_onboarding_approvals.py', 'tests/test_onboarding_consent.py',
        'tests/test_onboarding_intake.py', 'tests/test_onboarding_host.py',
        'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}
    assert select(['clusterctl/onboarding_approvals.py', 'clusterctl/onboarding_custody.py'], ROOT)[0] == 'onboarding'


def test_local_portal_covers_shared_http_auth_without_repeating_body_lifecycle(tmp_path):
    changed = ['clusterctl/onboarding_local_body.py', 'clusterd/server.py',
               'clusterd/handlers.py', 'clusterd/routes.py', 'tests/test_onboarding_local_body.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_auth.py', 'tests/test_clusterd.py', 'tests/test_human_approvals.py',
            'tests/test_being_seed.py', 'tests/test_onboarding_local_body.py'} <= set(tests)
    assert 'tests/test_onboarding_runtime.py' not in tests
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/admission.py'], ROOT) == ('full', ['tests'])
    assert select(['clusterd/server.py'], ROOT) == ('full', ['tests'])


def test_peer_host_keeps_signed_services_and_owner_separation_without_snapshot_rehearsals():
    changed = ['clusterctl/onboarding_peer_host.py', 'tests/test_onboarding_peer_host.py', 'tools/ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_source.py',
            'tests/test_onboarding_managed.py', 'tests/test_onboarding_host_ownership.py'} <= set(tests)
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['clusterctl/admission.py'], ROOT)[0] == 'full'


def test_native_peer_tool_keeps_crypto_export_and_context_checks_without_sdk_recovery_repeat(tmp_path):
    changed = ['clusterctl/onboarding_peer.py', 'clusterctl/onboarding_peer_native.py',
        'tools/export_local_matrix_identity.py', 'support/matrix-onboarding/PROVENANCE.json',
        'tests/test_onboarding_source.py', 'docs/design/onboarding-jobs.md']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_source.py', 'tests/test_onboarding_managed.py',
            'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_peer.py',
            'tests/test_onboarding_local_body.py', 'tests/test_onboarding_code_successor.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT) == ('full', ['tests'])


def test_account_mount_permissions_keep_shared_login_and_owner_isolation(tmp_path):
    changed = ['clusterctl/onboarding_accounts.py', 'tests/test_onboarding_accounts.py', 'tools/ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'account'
    assert {'tests/test_onboarding_shared_login.py', 'tests/test_onboarding_provider.py',
            'tests/test_onboarding_consent.py', 'tests/test_onboarding_ingress.py',
            'tests/test_onboarding_host_ownership.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_provider.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_intake_only_changes_keep_stream_crypto_and_owner_boundaries(tmp_path):
    changed = ['clusterctl/being_seed.py', 'clusterd/seed_ui.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_transfer.py', 'tests/test_being_seed.py',
            'tests/test_onboarding_intake.py', 'tests/test_onboarding_input.py',
            'tests/test_onboarding_release.py', 'tests/test_auth.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/matrix_host.py'], ROOT) == ('full', ['tests'])


def test_resumable_upload_keeps_http_auth_and_integrity_without_runtime_recovery(tmp_path):
    from tools.ci_scope import UPLOAD_FILES
    changed = sorted(UPLOAD_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_being_seed.py', 'tests/test_clusterd.py', 'tests/test_auth.py',
            'tests/test_onboarding_transfer.py', 'tests/test_onboarding_intake.py'} <= set(tests)
    assert 'tests/test_onboarding_existing.py' not in tests
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT) == ('full', ['tests'])


def test_telegram_upgrade_covers_native_binding_idle_database_and_receiving_mounts(tmp_path):
    from tools.ci_scope import TELEGRAM_FILES
    changed = sorted(TELEGRAM_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_telegram.py', 'tests/test_onboarding_code_successor.py',
            'tests/test_onboarding_host.py', 'tests/test_onboarding_intake.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_closed_runbook_docs_skip_runtime_jobs_but_mixed_changes_keep_coverage():
    docs = ['docs/runbooks/tribu-sdk-successor.md']
    assert select(docs, ROOT) == ('docs', [])
    assert select(docs + ['tools/ci_scope.py'], ROOT)[0] == 'ci'
    for boundary in ('clusterctl/onboarding_runtime.py', 'configs/nftables.conf',
                     'requirements-weave.txt', 'unknown.md'):
        assert select(docs + [boundary], ROOT)[0] == 'full'
    workflow = (ROOT / '.github/workflows/tests.yml').read_text()
    test_job = workflow.split('  test:\n', 1)[1].split('    steps:', 1)[0]
    assert "if: needs.scope.outputs.profile != 'docs'" in test_job


def test_membership_group_successor_keeps_receiving_contracts_without_physical_jobs(tmp_path):
    from tools.ci_scope import GROUP_FILES, GROUP_TESTS
    changed = sorted(GROUP_FILES)
    assert select(changed, ROOT) == ('sdk', list(GROUP_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for boundary in ('clusterctl/production_fences.py', 'constraints.txt', 'unknown.py'):
        assert select(changed + [boundary], ROOT) == ('full', ['tests'])


def test_homes_keep_read_auth_contracts_and_shared_changes_keep_full(tmp_path):
    from tools.ci_scope import HOME_FILES, HOME_TESTS
    assert select(sorted(HOME_FILES),ROOT)==('homes',list(HOME_TESTS))
    assert select(sorted(HOME_FILES)+['requirements-weave.txt'],ROOT)==('full',['tests'])
    assert select(sorted(HOME_FILES)+['clusterd/auth.py'],ROOT)==('full',['tests'])
    assert select(sorted(HOME_FILES)+['clusterctl/homes/unknown.py'],ROOT)==('full',['tests'])
    assert select(sorted(HOME_FILES),tmp_path)==('full',['tests'])


def test_home_worker_composition_keeps_qualification_and_mount_boundaries(tmp_path):
    from tools.ci_scope import HOME_WORKER_FILES, HOME_WORKER_TESTS
    changed = sorted(HOME_WORKER_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py'})
    assert select(changed, ROOT) == ('homes', list(HOME_WORKER_TESTS))
    assert select(changed, tmp_path) == ('full', ['tests'])
    for name in ('clusterctl/onboarding_sdk.py', 'clusterctl/onboarding_telegram.py',
                 'requirements-weave.txt', 'clusterctl/onboarding_target.py'):
        assert select(changed + [name], ROOT) == ('full', ['tests'])


def test_native_observation_keeps_actual_signed_presence_and_owner_contracts(tmp_path):
    changed = ['clusterctl/onboarding_target.py', 'tests/test_onboarding_owner_client.py',
               'tools/ci_scope.py', 'tests/test_ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_target.py', 'tests/test_onboarding_managed.py',
            'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_code_successor.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_sdk.py'], ROOT)[0] != 'portal'


def test_shared_style_consumer_guide_alone_skips_runtime_but_code_keeps_home_contracts():
    guide = 'docs/design/shared-home-styles.md'
    assert select([guide], ROOT) == ('docs', [])
    profile, tests = select([guide, 'clusterctl/homes/assets/home-style.js'], ROOT)
    assert profile == 'homes' and 'tests/test_home_styles.py' in tests
    assert select([guide, 'clusterctl/production_fences.py'], ROOT) == ('full', ['tests'])


def test_context_pages_stay_documentation_without_executable_changes():
    from tools.ci_scope import RUNBOOK_DOCS
    assert select(sorted(RUNBOOK_DOCS), ROOT) == ('docs', [])
    assert select([*sorted(RUNBOOK_DOCS), 'clusterctl/onboarding_host.py'], ROOT)[0] != 'docs'
    assert select([*sorted(RUNBOOK_DOCS), 'unknown-contract.json'], ROOT)[0] == 'full'


def test_exact_candidate_host_scope_covers_legacy_peer_and_rejects_other_bytes(monkeypatch):
    import subprocess
    from types import SimpleNamespace
    from tools import ci_scope
    name = 'clusterctl/onboarding_host.py'
    # The scope job reads the actual base; the unit test job has a shallow
    # checkout. Model the retained qualified hash pair as stable inputs; a
    # legitimate new host implementation must not require a golden-hash edit
    # merely to pass this selector-policy test. Unknown bytes still select full.
    original = b'explicit retained baseline fixture\n'
    candidate = b'explicit retained qualified candidate fixture\n'
    sha256 = ci_scope.hashlib.sha256
    monkeypatch.setattr(ci_scope.hashlib, 'sha256', lambda raw:
        SimpleNamespace(hexdigest=lambda: '742fb3e396d4619369152cde4c3811c22df18504e504d7012e99c99772040c59')
        if raw == original else SimpleNamespace(hexdigest=lambda: '0ec24cc2096f5b88b498d1e49578810404c2248b0a8309d027c30d28d5f2daee')
        if raw == candidate else sha256(raw))
    monkeypatch.setattr(ci_scope.subprocess, 'run', lambda *_args, **_kwargs:
        subprocess.CompletedProcess([], 0, original))
    actual_read = Path.read_bytes
    monkeypatch.setattr(Path, 'read_bytes', lambda path: candidate if path == ROOT / name else actual_read(path))
    changed = sorted(ci_scope.LOADED_STARTUP_FILES | {'tools/ci_scope.py', 'tests/test_ci_scope.py',
        name, 'tests/test_onboarding_host.py'})
    selected, tests = ci_scope.select(changed, ROOT, base='a' * 40)
    assert selected == 'peer' and 'tests/test_onboarding_peer_host.py' in tests
    read = Path.read_bytes
    for change in (lambda raw: raw + b'# future host change\n', lambda raw: raw.replace(b'\n', b'\r\n')):
        with monkeypatch.context() as patch:
            patch.setattr(Path, 'read_bytes', lambda path: change(read(path)) if path == ROOT / name else read(path))
            assert ci_scope.select(changed, ROOT, base='a' * 40)[0] != 'peer'
    for extra in ('requirements-dev.txt', 'clusterctl/onboarding_custody.py', 'unknown.py'):
        assert ci_scope.select(changed + [extra], ROOT, base='a' * 40)[0] != 'peer'
    monkeypatch.setattr(ci_scope.subprocess, 'run', lambda *_args, **_kwargs:
        subprocess.CompletedProcess([], 0, original + b'# different baseline\n'))
    assert ci_scope.select(changed, ROOT, base='a' * 40)[0] != 'peer'


def test_controlled_software_update_and_its_runbook_keep_receiving_coverage():
    from tools.ci_scope import LOADED_STARTUP_TESTS
    changed = ['clusterctl/onboarding_receiving_update.py', 'tests/test_source_bootstrap.py',
        'tests/test_guest_owner_bootstrap.py', 'tests/test_guest_bootstrap_controller.py',
        'tests/test_receiving_cohort_control.py', 'docs/runbooks/tribu-sdk-successor.md',
        'clusterctl/onboarding_peer.py', 'clusterctl/onboarding_source.py',
        'clusterctl/onboarding_runtime.py', 'tests/test_onboarding_group_authorities.py',
        'docs/design/onboarding-jobs.md', 'tools/ci_scope.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py', '.github/workflows/tests.yml']
    assert select(changed, ROOT) == ('peer', list(LOADED_STARTUP_TESTS))
    assert 'tests/test_onboarding_group_authorities.py' in LOADED_STARTUP_TESTS
    assert select([*changed, 'clusterctl/onboarding_custody.py'], ROOT)[0] == 'full'
    assert select([*changed, 'docs/unclassified-contract.md'], ROOT)[0] == 'full'


def test_native_tooling_capture_composes_owner_sdk_and_receiving_coverage():
    changed = ['clusterctl/onboarding_owner_client.py', 'clusterctl/onboarding_chat_native.py',
        'clusterctl/onboarding_code_successor.py', 'tools/build_onboarding_code.py',
        'support/matrix-agent-chat/TOOLING-PROVENANCE.json',
        'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_source_bootstrap.py', 'tools/ci_scope.py', 'tests/test_ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_sdk.py',
        'tests/test_onboarding_code_successor.py', 'tests/test_onboarding_release.py',
        'tests/test_source_bootstrap.py'} <= set(tests)
    assert select([*changed, 'clusterctl/onboarding_custody.py'], ROOT)[0] == 'full'


def test_reviewed_receiving_helpers_keep_scope_exact_and_qualify_default_callers(monkeypatch):
    import hashlib
    import subprocess
    from tools import ci_scope
    names = set(ci_scope.RECEIVING_SUPPORT_HASHES)
    # Exercise the retained-pair policy with stable fixture bytes. Legitimate
    # current source changes must not require updating a production allowlist
    # merely to keep this policy test green. Unknown bytes still select full.
    originals = {name:('retained baseline: '+name).encode() for name in names}
    candidates = {name:('retained qualified candidate: '+name).encode() for name in names}
    monkeypatch.setattr(ci_scope, 'RECEIVING_SUPPORT_HASHES', {
        name:(hashlib.sha256(originals[name]).hexdigest(),
              hashlib.sha256(candidates[name]).hexdigest()) for name in names})
    actual_read = Path.read_bytes
    monkeypatch.setattr(Path, 'read_bytes', lambda path:
        candidates[path.relative_to(ROOT).as_posix()] if path.is_relative_to(ROOT)
        and path.relative_to(ROOT).as_posix() in candidates else actual_read(path))
    def source(argv, **_kwargs):
        name = argv[-1].split(':',1)[1]
        return subprocess.CompletedProcess(argv,0,originals[name])
    monkeypatch.setattr(ci_scope.subprocess,'run',source)
    changed = sorted(ci_scope.LOADED_STARTUP_FILES | names | ci_scope.CI_FILES)
    profile, tests = ci_scope.select(changed, ROOT, base='a'*40)
    assert profile == 'peer'
    assert set(ci_scope.LOADED_STARTUP_TESTS) <= set(tests)
    assert 'tests/test_being_seed.py' in tests
    assert ci_scope.select(changed, ROOT) != ('peer', tests)
    for unrelated in ('clusterctl/onboarding_custody.py', 'requirements-weave.txt', 'unknown.py'):
        assert ci_scope.select([*changed, unrelated], ROOT, base='a'*40) != ('peer', tests)
    read_bytes = Path.read_bytes
    for name in names:
        with monkeypatch.context() as changed_byte:
            changed_byte.setattr(Path,'read_bytes', lambda path:
                read_bytes(path)+b'\n' if path == ROOT/name else read_bytes(path))
            assert ci_scope.select(changed, ROOT, base='a'*40) != ('peer', tests)
    monkeypatch.setattr(ci_scope.subprocess,'run',lambda argv, **_kwargs:
        subprocess.CompletedProcess(argv,0,originals[argv[-1].split(':',1)[1]]+b'\n'))
    assert ci_scope.select(changed, ROOT, base='a'*40) != ('peer', tests)
