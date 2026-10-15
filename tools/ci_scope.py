"""Select maintained CI coverage for known change boundaries.

Unknown or shared changes retain the full suite. Onboarding changes keep their
complete journey tests and the existing authority, registry, API and access
contracts. Workflow-only changes exercise the workflow and selector themselves.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

CI_FILES = {'.github/workflows/tests.yml', 'README.md', 'tools/ci_scope.py', 'tools/ci_guest_owner.py',
            'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}
# Closed documentation pages with no generated/runtime consumer. Unknown docs stay full.
RUNBOOK_DOCS = {'docs/runbooks/tribu-sdk-successor.md', 'docs/design/shared-home-styles.md',
    'README.md', 'RESUME.md', 'docs/PLAN.md', 'docs/design/matrix-convergence.md',
    'docs/design/onboarding-jobs.md', 'docs/design/provisioning-flow.md',
    'docs/design/tribe-agent-profile-and-volumes.md', 'docs/runbooks/host-restart-drill.md',
    'docs/runbooks/image-update-rolling-refresh.md', 'docs/runbooks/m1-incus-foundation.md',
    'docs/runbooks/release-candidate-freeze.md'}
CONTEXT_COPY_FILES = {'clusterctl/onboarding_guest.py', 'clusterctl/onboarding_host.py',
                      'tests/test_onboarding_guest.py', 'tests/test_onboarding_host.py'}
CONTEXT_COPY_TESTS = ('tests/test_onboarding_guest.py', 'tests/test_onboarding_host.py',
    'tests/test_onboarding_input.py', 'tests/test_onboarding_release.py', 'tests/test_onboarding_sdk.py',
    'tests/test_onboarding.py', 'tests/test_onboarding_worker_install.py', 'tests/test_onboarding_progress.py',
    'tests/test_onboarding_host_ownership.py', 'tests/test_onboarding_consent.py',
    'tests/test_onboarding_intake.py', 'tests/test_auth.py', 'tests/test_clusterd.py',
    'tests/test_production_fences.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
UPLOAD_FILES = {'clusterctl/being_seed.py', 'clusterd/seed_handlers.py',
    'clusterd/seed_ui.py', 'clusterd/routes.py', 'clusterd/server.py',
    'clusterd/handlers.py', 'clusterd/openapi.py', 'tests/test_being_seed.py',
    'tools/resume_seed_upload.py', 'clusterctl/cli.py', 'clusterctl/onboarding_intake.py',
    'clusterctl/onboarding_local_body.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding_local_body.py'}
UPLOAD_TESTS = ('tests/test_being_seed.py', 'tests/test_onboarding_transfer.py',
    'tests/test_onboarding_input.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding_local_body.py', 'tests/test_clusterd.py',
    'tests/test_auth.py', 'tests/test_human_approvals.py',
    'tests/test_onboarding_release.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
TELEGRAM_FILES = {'clusterctl/onboarding.py', 'clusterctl/onboarding_telegram.py',
    'clusterctl/onboarding_code_successor.py', 'clusterctl/onboarding_host.py',
    'tests/test_onboarding_code_successor.py', 'tests/test_onboarding_telegram.py'}
TELEGRAM_TESTS = ('tests/test_onboarding_telegram.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding.py', 'tests/test_onboarding_host.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding_guest.py', 'tests/test_onboarding_release.py',
    'tests/test_onboarding_consent.py', 'tests/test_onboarding_host_ownership.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
ONBOARDING_FILES = {'clusterctl/being_seed.py', 'clusterctl/onboarding.py',
    'clusterd/seed_handlers.py', 'clusterd/seed_ui.py', 'scripts/being-seed',
    'tools/build_onboarding_code.py', 'tools/build_onboarding_sdk.py',
    'tools/configure_onboarding_account.py', 'tools/install_onboarding_worker.py',
    'tools/check_rc_types.py', 'docs/design/onboarding-jobs.md', 'tests/test_being_seed.py',
    'clusterctl/onboarding_peer_native.py', 'support/matrix-onboarding/PROVENANCE.json'}
ONBOARDING_CONTRACTS = ('tests/test_being_seed.py', 'tests/test_admission.py',
    'tests/test_production_fences.py', 'tests/test_embodiments.py',
    'tests/test_matrix_host.py', 'tests/test_matrix_host_process.py',
    'tests/test_matrix_v8_snapshot.py', 'tests/test_matrix_status.py',
    'tests/test_matrix_parity.py', 'tests/test_effect_truth.py',
    'tests/test_honest_read_models.py', 'tests/test_auth.py', 'tests/test_clusterd.py',
    'tests/test_operational_assets.py', 'tests/test_ci_workflow.py', 'tests/test_ci_scope.py')
APPROVAL_FILES = {'clusterctl/onboarding_approvals.py', 'tests/test_onboarding_approvals.py'}
APPROVAL_TESTS = ('tests/test_onboarding_approvals.py', 'tests/test_onboarding_consent.py',
    'tests/test_onboarding_intake.py', 'tests/test_onboarding_host.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
PORTAL_FILES = {'clusterctl/onboarding_local_body.py', 'tools/export_local_matrix_identity.py',
    'tools/expose_native_peer.py',
    'clusterd/seed_handlers.py', 'clusterd/seed_ui.py', 'clusterd/handlers.py',
    'clusterd/routes.py', 'clusterd/server.py', 'tests/test_being_seed.py',
    'tests/test_onboarding_local_body.py', 'tools/check_rc_types.py'}
PORTAL_TESTS = ('tests/test_onboarding_local_body.py', 'tests/test_being_seed.py',
    'tests/test_clusterd.py', 'tests/test_auth.py', 'tests/test_human_approvals.py',
    'tests/test_onboarding_consent.py', 'tests/test_onboarding_actions.py',
    'tests/test_onboarding_ingress.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
IDENTITY_EXPORT_FILES = {'tools/export_local_matrix_identity.py', 'clusterctl/onboarding_local_body.py',
    'clusterd/seed_handlers.py', 'clusterd/seed_ui.py', 'tests/test_onboarding_local_body.py',
    'tests/test_onboarding_existing.py'}
IDENTITY_EXPORT_TESTS = tuple(sorted(set(PORTAL_TESTS) | {
    'tests/test_onboarding_existing.py', 'tests/test_onboarding_peer.py',
    'tests/test_onboarding_target.py'}))
CONTINUATION_FILES = PORTAL_FILES | UPLOAD_FILES | {
    'tools/continue_seed_onboarding.py', 'tests/test_onboarding_continuation.py',
    'tests/test_onboarding_existing.py'}
CONTINUATION_TESTS = tuple(sorted(set(PORTAL_TESTS) | set(UPLOAD_TESTS) | {
    'tests/test_onboarding_continuation.py', 'tests/test_onboarding_existing.py'}))
EXPORT_FILES = {'clusterctl/being_seed.py', 'clusterd/seed_ui.py',
    'support/being-seed-tools/PROVENANCE.json', 'support/being-seed-tools/tools/export_being.py',
    'tests/test_being_seed.py'}
EXPORT_TESTS = (*PORTAL_TESTS, 'tests/test_onboarding_input.py',
                'tests/test_onboarding_release.py', 'tests/test_onboarding_guest.py')
ACCOUNT_FILES = {'clusterctl/onboarding_accounts.py', 'tests/test_onboarding_accounts.py'}
ACCOUNT_TESTS = ('tests/test_onboarding_accounts.py', 'tests/test_onboarding_shared_login.py',
    'tests/test_onboarding_provider.py', 'tests/test_onboarding_ingress.py',
    'tests/test_onboarding_consent.py', 'tests/test_onboarding_actions.py',
    'tests/test_onboarding_host_ownership.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
WELCOME_FILES = {'clusterctl/onboarding_welcome.py', 'clusterctl/onboarding_host.py',
                 'tests/test_onboarding_welcome.py', 'tools/check_rc_types.py'}
WELCOME_TESTS = ('tests/test_onboarding_welcome.py', 'tests/test_onboarding.py',
    'tests/test_onboarding_host.py', 'tests/test_onboarding_telegram.py',
    'tests/test_onboarding_consent.py', 'tests/test_onboarding_approvals.py',
    'tests/test_onboarding_intake.py', 'tests/test_onboarding_host_ownership.py',
    'tests/test_onboarding_guest.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
PEER_FILES = {'clusterctl/onboarding_peer_host.py', 'tests/test_onboarding_peer_host.py',
              'tests/test_onboarding_managed.py'}
PEER_TESTS = ('tests/test_onboarding_peer_host.py', 'tests/test_onboarding_source.py',
    'tests/test_onboarding_managed.py', 'tests/test_onboarding_host_ownership.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
PEER_TOOL_FILES = {'clusterctl/onboarding_peer.py', 'clusterctl/onboarding_peer_native.py',
    'clusterctl/onboarding_source.py',
    'support/matrix-onboarding/PROVENANCE.json', 'tools/export_local_matrix_identity.py',
    'tests/test_onboarding_source.py', 'docs/design/onboarding-jobs.md'}
PEER_TOOL_TESTS = (*PEER_TESTS, 'tests/test_onboarding_peer.py',
    'tests/test_onboarding_local_body.py', 'tests/test_onboarding_code_successor.py')
OWNER_CLIENT_FILES = {'clusterctl/onboarding_owner_client.py', 'clusterctl/onboarding_host.py',
                      'clusterctl/onboarding_chat_native.py', 'tools/build_onboarding_code.py',
                      'support/matrix-agent-chat/TOOLING-PROVENANCE.json',
                      'tests/test_onboarding_owner_client.py', 'tools/check_rc_types.py',
                      'support/matrix-agent-chat/install_agent_chat.py', 'support/matrix-agent-chat/PROVENANCE.json'}
OWNER_CLIENT_TESTS = (*WELCOME_TESTS, *PEER_TESTS, 'tests/test_onboarding_owner_client.py',
                      'tests/test_onboarding_release.py',
                      'tests/test_onboarding_target.py', 'tests/test_onboarding_runtime.py',
                      'tests/test_onboarding_sdk.py', 'tests/test_onboarding_peer.py')
HOSTED_CHECK_FILES = PORTAL_FILES | {'clusterctl/onboarding_acceptance.py',
    'clusterctl/onboarding.py', 'clusterctl/onboarding_host.py', 'clusterctl/cli.py',
    'tests/test_onboarding_acceptance.py', 'tests/test_being_seed.py'}
HOSTED_CHECK_TESTS = (*PORTAL_TESTS, 'tests/test_onboarding_acceptance.py',
    'tests/test_onboarding.py', 'tests/test_onboarding_host.py',
    'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_worker_install.py',
    'tests/test_onboarding_progress.py', 'tests/test_onboarding_host_ownership.py')
NEW_SEED_FILES = CONTEXT_COPY_FILES | {'clusterctl/onboarding_input.py',
    'clusterctl/onboarding_intake.py', 'clusterctl/onboarding_acceptance.py',
    'tests/test_onboarding_new.py', 'tests/test_onboarding_input.py',
    'tests/test_onboarding_intake.py', 'tests/test_onboarding_acceptance.py'}
NEW_SEED_TESTS = tuple(sorted(set(CONTEXT_COPY_TESTS) | set(HOSTED_CHECK_TESTS) | {
    'tests/test_onboarding_new.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding_custody.py', 'tests/test_onboarding_approvals.py'}))
BROWSER_FILES = {'clusterctl/browser.py', 'clusterctl/onboarding_browser.py',
    'clusterctl/onboarding_host.py', 'clusterctl/onboarding.py',
    'clusterctl/onboarding_acceptance.py', 'tests/test_onboarding_browser.py',
    'tests/test_onboarding_host.py', 'tests/test_onboarding_acceptance.py',
    'tests/test_being_seed.py'}
BROWSER_TESTS = tuple(sorted(set(CONTEXT_COPY_TESTS) | set(HOSTED_CHECK_TESTS) | {
    'tests/test_onboarding_browser.py', 'tests/test_being_seed.py'}))

TRANSFER_FILES = HOSTED_CHECK_FILES | EXPORT_FILES | {
    'clusterctl/onboarding_transfer.py', 'clusterctl/onboarding_input.py', 'clusterctl/onboarding_release.py',
    'tests/test_onboarding_transfer.py', 'tests/test_onboarding_release.py',
    'support/being-seed-tools/tools/receive_being.py',
    'support/being-seed-tools/tools/protected_being.py',
    'tools/build_onboarding_code.py'}
TRANSFER_TESTS = tuple(sorted(set(HOSTED_CHECK_TESTS) | set(EXPORT_TESTS) | {
    'tests/test_onboarding_transfer.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding_code_successor.py'}))

ENROLLMENT_FILES = PORTAL_FILES | OWNER_CLIENT_FILES | PEER_FILES | {
    'clusterctl/onboarding_existing.py', 'clusterctl/onboarding_enrollment.py',
    'clusterctl/onboarding_enrollment_root.py', 'clusterctl/onboarding_target.py',
    'clusterctl/onboarding_managed.py', 'tools/build_onboarding_code.py',
    'tests/test_onboarding_existing.py', 'tests/test_onboarding_managed.py',
    'tests/test_onboarding_code_successor.py',
    'docs/design/onboarding-jobs.md'}
ENROLLMENT_TESTS = tuple(sorted(set(PORTAL_TESTS) | {
    'tests/test_onboarding_existing.py', 'tests/test_onboarding_admission.py',
    'tests/test_onboarding_release.py', 'tests/test_onboarding_input.py',
    'tests/test_onboarding_progress.py', 'tests/test_onboarding.py',
    'tests/test_onboarding_host.py', 'tests/test_onboarding_host_ownership.py',
    'tests/test_onboarding_intake.py', 'tests/test_onboarding_approvals.py',
    'tests/test_onboarding_code_successor.py', 'tests/test_onboarding_sdk.py',
    'tests/test_onboarding_managed.py', 'tests/test_onboarding_peer_host.py',
    'tests/test_admission.py', 'tests/test_production_fences.py',
    'tests/test_embodiments.py',
    'tests/test_onboarding_target.py::test_receiving_target_runtime_retries_keep_keys_origin_and_receiving_writes',
    'tests/test_onboarding_target.py::test_receiving_credential_upgrade_keeps_origin_memory_and_runtime_reload',
    'tests/test_onboarding_target.py::test_native_credential_publication_recovers_each_lost_ack_without_new_identity',
    'tests/test_onboarding_target.py::test_credential_publication_refuses_running_writer_and_preserves_changed_runtime',
    'tests/test_onboarding_custody.py::test_existing_identity_and_wrong_or_missing_grant_create_no_keys',
    'tests/test_onboarding_credential.py::test_response_cannot_change_history_or_credential_and_expired_request_cannot_get_fresh_root_signature',
}))

INPUT_CACHE_FILES = {'clusterctl/onboarding_input.py', 'clusterctl/onboarding_host.py',
    'clusterctl/onboarding_worker.py', 'tests/test_onboarding_input.py',
    'docs/design/onboarding-jobs.md'}
INPUT_CACHE_TESTS = ('tests/test_onboarding_input.py', 'tests/test_onboarding_host.py',
    'tests/test_onboarding_host_ownership.py', 'tests/test_onboarding_guest.py',
    'tests/test_onboarding_release.py', 'tests/test_onboarding_progress.py',
    'tests/test_onboarding_worker_install.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')

SDK_FILES = {'requirements-weave.txt', 'RESUME.md', 'clusterctl/onboarding_sdk.py',
    'clusterctl/onboarding_chat_native.py', 'support/matrix-agent-chat/TOOLING-PROVENANCE.json',
    'clusterctl/matrix_host.py', 'clusterctl/onboarding_peer.py',
    'clusterctl/onboarding_peer_native.py', 'clusterctl/onboarding_owner_client.py',
    'support/matrix-onboarding/PROVENANCE.json',
    'support/matrix-agent-chat/install_agent_chat.py',
    'support/matrix-agent-chat/PROVENANCE.json', 'tests/test_clusterd.py',
    'tests/test_onboarding_peer.py',
    'clusterctl/onboarding_code_successor.py', 'tests/test_onboarding_code_successor.py',
    'tests/integration/test_recovery_rebirth_containers.py',
    'docs/runbooks/tribu-sdk-successor.md'}
SDK_TESTS = tuple(sorted(set(ONBOARDING_CONTRACTS) | {
    'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding_peer.py', 'tests/test_onboarding_source.py',
    'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_managed.py',
    'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_target.py',
    'tests/test_onboarding_runtime.py', 'tests/test_onboarding_service.py',
    'tests/test_onboarding_host.py', 'tests/test_onboarding_guest.py',
    'tests/test_onboarding_release.py', 'tests/test_onboarding_input.py',
    'tests/test_onboarding_admission.py', 'tests/test_onboarding_custody.py',
    'tests/test_onboarding_credential.py'}))


SDK_BOOTSTRAP_FILES = {'clusterctl/onboarding_sdk.py', 'tests/test_onboarding_sdk.py',
                       'docs/runbooks/tribu-sdk-successor.md'}
SDK_BOOTSTRAP_TESTS = ('tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
                       'tests/test_onboarding_release.py', 'tests/test_ci_scope.py',
                       'tests/test_ci_workflow.py')


UPDATE_INTENT_FILES = {'clusterctl/onboarding_code_successor.py',
                       'tests/test_receiving_update_journal.py',
                       'docs/runbooks/tribu-sdk-successor.md'}
UPDATE_INTENT_TESTS = ('tests/test_receiving_update_journal.py', 'tests/test_operation_journal.py',
                       'tests/test_onboarding_code_successor.py', 'tests/test_onboarding_sdk.py',
                       'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')

UPDATE_PREFLIGHT_FILES = {'clusterctl/onboarding_receiving_update.py', 'clusterctl/onboarding_sdk.py',
    'tests/test_receiving_update_preflight.py', 'docs/runbooks/tribu-sdk-successor.md',
    'tools/check_rc_types.py',
    'tests/fixtures/receiving_reader/canonical.py',
    'tests/fixtures/receiving_reader/release_compatibility.py',
    'tests/fixtures/receiving_reader/PROVENANCE.json'}
UPDATE_PREFLIGHT_TESTS = ('tests/test_receiving_update_preflight.py', 'tests/test_onboarding_sdk.py',
    'tests/test_onboarding_code_successor.py', 'tests/test_onboarding_release.py',
    'tests/test_receiving_update_journal.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')

UPDATE_SELECTION_FILES = {'clusterctl/onboarding_code_successor.py', 'clusterctl/onboarding_host.py',
    'clusterctl/onboarding_runtime.py', 'clusterctl/onboarding_sdk.py', 'clusterctl/onboarding_service.py',
    'clusterctl/onboarding_source.py', 'clusterctl/onboarding_target.py',
    'tests/test_onboarding_code_successor.py', 'tests/test_receiving_update_selection.py',
    'tests/test_onboarding_managed.py', 'docs/runbooks/tribu-sdk-successor.md'}
UPDATE_SELECTION_TESTS = ('tests/test_receiving_update_selection.py', 'tests/test_receiving_update_preflight.py',
    'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding_runtime.py', 'tests/test_onboarding_service.py', 'tests/test_onboarding_source.py',
    'tests/test_onboarding_host.py', 'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_managed.py',
    'tests/test_onboarding_group.py', 'tests/test_onboarding_release.py', 'tests/test_receiving_update_journal.py',
    'tests/test_onboarding_target.py::test_receiving_target_runtime_retries_keep_keys_origin_and_receiving_writes',
    'tests/test_onboarding_target.py::test_receiving_credential_upgrade_keeps_origin_memory_and_runtime_reload',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')

HOST_SELECTION_FILES = {'clusterctl/onboarding.py', 'clusterctl/onboarding_host.py',
    'clusterctl/onboarding_worker.py', 'clusterctl/onboarding_receiving_update.py',
    'clusterctl/onboarding_homes.py',
    'clusterctl/operation_journal.py', 'tests/test_receiving_host_selection.py',
    'tests/test_onboarding_homes.py',
    'tests/test_clusterctl.py',
    'docs/runbooks/tribu-sdk-successor.md'}
HOST_SELECTION_TESTS = ('tests/test_receiving_host_selection.py',
    'tests/test_receiving_update_journal.py', 'tests/test_operation_journal.py',
    'tests/test_onboarding.py', 'tests/test_onboarding_host.py',
    'tests/test_onboarding_host_ownership.py', 'tests/test_onboarding_progress.py',
    'tests/test_onboarding_homes.py', 'tests/test_onboarding_worker_install.py',
    'tests/test_home_worker_successor.py', 'tests/test_onboarding_new.py',
    'tests/test_onboarding_consent.py', 'tests/test_onboarding_intake.py',
    'tests/test_onboarding_code_successor.py', 'tests/test_receiving_update_preflight.py',
    'tests/test_onboarding_managed.py', 'tests/test_clusterctl.py', 'tests/test_transfer.py',
    'tests/test_rebirth.py', 'tests/test_recovery_rebirth.py', 'tests/test_volume_relocation.py',
    'tests/test_clusterd.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


GROUP_FILES = {'tests/test_onboarding_group.py',
    'clusterctl/onboarding_acceptance.py', 'clusterctl/onboarding_target.py',
    'clusterctl/onboarding_host.py',
    'clusterctl/onboarding_peer_host.py', 'clusterctl/onboarding_source.py',
    'clusterctl/onboarding_runtime.py', 'tools/managed_peer_plan.py',
    'tests/test_onboarding_peer_host.py', 'AGENTS.md', 'RESUME.md',
    'docs/design/onboarding-jobs.md'} | SDK_FILES
GROUP_TESTS = ('tests/test_onboarding_group.py', 'tests/test_onboarding_acceptance.py',
    'tests/test_onboarding_host.py',
    'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding_source.py', 'tests/test_onboarding_peer_host.py',
    'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_runtime.py',
    'tests/test_matrix_host.py', 'tests/test_matrix_status.py',
    'tests/test_onboarding_peer.py::test_actual_native_peer_accept_keeps_credential_receipt_and_receiving_writes',
    'tests/test_onboarding_target.py', 'tests/test_onboarding_credential.py',
    'tests/test_admission.py', 'tests/test_production_fences.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


RECEIVING_RUNTIME_FILES = {'clusterctl/onboarding_peer.py', 'clusterctl/onboarding_runtime.py',
    'tests/test_onboarding_peer.py', 'tests/test_onboarding_runtime.py'}

LOADED_STARTUP_FILES = {'RESUME.md', 'clusterctl/onboarding_sdk.py', 'clusterctl/onboarding_target.py',
    'clusterctl/onboarding_code_successor.py',
    'clusterctl/onboarding_service.py', 'tests/test_source_bootstrap.py',
    'clusterctl/onboarding_runtime.py', 'clusterctl/onboarding_source.py', 'clusterctl/owner_process.py',
    'clusterctl/onboarding_receiving_update.py', 'tests/test_receiving_cohort_control.py',
    'tests/test_receiving_host_selection.py', 'tests/test_receiving_update_journal.py',
    'tests/test_onboarding_sdk.py', 'tests/test_onboarding_target.py', 'tests/test_onboarding_runtime.py',
    'tests/test_onboarding_code_successor.py',
    'tests/test_onboarding_source.py', 'tests/test_onboarding_group_authorities.py',
    'docs/design/onboarding-jobs.md', 'tests/test_receiving_process_observation.py',
    'tests/test_source_owner_adapter.py',
    'tests/test_receiving_update_preflight.py', 'tests/test_receiving_update_selection.py',
    'tests/test_onboarding_service.py', 'clusterctl/onboarding_peer.py',
    'tests/test_onboarding_peer.py', 'tests/test_guest_service_bootstrap.py', 'tests/test_guest_owner_bootstrap.py',
    'tests/test_guest_bootstrap_controller.py', 'docs/runbooks/tribu-sdk-successor.md',
    'tests/fixtures/receiving_reader/canonical.py',
    'tests/fixtures/receiving_reader/release_compatibility.py',
    'tests/fixtures/receiving_reader/PROVENANCE.json'}
LOADED_STARTUP_TESTS = ('tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
    'tests/test_source_bootstrap.py',
    'tests/test_receiving_cohort_control.py', 'tests/test_receiving_host_selection.py',
    'tests/test_receiving_update_journal.py',
    'tests/test_receiving_update_selection.py', 'tests/test_receiving_update_preflight.py',
    'tests/test_onboarding_source.py', 'tests/test_onboarding_group_authorities.py',
    'tests/test_onboarding_runtime.py', 'tests/test_onboarding_service.py',
    'tests/test_source_owner_adapter.py',
    'tests/test_receiving_process_observation.py', 'tests/test_onboarding_group.py',
    'tests/test_onboarding_target.py', 'tests/test_onboarding_admission.py',
    'tests/test_onboarding_peer.py', 'tests/test_guest_service_bootstrap.py', 'tests/test_guest_owner_bootstrap.py',
    'tests/test_guest_bootstrap_controller.py',
    'tests/test_matrix_host_process.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


HOME_FILES = {'clusterctl/homes/__init__.py', 'clusterctl/homes/policy.py',
    'clusterctl/homes/launcher.py', 'clusterctl/homes/launcher/index.html',
    'clusterctl/homes/launcher/launcher.js', 'clusterctl/homes/launcher/launcher.css',
    'tests/test_home_launcher.py', 'docs/design/miniapps-launcher.md',
    'clusterctl/homes/sessions.py', 'clusterctl/homes/authority.py',
    'clusterctl/homes/registry.py', 'clusterctl/homes/service.py',
    'clusterctl/homes/passkeys.py', 'clusterctl/homes/assets/passkeys.js',
    'clusterctl/homes/styles.py', 'tests/test_home_styles.py',
    'clusterctl/homes/homemaker.py', 'tests/test_home_homemaker.py',
    'tools/qualify_homemaker_browser.py',
    'tools/qualify_home_style_owner.py',
    'clusterctl/homes/assets/home-style.js', 'clusterctl/homes/assets/artifact-style.js',
    'clusterctl/homes/assets/home-miniapp-login.js',
    'docs/design/shared-home-styles.md', 'tests/js/home-style-client.cjs',
    'clusterctl/homes/login.py', 'clusterctl/homes/assets/login.js',
    'requirements-home-login.txt', 'tests/test_home_login.py', 'docs/design/home-shared-login.md',
    'tools/qualify_home_login_browser.py',
    'clusterctl/homes/assets/access-client.js', 'tests/test_home_client.py',
    'tests/js/home-access-client.cjs', 'docs/design/home-browser-client.md',
    'clusterctl/homes/examples/library/index.html',
    'clusterctl/homes/examples/library/client.js', 'clusterctl/homes/examples/library/style.css',
    'requirements-homes.txt', 'tests/test_home_passkeys.py',
    'clusterctl/homes/host.py', 'clusterctl/homes/provision.py',
    'clusterctl/homes/assets/home.css', 'docs/design/artifact-homes.md',
    'clusterd/assets/fonts/space-grotesk-latin.woff2',
    'clusterd/assets/fonts/OFL.txt', 'clusterd/assets/fonts/PROVENANCE.json',
    'tests/test_home_access.py', 'tests/test_home_gateway.py', 'tests/test_home_host.py'}
HOME_TESTS = ('tests/test_home_launcher.py', 'tests/test_home_access.py', 'tests/test_home_gateway.py', 'tests/test_home_host.py',
              'tests/test_home_passkeys.py', 'tests/test_home_client.py', 'tests/test_home_styles.py', 'tests/test_home_login.py', 'tests/test_home_homemaker.py',
              'tests/test_auth.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


HOME_PROVISION_FILES = HOME_FILES | {'clusterctl/onboarding_homes.py', 'clusterctl/onboarding_worker.py',
    'tools/install_onboarding_worker.py', 'tests/test_onboarding_homes.py'}
HOME_PROVISION_TESTS = HOME_TESTS + ('tests/test_onboarding_homes.py', 'tests/test_onboarding.py',
    'tests/test_onboarding_progress.py', 'tests/test_onboarding_worker_install.py',
    'tests/test_onboarding_host_ownership.py', 'tests/test_operational_assets.py')

HOME_WORKER_FILES = {'clusterctl/onboarding_host.py', 'tests/test_onboarding_host.py',
    'tools/build_home_worker_successor.py', 'tests/test_home_worker_successor.py',
    'clusterctl/onboarding_worker.py', 'clusterctl/onboarding_homes.py',
    'clusterctl/homes/service.py', 'tests/test_onboarding_homes.py',
    'docs/design/artifact-homes.md'}
HOME_WORKER_TESTS = ('tests/test_home_worker_successor.py', 'tests/test_onboarding_host.py',
    'tests/test_onboarding_telegram.py', 'tests/test_onboarding_host_ownership.py',
    'tests/test_onboarding_homes.py', 'tests/test_onboarding_worker_install.py',
    'tests/test_operational_assets.py', 'tests/test_ci_scope.py', 'tests/test_ci_workflow.py',
    'tests/test_home_gateway.py', 'tests/test_home_access.py')


def host_observation_only(root: Path, base: str) -> bool:
    """Recognize exact qualified host receiving changes, never a filename.

    A host filename alone cannot narrow provisioning/access qualification.
    The initial one-literal metadata fix is compared against its actual base.
    The candidate/deadline increment is an exact whole-file hash pair: all
    default paths are retained and qualified by the host/peer regression set.
    Any other byte change keeps its broader profile, including future edits.
    """
    if not re.fullmatch(r'[0-9a-f]{40}', base):
        return False
    name='clusterctl/onboarding_host.py'
    before=subprocess.run(['git','show',base+':'+name],cwd=root,capture_output=True,check=False)
    if before.returncode:
        return False
    try:
        original=before.stdout
        current=(root/name).read_bytes()
    except OSError:
        return False
    old=b'set(value) != {"phase", "request", "receipt"}'
    new=b"set(value) - {'group', 'receiving_controller'} != {\"phase\", \"request\", \"receipt\"}"
    if original.count(old)==1 and original.replace(old,new,1)==current:
        return True
    if (hashlib.sha256(original).hexdigest(), hashlib.sha256(current).hexdigest()) == (
        'cf3878966677401d094410595541f3f5395b0964d28910057299443c9b86a1a5',
        'cc1e19f193e69cc67c08d121243067813f6ae6b56bbbb358cf5888be2909c216'):
        # Extend the existing prepared-SDK entry to the three bootstrap verbs.
        return True
    return (hashlib.sha256(original).hexdigest() in {
        '742fb3e396d4619369152cde4c3811c22df18504e504d7012e99c99772040c59',
        '8b0a728465958acb8da5ae0d212fd69c3b548a07f9f9d677e66ec3146b3780d2'}
        and hashlib.sha256(current).hexdigest() in {
        '0ec24cc2096f5b88b498d1e49578810404c2248b0a8309d027c30d28d5f2daee',
        'b33a3bdb9929088a7eb6e9226e871131195830ba1b4b5a4419adcbe6afcb8397',
        'c065e236c07f0af2a2b580be88730ad06b204e2e23b827449759184ec52e4aa6',
        '45bb1547863ee1dfcbcdeac970a7a217a792e8755a52df9b63ffed152819c32c'})



# Exact reviewed shared-helper deltas preserve unrelated behavior. Unknown bytes
# retain full qualification; a filename or a passing narrower run is not enough.
RECEIVING_SUPPORT_HASHES = {
    'clusterctl/being_seed.py': (
        '9abf29b0948a0bafc3d9ba89e761a0993f45d8b6e9d9a84749abed120356fc14',
        'f3086cd0f148d9b89b7ff6c36d39d7ecd08d57d0f5af4495a29126649107b9f4'),
    'clusterctl/onboarding.py': (
        '22502def8f11549d6b0be262e131dadd95c2de9d897e295e2cfe5eb40e4b1e99',
        'ba6c5eab4ea1c4397dff2e8cec2e47480800d142a8c2846db0d7c7a23a3bdc91'),
    'tests/integration/test_recovery_rebirth_containers.py': (
        'ea7100770ed295650a4c0a9ebf614e6df30d3d108fd91086de162b6e318fe282',
        '85e2328f47736372ef2d71067dd390d240978a592aaf5fdca42f9ff33fdcab43'),
}


def receiving_support_only(root: Path, base: str, names: set[str]) -> bool:
    if not re.fullmatch(r'[0-9a-f]{40}', base):
        return False
    for name in names:
        before = subprocess.run(['git','show',base+':'+name],cwd=root,capture_output=True,check=False)
        try:
            actual = (hashlib.sha256(before.stdout).hexdigest(),
                      hashlib.sha256((root/name).read_bytes()).hexdigest())
        except OSError:
            return False
        if before.returncode or actual != RECEIVING_SUPPORT_HASHES[name]:
            return False
    return True


def select(changed: list[str], root: Path, *, base: str = '') -> tuple[str, list[str]]:
    pins = {'requirements-weave.txt', 'clusterctl/onboarding_sdk.py', 'clusterctl/matrix_host.py'}
    detached_pins = pins - {'clusterctl/onboarding_sdk.py'}
    metadata = {'support/matrix-onboarding/PROVENANCE.json'} & set(changed)
    if (pins < set(changed) and sdk_pin_files_only(root, base, detached_pins)
            and (not metadata or sdk_pin_metadata_only(root, base))):
        remaining = sorted(set(changed) - detached_pins - metadata)
        profile, tests = select(remaining, root, base=base)
        if profile == 'peer' and all((root / path).is_file() for path in SDK_TESTS):
            # Compose existing receiving coverage with the full SDK contract.
            # Detached files were proven literal-only. Keep SDK source changes
            # in receiving qualification; unknown/sensitive edits stay broader.
            return 'sdk', list(dict.fromkeys((*tests, *SDK_TESTS)))
    host_files={'clusterctl/onboarding_host.py','tests/test_onboarding_host.py'}
    # A receiving release also installs its native owner attachment. Compose
    # the two existing coverage sets instead of falling through to unrelated
    # physical/archive/model qualification for this known combined delta.
    owner_files = OWNER_CLIENT_FILES - host_files
    owner_delta = bool(set(changed) & (owner_files - {'tools/check_rc_types.py'}))
    loaded_files = LOADED_STARTUP_FILES | owner_files
    loaded_tests = (tuple(dict.fromkeys((*LOADED_STARTUP_TESTS, *OWNER_CLIENT_TESTS)))
                    if owner_delta else LOADED_STARTUP_TESTS)
    host_tests=(*loaded_tests,'tests/test_onboarding_host.py',
                'tests/test_onboarding_host_ownership.py','tests/test_onboarding_managed.py',
                'tests/test_onboarding_peer_host.py')
    support = set(changed) & RECEIVING_SUPPORT_HASHES.keys()
    support_tests = (*host_tests, 'tests/test_being_seed.py')
    if (support and set(changed) <= loaded_files | CI_FILES | host_files
            | RECEIVING_SUPPORT_HASHES.keys() | {'tests/test_being_seed.py'}
            and all((root/path).is_file() for path in support_tests)
            and receiving_support_only(root, base, support)
            and (not (set(changed) & host_files)
                 or host_files <= set(changed) and host_observation_only(root, base))):
        return 'peer', list(dict.fromkeys(support_tests))
    if (host_files <= set(changed) and set(changed) <= loaded_files | CI_FILES | host_files
            and all((root/path).is_file() for path in host_tests) and host_observation_only(root,base)):
        return 'peer',list(dict.fromkeys(host_tests))
    if ({'tests/test_receiving_process_observation.py', 'tests/test_source_bootstrap.py',
            'tests/test_guest_owner_bootstrap.py'} & set(changed)
            and set(changed) <= loaded_files | CI_FILES
            and all((root / path).is_file() for path in loaded_tests)):
        # Actual same-connection/process startup, retained SDK and service paths.
        # No changed archive, physical recovery, authority or native model code.
        return 'peer', list(loaded_tests)
    if not changed:
        return 'full', ['tests']
    if set(changed) <= RUNBOOK_DOCS:
        return 'docs', []
    if set(changed) <= CI_FILES | RUNBOOK_DOCS:
        return 'ci', ['tests/test_ci_scope.py', 'tests/test_ci_workflow.py']
    if ({'clusterctl/onboarding_code_successor.py', 'tests/test_onboarding_code_successor.py'} <= set(changed)
            and set(changed) <= {'clusterctl/onboarding_code_successor.py',
                'tests/test_onboarding_code_successor.py'} | CI_FILES | RUNBOOK_DOCS
            and all((root / path.split('::', 1)[0]).is_file() for path in UPDATE_SELECTION_TESTS)):
        # Retained generation interpretation keeps SDK bytes, context, journal,
        # actual receiving launchers and host selectors. No dependency, custody,
        # archive or physical recovery implementation changed.
        return 'update-selection', list(UPDATE_SELECTION_TESTS)
    if ({'clusterctl/onboarding_receiving_update.py', 'tests/test_receiving_host_selection.py'} <= set(changed)
            and set(changed) <= HOST_SELECTION_FILES | CI_FILES
            and all((root / path).is_file() for path in HOST_SELECTION_TESTS)):
        # Runtime selector refresh, job fences and opt-in journal observation
        # CAS. Include existing journal consumers; no SDK/bootstrap, new native
        # authority, account, admission or service code is changed here.
        return 'host-selection', list(HOST_SELECTION_TESTS)
    if ({'clusterctl/onboarding_service.py', 'tests/test_receiving_update_selection.py'} <= set(changed)
            and set(changed) <= UPDATE_SELECTION_FILES | CI_FILES
            and all((root / path.split('::', 1)[0]).is_file() for path in UPDATE_SELECTION_TESTS)):
        # Exact SDK/import startup and unit CAS: qualify the actual receiving
        # launchers/admission and retained context, not archive export or new keys.
        return 'update-selection', list(UPDATE_SELECTION_TESTS)
    if ({'clusterctl/onboarding_receiving_update.py', 'tests/test_receiving_update_preflight.py'} <= set(changed)
            and set(changed) <= UPDATE_PREFLIGHT_FILES | CI_FILES
            and all((root / path).is_file() for path in UPDATE_PREFLIGHT_TESTS)):
        # Actual candidate process/offline installation, not service selection,
        # authority adoption, admission or dependency-pin qualification.
        return 'update-preflight', list(UPDATE_PREFLIGHT_TESTS)
    if ('clusterctl/onboarding_sdk.py' in changed
            and set(changed) <= SDK_BOOTSTRAP_FILES | CI_FILES
            and all((root / path).is_file() for path in SDK_BOOTSTRAP_TESTS)):
        # Offline bootstrap and immutable SDK generations only. Native authority,
        # admission, dependency pins and host mutations retain their broader scope.
        return 'sdk-bootstrap', list(SDK_BOOTSTRAP_TESTS)
    if ('tests/test_receiving_update_journal.py' in changed
            and set(changed) <= UPDATE_INTENT_FILES | CI_FILES
            and all((root / path).is_file() for path in UPDATE_INTENT_TESTS)):
        # Exact durable intent and retained-generation verification. Host/native
        # effect adapters, dependency pins and authority changes stay broader.
        return 'update-intent', list(UPDATE_INTENT_TESTS)
    observation_tests = ('tests/test_onboarding_target.py', 'tests/test_onboarding_managed.py',
        'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')
    if ('clusterctl/onboarding_target.py' in changed
            and set(changed) <= {'clusterctl/onboarding_target.py',
                                'tests/test_onboarding_owner_client.py'} | CI_FILES
            and all((root/path).is_file() for path in observation_tests)):
        return 'portal', list(observation_tests)
    if ('tools/build_home_worker_successor.py' in changed
            and set(changed) <= HOME_WORKER_FILES | CI_FILES
            and all((root/path).is_file() for path in HOME_WORKER_TESTS)):
        return 'homes', list(HOME_WORKER_TESTS)
    if (set(changed) & {'clusterctl/onboarding_homes.py', 'clusterctl/onboarding_worker.py',
                        'tools/install_onboarding_worker.py', 'tests/test_onboarding_homes.py'}
            and set(changed) <= HOME_PROVISION_FILES | CI_FILES
            and all((root/path).is_file() for path in HOME_PROVISION_TESTS)):
        return 'homes', list(HOME_PROVISION_TESTS)
    if (set(changed) & HOME_FILES and set(changed) <= HOME_FILES | CI_FILES
            and all((root / path).is_file() for path in HOME_TESTS)):
        # Home-only read authority retains auth and workflow contracts. Native
        # custody, dependencies, admission and provisioning changes stay full.
        return 'homes', list(HOME_TESTS)
    if ('tests/test_onboarding_group.py' in changed
            and set(changed) <= GROUP_FILES | CI_FILES
            and all((root / path.split('::', 1)[0]).is_file() for path in GROUP_TESTS)):
        # Signed group selection, exact SDK and native/receiving contracts.
        # No changed archive exporter, physical recovery or model lifecycle.
        return 'sdk', list(GROUP_TESTS)
    if (set(changed) & {'clusterctl/onboarding_peer.py', 'clusterctl/onboarding_runtime.py'}
            and set(changed) <= RECEIVING_RUNTIME_FILES | CI_FILES
            and all((root / path).is_file() for path in SDK_TESTS)):
        # This receiving adapter change keeps the complete existing native SDK,
        # admission, custody, current-authority and code-successor qualification.
        # It changes no archive/export, Incus mounts or physical recovery code.
        # Those changes, dependencies and authority primitives keep broader CI.
        return 'peer', list(SDK_TESTS)
    if ({'requirements-weave.txt', 'clusterctl/onboarding_sdk.py',
         'clusterctl/matrix_host.py'} <= set(changed)
            and set(changed) <= SDK_FILES | CI_FILES
            and all((root / path).is_file() for path in SDK_TESTS)):
        # One exact Matrix successor, not a general dependency upgrade. Cover
        # installed-byte integrity, native services, custody/authority, host
        # contracts and retained receiving context. Physical recovery and the
        # unrelated offline-release sandbox retain their own full profile.
        return 'sdk', list(SDK_TESTS)
    if ('clusterctl/onboarding_input.py' in changed
            and set(changed) <= INPUT_CACHE_FILES | CI_FILES
            and all((root / path).is_file() for path in INPUT_CACHE_TESTS)):
        return 'portal', list(INPUT_CACHE_TESTS)
    if (set(changed) & {'clusterctl/browser.py', 'clusterctl/onboarding_browser.py'}
            and set(changed) <= BROWSER_FILES | CI_FILES
            and all((root / path).is_file() for path in BROWSER_TESTS)):
        # Code-only browser installation retains context/SDK, job retries and
        # owner/API acceptance. No custody, dependency or recovery changes.
        return 'portal', list(BROWSER_TESTS)
    if (set(changed) & {'tools/export_local_matrix_identity.py', 'clusterctl/onboarding_local_body.py'}
            and set(changed) <= IDENTITY_EXPORT_FILES | CI_FILES
            and all((root / path).is_file() for path in IDENTITY_EXPORT_TESTS)):
        # Public export and report reuse keep real signed application/native
        # binding, writer locks, enrollment custody and HTTP owner contracts.
        # No SDK, physical recovery, body execution or authority code changes.
        return 'portal', list(IDENTITY_EXPORT_TESTS)
    if (set(changed) & {'clusterctl/onboarding_input.py', 'tests/test_onboarding_new.py'}
            and set(changed) <= NEW_SEED_FILES | CI_FILES
            and all((root / path).is_file() for path in NEW_SEED_TESTS)):
        # Fresh empty memory and maintained context execution retain owner
        # isolation, original SDK/context pins, native custody and all job/API
        # acceptance contracts. No changed dependency or physical recovery.
        return 'portal', list(NEW_SEED_TESTS)
    if ('clusterctl/onboarding_guest.py' in changed
            and set(changed) <= CONTEXT_COPY_FILES | CI_FILES
            and all((root / path).is_file() for path in CONTEXT_COPY_TESTS)):
        # File-copy recovery retains the full receiving, immutable SDK,
        # owner/job isolation and API contracts. Physical container recovery,
        # custody and dependency changes still require their wider profiles.
        return 'portal', list(CONTEXT_COPY_TESTS)
    if (set(changed) & {'tools/continue_seed_onboarding.py', 'tests/test_onboarding_continuation.py'}
            and set(changed) <= CONTINUATION_FILES | CI_FILES
            and all((root / path).is_file() for path in CONTINUATION_TESTS)):
        # The finite participant client keeps actual native two-phase signing,
        # private owner HTTP isolation, archive receiving and worker retries.
        # It changes no SDK, authority primitive or container recovery path.
        return 'portal', list(CONTINUATION_TESTS)
    if (set(changed) & {'clusterctl/onboarding_telegram.py', 'tests/test_onboarding_telegram.py'}
            and set(changed) <= TELEGRAM_FILES | CI_FILES
            and all((root / path).is_file() for path in TELEGRAM_TESTS)):
        # Qualified bridge software and SQLite/idle succession do not replace
        # a Matrix SDK, authority, body or container recovery implementation.
        return 'portal', list(TELEGRAM_TESTS)
    if (set(changed) & {'clusterctl/being_seed.py', 'tests/test_being_seed.py'}
            and set(changed) <= UPLOAD_FILES | CI_FILES
            and all((root / path).is_file() for path in UPLOAD_TESTS)):
        # Stream framing/resumption retains owner authorization, protected
        # archive integrity and receiving intake; no runtime/custody changes.
        return 'portal', list(UPLOAD_TESTS)
    if (set(changed) & {'clusterctl/onboarding_enrollment.py', 'tests/test_onboarding_existing.py'}
            and set(changed) <= ENROLLMENT_FILES | CI_FILES
            and all((root / path.split("::", 1)[0]).is_file() for path in ENROLLMENT_TESTS)):
        # Native existing-Root enrollment retains both custody ceremonies,
        # receiving crash recovery, exact SDK/context, owner HTTP isolation,
        # admission/fencing and signed Source coordination. Dependency pins,
        # authority primitives and physical recovery changes remain full.
        return 'onboarding', list(ENROLLMENT_TESTS)
    if (set(changed) & {'clusterctl/onboarding_transfer.py', 'tests/test_onboarding_transfer.py'}
            and set(changed) <= TRANSFER_FILES | CI_FILES
            and all((root / path).is_file() for path in TRANSFER_TESTS)):
        # Recipient and authenticated archive boundaries retain real receiving,
        # host input/plan, retry, native-owner and HTTP authorization contracts.
        # SDK/dependency/custody changes cannot select this narrow profile.
        return 'portal', list(TRANSFER_TESTS)
    if (set(changed) & {'clusterctl/onboarding_acceptance.py', 'tests/test_onboarding_acceptance.py'}
            and set(changed) <= HOSTED_CHECK_FILES | CI_FILES
            and all((root / path).is_file() for path in HOSTED_CHECK_TESTS)):
        # Read-only hosted metadata and owner witnesses retain the exact native
        # owner-client prerequisite, job/retry and HTTP isolation contracts.
        # Guest SDK, custody and dependency changes still require wider coverage.
        return 'portal', sorted(set(HOSTED_CHECK_TESTS))
    if (set(changed) & {'clusterctl/onboarding_owner_client.py', 'tests/test_onboarding_owner_client.py'}
            and set(changed) <= OWNER_CLIENT_FILES | CI_FILES
            and all((root / path).is_file() for path in OWNER_CLIENT_TESTS)):
        # A host-only owner command retains native socket authentication,
        # admission, immutable SDK/context and first-welcome boundaries.
        return 'peer', sorted(set(OWNER_CLIENT_TESTS))
    if ('clusterctl/being_seed.py' in changed
            and set(changed) <= {'clusterctl/being_seed.py', 'clusterd/seed_ui.py', 'tests/test_being_seed.py'} | CI_FILES
            and all((root / path).is_file() for path in TRANSFER_TESTS)):
        # Intake/UI-only changes keep archive crypto, HTTP owners, context and
        # worker retry coverage without rebuilding unchanged recovery hosts.
        return 'portal', list(TRANSFER_TESTS)
    if ('support/being-seed-tools/tools/export_being.py' in changed
            and set(changed) <= EXPORT_FILES | CI_FILES
            and all((root / path).is_file() for path in EXPORT_TESTS)):
        return 'portal', list(EXPORT_TESTS)
    if (set(changed) & {'clusterctl/onboarding_welcome.py', 'tests/test_onboarding_welcome.py'}
            and set(changed) <= WELCOME_FILES | CI_FILES
            and all((root / path).is_file() for path in WELCOME_TESTS)):
        return 'welcome', list(WELCOME_TESTS)
    if set(changed) <= ACCOUNT_FILES | CI_FILES and all((root / path).is_file() for path in ACCOUNT_TESTS):
        return 'account', list(ACCOUNT_TESTS)
    if set(changed) <= PEER_FILES | CI_FILES and all((root / path).is_file() for path in PEER_TESTS):
        # Host-only peer coordination retains signed Source, receiving
        # admission/selection and owner separation. Guest assets, snapshots,
        # authority storage and dependency changes retain broader coverage.
        return 'peer', list(PEER_TESTS)
    if (set(changed) <= PEER_TOOL_FILES | PEER_FILES | CI_FILES
            and all((root / path).is_file() for path in PEER_TOOL_TESTS)):
        # A maintained tool successor keeps the SDK and all context assets.
        # Qualify custody/acceptance, original native services, installed tool
        # integrity and local identity export; dependency changes stay full.
        return 'peer', list(PEER_TOOL_TESTS)
    if (set(changed) & {'clusterctl/onboarding_local_body.py', 'tools/export_local_matrix_identity.py',
                       'tests/test_onboarding_local_body.py'}
            and set(changed) <= PORTAL_FILES | CI_FILES
            and all((root / path).is_file() for path in PORTAL_TESTS)):
        # This owner-intake change still exercises all shared HTTP, access,
        # owner and human-approval contracts. It changes no Incus/admission,
        # guest runtime, provider execution or native body lifecycle code.
        return 'portal', list(PORTAL_TESTS)
    if (set(changed) <= APPROVAL_FILES | CI_FILES
            and all((root / path).is_file() for path in APPROVAL_TESTS)):
        return 'approval', list(APPROVAL_TESTS)
    def onboarding(path):
        return (path in ONBOARDING_FILES or path in CI_FILES
                or re.fullmatch(r'(?:clusterctl/onboarding_|tests/test_onboarding)[A-Za-z0-9_]*\.py', path))
    if all(onboarding(path) for path in changed):
        # Resolve enumeration relative to the supplied checkout, not the caller.
        tests = [p.relative_to(root).as_posix() for p in sorted(root.joinpath('tests').glob('test_onboarding*.py'))]
        if (tests and all(re.fullmatch(r'tests/test_onboarding[A-Za-z0-9_]*\.py', path) for path in tests)
                and all((root / path).is_file() for path in ONBOARDING_CONTRACTS)):
            return 'onboarding', sorted(set(tests) | set(ONBOARDING_CONTRACTS))
    return 'full', ['tests']


SDK_PIN_TESTS = ('tests/test_onboarding_sdk.py', 'tests/test_matrix_host.py',
    'tests/test_matrix_status.py', 'tests/test_onboarding_group.py',
    'tests/test_clusterd.py::test_ontology_read_routes',
    'tests/test_onboarding_peer.py::test_tool_capture_requires_the_exact_upstream_bytes',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


def sdk_pin_only(root: Path, base: str, changed: list[str]) -> bool:
    """Narrow repeated qualification only when executable changes are pin literals.

    File names alone cannot prove this. Any altered function, import, schema or
    dependency other than the exact Matrix commit retains the full SDK profile.
    """
    pins = {'requirements-weave.txt', 'clusterctl/onboarding_sdk.py',
            'clusterctl/matrix_host.py'}
    allowed = pins | CI_FILES | {'RESUME.md', 'support/matrix-onboarding/PROVENANCE.json',
                                 'tests/test_clusterd.py'}
    if not pins <= set(changed) or not set(changed) <= allowed:
        return False
    return (sdk_pin_files_only(root, base, pins)
            and all((root / path.split('::', 1)[0]).is_file() for path in SDK_PIN_TESTS))


def sdk_pin_files_only(root: Path, base: str, pins: set[str]) -> bool:
    """Prove only the selected detached files contain pin-literal changes."""
    if not pins or not pins <= {'requirements-weave.txt', 'clusterctl/onboarding_sdk.py', 'clusterctl/matrix_host.py'}:
        return False
    for name in sorted(pins):
        before = subprocess.run(['git', 'show', base + ':' + name], cwd=root,
                                 capture_output=True, check=False)
        if before.returncode:
            return False
        try:
            original, current = before.stdout.decode(), (root / name).read_text()
        except (OSError, UnicodeError):
            return False
        if name == 'requirements-weave.txt':
            pattern = r'(?m)(^daimon-matrix @ git\+https://github\.com/AlterMundi/daimon-matrix\.git@)[0-9a-f]{40}$'
        else:
            variable = 'MATRIX_COMMIT' if name.endswith('onboarding_sdk.py') else 'MATRIX_CONTRACT_COMMIT'
            pattern = r'(?m)(^' + variable + r' = )[\"\x27][0-9a-f]{40}[\"\x27]$'
        old, old_count = re.subn(pattern, r'\1<PIN>', original)
        new, new_count = re.subn(pattern, r'\1<PIN>', current)
        if old_count != 1 or new_count != 1 or old != new:
            return False
    return True


def sdk_pin_metadata_only(root: Path, base: str) -> bool:
    """Carry the same vendored tool while updating its installed-SDK record."""
    name = 'support/matrix-onboarding/PROVENANCE.json'
    before = subprocess.run(['git', 'show', base + ':' + name], cwd=root, capture_output=True, check=False)
    try:
        original = json.loads(before.stdout)
        current = json.loads((root / name).read_bytes())
        selected = re.search(r'(?m)^MATRIX_CONTRACT_COMMIT = [\"\x27]([0-9a-f]{40})[\"\x27]$',
            (root / 'clusterctl/matrix_host.py').read_text())
        return (before.returncode == 0 and selected is not None
                and current.get('installed_sdk_commit') == selected.group(1)
                and 'installed_sdk_commit' in original
                and current == {**original, 'installed_sdk_commit': current['installed_sdk_commit']})
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def scope_base(root: Path, base: str, head: str) -> str:
    """Scope a tested PR merge against its actual first parent.

    GitHub's event base can precede concurrent main merges. Include those in the
    tested tree, but do not misclassify their already-qualified files as PR edits.
    Trust the merge parent only when its other parent is the event's exact head.
    """
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        return base
    result = subprocess.run(['git', 'rev-list', '--parents', '-n', '1', 'HEAD'],
                             cwd=root, capture_output=True, check=False)
    parts = result.stdout.decode().split() if result.returncode == 0 else []
    if len(parts) == 3 and parts[2] == head and re.fullmatch(r'[0-9a-f]{40}', parts[1]):
        return parts[1]
    return base


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='')
    parser.add_argument('--head', default='')
    parser.add_argument('--full', action='store_true')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    base = scope_base(root, args.base, args.head)
    changed = []
    if not args.full and re.fullmatch(r'[0-9a-f]{40}', base):
        result = subprocess.run(['git', 'diff', '--name-only', '-z', base, 'HEAD'],
                                cwd=root, capture_output=True, check=False)
        if result.returncode == 0:
            changed = result.stdout.decode().rstrip('\0').split('\0') if result.stdout else []
    profile, tests = select(changed, root, base=base)
    if profile == 'sdk' and sdk_pin_only(root, base, changed):
        # Retain prior unchanged authority/custody/receiving qualification.
        tests = list(SDK_PIN_TESTS)
    print(json.dumps({'profile': profile, 'tests': tests, 'changed': changed}))
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as stream:
            stream.write('profile=' + profile + '\n')
            stream.write('pytest_args=' + ' '.join(tests) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
