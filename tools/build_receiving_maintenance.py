"""Build the fixed maintenance helper closure using the retained SDK successor API.

Only public release/code/SDK artifacts are read. This does not qualify a release,
install a private SDK, select a runtime or interrupt a service.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from clusterctl import onboarding_code_successor
from tools.build_onboarding_code import MODULES

# The original context and helper closure stay preserved. Add maintenance's
# transitive Cluster dependencies explicitly; do not capture unrelated code.
# Archive-transfer upgrades change frozen export context and are a separate
# profile; routine maintenance does not add that module to a legacy context.
MAINTENANCE_MODULES = tuple(dict.fromkeys((*(name for name in MODULES if name != 'onboarding_transfer.py'),
    'receiving_maintenance.py', 'onboarding_source.py', 'onboarding_peer_host.py',
    'onboarding_host.py', 'onboarding_qualification.py', 'onboarding_receiving_update.py',
    'onboarding_owner_control.py', 'operation_journal.py', 'idempotency.py',
    'onboarding_intake.py', 'onboarding_progress.py', 'onboarding_managed.py',
    'onboarding_authority.py', 'onboarding_registry.py', 'onboarding_actions.py',
    'onboarding_local_body.py', 'onboarding_enrollment.py', 'onboarding_enrollment_root.py',
    'onboarding_accounts.py', 'onboarding_consent.py', 'onboarding_approvals.py',
    'onboarding_custody.py', 'onboarding_holder_backup.py', 'onboarding_welcome.py',
    'onboarding_acceptance.py', 'onboarding_ingress.py', 'onboarding_browser.py', 'browser.py')))


def build(base: Path, base_digest: str, source: Path, sdk: Path, output: Path, *,
          matrix_commit: str, matrix_wheel_sha256: str) -> dict:
    return onboarding_code_successor.build(base, base_digest, source,
        MAINTENANCE_MODULES, output, sdk=sdk, matrix_commit=matrix_commit,
        matrix_wheel_sha256=matrix_wheel_sha256)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--base-digest', required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--matrix-commit', required=True)
    parser.add_argument('--matrix-wheel-sha256', required=True)
    args = parser.parse_args(argv)
    source = Path(__file__).resolve().parents[1] / 'clusterctl'
    print(json.dumps(build(args.base, args.base_digest, source, args.sdk, args.output,
        matrix_commit=args.matrix_commit, matrix_wheel_sha256=args.matrix_wheel_sha256)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
