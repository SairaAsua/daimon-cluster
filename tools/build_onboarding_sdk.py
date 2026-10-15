"""Build a pinned, hash-locked Matrix wheelhouse from public source only."""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from clusterctl import onboarding_sdk
from clusterctl.onboarding import OnboardingError, private_directory
from clusterctl.onboarding_input import relative

ROOT = Path(__file__).resolve().parents[1]


def _revision(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
        raise OnboardingError('pinned_matrix_revision_required')
    return value


def seal(output: Path, *, matrix_commit: str = onboarding_sdk.MATRIX_COMMIT) -> dict:
    matrix_commit = _revision(matrix_commit)
    # Downloaded wheels inherit the caller's umask. Close this entirely new,
    # unqualified code artifact before admitting it as receiving authority.
    output.chmod(0o755)
    for path in output.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    rows = [onboarding_sdk.wheel(path, uid=os.geteuid()) for path in sorted((output / "wheels").iterdir())]
    matrix = [row for row in rows if row['distribution'] == 'daimon-matrix']
    if len(matrix) != 1:
        raise OnboardingError('invalid_onboarding_sdk')
    value = dict(schema=onboarding_sdk.SCHEMA, matrix_commit=matrix_commit, wheels=rows)
    (output / "sdk.json").write_text(json.dumps(value, sort_keys=True))
    (output / "requirements.txt").write_bytes(onboarding_sdk.requirement_lines(rows))
    (output / "sdk.json").chmod(0o644)
    (output / "requirements.txt").chmod(0o644)
    onboarding_sdk.verify(output.parent, uid=os.geteuid(), matrix_commit=matrix_commit,
        matrix_wheel_sha256=matrix[0]['sha256'])
    return value


def build(checkout: Path, output: Path, *, matrix_commit: str = onboarding_sdk.MATRIX_COMMIT) -> dict:
    matrix_commit = _revision(matrix_commit)
    if output.name != "sdk":
        raise OnboardingError("onboarding_sdk_directory_required")
    if output.exists() or output.is_symlink():
        raise OnboardingError("onboarding_sdk_destination_exists")
    private_directory(output.parent)
    result = subprocess.run(["git", "-C", str(checkout), "archive", "--format=tar",
                             matrix_commit], capture_output=True, timeout=60, check=False)
    if result.returncode or len(result.stdout) > 64 * 1024**2:
        raise OnboardingError("pinned_matrix_code_unavailable")
    output.mkdir(mode=0o755)
    wheels = output / "wheels"
    wheels.mkdir(mode=0o755)
    with tempfile.TemporaryDirectory(prefix="daimon-sdk-build-") as scratch:
        source = Path(scratch)
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            for member in archive.getmembers():
                path = source / relative(member.name.rstrip("/"))
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif member.isfile() and member.size <= 32 * 1024**2:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise OnboardingError("invalid_pinned_matrix_archive")
                    with stream, path.open("xb") as dest:
                        dest.write(stream.read())
                else:
                    raise OnboardingError("invalid_pinned_matrix_archive")
        environment = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000", "PYTHONHASHSEED": "0",
                       "PIP_CONFIG_FILE": os.devnull, "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        result = subprocess.run([sys.executable, "-m", "pip", "wheel", "--only-binary=:all:",
                                 "--constraint", str(ROOT / "constraints.txt"),
                                 "--wheel-dir", str(wheels), str(source), "websockets==15.0.1"],
                                env=environment, capture_output=True, timeout=300, check=False)
        if result.returncode:
            raise OnboardingError("pinned_matrix_wheel_build_refused")
    return seal(output, matrix_commit=matrix_commit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-checkout", type=Path, required=True)
    parser.add_argument("--matrix-commit", default=onboarding_sdk.MATRIX_COMMIT,
                        help="exact approved source revision; default preserves the configured SDK pin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(args.matrix_checkout, args.output, matrix_commit=args.matrix_commit)
        print(json.dumps(dict(matrix_commit=value["matrix_commit"], wheel_count=len(value["wheels"]))))
        return 0
    except Exception:
        print(json.dumps({"error": "onboarding_sdk_build_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
