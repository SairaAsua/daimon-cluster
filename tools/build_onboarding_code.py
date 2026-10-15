"""Assemble code-only receiving artifacts; no identity, memory or credential reads."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError, private_directory
from clusterctl.onboarding_input import relative

HMK_COMMIT = "518f350889001b7f70ac3dd4f843a9e0c16d256c"
ROOT = Path(__file__).resolve().parents[1]
MODULES = ("__init__.py", "being_seed.py", "onboarding_transfer.py", "onboarding.py", "onboarding_input.py",
           "onboarding_release.py", "onboarding_code_successor.py", "onboarding_owner_client.py", "onboarding_peer.py", "onboarding_group_admission.py", "onboarding_guest.py", "onboarding_mounts.py", "onboarding_sdk.py",
           "onboarding_target.py", "onboarding_existing.py", "onboarding_credential.py", "owner_process.py", "onboarding_admission.py",
           "onboarding_runtime.py", "onboarding_views.py", "onboarding_service.py", "onboarding_ssh.py", "onboarding_provider.py", "onboarding_telegram.py", "admission.py", "admission_supervisor.py", "fences.py", "production_fences.py")


def copy_code(source: Path, target: Path) -> None:
    # An ordinary checkout is mutable. Its captured bytes become authority
    # only after the resulting artifact digest is qualified and selected.
    being_seed._path(source)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as incoming:
        before = os.fstat(incoming.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_size > 32 * 1024**2):
            raise OnboardingError("owned_build_code_required")
        raw = incoming.read(32 * 1024**2 + 1)
        after = os.fstat(incoming.fileno())
        if len(raw) > 32 * 1024**2 or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise OnboardingError("build_code_changed")
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o755 if source.stat().st_mode & 0o100 else 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def capture_peer_tool(output: Path) -> None:
    from clusterctl.onboarding_peer import TOOL_MODULE, TOOL_SHA256
    source = ROOT / 'clusterctl/onboarding_peer_native.py'
    target = output / 'clusterctl' / TOOL_MODULE
    copy_code(source, target)
    if hashlib.sha256(onboarding_release.regular(target, uid=os.geteuid())).hexdigest() != TOOL_SHA256:
        raise OnboardingError('qualified_native_peer_tool_required')


def capture_chat_tool(output: Path) -> None:
    from clusterctl.onboarding_owner_client import TOOLING_INSTALLER_MODULE, TOOLING_INSTALLER_SHA256
    target = output / 'clusterctl' / TOOLING_INSTALLER_MODULE
    copy_code(ROOT / 'clusterctl' / TOOLING_INSTALLER_MODULE, target)
    if hashlib.sha256(onboarding_release.regular(target, uid=os.geteuid())).hexdigest() != TOOLING_INSTALLER_SHA256:
        raise OnboardingError('qualified_native_peer_tool_required')


def build(checkout: Path, commons: Path, selected_profile: dict, output: Path, *, sdk: Path | None = None,
          telegram: Path | None = None) -> dict:
    selected_profile = onboarding_release.profile(selected_profile)
    if output.exists() or output.is_symlink():
        raise OnboardingError("receiving_code_destination_exists")
    private_directory(output.parent)
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "--format=tar", HMK_COMMIT,
                              "scripts", "LICENSE"], capture_output=True, check=False, timeout=60)
    if archive.returncode or len(archive.stdout) > 32 * 1024**2:
        raise OnboardingError("pinned_hmk_code_unavailable")
    output.mkdir(mode=0o755)
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as incoming:
        for member in incoming.getmembers():
            path = output / "hmk" / relative(member.name.rstrip("/"))
            if member.isdir():
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
            elif member.isfile() and member.size <= 32 * 1024**2:
                stream = incoming.extractfile(member)
                if stream is None:
                    raise OnboardingError("invalid_pinned_hmk_archive")
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with stream, os.fdopen(descriptor, "wb") as outgoing:
                    shutil.copyfileobj(stream, outgoing)
            else:
                raise OnboardingError("invalid_pinned_hmk_archive")
    for name in MODULES:
        copy_code(ROOT / "clusterctl" / name, output / "clusterctl" / name)
    capture_peer_tool(output)
    capture_chat_tool(output)
    for path in sorted((ROOT / "support/being-seed-tools").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            copy_code(path, output / path.relative_to(ROOT))
    copy_code(ROOT / "support/source-inheritance.md", output / "inheritance.md")
    if telegram is not None:
        from clusterctl.onboarding_telegram import ARCHIVE, BINARY, COMMIT
        copy_code(telegram, output / 'telegram/telecodex')
        binary = output / 'telegram/telecodex'
        if hashlib.sha256(binary.read_bytes()).hexdigest() != BINARY:
            raise OnboardingError('qualified_telegram_binary_required')
        binary.chmod(0o755)
        (output / 'telegram/artifact.json').write_text(json.dumps(dict(
            commit=COMMIT, archive_sha256=ARCHIVE, binary_sha256=BINARY,
            rust='1.95.0', features='--no-default-features'), sort_keys=True))
        (output / 'telegram/artifact.json').chmod(0o644)
    if sdk is not None:
        from clusterctl import onboarding_sdk
        onboarding_sdk.verify(sdk.parent, uid=os.geteuid())
        for path in sorted(sdk.rglob("*")):
            if path.is_file():
                copy_code(path, output / "sdk" / path.relative_to(sdk))
    for name in selected_profile["skills"]:
        source = commons / name
        if not source.is_dir() or source.is_symlink():
            raise OnboardingError("approved_common_skill_required")
        for path in sorted(source.rglob("*")):
            if "__pycache__" in path.parts:
                continue
            if path.is_file():
                copy_code(path, output / "skills" / name / path.relative_to(source))
            elif path.is_symlink():
                raise OnboardingError("approved_common_skill_required")
    provenance = dict(schema="cluster-onboarding-code-provenance/v1", hmk_commit=HMK_COMMIT,
                      hmk_archive_sha256=hashlib.sha256(archive.stdout).hexdigest(),
                      scope="receiving code only; no live authority or acceptance")
    (output / "provenance.json").write_text(json.dumps(provenance, sort_keys=True))
    (output / "provenance.json").chmod(0o644)
    # Path.mkdir(parents=True) uses the process umask for intermediate parents.
    # This entirely new code tree must be read-only to receiving users.
    for directory in output.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    fingerprint = onboarding_release.seal(output, selected_profile)
    onboarding_release.verify(output, fingerprint, uid=os.geteuid())
    return {"release_digest": fingerprint, "hmk_commit": HMK_COMMIT}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hmk-checkout", type=Path)
    parser.add_argument("--commons", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-base", type=Path)
    parser.add_argument("--base-digest")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--telegram-artifact", type=Path)
    args = parser.parse_args()
    try:
        if args.runtime_base is not None:
            if (args.base_digest is None or any(value is not None for value in (
                    args.hmk_checkout, args.commons, args.profile, args.sdk, args.telegram_artifact))):
                raise OnboardingError('qualified_onboarding_runtime_required')
            from clusterctl.onboarding_code_successor import build as build_successor
            result = build_successor(args.runtime_base, args.base_digest, ROOT / 'clusterctl', MODULES, args.output)
        else:
            if args.base_digest is not None or any(value is None for value in (args.hmk_checkout, args.commons, args.profile)):
                raise OnboardingError('receiving_code_build_configuration_required')
            result = build(args.hmk_checkout, args.commons, json.loads(args.profile.read_bytes()), args.output,
                           sdk=args.sdk, telegram=args.telegram_artifact)
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({"error": "receiving_code_build_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
