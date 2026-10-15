"""Disposable multi-container proof for recovery-role separation."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT


ROOT = Path(__file__).resolve().parents[2]
MATRIX_COMMIT = MATRIX_CONTRACT_COMMIT
pytestmark = pytest.mark.skipif(
    os.environ.get("DAIMON_RUN_DOCKER_RECOVERY_TESTS") != "1"
    or not os.environ.get("DAIMON_MATRIX_SOURCE"),
    reason=(
        "set DAIMON_RUN_DOCKER_RECOVERY_TESTS=1 and DAIMON_MATRIX_SOURCE "
        "for the disposable host proof"
    ),
)


def _run(
    arguments: list[str], *, check: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, check=check)


def _write_private(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def _container(
    image: str,
    mounts: list[tuple[Path, str, bool]],
    script: str,
) -> subprocess.CompletedProcess[str]:
    arguments = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "768m",
        "--cpus",
        "2",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,mode=700,size=128m",
    ]
    for source, target, readonly in mounts:
        mount = f"type=bind,src={source},dst={target}"
        if readonly:
            mount += ",readonly"
        arguments.extend(["--mount", mount])
    arguments.extend([image, "sh", "-ceu", script])
    return _run(arguments, check=False)


def _require_ok(result: subprocess.CompletedProcess[str], role: str) -> None:
    assert result.returncode == 0, (
        f"{role} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def _last_document(output: str) -> dict:
    lines = [line for line in output.splitlines() if line.startswith("{")]
    assert lines, output
    value = json.loads(lines[-1])
    assert isinstance(value, dict)
    return value


def test_recovery_roles_cross_only_closed_mounts(tmp_path: Path) -> None:
    test_id = uuid.uuid4().hex[:12]
    image = f"daimon-recovery-host-test:{test_id}"
    bootstrap = tmp_path / "bootstrap"
    public = tmp_path / "public"
    root = tmp_path / "offline-root"
    source = tmp_path / "source-host"
    snapshot = tmp_path / "snapshot-transfer"
    target = tmp_path / "target-host"
    for directory in (bootstrap, public, root, source, snapshot, target):
        directory.mkdir(mode=0o700)

    old_root_password = secrets.token_hex(24).encode()
    new_root_password = secrets.token_hex(24).encode()
    source_password = secrets.token_hex(24).encode()
    discarded_password = secrets.token_hex(24).encode()
    target_password = secrets.token_hex(24).encode()
    _write_private(root / "old.password", old_root_password)
    _write_private(root / "new.password", new_root_password)
    _write_private(source / "runtime.password", source_password)
    _write_private(bootstrap / "discarded-runtime.password", discarded_password)
    _write_private(target / "target.password", target_password)
    profile = {
        "schema": "dm.operator.bootstrap-profile/v1",
        "embodiments": [
            {
                "advertised_endpoint": "http://127.0.0.1:19686/dm-peer/v1",
                "body_ref": "cluster:discarded-peer:compaii",
                "label": "discarded",
                "listen_host": "127.0.0.1",
                "listen_port": 19686,
                "principal_id": "compaii@discarded-peer",
            },
            {
                "advertised_endpoint": "http://127.0.0.1:18686/dm-peer/v1",
                "body_ref": "cluster:disposable-source:compaii",
                "label": "source",
                "listen_host": "127.0.0.1",
                "listen_port": 18686,
                "principal_id": "compaii@disposable-source",
            },
        ],
    }
    _write_private(
        public / "bootstrap-profile.json",
        json.dumps(profile, sort_keys=True, separators=(",", ":")).encode(),
    )
    recovery_profile = {
        "schema": "dm.operator.rebirth-target-profile/v1",
        "label": "recovered",
        "body_ref": "cluster:disposable-recovered:compaii",
        "principal_id": "compaii@disposable-recovered",
        "listen_host": "127.0.0.1",
        "listen_port": 21686,
        "advertised_endpoint": "http://127.0.0.1:21686/dm-peer/v1",
        "targets": [],
    }
    _write_private(
        public / "recovery-profile.json",
        json.dumps(recovery_profile, sort_keys=True, separators=(",", ":")).encode(),
    )

    matrix_source = Path(os.environ["DAIMON_MATRIX_SOURCE"]).resolve(strict=True)
    matrix_head = _run(
        ["git", "-C", str(matrix_source), "rev-parse", "HEAD"], check=False
    )
    _require_ok(matrix_head, "matrix-source-head")
    assert matrix_head.stdout.strip() == MATRIX_COMMIT
    matrix_shallow = _run(
        ["git", "-C", str(matrix_source), "rev-parse", "--is-shallow-repository"],
        check=False,
    )
    _require_ok(matrix_shallow, "matrix-source-shallow-check")
    assert matrix_shallow.stdout.strip() == "false"
    build_context = tmp_path / "build-context"
    build_context.mkdir(mode=0o700)
    shutil.copy2(
        ROOT / "tests/integration/recovery-rebirth/Dockerfile",
        build_context / "Dockerfile",
    )
    shutil.copy2(ROOT / "constraints.txt", build_context / "constraints.txt")
    shutil.copy2(
        ROOT / "tests/integration/recovery-rebirth/role.py",
        build_context / "role.py",
    )
    shutil.copytree(
        ROOT / "clusterctl",
        build_context / "clusterctl",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (build_context / "configs").mkdir(mode=0o700)
    shutil.copy2(
        ROOT / "configs/clusterctl.yaml", build_context / "configs/clusterctl.yaml"
    )
    bundled = _run(
        [
            "git",
            "-C",
            str(matrix_source),
            "bundle",
            "create",
            str(build_context / "matrix.bundle"),
            "HEAD",
        ],
        check=False,
    )
    _require_ok(bundled, "matrix-source-bundle")
    verified_bundle = _run(
        ["git", "bundle", "verify", str(build_context / "matrix.bundle")],
        check=False,
    )
    _require_ok(verified_bundle, "matrix-source-bundle-verify")

    try:
        built = _run(
            [
                "docker",
                "build",
                "--tag",
                image,
                "--build-arg",
                f"MATRIX_COMMIT={MATRIX_COMMIT}",
                "--file",
                str(build_context / "Dockerfile"),
                str(build_context),
            ],
            check=False,
        )
        _require_ok(built, "image-build")
        provenance = _container(
            image,
            [],
            "python - <<'PY'\n"
            "import importlib.metadata, json\n"
            "d = importlib.metadata.distribution('daimon-matrix')\n"
            "print(d.read_text('direct_url.json'))\n"
            "PY",
        )
        _require_ok(provenance, "image-provenance")
        assert json.loads(provenance.stdout)["vcs_info"]["commit_id"] == MATRIX_COMMIT

        bootstrapped = _container(
            image,
            [
                (bootstrap, "/bootstrap", False),
                (public, "/public", False),
                (root, "/offline-root", False),
                (source, "/source-host", False),
            ],
            "daimon-synthetic-bootstrap --output /bootstrap/out "
            "--profile /public/bootstrap-profile.json --root-password-fd 3 "
            "--runtime-password-fd discarded=4 --runtime-password-fd source=5 "
            "3</offline-root/old.password "
            "4</bootstrap/discarded-runtime.password "
            "5</source-host/runtime.password\n"
            "python /opt/daimon-recovery-role.py export-bootstrap "
            "--bootstrap /bootstrap/out --public /public --root /offline-root "
            "--source /source-host --label source "
            "--require-absent /target-host --require-absent /snapshot-transfer",
        )
        _require_ok(bootstrapped, "synthetic-bootstrap")
        assert _last_document(bootstrapped.stdout)["foreign_mounts_absent"] is True

        # The explicitly synthetic genesis staging is destroyed before the
        # separated source, offline-root and target roles begin.
        shutil.rmtree(bootstrap)
        assert not bootstrap.exists()

        snapshotted = _container(
            image,
            [
                (public, "/public", False),
                (source, "/source-host", False),
                (snapshot, "/snapshot-transfer", False),
            ],
            "python /opt/daimon-recovery-role.py source-snapshot "
            "--source /source-host --snapshot /snapshot-transfer/canonical "
            "--evidence /public/source-evidence.json "
            "--require-absent /offline-root --require-absent /target-host",
        )
        _require_ok(snapshotted, "source-host")
        source_evidence = _last_document(snapshotted.stdout)
        assert source_evidence["custody_files_exported"] is False
        recovery_manifest = json.loads(
            (snapshot / "canonical/snapshot.json").read_bytes()
        )
        assert {row["name"] for row in recovery_manifest["files"]} == {
            "ledger.sqlite",
            "runtime.json",
        }
        assert {path.name for path in (snapshot / "canonical/payload").iterdir()} == {
            "ledger.sqlite",
            "runtime.json",
        }
        assert (source / "full-portable-snapshot/payload/custody.json").is_file()
        assert not any("custody" in path.name for path in snapshot.rglob("*"))

        recovered = _container(
            image,
            [(public, "/public", False), (root, "/offline-root", False)],
            "daimon-rebirth synthetic-single-store-recover "
            "--authority /public/authority.json "
            "--root-custody /offline-root/old-root-custody.json "
            "--current-password-fd 3 --replacement-password-fd 4 "
            "--output /offline-root/recovered "
            "3</offline-root/old.password 4</offline-root/new.password\n"
            "python /opt/daimon-recovery-role.py publish-document "
            "--source /offline-root/recovered/recovery.json "
            "--destination /public/recovery.json "
            "--require-absent /source-host --require-absent /target-host "
            "--require-absent /snapshot-transfer",
        )
        _require_ok(recovered, "offline-root-recover")

        prepared = _container(
            image,
            [(public, "/public", False), (target, "/target-host", False)],
            "daimon-rebirth prepare-recovery --authority /public/authority.json "
            "--recovery /public/recovery.json --profile /public/recovery-profile.json "
            "--output /target-host/preparation --password-fd 3 "
            "3</target-host/target.password\n"
            "python /opt/daimon-recovery-role.py publish-document "
            "--source /target-host/preparation/request.json "
            "--destination /public/request.json "
            "--require-absent /offline-root --require-absent /source-host "
            "--require-absent /snapshot-transfer",
        )
        _require_ok(prepared, "target-prepare")

        authorized = _container(
            image,
            [(public, "/public", False), (root, "/offline-root", False)],
            "daimon-rebirth synthetic-single-store-authorize-recovery "
            "--authority /public/authority.json "
            "--recovery /public/recovery.json --request /public/request.json "
            "--recovered-root-custody /offline-root/recovered/root-custody.json "
            "--root-password-fd 3 --output /public/activation.json "
            "3</offline-root/new.password\n"
            "test ! -e /source-host && test ! -e /target-host "
            "&& test ! -e /snapshot-transfer",
        )
        _require_ok(authorized, "offline-root-authorize")

        activated = _container(
            image,
            [(public, "/public", True), (target, "/target-host", False)],
            "daimon-rebirth activate-recovery --base-runtime /public/base-runtime.json "
            "--preparation-dir /target-host/preparation --request /public/request.json "
            "--activation /public/activation.json --output /target-host/package "
            "--password-fd 3 3</target-host/target.password\n"
            "test ! -e /offline-root && test ! -e /source-host "
            "&& test ! -e /snapshot-transfer",
        )
        _require_ok(activated, "target-activate")

        restored = _container(
            image,
            [
                (public, "/public", True),
                (snapshot, "/snapshot-transfer", True),
                (target, "/target-host", False),
            ],
            "python -m clusterctl.cli --state-dir /target-host/state "
            "rebirth-recovery-restore --package-dir /target-host/package "
            "--snapshot-dir /snapshot-transfer/canonical --password-fd 3 "
            "--idempotency-key 11111111-1111-4111-8111-111111111111 --json "
            "3</target-host/target.password >/target-host/restore-result.json\n"
            "test ! -e /offline-root && test ! -e /source-host",
        )
        _require_ok(restored, "target-restore")

        verified = _container(
            image,
            [(public, "/public", True), (target, "/target-host", False)],
            "python /opt/daimon-recovery-role.py verify-target "
            "--target /target-host --source-evidence /public/source-evidence.json "
            "--require-absent /offline-root --require-absent /source-host "
            "--require-absent /snapshot-transfer",
        )
        _require_ok(verified, "target-runtime")
        evidence = _last_document(verified.stdout)
        assert evidence["old_event_restored"] is True
        assert evidence["fresh_event_authored"] is True
        assert evidence["event_count"] == 2
        assert evidence["active_embodiment_ids"] == [evidence["target_embodiment_id"]]
        assert (
            source_evidence["source_origin"]["embodiment_id"]
            != evidence["target_embodiment_id"]
        )

        exchange_files = sorted(
            [path for path in public.rglob("*") if path.is_file()]
            + [path for path in snapshot.rglob("*") if path.is_file()]
        )
        public_bytes = b"".join(path.read_bytes() for path in exchange_files)
        for secret in (
            old_root_password,
            new_root_password,
            source_password,
            discarded_password,
            target_password,
        ):
            assert secret not in public_bytes
            assert secret.decode() not in "\n".join(
                result.stdout + result.stderr
                for result in (
                    bootstrapped,
                    snapshotted,
                    recovered,
                    prepared,
                    authorized,
                    activated,
                    restored,
                    verified,
                )
            )
        assert not any("custody" in path.name for path in exchange_files)
        print(
            json.dumps(
                {
                    **evidence,
                    "custody_free_transfer": True,
                    "image_matrix_commit": MATRIX_COMMIT,
                    "public_exchange_sha256": hashlib.sha256(public_bytes).hexdigest(),
                    "recovery_transfer_files": sorted(
                        row["name"] for row in recovery_manifest["files"]
                    ),
                    "roles": [
                        "synthetic-bootstrap",
                        "source-host",
                        "offline-root",
                        "target-preparation",
                        "target-restore",
                    ],
                },
                sort_keys=True,
            )
        )
    finally:
        _run(["docker", "image", "rm", "--force", image], check=False)
