"""Executable checks for security-sensitive inline CI preparation logic."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest


def _private_inventory() -> Any:
    workflow = Path(__file__).parents[1] / ".github/workflows/tests.yml"
    raw = workflow.read_text(encoding="utf-8")
    step = raw.index("Harden and record the trusted qualification interpreter")
    marker = "          python - <<'PY'\n"
    start = raw.index(marker, step) + len(marker)
    end = raw.index("          PY\n", start)
    source = "\n".join(
        line.removeprefix("          ") for line in raw[start:end].splitlines()
    )
    parsed = ast.parse(source)
    names = {"digest_file", "inventory", "normalised_mode"}
    functions = [
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    assert {node.name for node in functions} == names
    namespace = {
        "Path": Path,
        "hashlib": hashlib,
        "json": json,
        "os": os,
        "stat": stat,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), workflow, "exec"), namespace)
    return namespace["inventory"]


def test_private_ci_prefix_inventory_rejects_writable_member(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private-prefix"
    private.mkdir(mode=0o700)
    member = private / "module.py"
    member.write_bytes(b"VALUE = 1\n")
    member.chmod(0o620)

    inventory = _private_inventory()
    with pytest.raises(AssertionError):
        inventory(private, private=True)

    member.chmod(0o600)
    assert inventory(private, private=True) == [
        ["directory", ".", 0o700],
        ["file", "module.py", 0o600, 10, hashlib.sha256(b"VALUE = 1\n").hexdigest()],
    ]


def test_private_ci_prefix_inventory_rejects_writable_directory(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private-prefix"
    private.mkdir(mode=0o700)
    package = private / "package"
    package.mkdir(mode=0o720)
    package.chmod(0o720)

    inventory = _private_inventory()
    with pytest.raises(AssertionError):
        inventory(private, private=True)

    package.chmod(0o700)
    assert inventory(private, private=True) == [
        ["directory", ".", 0o700],
        ["directory", "package", 0o700],
    ]


def test_ci_sandbox_preflight_is_hosted_runner_only_and_preserves_isolation() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github/workflows/tests.yml"
    ).read_text(encoding="utf-8")
    start = workflow.index(
        "      - name: Prove the disposable runner supports the qualification sandbox"
    )
    end = workflow.index("      - run: python -m pip install", start)
    step = workflow[start:end]

    assert 'test "${RUNNER_ENVIRONMENT:-}" = github-hosted' in step
    assert "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" in step
    assert "--unshare-all" in step
    assert "--clearenv" in step
    assert "--ro-bind / /" not in step
    assert "--share-net" not in step
    assert '--ro-bind "$private_prefix" /python' in step
    assert "--setenv LD_LIBRARY_PATH /python/lib" in step
    assert '"/python/bin/$PRIVATE_PYTHON" -m venv --copies /work/venv' in step
    assert 'test "$(readlink /proc/self/ns/net)" != "$HOST_NET_NAMESPACE"' in step
    assert 'test "$(wc -l < /proc/net/route)" -eq 1' in step
    assert "test ! -e /home/runner" in step
    assert "test ! -e /run/docker.sock" in step


def test_ci_bubblewrap_install_is_cached_bounded_and_fail_closed() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github/workflows/tests.yml"
    ).read_text(encoding="utf-8")
    start = workflow.index("      - name: Install the offline qualification sandbox")
    end = workflow.index(
        "      - name: Prove the disposable runner supports the qualification sandbox",
        start,
    )
    step = workflow[start:end]

    assert "apt-get update" not in step
    assert "/var/lib/apt/lists/*_Packages*" in step
    assert "/usr/bin/timeout --kill-after=5s 120s" in step
    assert step.count("/usr/bin/apt-get install") == 1
    assert "--no-install-recommends" in step
    assert "Acquire::Retries=2" in step
    assert "Acquire::http::Timeout=15" in step
    assert "Acquire::https::Timeout=15" in step
    assert "Dpkg::Lock::Timeout=30" in step
    assert "test -x /usr/bin/bwrap" in step


def test_recovery_workflow_uses_the_actual_host_matrix_contract_pin() -> None:
    import re
    from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT
    root = Path(__file__).parents[1]
    tree = ast.parse((root/'tests/integration/test_recovery_rebirth_containers.py').read_text())
    assert any(isinstance(node, ast.ImportFrom) and node.module == 'clusterctl.matrix_host'
               and any(alias.name == 'MATRIX_CONTRACT_COMMIT' for alias in node.names)
               for node in tree.body)
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'MATRIX_COMMIT'
                           for target in node.targets)]
    assert len(assignments) == 1 and isinstance(assignments[0].value, ast.Name)
    assert assignments[0].value.id == 'MATRIX_CONTRACT_COMMIT'
    workflow = (root/'.github/workflows/tests.yml').read_text().split('  recovery-rebirth-disposable-hosts:', 1)[1]
    assert re.search(r'ref: ([0-9a-f]{40})', workflow).group(1) == MATRIX_CONTRACT_COMMIT
    assert re.search(r'git -C matrix-source rev-parse HEAD.*?([0-9a-f]{40})', workflow, re.S).group(1) == MATRIX_CONTRACT_COMMIT


def test_guest_owner_contract_uses_kernel_uid_mapping_and_is_not_run_twice() -> None:
    workflow = (Path(__file__).parents[1] / '.github/workflows/tests.yml').read_text()
    step = workflow.split('      - name: Test the guest owner under its actual UID contract\n', 1)[1].split('      - name:', 1)[0]
    assert "contains(needs.scope.outputs.pytest_args, 'tests/test_guest_owner_bootstrap.py')" in step
    assert "needs.scope.outputs.profile == 'full'" in step
    assert 'qualification_uid="$(id -u)"' in step and 'qualification_gid="$(id -g)"' in step
    assert 'sudo unshare --user --map-users="$qualification_uid,1000,1" --map-groups="$qualification_gid,1000,1"' in step
    assert '--setuid=1000 --setgid=1000' in step
    assert 'tests/test_guest_owner_bootstrap.py' in step and '-W error::ResourceWarning' in step
    assert workflow.count('--deselect=tests/test_guest_owner_bootstrap.py') == 1
