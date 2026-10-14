"""clusterctl v0.1.0 tests (issue #10).

Unit tests run against FakeAdapter fixtures with a tmp state_dir.
Integration tests exercise IncusAdapter against the live incus daemon
(iso-a / iso-b, their preserved historical tribe-agent profile). They require
CLUSTER_LIVE_INCUS_TESTS=1 and an explicitly prepared disposable host; ordinary
unit qualification never probes a development host's live Incus daemon.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from clusterctl import cli
from clusterctl.adapters import FakeAdapter, IncusAdapter
from clusterctl.config import load_config
from clusterctl.inventory import STATUS_SCHEMA, load_specs, reconcile

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "configs" / "clusterctl.yaml"

STATUS_FIELDS = {
    "schema",
    "name",
    "species",
    "host",
    "state",
    "resource_fence_state",
    "image_version",
    "budgets",
    "durable_bytes",
    "hmk_integrity",
    "uptime_s",
    "last_audit_event",
    "body_ref",
    "embodiment_id",
    "incarnation_id",
}
BUDGET_FIELDS = {"cpu", "memory_mib", "disk_gib"}


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def _write_spec(state_dir: Path, name: str, **overrides) -> None:
    spec = {
        "schema": "instance-spec/v1",
        "name": name,
        "species": "daimon-agent",
        "image_version": "daimon-base-2026-08-01.1",
        "budgets": {"cpu": 1, "memory_mib": 1536, "disk_gib": 8},
        "created_ms": 1754000000000,
        "created_by": "human:test",
    }
    spec.update(overrides)
    inst_dir = state_dir / "instances"
    inst_dir.mkdir(parents=True, exist_ok=True)
    (inst_dir / f"{name}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))


def _actual(name: str, state: str = "running", cpu: int = 1, memory_mib: int = 1536,
            disk_gib: int = 8, image_version: str = "daimon-base-2026-08-01.1",
            uptime_s: int = 42) -> dict:
    return {
        "name": name,
        "state": state,
        "image_version": image_version,
        "budgets": {"cpu": cpu, "memory_mib": memory_mib, "disk_gib": disk_gib},
        "uptime_s": uptime_s,
    }


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    d = tmp_path / "state"
    d.mkdir()
    _write_spec(d, "ok-runner")                       # matches actual -> running
    _write_spec(d, "ok-stopped")                      # matches actual -> stopped
    _write_spec(d, "ghost")                           # no actual -> missing
    _write_spec(d, "drifty", budgets={"cpu": 2, "memory_mib": 1536, "disk_gib": 8})
    return d


@pytest.fixture()
def fake_adapter() -> FakeAdapter:
    return FakeAdapter([
        _actual("ok-runner", state="running"),
        _actual("ok-stopped", state="stopped", uptime_s=None),
        _actual("drifty", state="running", cpu=1),    # declared cpu=2 -> drifted
        _actual("stray", state="running"),            # no spec -> undeclared
    ])


def _records(state_dir: Path, adapter: FakeAdapter) -> list[dict]:
    specs = load_specs(state_dir / "instances")
    return reconcile(specs, adapter, "testhost")


def _by_name(records: list[dict]) -> dict[str, dict]:
    return {r["name"]: r for r in records}


# --------------------------------------------------------------------------
# Classification tests (fake adapter)
# --------------------------------------------------------------------------

def test_classification_running(state_dir, fake_adapter):
    assert _by_name(_records(state_dir, fake_adapter))["ok-runner"]["state"] == "running"


def test_classification_stopped(state_dir, fake_adapter):
    assert _by_name(_records(state_dir, fake_adapter))["ok-stopped"]["state"] == "stopped"


def test_classification_missing(state_dir, fake_adapter):
    assert _by_name(_records(state_dir, fake_adapter))["ghost"]["state"] == "missing"


def test_classification_undeclared(state_dir, fake_adapter):
    assert _by_name(_records(state_dir, fake_adapter))["stray"]["state"] == "undeclared"


def test_classification_drifted(state_dir, fake_adapter):
    assert _by_name(_records(state_dir, fake_adapter))["drifty"]["state"] == "drifted"


def test_generic_spec_cannot_publish_matrix_identity(state_dir, fake_adapter):
    _write_spec(
        state_dir,
        "forged-generic",
        instance_kind="generic-instance",
        body_ref="matrix:body:forged",
        embodiment_id="embodiment:forged",
        current_incarnation_id="incarnation:forged",
    )
    adapter = FakeAdapter([*fake_adapter.list_instances(), _actual("forged-generic")])
    record = _by_name(_records(state_dir, adapter))["forged-generic"]
    assert record["body_ref"] is None
    assert record["embodiment_id"] is None
    assert record["incarnation_id"] is None


def test_drift_detail_entries(state_dir, fake_adapter):
    rec = _by_name(_records(state_dir, fake_adapter))["drifty"]
    assert rec["drift"] == [{"field": "cpu", "declared": 2, "actual": 1}]


# --------------------------------------------------------------------------
# Schema shape tests
# --------------------------------------------------------------------------

def test_status_schema_shape(state_dir, fake_adapter):
    records = _records(state_dir, fake_adapter)
    assert records, "expected at least one record"
    for rec in records:
        assert STATUS_FIELDS <= set(rec), f"missing fields in {rec['name']}"
        assert rec["schema"] == STATUS_SCHEMA
        assert set(rec["budgets"]) == BUDGET_FIELDS
        assert rec["host"] == "testhost"
        assert rec["resource_fence_state"] == "unknown"
        assert rec["hmk_integrity"] == "unknown"


def test_cli_list_json_schema_shape(state_dir, fake_adapter, capsys):
    rc = cli.run(["--state-dir", str(state_dir), "list", "--json"], adapter=fake_adapter)
    assert rc == 0
    records = json.loads(capsys.readouterr().out)
    assert isinstance(records, list) and records
    for rec in records:
        assert STATUS_FIELDS <= set(rec)
        assert rec["schema"] == STATUS_SCHEMA


def test_cli_status_json_includes_drift(state_dir, fake_adapter, capsys):
    rc = cli.run(["--state-dir", str(state_dir), "status", "drifty", "--json"],
                 adapter=fake_adapter)
    assert rc == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["state"] == "drifted"
    assert rec["drift"] == [{"field": "cpu", "declared": 2, "actual": 1}]


# --------------------------------------------------------------------------
# Side-effect-free read check
# --------------------------------------------------------------------------

def _tree_snapshot(root: Path) -> dict:
    snap = {}
    for p in sorted(root.rglob("*")):
        st = p.stat()
        snap[str(p)] = (st.st_mtime_ns, st.st_size, p.is_dir())
    return snap


def test_reads_are_side_effect_free(state_dir, fake_adapter, capsys):
    before = _tree_snapshot(state_dir)
    assert cli.run(["--state-dir", str(state_dir), "list"], adapter=fake_adapter) == 0
    assert cli.run(["--state-dir", str(state_dir), "list", "--json"], adapter=fake_adapter) == 0
    assert cli.run(["--state-dir", str(state_dir), "status", "ok-runner"], adapter=fake_adapter) == 0
    assert cli.run(["--state-dir", str(state_dir), "status", "ok-runner", "--json"],
                   adapter=fake_adapter) == 0
    capsys.readouterr()  # drain
    assert _tree_snapshot(state_dir) == before


# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------

def test_status_unknown_name_exit_3(state_dir, fake_adapter, capsys):
    rc = cli.run(["--state-dir", str(state_dir), "status", "no-such-instance"],
                 adapter=fake_adapter)
    assert rc == 3
    assert "not found" in capsys.readouterr().err


def test_list_exit_0(state_dir, fake_adapter, capsys):
    assert cli.run(["--state-dir", str(state_dir), "list"], adapter=fake_adapter) == 0
    capsys.readouterr()


def test_config_show_exit_0_and_fields(capsys):
    rc = cli.run(["--config", str(CONFIG_PATH), "config-show", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema"] == "clusterctl-config/v1"
    assert data["profile"] == "daimon-agent"
    assert data["host_id"]


def test_repo_config_loads():
    cfg = load_config(CONFIG_PATH)
    assert cfg.host_id
    assert cfg.incus_project
    assert cfg.profile == "daimon-agent"
    assert cfg.state_dir  # default /var/lib/daimon-cluster


# --------------------------------------------------------------------------
# Live incus integration (skipped when incus is unavailable)
# --------------------------------------------------------------------------

def _incus_available() -> bool:
    if os.environ.get('CLUSTER_LIVE_INCUS_TESTS') != '1':
        return False
    env = dict(os.environ)
    env["PATH"] = env.get("PATH", "") + ":/usr/sbin"
    try:
        proc = subprocess.run(["sudo", "incus", "list"],
                              capture_output=True, text=True, env=env, timeout=30)
        return proc.returncode == 0
    except Exception:
        return False


INCUS_AVAILABLE = _incus_available()
requires_incus = pytest.mark.skipif(not INCUS_AVAILABLE,
                                    reason="disposable live Incus fixture not explicitly selected/available")


@requires_incus
def test_incus_adapter_lists_tribe_agent_instances(tmp_path):
    adapter = IncusAdapter(profile="tribe-agent", project="default")
    instances = {inst["name"]: inst for inst in adapter.list_instances()}
    assert "iso-a" in instances
    assert "iso-b" in instances
    for inst in instances.values():
        assert inst["state"] in ("running", "stopped")
        assert set(inst["budgets"]) == BUDGET_FIELDS


@requires_incus
def test_incus_cli_status_iso_a_undeclared(tmp_path, capsys):
    # The historical fixtures keep their original profile; onboarding uses
    # a separate daimon-agent profile and must not change these bodies.
    # Empty tmp state_dir -> no specs -> iso-a must classify as undeclared.
    adapter = IncusAdapter(profile="tribe-agent", project="default")
    rc = cli.run(["--config", str(CONFIG_PATH), "--state-dir", str(tmp_path),
                  "status", "iso-a", "--json"], adapter=adapter)
    assert rc == 0
    rec = json.loads(capsys.readouterr().out)
    assert rec["schema"] == STATUS_SCHEMA
    assert rec["name"] == "iso-a"
    assert rec["state"] == "undeclared"
    assert rec["resource_fence_state"] == "unknown"
    assert rec["hmk_integrity"] == "unknown"
