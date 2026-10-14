"""Accepted-only provisioning and preserved owner files/artifact history."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from clusterctl.homes.provision import owner_pointer, provision, sha
from clusterctl.onboarding import JobStore, OnboardingError
from clusterctl.onboarding_homes import AcceptedHomes
from clusterctl.onboarding_progress import Progress
from clusterctl.onboarding_worker import Worker
from tests.test_onboarding import FixtureBackend, plan


def test_offline_approved_source_works_after_checkout_advances_and_preserves_origin(
    tmp_path,
):
    from clusterctl.onboarding_homes import selected_bundle
    from clusterctl.homes.provision import initialize_source

    repo = tmp_path / "development"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)

    def git(*args):
        return (
            subprocess.check_output(
                ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )

    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Fixture")
    (repo / "selected.txt").write_text("Approved source")
    git("add", "selected.txt")
    git("commit", "-m", "Approved")
    selected = git("rev-parse", "HEAD")
    (repo / "later.txt").write_text("Later unrelated development")
    git("add", "later.txt")
    git("commit", "-m", "Later")
    latest = git("rev-parse", "HEAD")
    bundle = tmp_path / "selected.bundle"
    selected_bundle(repo, selected, bundle)
    assert git("rev-parse", "HEAD") == latest
    assert git("for-each-ref", "refs/daimon-home") == ""
    home = tmp_path / "receiver"
    home.mkdir(mode=0o700)
    cache = home / ".local/state/daimon-home/skills-source"
    initialize_source(home, cache, bundle)
    initialize_source(home, cache, bundle)

    def receiving(*args):
        return (
            subprocess.check_output(["git", "-C", str(cache), *args]).decode().strip()
        )

    assert (
        receiving("config", "--get", "remote.origin.url")
        == "https://github.com/AlterMundi/Skills.git"
    )
    assert receiving("show", selected + ":selected.txt") == "Approved source"
    subprocess.run(
        [
            "git",
            "-C",
            str(cache),
            "remote",
            "set-url",
            "origin",
            "https://another.example/repository",
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="origin_preserved"):
        initialize_source(home, cache, bundle)
    assert (
        receiving("config", "--get", "remote.origin.url")
        == "https://another.example/repository"
    )


def test_home_hook_requires_committed_admission_and_retries_same_placement(tmp_path):
    progress_path = tmp_path / "progress"
    progress_path.mkdir(mode=0o750)
    progress = Progress(progress_path, worker_uid=os.geteuid())
    backend = FixtureBackend()
    store = JobStore(tmp_path / "jobs")
    job = plan()
    pending = store.submit(job, backend)
    selection = {
        "owner": pending["owner"],
        "plan_digest": pending["plan_digest"],
        "home": "selected-home",
    }
    calls = []

    class Provider:
        def reconcile(self, placement):
            calls.append(placement)
            return {
                "state": "complete",
                "selection_digest": hashlib.sha256(
                    json.dumps(
                        placement, sort_keys=True, separators=(",", ":")
                    ).encode()
                ).hexdigest(),
            }

    homes = AcceptedHomes(
        progress=progress_path,
        worker_uid=os.geteuid(),
        placements={"eko": selection},
        state=tmp_path / "homes",
        provider=Provider(),
    )
    assert homes(pending)["state"] == "not-selected"
    worker = Worker(store, lambda: backend, publish=progress.publish)
    for _ in range(6):
        worker.once()
    accepted = progress.read("eko", owner="sai")
    assert 'matrix' in accepted['completed_steps'] and accepted['active'] is False
    assert homes(accepted)["state"] == "complete" and len(calls) == 1
    assert homes(accepted)["retried"] is True and len(calls) == 1
    selection["owner"] = "another-human"
    with pytest.raises(OnboardingError, match="placement_required"):
        homes(accepted)
    selection["owner"] = "sai"
    progress._file("eko").unlink()
    with pytest.raises(FileNotFoundError):
        homes(accepted)


def test_committed_home_reconciliation_survives_unrelated_acceptance_failure():
    from types import SimpleNamespace
    calls = []
    class Homes:
        def reconcile_committed(self, name):
            calls.append(name)
    def tick(*args):
        raise OnboardingError('unrelated_acceptance_failure')
    worker = Worker(SimpleNamespace(tick=tick), lambda: None, homes=Homes())
    assert worker._tick('eko')['state'] == 'attention-required'
    assert calls == ['eko']


def test_local_provisioning_keeps_context_artifacts_and_exact_predecessors(tmp_path):
    home = tmp_path / "owner"
    home.mkdir(mode=0o700)
    context = home / ".codex"
    context.mkdir(mode=0o775)
    context.chmod(0o775)
    pointer = context / "AGENTS.md"
    pointer.write_bytes(b"Original identity and instructions\n")
    pointer.chmod(0o600)
    saved = home / ".local/share/daimon-home/objects"
    saved.mkdir(parents=True)
    saved.parent.chmod(0o700)
    (saved / "original.bin").write_bytes(b"Unchanged selected history")
    declaration = {
        "schema": "dm.home.receiving/v1",
        "skills_commit": "a" * 40,
        "previous": {"pointer": sha(pointer.read_bytes())},
        "binding": {
            "name": "Home",
            "public_url": "https://home.example",
            "vpn_url": "https://private-home.example",
            "store": str(saved.parent),
            "public_port": 8801,
            "vpn_port": 8811,
            "ring": [],
        },
    }

    def installer(repository, commit, receiving, state):
        package = receiving / ".agents/skills/daimon-home/scripts"
        package.mkdir(parents=True, exist_ok=True)
        (package / "home.py").write_text(
            'import argparse,json\np=argparse.ArgumentParser();p.add_argument("--binding");p.add_argument("command");a=p.parse_args();print(json.dumps(json.load(open(a.binding))))\n'
        )
        return commit

    first = provision(home, declaration, repository=tmp_path, install=installer)
    before = {
        str(path): path.read_bytes()
        for path in (
            pointer,
            home / ".config/daimon-home/binding.json",
            home / ".local/bin/daimon-home",
        )
    }
    assert provision(home, declaration, repository=tmp_path, install=installer) == first
    assert all(path.read_bytes() == before[str(path)] for path in map(Path, before))
    assert (saved / "original.bin").read_bytes() == b"Unchanged selected history"
    assert pointer.read_bytes().startswith(b"Original identity and instructions\n")
    assert pointer.read_text().count("# Artifact home binding") == 1
    assert context.stat().st_mode & 0o777 == 0o775
    binding = home / ".config/daimon-home/binding.json"
    binding.write_text("human-selected custom binding")
    with pytest.raises(ValueError, match="preserved"):
        provision(home, declaration, repository=tmp_path, install=installer)
    assert binding.read_text() == "human-selected custom binding"


def test_fresh_store_exists_before_service_install(tmp_path):
    home = tmp_path / "owner"
    home.mkdir(mode=0o700)
    store = home / ".local/share/daimon-home"
    declaration = {
        "schema": "dm.home.receiving/v1",
        "skills_commit": "a" * 40,
        "previous": {},
        "binding": {"public_url": "https://home.example", "store": str(store)},
    }

    def installer(repository, commit, receiving, state):
        assert store.is_dir() and store.stat().st_mode & 0o777 == 0o700
        helper = receiving / ".agents/skills/daimon-home/scripts/home.py"
        helper.parent.mkdir(parents=True)
        helper.write_text(
            'import argparse,json\np=argparse.ArgumentParser();p.add_argument("--binding");p.add_argument("command");a=p.parse_args();print(json.dumps(json.load(open(a.binding))))\n'
        )
        return commit

    provision(home, declaration, repository=tmp_path, install=installer)


def test_home_pointer_preserves_newer_context_and_custom_or_symlink_files(tmp_path):
    original = b"Owner identity\n"
    installed = owner_pointer(original, "https://home.example")
    extended = (
        installed + b"\n# Current memory policy\nHuman-authorized contextual recall.\n"
    )
    assert owner_pointer(extended, "https://home.example") == extended
    with pytest.raises(ValueError, match="custom_home_pointer"):
        owner_pointer(
            original + b"\n# Artifact home binding\n\nA custom declaration.\n",
            "https://home.example",
        )
    from clusterctl.homes.provision import replace

    backups = tmp_path / "backups"
    backups.mkdir()
    protected = tmp_path / "original"
    protected.write_bytes(original)
    alias = tmp_path / "alias"
    alias.symlink_to(protected)
    with pytest.raises(OSError):
        replace(
            alias, b"changed", previous=sha(original), home=tmp_path, backups=backups
        )
    assert protected.read_bytes() == original


def test_typed_delivery_registers_shared_authority_and_retries_without_rebinding(
    tmp_path, monkeypatch
):
    from contextlib import nullcontext
    from copy import deepcopy
    import io
    from types import SimpleNamespace

    from clusterctl.homes.host import register
    from clusterctl.homes.policy import Actor
    from clusterctl.onboarding_homes import IncusProvider
    from tests.test_home_host import configuration, write

    config = configuration(tmp_path)
    row = config["homes"].pop("one")
    for field, name in (
        ("owner_token_file", "owner.key"),
        ("gateway_token_file", "gateway.key"),
    ):
        row[field] = write(tmp_path / "keys" / name, b"fixture-" + name.encode())
    file = tmp_path / "config.json"
    write(file, json.dumps(config).encode())
    details = {
        "home": row,
        "home_ref": "one",
        "owner_being_ref": "being-one",
        "gateway_config": str(file),
        "gateway_uid": os.geteuid(),
        "gateway_gid": os.getegid(),
        "gateway_python": "/qualified/python",
        "gateway_code": str(tmp_path),
        "previous_unit_sha256": None,
    }
    declaration = {
        "binding": {
            "public_url": row["public_url"],
            "vpn_url": row["vpn_url"],
            "store": "/home/agent/.local/share/daimon-home",
            "public_port": 8801,
            "access": {
                "home_ref": "one",
                "owner_url": "http://127.0.0.1:8821",
                "owner_token_file": "/home/agent/.config/daimon-home/owner.key",
                "gateway_token_file": "/home/agent/.config/daimon-home/gateway.key",
            },
        }
    }
    devices, files, executions, host_restarts = {}, {}, [], []

    class Authority:
        def __init__(self, *a, **k):
            pass

        def actor(self, ref):
            return Actor(ref, "being", "a" * 64, "Existing")

    class Backend:
        def run(self, argv):
            if argv[0] == "query":
                return json.dumps({"devices": devices})
            if argv[0] == "file":
                files[argv[3]] = Path(argv[2]).read_bytes()
            elif argv[0] == "config":
                devices[argv[4]] = {
                    key: value for key, value in (v.split("=", 1) for v in argv[6:])
                }
                devices[argv[4]]["type"] = argv[5]
            else:
                executions.append(argv)
            return ""

    def host_run(argv, **kwargs):
        if argv[0] == "systemctl":
            host_restarts.append(argv)
            return SimpleNamespace(stdout=b"")
        reference = argv[argv.index("--reference") + 1]
        result = register(file, reference, row, previous_digest=argv[-1])
        return SimpleNamespace(stdout=json.dumps(result).encode())

    class Response(io.BytesIO):
        status = 200

    monkeypatch.setattr("clusterctl.homes.authority.NativeAuthority", Authority)
    monkeypatch.setattr("subprocess.run", host_run)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **k: nullcontext(
            Response(
                json.dumps(
                    {
                        "home_ref": "one",
                        "access_contract": "dm.resource-access/v1",
                        "entries": [],
                    }
                ).encode()
            )
        ),
    )
    provider = IncusProvider(SimpleNamespace(root=tmp_path), Backend())
    broken = deepcopy(declaration)
    broken["binding"]["access"]["home_ref"] = "other"
    with pytest.raises(OnboardingError, match="matching_home_receiving"):
        provider.deliver({"delivery": details}, broken, "accepted-instance")
    assert not files and not devices
    provider.deliver({"delivery": details}, declaration, "accepted-instance")
    assert json.loads(file.read_bytes())["homes"]["one"] == row
    assert (
        files["accepted-instance/home/agent/.config/daimon-home/owner.key"]
        == b"fixture-owner.key"
    )
    assert devices["daimon-home-owner"]["bind"] == "instance"
    assert devices["daimon-home-public"]["bind"] == "host"
    assert any(argv[-1] == "sync" for argv in executions)
    provider.deliver({"delivery": details}, declaration, "accepted-instance")
    assert len(host_restarts) == 1
    assert len(devices) == 2


def test_worker_preflight_checks_selected_gateway_uid_without_reading_keys(tmp_path, monkeypatch):
    from clusterctl.homes import service
    from tests.test_home_host import configuration
    config = configuration(tmp_path)
    owner = os.geteuid()
    # The root worker differs from the selected gateway owner; service reads
    # still require the current UID, while worker preflight checks metadata.
    monkeypatch.setattr(service.os, 'geteuid', lambda: owner + 1)
    with pytest.raises(ValueError, match='private_home_credential_required'):
        service.validate_config(config)
    assert service.validate_config(config, credential_uid=owner) == config
    with pytest.raises(ValueError, match='private_home_credential_required'):
        service.validate_config(config, credential_uid=owner + 1)
    def no_read(*args):
        raise AssertionError('metadata preflight must not read credentials')
    monkeypatch.setattr(service, 'private_text', no_read)
    assert service.validate_config(config, credential_uid=owner) == config


def test_provider_refuses_absent_or_different_admitted_being_before_guest_writes(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from clusterctl.onboarding import Observation, digest
    from clusterctl.onboarding_homes import IncusProvider
    job = plan()
    admission = {'state': 'absent', 'being_ref': 'being-other'}
    class Managed:
        def __init__(self, backend):
            pass
        def observe(self, selected):
            assert selected == job
            return Observation(admission['state'])
        def _expected(self, selected):
            return {'being_ref': admission['being_ref']}
    monkeypatch.setattr('clusterctl.onboarding_managed.ManagedRuntime', Managed)
    details = {'home': {'owner_being_ref': 'being-selected'}, 'owner_being_ref': 'being-selected'}
    monkeypatch.setattr('clusterctl.onboarding_homes.validate_delivery', lambda value: value)
    backend = SimpleNamespace(authorize=lambda *args: True,
                              _environment=lambda p: Observation('complete'))
    store = JobStore(tmp_path / 'jobs')
    store.submit(job, backend)
    provider = IncusProvider(store, backend)
    placement = {'name': job['name'], 'plan_digest': digest(job), 'delivery': details}
    with pytest.raises(OnboardingError, match='home_admission_unconfirmed'):
        provider.reconcile(placement)
    admission['state'] = 'complete'
    with pytest.raises(OnboardingError, match='home_admission_owner_conflict'):
        provider.reconcile(placement)
