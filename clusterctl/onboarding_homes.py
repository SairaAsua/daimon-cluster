"""Accepted-body home hook; reuse worker progress, not a new watcher or stage.

The hook never activates a body or replays its onboarding. Host-approved home
placements bind to the existing owner and complete plan digest. Installation is
delivered by a typed host provider under that placement's existing resource
grant; the hook itself cannot run arbitrary source-supplied commands.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .onboarding import OnboardingError
from .onboarding_progress import Progress


def selected_bundle(repository, commit, destination):
    """Bundle an approved commit without changing the development checkout."""
    import subprocess

    reference = "refs/daimon-home/bundle-" + uuid.uuid4().hex
    subprocess.run(
        ["git", "-C", str(repository), "update-ref", reference, commit, "0" * 40],
        check=True,
        capture_output=True,
    )
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "bundle",
                "create",
                str(destination),
                reference,
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        Path(destination).chmod(0o600)
    finally:
        # A concurrent change is preserved, never force-deleted.
        subprocess.run(
            ["git", "-C", str(repository), "update-ref", "-d", reference, commit],
            check=True,
            capture_output=True,
        )


class AcceptedHomes:
    def __init__(self, *, progress, worker_uid, placements, state, provider):
        self.progress = Path(progress)
        self.worker_uid = worker_uid
        self.placements = placements
        self.provider = provider
        self.state = Path(state)
        from .onboarding import private_directory

        private_directory(self.state, create=True)
        self.path = self.state / "home-jobs.sqlite"
        if not self.path.exists():
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            os.close(descriptor)
        if (
            self.path.is_symlink()
            or self.path.stat().st_uid != worker_uid
            or self.path.stat().st_mode & 0o077
        ):
            raise OnboardingError("trusted_home_job_store_required")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS homes(name TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                "plan TEXT NOT NULL, selection TEXT NOT NULL, state TEXT NOT NULL)"
            )

    def reconcile_committed(self, name):
        """Home admission is independent of still-pending human acceptance."""
        placement = self.placements.get(name)
        if placement is None:
            return {"state": "not-selected"}
        try:
            value = Progress(self.progress, worker_uid=self.worker_uid).read(
                name, owner=placement['owner'])
        except FileNotFoundError:
            return {"state": "waiting", "reason": "home_admission_unconfirmed"}
        return self(value)

    def __call__(self, value):
        value = Progress.validate(value)
        placement = self.placements.get(value["name"])
        if not placement or 'matrix' not in value['completed_steps']:
            return {"state": "not-selected"}
        if placement['owner'] != value['owner'] or placement['plan_digest'] != value['plan_digest']:
            raise OnboardingError('accepted_home_placement_required')
        committed = Progress(self.progress, worker_uid=self.worker_uid).read(
            value['name'], owner=placement['owner'])
        if (
            os.geteuid() != self.worker_uid
            or placement["owner"] != value["owner"]
            or placement["plan_digest"] != value["plan_digest"]
            or committed['plan_digest'] != value['plan_digest']
            or 'matrix' not in committed['completed_steps']
        ):
            raise OnboardingError("accepted_home_placement_required")
        selected = hashlib.sha256(
            json.dumps(placement, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT owner,plan,selection,state FROM homes WHERE name=?",
                (value["name"],),
            ).fetchone()
            if old and old[:2] != (value["owner"], value["plan_digest"]):
                raise OnboardingError("existing_home_job_preserved")
            if old and old[2] == selected and old[3] == "complete":
                return {"state": "complete", "retried": True}
            db.execute(
                "INSERT OR REPLACE INTO homes VALUES(?,?,?,?,?)",
                (
                    value["name"],
                    value["owner"],
                    value["plan_digest"],
                    selected,
                    "dispatching",
                ),
            )
            db.commit()
        # Provider owns exact incarnation/resource checks and idempotent guest
        # writes. A lost receipt repeats the same bounded placement, not a new
        # body, grant, public artifact or native model turn.
        receipt = self.provider.reconcile(placement)
        if (
            not isinstance(receipt, dict)
            or receipt.get("state") != "complete"
            or receipt.get("selection_digest") != selected
        ):
            return {"state": "waiting", "reason": "home_delivery_unconfirmed"}
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "UPDATE homes SET state=? WHERE name=? AND owner=? AND plan=? AND selection=?",
                (
                    "complete",
                    value["name"],
                    value["owner"],
                    value["plan_digest"],
                    selected,
                ),
            )
            db.commit()
        return {"state": "complete", "retried": False}


class IncusProvider:
    """Typed delivery into the already accepted, plan-owned agent namespace."""

    def __init__(self, store, backend):
        self.store, self.backend = store, backend

    def reconcile(self, placement):
        from . import being_seed
        from .onboarding import private_directory
        # Home callbacks run independently of acceptance. Their receiving calls
        # must nevertheless own the same job lock and resolve the current
        # runtime after acquiring it, just like the ordinary worker tick.
        directory = private_directory(self.store.directory(placement['name']))
        with being_seed._locked(directory):
            backend = self.backend() if callable(self.backend) else self.backend
            return IncusProvider(self.store, backend)._reconcile(placement)

    def _reconcile(self, placement):
        from .homes.provision import regular, sha
        from .onboarding import digest, validate_plan
        import tempfile

        record = self.store._load(placement["name"])
        plan = validate_plan(record["plan"])
        fingerprint = digest(plan)
        if (
            fingerprint != placement["plan_digest"]
            or not self.backend.authorize(plan, fingerprint)
            or self.backend._environment(plan).state != "complete"
        ):
            raise OnboardingError("accepted_home_environment_required")
        from .onboarding_managed import ManagedRuntime
        managed = ManagedRuntime(self.backend)
        if managed.observe(plan).state != 'complete':
            raise OnboardingError('home_admission_unconfirmed')
        expected = managed._expected(plan)
        delivery = validate_delivery(placement['delivery'])
        if (expected['being_ref'] != delivery['owner_being_ref']
                or expected['being_ref'] != delivery['home']['owner_being_ref']):
            raise OnboardingError('home_admission_owner_conflict')
        source = Path(placement["provider_file"])
        if sha(regular(source)) != placement["provider_sha256"]:
            raise OnboardingError("qualified_home_provider_required")
        declaration = Path(placement["declaration_file"])
        raw = regular(declaration)
        if sha(raw) != placement["declaration_sha256"]:
            raise OnboardingError("qualified_home_placement_required")
        value = json.loads(raw)
        if value["skills_commit"] != placement["skills_commit"]:
            raise OnboardingError("qualified_home_skill_required")
        instance = self.backend.instance(plan)
        run = self.backend.run
        destination = "/opt/daimon-home-provider"
        run(["exec", instance, "--", "mkdir", "-p", destination])
        run(
            [
                "file",
                "push",
                str(source),
                instance + destination + "/provision.py",
                "--uid",
                "0",
                "--gid",
                "0",
                "--mode",
                "0644",
            ]
        )
        run(
            [
                "file",
                "push",
                str(declaration),
                instance + destination + "/declaration.json",
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--mode",
                "0600",
            ]
        )
        repository = Path(placement["repository"])
        with tempfile.TemporaryDirectory(
            prefix="home-skill-bundle-", dir=self.store.root
        ) as temporary:
            bundle = Path(temporary) / "skills.bundle"
            selected_bundle(repository, placement["skills_commit"], bundle)
            run(
                [
                    "file",
                    "push",
                    str(bundle),
                    instance + destination + "/skills.bundle",
                    "--uid",
                    "1000",
                    "--gid",
                    "1000",
                    "--mode",
                    "0600",
                ]
            )
        run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "python3",
                destination + "/provision.py",
                "--home",
                "/home/agent",
                "--repository",
                "/home/agent/.local/state/daimon-home/skills-source",
                "--source-bundle",
                destination + "/skills.bundle",
            ]
        )
        run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "python3",
                destination + "/provision.py",
                "--home",
                "/home/agent",
                "--declaration",
                destination + "/declaration.json",
                "--repository",
                "/home/agent/.local/state/daimon-home/skills-source",
            ]
        )
        self.deliver(placement, value, instance)
        selected = hashlib.sha256(
            json.dumps(placement, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {"state": "complete", "selection_digest": selected}

    def deliver(self, placement, declaration, instance):
        """Only verified service/routing/grant delivery yields completion."""
        from .homes.host import ensure_proxy, guest_unit
        from .homes.provision import sha
        from .onboarding_release import regular
        import tempfile
        import subprocess
        import pwd
        from urllib.parse import urlsplit

        from .homes.service import validate_config

        details = validate_delivery(placement["delivery"])
        home = details["home"]
        config_path = Path(details["gateway_config"])
        uid, gid = details["gateway_uid"], details["gateway_gid"]
        original = regular(config_path, uid=uid)
        config = validate_config(json.loads(original), credential_uid=uid)
        if home["owner_being_ref"] != details["owner_being_ref"]:
            raise OnboardingError("home_delivery_owner_conflict")
        binding = declaration["binding"]
        access = binding.get("access", {})
        if (
            access.get("home_ref") != details["home_ref"]
            or access.get("owner_url") != f"http://127.0.0.1:{config['owner_port']}"
            or binding.get("public_url") != home["public_url"]
            or binding.get("vpn_url") != home["vpn_url"]
        ):
            raise OnboardingError("matching_home_receiving_binding_required")
        validate_config(
            {**config, "homes": {**config["homes"], details["home_ref"]: home}},
            credential_uid=uid,
        )
        # Transport only the two resource-scoped home credentials, not any
        # Matrix, account, bot, SSH or custody material.
        destinations = access
        for field in ("gateway_token_file", "owner_token_file"):
            destination = Path(destinations[field])
            if (
                destination.parent != Path("/home/agent/.config/daimon-home")
                or destination.name
                != {
                    "gateway_token_file": "gateway.key",
                    "owner_token_file": "owner.key",
                }[field]
            ):
                raise OnboardingError("dedicated_home_key_destination_required")
            source = Path(home[field])
            if source.parent != config_path.parent / "keys":
                raise OnboardingError("dedicated_home_key_source_required")
            regular(source, uid=uid)
            if source.stat().st_mode & 0o077:
                raise OnboardingError("private_home_key_required")
            self.backend.run(
                [
                    "file",
                    "push",
                    str(source),
                    instance + str(destination),
                    "--uid",
                    "1000",
                    "--gid",
                    "1000",
                    "--mode",
                    "0600",
                ]
            )
        with tempfile.TemporaryDirectory(
            prefix="home-service-", dir=self.store.root
        ) as temporary:
            unit = Path(temporary) / "daimon-home.service"
            unit.write_bytes(guest_unit(declaration["binding"]))
            unit.chmod(0o600)
            self.backend.run(
                [
                    "file",
                    "push",
                    str(unit),
                    instance + "/opt/daimon-home-provider/daimon-home.service",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--mode",
                    "0600",
                ]
            )
        args = [
            "exec",
            instance,
            "--",
            "python3",
            "/opt/daimon-home-provider/provision.py",
            "--unit-file",
            "/opt/daimon-home-provider/daimon-home.service",
        ]
        if details["previous_unit_sha256"]:
            args += ["--previous-unit-sha256", details["previous_unit_sha256"]]
        self.backend.run(args)
        self.backend.run(["exec", instance, "--", "systemctl", "daemon-reload"])
        self.backend.run(
            [
                "exec",
                instance,
                "--",
                "systemctl",
                "enable",
                "--now",
                "daimon-home.service",
            ]
        )
        self.backend.run(
            ["exec", instance, "--", "systemctl", "restart", "daimon-home.service"]
        )
        self.backend.run(
            [
                "exec",
                instance,
                "--",
                "systemctl",
                "is-active",
                "--quiet",
                "daimon-home.service",
            ]
        )
        port = urlsplit(home["backend"]).port
        ensure_proxy(
            self.backend.run,
            instance,
            "daimon-home-public",
            {
                "type": "proxy",
                "bind": "host",
                "listen": f"tcp:127.0.0.1:{port}",
                "connect": "tcp:127.0.0.1:"
                + str(declaration["binding"]["public_port"]),
            },
        )
        owner_port = config["owner_port"]
        ensure_proxy(
            self.backend.run,
            instance,
            "daimon-home-owner",
            {
                "type": "proxy",
                "bind": "instance",
                "listen": f"tcp:127.0.0.1:{owner_port}",
                "connect": f"tcp:127.0.0.1:{owner_port}",
            },
        )
        # Gateway registration runs under its existing owner, retaining epoch
        # bindings and exact config CAS. The worker has no reader token shortcut.
        row = config_path.parent / (
            "home-row-" + sha(json.dumps(home, sort_keys=True).encode()) + ".json"
        )
        if not row.exists():
            fd = os.open(
                row, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as stream:
                os.fchown(stream.fileno(), uid, gid)
                stream.write(json.dumps(home).encode())
        if json.loads(regular(row, uid=uid)) != home:
            raise OnboardingError("existing_home_registration_row_preserved")
        argv = [
            "/usr/sbin/runuser",
            "-u",
            pwd.getpwuid(uid).pw_name,
            "--",
            details["gateway_python"],
            "-m",
            "clusterctl.homes.host",
            "register",
            "--config",
            str(config_path),
            "--reference",
            details["home_ref"],
            "--row",
            str(row),
            "--previous-digest",
            sha(original),
        ]
        registered = json.loads(
            subprocess.run(
                argv,
                cwd=details["gateway_code"],
                capture_output=True,
                check=True,
                timeout=60,
            ).stdout
        )
        if registered["status"] != "unchanged":
            subprocess.run(
                ["systemctl", "restart", "daimon-home-access.service"],
                capture_output=True,
                check=True,
                timeout=40,
            )
        self.backend.run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "/home/agent/.local/bin/daimon-home",
                "sync",
            ]
        )
        # An actual external projection, not only a running process/file, proves
        # the selected home is routed to the common authority and usable.
        import urllib.request

        with urllib.request.urlopen(
            home["public_url"] + "/catalog.json", timeout=20
        ) as response:
            value = json.load(response)
            if (
                response.status != 200
                or value.get("home_ref") != details["home_ref"]
                or value.get("access_contract") != "dm.resource-access/v1"
                or not isinstance(value.get("entries"), list)
            ):
                raise OnboardingError("home_frontend_delivery_unconfirmed")


def configure(path, *, progress, store, backend, worker_uid):
    from . import being_seed
    import re

    value = being_seed._read(Path(path))
    if (
        set(value) != {"schema", "state", "placements"}
        or value["schema"] != "dm.home-onboarding.host/v1"
        or not isinstance(value["placements"], dict)
        or not Path(value["state"]).is_absolute()
    ):
        raise OnboardingError("invalid_home_onboarding_configuration")
    required = {
        "name",
        "owner",
        "plan_digest",
        "provider_file",
        "provider_sha256",
        "declaration_file",
        "declaration_sha256",
        "repository",
        "skills_commit",
        "delivery",
    }
    for name, placement in value["placements"].items():
        if (
            not being_seed.NAME.fullmatch(name)
            or set(placement) != required
            or placement["name"] != name
            or not being_seed.NAME.fullmatch(placement["owner"])
            or any(
                not isinstance(placement[key], str)
                or not Path(placement[key]).is_absolute()
                for key in ("provider_file", "declaration_file", "repository")
            )
            or any(
                not isinstance(placement[key], str)
                or not re.fullmatch("[a-f0-9]{64}", placement[key])
                for key in ("plan_digest", "provider_sha256", "declaration_sha256")
            )
            or not isinstance(placement["skills_commit"], str)
            or not re.fullmatch("[a-f0-9]{40}", placement["skills_commit"])
        ):
            raise OnboardingError("invalid_home_onboarding_placement")
        validate_delivery(placement["delivery"])
    return AcceptedHomes(
        progress=progress,
        worker_uid=worker_uid,
        placements=value["placements"],
        state=Path(value["state"]),
        provider=IncusProvider(store, backend),
    )


def validate_delivery(value):
    import re

    fields = {
        "home",
        "home_ref",
        "owner_being_ref",
        "gateway_config",
        "gateway_uid",
        "gateway_gid",
        "gateway_python",
        "gateway_code",
        "previous_unit_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not isinstance(value["home"], dict)
        or not isinstance(value["home_ref"], str)
        or not re.fullmatch("[A-Za-z0-9:_-]{1,128}", value["home_ref"])
        or any(
            type(value[key]) is not int or value[key] < 0
            for key in ("gateway_uid", "gateway_gid")
        )
        or any(
            not isinstance(value[key], str)
            or not Path(value[key]).is_absolute()
            or ".." in Path(value[key]).parts
            for key in ("gateway_config", "gateway_python", "gateway_code")
        )
        or not isinstance(value["owner_being_ref"], str)
        or value["home"].get("owner_being_ref") != value["owner_being_ref"]
        or value["previous_unit_sha256"] is not None
        and not re.fullmatch("[a-f0-9]{64}", value["previous_unit_sha256"])
    ):
        raise OnboardingError("invalid_home_delivery_placement")
    return value
