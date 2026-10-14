"""Host-owned onboarding configuration and exact Incus body reconciliation.

Neither participant labels nor files writable by intake authorize execution.
Only an owner-local grant of the exact plan is accepted. Guest stages use the
maintained installer; no command from a source archive is executed.
"""
from __future__ import annotations

import json
import hashlib
import inspect
import math
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import being_seed, onboarding_code_successor, onboarding_consent, onboarding_input, onboarding_mounts, onboarding_release
from .onboarding_custody import FirstCustody, document
from .onboarding import Observation, OnboardingError, digest, private_directory, validate_plan
from .onboarding_progress import Progress


def sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


RUNTIME_SELECTION_KEYS = frozenset({'runtime_code', 'runtime_digest', 'runtime_by_name'})


class CurrentHostConfig:
    """Refresh verified runtime selectors without moving a warm worker's roots.

    Exact changed configuration is fully validated once. Runtime selection may
    advance; jobs/grants/account/admission/Telegram directories, home placements
    and other process configuration require their separate explicit lifecycle.
    """
    def __init__(self, path: Path):
        self.path = path
        self._value = being_seed._read(path)
        self._config = HostConfig.load(path, expected_value=self._value)
        if being_seed._read(path) != self._value:
            raise OnboardingError('onboarding_worker_configuration_changed')
        self._fixed = {key: value for key, value in self._value.items() if key not in RUNTIME_SELECTION_KEYS}
        self._lock = threading.Lock()

    def current(self) -> HostConfig:
        with self._lock:
            return self._current()

    def _current(self) -> HostConfig:
        value = being_seed._read(self.path)
        if value == self._value:
            return self._config
        if {key: item for key, item in value.items() if key not in RUNTIME_SELECTION_KEYS} != self._fixed:
            raise OnboardingError('onboarding_worker_configuration_restart_required')
        candidate = HostConfig.load(self.path, expected_value=value)
        if being_seed._read(self.path) != value:
            raise OnboardingError('onboarding_worker_configuration_changed')
        self._value, self._config = value, candidate
        return candidate


@dataclass(frozen=True)
class HostConfig:
    jobs: Path
    grants: Path
    native_image: str
    browser_image: str
    release_digest: str
    pool: str
    profile: str
    concurrency: int
    progress: Path | None = None
    inputs: Path | None = None
    code: Path | None = None
    views: Path | None = None
    consent_state: Path | None = None
    consent_uid: int | None = None
    qualification: bool = False
    custody: Path | None = None
    custody_grants: Path | None = None
    admission: Path | None = None
    accounts: Path | None = None
    intake_policy: Path | None = None
    custody_policy: Path | None = None
    ssh_ingress: Path | None = None
    owner_approval_policy: Path | None = None
    runtime_code: Path | None = None
    runtime_digest: str | None = None
    peer: Path | None = None
    runtime_by_name: dict[str, tuple[Path, str]] | None = None
    telegram_code: Path | None = None
    telegram_digest: str | None = None
    browser_artifact: dict[str, str] | None = None

    @classmethod
    def load(cls, path: Path, *, expected_value: dict | None = None) -> HostConfig:
        value = being_seed._read(path)
        if expected_value is not None and value != expected_value:
            raise OnboardingError('onboarding_worker_configuration_changed')
        consent_keys = {"consent_state", "consent_uid"}
        custody_keys = {"custody", "custody_grants"}
        runtime_keys = {"runtime_code", "runtime_digest"}
        telegram_keys = {"telegram_code", "telegram_digest"}
        if (set(value) - consent_keys - custody_keys - runtime_keys - telegram_keys - {"qualification", "admission", "accounts", "intake_policy", "custody_policy", "ssh_ingress", "owner_approval_policy", "peer", "runtime_by_name", "browser_artifact"} != {"schema", "jobs", "grants", "progress", "native_image", "browser_image",
                           "release_digest", "pool", "profile", "concurrency", "inputs", "code", "views"}
                or value.get("schema") != "cluster-onboarding-host/v1"
                or any(not sha(value[key]) for key in ("native_image", "browser_image", "release_digest"))
                or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                       for key in ("pool", "profile"))
                or type(value["concurrency"]) is not int or not 1 <= value["concurrency"] <= 8
                or type(value.get("qualification", False)) is not bool):
            raise OnboardingError("invalid_onboarding_host_configuration")
        directories = {}
        for key in ("jobs", "grants", "inputs", "views"):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError("invalid_onboarding_host_configuration")
            directories[key] = private_directory(Path(value[key]))
        if len(set(directories.values())) != len(directories):
            raise OnboardingError("invalid_onboarding_host_configuration")
        if not isinstance(value["progress"], str) or not Path(value["progress"]).is_absolute():
            raise OnboardingError("invalid_onboarding_host_configuration")
        progress = Path(value["progress"])
        Progress(progress, worker_uid=progress.stat().st_uid)._directory()
        if progress.stat().st_uid != path.stat().st_uid or progress in directories.values():
            raise OnboardingError("invalid_onboarding_host_configuration")
        if not isinstance(value["code"], str) or not Path(value["code"]).is_absolute():
            raise OnboardingError("invalid_onboarding_host_configuration")
        code = Path(value["code"])
        onboarding_release.verify(code, value["release_digest"], uid=path.stat().st_uid)
        runtime_code, runtime_digest = None, None
        if runtime_keys & set(value):
            if (not runtime_keys <= set(value) or not sha(value['runtime_digest'])
                    or not isinstance(value['runtime_code'], str)
                    or not Path(value['runtime_code']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            runtime_code, runtime_digest = Path(value['runtime_code']), value['runtime_digest']
            onboarding_code_successor.verify(runtime_code, runtime_digest, code,
                                             value['release_digest'], uid=path.stat().st_uid)
        consent_state, consent_uid = None, None
        telegram_code, telegram_digest = None, None
        if telegram_keys & set(value):
            if (not telegram_keys <= set(value) or not sha(value['telegram_digest'])
                    or not isinstance(value['telegram_code'], str)
                    or not Path(value['telegram_code']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            telegram_code, telegram_digest = Path(value['telegram_code']), value['telegram_digest']
            onboarding_code_successor.verify(telegram_code, telegram_digest, code,
                                             value['release_digest'], uid=path.stat().st_uid)
            from .onboarding_telegram import artifact, COMMIT, RETAINED_CURRENT_COMMIT
            # A Matrix successor preserves an already-qualified independent
            # Telegram selection; it does not require replacing that consumer.
            if artifact(telegram_code, uid=path.stat().st_uid)['commit'] not in {
                    COMMIT, RETAINED_CURRENT_COMMIT}:
                raise OnboardingError('qualified_telegram_successor_required')
        runtime_by_name = None
        if "runtime_by_name" in value:
            runtime_by_name = {}
            if not isinstance(value["runtime_by_name"], dict) or not 1 <= len(value["runtime_by_name"]) <= being_seed.MAX_SEEDS:
                raise OnboardingError("invalid_onboarding_host_configuration")
            for name, selected in value["runtime_by_name"].items():
                if (not isinstance(name, str) or not being_seed.NAME.fullmatch(name)
                    or not isinstance(selected, dict) or set(selected) != {"runtime_code", "runtime_digest"}
                    or not isinstance(selected["runtime_code"], str) or not Path(selected["runtime_code"]).is_absolute()
                    or not sha(selected["runtime_digest"])):
                    raise OnboardingError("invalid_onboarding_host_configuration")
                selected_code = Path(selected["runtime_code"])
                onboarding_code_successor.verify(selected_code, selected["runtime_digest"], code, value["release_digest"], uid=path.stat().st_uid)
                runtime_by_name[name] = (selected_code, selected["runtime_digest"])
        if consent_keys & set(value):
            if (not consent_keys <= set(value) or not isinstance(value["consent_state"], str)
                    or not Path(value["consent_state"]).is_absolute()
                    or type(value["consent_uid"]) is not int or value["consent_uid"] < 0):
                raise OnboardingError("invalid_onboarding_host_configuration")
            consent_state, consent_uid = being_seed._path(Path(value["consent_state"])), value["consent_uid"]
            info = consent_state.stat()
            if info.st_uid != consent_uid or info.st_mode & 0o077 or not consent_state.is_dir():
                raise OnboardingError("invalid_onboarding_host_configuration")
        custody, custody_grants = None, None
        if custody_keys & set(value):
            if not custody_keys <= set(value) or consent_state is None:
                raise OnboardingError("invalid_onboarding_host_configuration")
            for key in custody_keys:
                if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                    raise OnboardingError("invalid_onboarding_host_configuration")
                private_directory(Path(value[key]))
            custody, custody_grants = Path(value["custody"]), Path(value["custody_grants"])
            boundaries = set(directories.values()) | {progress, consent_state, code}
            if runtime_code is not None:
                boundaries.add(runtime_code)
            boundaries.update(row[0] for row in (runtime_by_name or {}).values())
            if telegram_code is not None:
                boundaries.add(telegram_code)
            if (any(path == other or path.is_relative_to(other) or other.is_relative_to(path)
                    for path in (custody, custody_grants) for other in boundaries)
                    or custody == custody_grants or custody.is_relative_to(custody_grants)
                    or custody_grants.is_relative_to(custody)):
                raise OnboardingError("separate_onboarding_custody_required")
        admission = None
        if 'admission' in value:
            if (custody is None or not isinstance(value['admission'], str)
                    or not Path(value['admission']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            admission = Path(value['admission'])
            being_seed._read(admission)
        accounts = None
        if 'accounts' in value:
            if (not isinstance(value['accounts'], str) or not Path(value['accounts']).is_absolute()
                    or consent_state is None):
                raise OnboardingError('invalid_onboarding_host_configuration')
            accounts = private_directory(Path(value['accounts']))
        intake_policy = None
        if 'intake_policy' in value:
            if (not isinstance(value['intake_policy'], str) or not Path(value['intake_policy']).is_absolute()
                    or consent_state is None):
                raise OnboardingError('invalid_onboarding_host_configuration')
            intake_policy = Path(value['intake_policy'])
            from .onboarding_intake import policy
            policy(intake_policy, value['release_digest'])
        custody_policy = None
        if 'custody_policy' in value:
            if (custody is None or intake_policy is None or not isinstance(value['custody_policy'], str)
                    or not Path(value['custody_policy']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            from .onboarding_custody import CustodyPolicy
            custody_policy = Path(value['custody_policy'])
            CustodyPolicy(custody_policy)
        ssh_ingress = None
        if 'ssh_ingress' in value:
            if (not isinstance(value['ssh_ingress'], str) or not Path(value['ssh_ingress']).is_absolute()
                    or consent_state is None):
                raise OnboardingError('invalid_onboarding_host_configuration')
            from .onboarding_ingress import policy as ingress_policy
            ssh_ingress = Path(value['ssh_ingress'])
            ingress_policy(ssh_ingress)
        owner_approval_policy = None
        if 'owner_approval_policy' in value:
            if (custody_policy is None or not isinstance(value['owner_approval_policy'], str)
                    or not Path(value['owner_approval_policy']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            from .onboarding_approvals import Approvals
            owner_approval_policy = Path(value['owner_approval_policy'])
            Approvals(owner_approval_policy)
        peer = None
        if 'peer' in value:
            if (custody is None or not isinstance(value['peer'], str) or not Path(value['peer']).is_absolute()):
                raise OnboardingError('invalid_onboarding_host_configuration')
            peer = Path(value['peer'])
            being_seed._read(peer)
        browser_artifact = None
        if 'browser_artifact' in value:
            from .onboarding_browser import artifact as browser_artifact_record
            browser_artifact = browser_artifact_record(value['browser_artifact'], value['browser_image'])
        return cls(directories["jobs"], directories["grants"], value["native_image"],
                   value["browser_image"], value["release_digest"], value["pool"],
                   value["profile"], value["concurrency"], progress, directories["inputs"], code, directories["views"],
                   consent_state, consent_uid, value.get("qualification", False), custody, custody_grants, admission, accounts, intake_policy, custody_policy, ssh_ingress, owner_approval_policy, runtime_code, runtime_digest, peer, runtime_by_name, telegram_code, telegram_digest, browser_artifact)

    def approved_plans(self) -> list[dict]:
        if self.intake_policy is not None:
            from .onboarding_intake import Intake
            Intake(self).once()
        private_directory(self.grants)
        plans = []
        for path in sorted(self.grants.iterdir()):
            if path.suffix != ".json" or not being_seed.NAME.fullmatch(path.stem):
                continue
            try:
                grant = being_seed._read(path)
                plan = validate_plan(grant["plan"])
                if plan["name"] == path.stem and HostBackend(self).authorize(plan, digest(plan)):
                    plans.append(plan)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return plans


class HostBackend:
    def __init__(self, config: HostConfig, *, run: Callable | None = None, input_cache=None):
        self.config = config
        self.run = run or self._run
        self.input_cache = input_cache if input_cache is not None else onboarding_input.VerificationCache()

    @staticmethod
    def _run(argv: list[str], *, timeout_seconds: float | None = None,
             input_data: str | None = None) -> str:
        # No shell, no source-supplied program, and never leak captured stderr.
        # Preserving tens of thousands of source files includes durable fsyncs.
        # Give only the typed context installation a larger finite window;
        # inventory, memory and other control commands retain their old bound.
        context_install = argv[0] == 'exec' and any(
            argv[i:i + 4] == ['execute', 'context', '--home', '/home/agent']
            for i in range(len(argv) - 3))
        if timeout_seconds is not None and (not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 65):
            raise OnboardingError('receiving_host_deadline_required')
        timeout = timeout_seconds if timeout_seconds is not None else (7200 if context_install else 1800)
        if input_data is not None and (not isinstance(input_data, str)
                                      or len(input_data.encode()) > being_seed.MAX_SELECTION):
            raise OnboardingError('invalid_receiving_control_request')
        try:
            options: dict = {} if input_data is None else {'input': input_data}
            result = subprocess.run(["incus", *argv], capture_output=True, text=True,
                                    timeout=timeout, check=False, **options)
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError("onboarding_host_operation_failed") from None
        if result.returncode:
            raise OnboardingError("onboarding_host_operation_failed")
        return result.stdout

    def authorize(self, plan: dict, plan_digest: str) -> bool:
        if digest(validate_plan(plan)) != plan_digest or plan["release_digest"] != self.config.release_digest:
            return False
        if self.config.intake_policy is not None:
            from .onboarding_intake import allows
            if not allows(self.config, plan):
                return False
        if self.config.custody_policy is not None:
            from .onboarding_custody import CustodyPolicy
            if CustodyPolicy(self.config.custody_policy).value['revoked']:
                return False
        try:
            private_directory(self.config.grants)
            grant = being_seed._read(self.config.grants / (plan["name"] + ".json"))
        except (OSError, ValueError):
            return False
        return (set(grant) == {"schema", "plan", "revoked"}
                and grant.get("schema") == "cluster-onboarding-host-grant/v1"
                and grant.get("plan") == plan and grant.get("revoked") is False)

    @staticmethod
    def instance(plan: dict) -> str:
        # This namespace cannot name an existing administrative account/body.
        return "dm-" + plan["name"]

    def _inventory(self) -> tuple[list, list]:
        instances = json.loads(self.run(["list", "--format=json"]))
        volumes = json.loads(self.run(["storage", "volume", "list", self.config.pool, "--format=json"]))
        if not isinstance(instances, list) or not isinstance(volumes, list):
            raise OnboardingError("invalid_onboarding_environment_observation")
        return instances, volumes

    def _environment(self, plan: dict) -> Observation:
        instances, volumes = self._inventory()
        name, fingerprint = self.instance(plan), digest(plan)
        rows = [row for row in instances if row.get("name") == name]
        homes = [row for row in volumes if row.get("name") == name + "-home" and row.get("type") == "custom"]
        if len(rows) > 1 or len(homes) > 1:
            return Observation("conflict", reason="observed_state_conflict")
        if homes:
            home = json.loads(self.run(["query", "/1.0/storage-pools/" + self.config.pool
                                        + "/volumes/custom/" + name + "-home"]))
            if (home.get("config", {}).get("user.dm.onboarding-plan") != fingerprint
                    or home.get("config", {}).get("size") != "22GiB"):
                return Observation("conflict", reason="observed_state_conflict")
        if not rows:
            return Observation("absent", safe_to_execute=True)
        row = rows[0]
        config = row.get("config", {})
        expected_image = self.config.browser_image if plan["browser"] else self.config.native_image
        if (config.get("user.dm.onboarding-plan") != fingerprint
                or config.get("volatile.base_image") != expected_image):
            return Observation("conflict", reason="observed_state_conflict")
        devices = row.get("expanded_devices", {})
        root = devices.get("root", {})
        if root != {"type": "disk", "path": "/", "pool": self.config.pool, "size": "8GiB"}:
            return Observation("conflict", reason="observed_state_conflict")
        attached = devices.get("home")
        expected_home = {"type": "disk", "path": "/home/agent", "pool": self.config.pool, "source": name + "-home"}
        if attached is not None and attached != expected_home:
            return Observation("conflict", reason="observed_state_conflict")
        if not homes or attached is None or row.get("status") == "Stopped":
            return Observation("absent", safe_to_execute=True)
        if row.get("status") != "Running":
            return Observation("uncertain", reason="uncertain_external_effect")
        return Observation("complete", {"verified": True, "root_gib": 8, "home_gib": 22})

    def observe(self, plan: dict, stage: str, operation_id: str) -> Observation:
        if not self.authorize(plan, digest(plan)):
            return Observation("waiting", reason="host_authorization_required")
        if stage == "environment":
            return self._environment(plan)
        if stage not in {'context', 'environment'} and plan['browser'] and self.config.browser_artifact is not None:
            from .onboarding_browser import Browser
            state = Browser(self).observe(plan)
            if state.state != 'complete':
                return state
        if stage == 'welcome' and self.config.code and self.config.consent_state:
            from .onboarding_welcome import Welcome
            return Welcome(self).observe(plan)
        if stage == 'acceptance' and self.config.admission is not None:
            if self.config.telegram_code is not None:
                current_telegram = self._telegram_observation(plan)
                if current_telegram.state != 'complete':
                    return current_telegram
            from .onboarding_managed import ManagedRuntime
            from .onboarding_owner_client import OwnerClient
            managed = ManagedRuntime(self)
            current = managed.observe(plan)
            if current.state != 'complete':
                return current
            client = OwnerClient(self).observe(plan, managed._expected(plan))
            if client.state != 'complete':
                return client
            from .onboarding_acceptance import HostedChecks
            checks = HostedChecks(self)
            if self.config.progress is None or self.config.inputs is None:
                return checks.observe(plan)
            memory_write = checks.memory_write_observe(plan)
            if memory_write.state != 'complete':
                return memory_write
            current_checks = checks.observe(plan)
            cli_resume = checks.cli_resume_observe(plan)
            if cli_resume.state == 'absent':
                return cli_resume
            if self.config.peer is not None:
                matrix = checks.matrix_delivery_observe(plan)
                if matrix.state == 'absent':
                    return matrix
            return current_checks
        if stage in {"context", "matrix"} and not self._consented(plan, stage=stage):
            return Observation("waiting", reason="identity_authorization_required")
        if stage in {"context", "memory"} and self.config.code and self.config.inputs and self.config.views:
            current = self._guest_observe(plan, stage)
            if stage == 'context' and current.state == 'complete' and plan['browser'] and self.config.browser_artifact is not None:
                from .onboarding_browser import Browser
                selected = Browser(self).observe(plan)
                return (Observation('complete', {**current.facts, **selected.facts})
                    if selected.state == 'complete' else selected)
            return current
        if stage == 'access' and self.config.code and self.config.consent_state:
            key = self._ssh_key(plan)
            if key is None:
                return Observation('waiting', reason='account_authorization_required')
            guest = self._ssh_command(plan, 'observe', key)
            if not guest['installed']:
                return Observation('absent', safe_to_execute=True)
            if self.config.ssh_ingress is not None:
                from .onboarding_ingress import Ingress
                if not Ingress(self).observe(plan, guest):
                    return Observation('absent', safe_to_execute=True)
            if self.config.accounts is not None:
                from .onboarding_accounts import ManagedAccount
                return ManagedAccount(self).observe(plan)
            # A listening sshd is not a successful human login or a provider
            # turn. The access stage remains pending until both are observed.
            return Observation('waiting', reason='account_authorization_required')
        if stage == 'telegram' and self.config.code and self.config.consent_state:
            supplied = self._telegram_connections(plan)
            if supplied is None:
                return Observation('waiting', reason='connection_data_required')
            _, base, _ = self._guest_paths(plan)
            _, _, software_mounts = self._telegram_paths(plan, base)
            if not self._mounted(plan, {'onboarding-connections': self._telegram_mount(plan), **software_mounts}):
                return Observation('absent', safe_to_execute=True)
            value = self._telegram_command(plan, 'observe')
            if not value.get('configured') or not value.get('listening'):
                return Observation('absent', safe_to_execute=True)
            # Service readiness is recorded separately from the real human
            # conversation, steering/topics and continuity acceptance.
            return Observation('complete', dict(verified=True, telegram_ready=True))
        if stage == "matrix" and self.config.custody and self.config.custody_grants:
            ceremony = self._ceremony(plan)
            decision = self._decision(plan)
            if decision is None or not ceremony.authorize(plan):
                return Observation("waiting", reason="identity_authorization_required")
            observed = ceremony.observe(plan)
            if observed is not None and observed.get("waiting"):
                return Observation("waiting", reason="identity_authorization_required")
            if observed is None or not observed.get("ready", observed.get("backup_restore_verified", False)):
                return Observation("absent", safe_to_execute=True)
            if self.config.code and self.config.views and (self.config.code / "sdk/sdk.json").exists():
                _, code, mounts = self._guest_paths(plan)
                mounts.update(self._runtime_paths(plan, code)[2])
                mounts["onboarding-matrix-public"] = self._matrix_mount(plan)
                if not self._mounted(plan, mounts):
                    return Observation("absent", safe_to_execute=True)
                if self._sdk_successor(plan) and not self._target_call(plan, 'sdk-observe')['ready']:
                    return Observation('absent', safe_to_execute=True)
                target = self._matrix_command(plan, "observe")
                if target["phase"] in {"absent", "prepared", "v7", "credential-pending", "v8-published", "peer-published"}:
                    return Observation("absent", safe_to_execute=True)
                if self.config.peer is not None:
                    from .onboarding_peer_host import PeerHost
                    if PeerHost(self).application(plan) is None:
                        return Observation('absent', safe_to_execute=True)
                if self.config.admission is not None:
                    from .onboarding_managed import ManagedRuntime
                    return ManagedRuntime(self).observe(plan)
            # Current receiving authority is not physical/canonical admission.
            return Observation("waiting", reason="backend_unavailable")
        # Do not invent success for native enrollment or receiving acceptance.
        # The remaining typed stage adapters are added with their actual tests.
        reason = {"matrix": "identity_authorization_required", "access": "account_authorization_required",
                  "acceptance": "human_contact_required"}.get(stage, "backend_unavailable")
        return Observation("waiting", reason=reason)

    def execute(self, plan: dict, stage: str, operation_id: str) -> None:
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        if stage not in {'context', 'environment'} and plan['browser'] and self.config.browser_artifact is not None:
            from .onboarding_browser import Browser
            selected = Browser(self)
            if selected.observe(plan).state != 'complete':
                selected.execute(plan)
                return
        if stage == 'welcome' and self.config.code and self.config.consent_state:
            from .onboarding_welcome import Welcome
            Welcome(self).execute(plan)
            return
        if stage == 'acceptance' and self.config.admission is not None:
            if self.config.telegram_code is not None and self._telegram_observation(plan).state != 'complete':
                self.upgrade_telegram(plan)
                return
            from .onboarding_managed import ManagedRuntime
            from .onboarding_owner_client import OwnerClient
            managed = ManagedRuntime(self)
            if managed.observe(plan).state != 'complete':
                managed.execute(plan)
            OwnerClient(self).execute(plan, managed._expected(plan))
            from .onboarding_acceptance import HostedChecks
            if self.config.progress is not None and self.config.inputs is not None:
                HostedChecks(self).verify_memory_write(plan)
                HostedChecks(self).verify_cli_resume(plan)
                if self.config.peer is not None:
                    HostedChecks(self).verify_matrix_delivery(plan)
            return
        if stage in {"context", "matrix"} and not self._consented(plan, stage=stage):
            raise OnboardingError("identity_authorization_required")
        if stage in {"context", "memory"} and self.config.code and self.config.inputs and self.config.views:
            self._guest_execute(plan, stage)
            if stage == 'context' and plan['browser'] and self.config.browser_artifact is not None:
                from .onboarding_browser import Browser
                Browser(self).execute(plan)
            return
        if stage == 'access' and self.config.code and self.config.consent_state:
            key = self._ssh_key(plan)
            if key is None:
                raise OnboardingError('account_authorization_required')
            self._ssh_command(plan, 'install', key)
            if self.config.ssh_ingress is not None:
                from .onboarding_ingress import Ingress
                Ingress(self).execute(plan, self._ssh_command(plan, 'observe', key))
            if self.config.accounts is not None:
                from .onboarding_accounts import ManagedAccount
                ManagedAccount(self).execute(plan)
            return
        if stage == 'telegram' and self.config.code and self.config.consent_state:
            supplied = self._telegram_connections(plan)
            if supplied is None or self.config.views is None:
                raise OnboardingError('connection_data_required')
            from .onboarding_telegram import reserve
            reserve(self.config.jobs, plan, supplied)
            onboarding_mounts.prepare_connections(self.config.views, plan, supplied)
            self._attach_telegram(plan)
            mount = self._telegram_mount(plan)
            if not self._mounted(plan, {'onboarding-connections': mount}):
                self._dispatch(plan, ['config', 'device', 'add', self.instance(plan), 'onboarding-connections', 'disk',
                    *[key + '=' + value for key, value in mount.items() if key != 'type']])
            self._telegram_command(plan, 'prepare')
            self._telegram_command(plan, 'native-install')
            self._telegram_probe(plan)
            self._telegram_command(plan, 'install')
            return
        if stage == "matrix" and self.config.custody and self.config.custody_grants:
            decision = self._decision(plan)
            if decision is None:
                raise OnboardingError("identity_authorization_required")
            ceremony = self._ceremony(plan)
            prior = ceremony.observe(plan)
            if prior is None or not prior.get("ready", prior.get("backup_restore_verified", False)):
                ceremony.prepare(plan, identity_mode=decision["matrix_identity_mode"])
            if self.config.code and self.config.views and (self.config.code / "sdk/sdk.json").exists():
                if not self._matrix_execute(plan, ceremony):
                    return
                if self.config.peer is not None:
                    from .onboarding_peer_host import PeerHost
                    PeerHost(self).execute(plan)
                if self.config.admission is not None:
                    from .onboarding_managed import ManagedRuntime
                    ManagedRuntime(self).execute(plan)
            return
        if stage != "environment":
            raise OnboardingError("unsupported_onboarding_host_stage")
        observed = self._environment(plan)
        if observed.state == "complete":
            return
        if observed.state != "absent" or not observed.safe_to_execute:
            raise OnboardingError("onboarding_environment_conflict")
        instances, volumes = self._inventory()
        name, fingerprint = self.instance(plan), digest(plan)
        if not any(row.get("name") == name for row in instances):
            image = self.config.browser_image if plan["browser"] else self.config.native_image
            self._dispatch(plan, ["init", image, name, "--profile", self.config.profile,
                      "--storage", self.config.pool, "--device", "root,size=8GiB",
                      "--config", "user.dm.onboarding-plan=" + fingerprint])
        if not any(row.get("name") == name + "-home" and row.get("type") == "custom" for row in volumes):
            self._dispatch(plan, ["storage", "volume", "create", self.config.pool, name + "-home",
                      "size=22GiB", "user.dm.onboarding-plan=" + fingerprint])
        instances, _ = self._inventory()
        row = next(row for row in instances if row.get("name") == name)
        if "home" not in row.get("expanded_devices", {}):
            self._dispatch(plan, ["config", "device", "add", name, "home", "disk", "pool=" + self.config.pool,
                      "source=" + name + "-home", "path=/home/agent"])
        if row.get("status") == "Stopped":
            self._dispatch(plan, ["start", name])

    def _consented(self, plan: dict, *, stage: str) -> bool:
        # Disposable context-only qualification has no participant decision.
        # A deployed host config supplies the private intake boundary.
        if self.config.consent_state is None:
            return stage == "context" and self.config.qualification and plan["name"].startswith("qualify-")
        return self._decision(plan) is not None

    def _ssh_key(self, plan: dict) -> str | None:
        """Read only the selected participant's public key at the intake boundary."""
        value = self._connection_data(plan)
        if value is None:
            return None
        from .onboarding_ssh import public_key
        key = value.get('ssh_public_key')
        if key is None:
            return None
        public_key(key)
        return key

    def _connection_data(self, plan: dict) -> dict | None:
        """Private intake data stays within the selected host-owned job."""
        if self.config.consent_state is None or self.config.consent_uid is None:
            raise OnboardingError('account_authorization_required')
        intake_uid = self.config.consent_uid
        # This also validates private intake directories and seed ownership.
        if self._decision(plan) is None:
            return None
        directory = being_seed._directory(self.config.consent_state, plan['name'])
        def read_private(name: str) -> dict:
            path = directory / name
            raw = onboarding_release.regular(path, uid=intake_uid, limit=65536)
            if path.stat().st_mode & 0o077:
                raise OnboardingError('private_onboarding_connections_required')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise OnboardingError('account_authorization_required')
            return value
        record = read_private('record.json')
        if (record.get('schema') != being_seed.SCHEMA or record.get('name') != plan['name']
                or record.get('created_by') != plan['owner']):
            raise OnboardingError('account_authorization_required')
        try:
            value = read_private('connections.json')
        except FileNotFoundError:
            return None
        return value

    def _ssh_command(self, plan: dict, action: str, key: str) -> dict:
        if self._environment(plan).state != 'complete':
            raise OnboardingError('qualified_guest_environment_required')
        _, code, mounts = self._guest_paths(plan)
        if not self._mounted(plan, mounts):
            raise OnboardingError('qualified_guest_environment_required')
        launcher = ('import sys; sys.path.insert(0,sys.argv.pop(1)); '
                    'from clusterctl.onboarding_ssh import main; raise SystemExit(main())')
        value = json.loads(self._dispatch(plan, ['exec', self.instance(plan), '--',
            'python3', '-B', '-I', '-c', launcher, str(code), action, '--code', str(code),
            '--plan', '/home/agent/.onboarding-input/plan.json', '--public-key', key]))
        if (not isinstance(value, dict) or type(value.get('installed')) is not bool
                or value.get('plan_digest') != digest(plan) or value.get('port') != 2222):
            raise OnboardingError('invalid_onboarding_observation')
        return value

    def _telegram_connections(self, plan: dict) -> dict | None:
        value = self._connection_data(plan)
        if value is None or not {'telegram_bot_token', 'telegram_chat_id'} <= set(value):
            return None
        from .onboarding_telegram import connections
        return connections({key: value[key] for key in ('telegram_bot_token', 'telegram_chat_id')})

    def _telegram_mount(self, plan: dict) -> dict:
        if self.config.views is None:
            raise OnboardingError('receiving_code_configuration_required')
        return dict(type='disk', source=str(self.config.views / digest(plan) / 'connections'),
                    path='/home/agent/.onboarding-connections', readonly='true', shift='true')

    def _telegram_command(self, plan: dict, action: str) -> dict:
        if self._environment(plan).state != 'complete':
            raise OnboardingError('qualified_guest_environment_required')
        _, base, mounts = self._guest_paths(plan)
        code, software_args, software_mounts = self._telegram_paths(plan, base)
        mounts.update(software_mounts)
        mounts['onboarding-connections'] = self._telegram_mount(plan)
        if not self._mounted(plan, mounts):
            raise OnboardingError('qualified_guest_environment_required')
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_telegram import main;raise SystemExit(main())')
        identity = [] if action in {'install', 'observe', 'native-install', 'upgrade'} else ['--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent']
        value = json.loads(self._dispatch(plan, ['exec', self.instance(plan), *identity, '--', 'python3', '-B', '-I',
            '-c', launcher, str(code), action, '--code', str(base), *software_args, '--plan', '/home/agent/.onboarding-input/plan.json']))
        if (not isinstance(value, dict) or action != 'probe' and value.get('plan_digest') != digest(plan)):
            raise OnboardingError('invalid_onboarding_observation')
        return value

    def _telegram_paths(self, plan: dict, base: Path) -> tuple[Path, list[str], dict]:
        if self.config.telegram_code is None and self.config.telegram_digest is None:
            return base, [], {}
        if self.config.code is None or self.config.telegram_code is None or self.config.telegram_digest is None:
            raise OnboardingError('qualified_telegram_successor_required')
        fingerprint = self.config.telegram_digest
        onboarding_code_successor.verify(self.config.telegram_code, fingerprint,
            self.config.code, plan['release_digest'], uid=os.geteuid())
        code = Path('/opt/daimon-onboarding-telegram') / fingerprint
        mount = dict(type='disk', source=str(self.config.telegram_code), path=str(code), readonly='true', shift='true')
        return code, ['--runtime-code', str(code), '--runtime-digest', fingerprint], {
            'telegram-' + fingerprint[:54]: mount}

    def _attach_telegram(self, plan: dict) -> None:
        _, base, _ = self._guest_paths(plan)
        _, _, mounts = self._telegram_paths(plan, base)
        if not self._mounted(plan, mounts):
            for name, mount in mounts.items():
                self._dispatch(plan, ['config', 'device', 'add', self.instance(plan), name, 'disk',
                    *[key + '=' + value for key, value in mount.items() if key != 'type']])

    def _telegram_observation(self, plan: dict) -> Observation:
        _, base, _ = self._guest_paths(plan)
        _, _, mounts = self._telegram_paths(plan, base)
        if not self._mounted(plan, mounts):
            return Observation('absent', safe_to_execute=True)
        value = self._telegram_command(plan, 'observe')
        if value.get('upgrade_waiting'):
            return Observation('waiting', reason='telegram_idle_required')
        if not value.get('listening'):
            return Observation('absent', safe_to_execute=True)
        return Observation('complete', dict(verified=True, telegram_ready=True))

    def upgrade_telegram(self, plan: dict) -> dict:
        """Explicit selected software only; no native daemon or Matrix restart."""
        if self.config.telegram_code is None:
            raise OnboardingError('qualified_telegram_successor_required')
        self._attach_telegram(plan)
        self._telegram_probe(plan)
        return self._telegram_command(plan, 'upgrade')

    def _telegram_probe(self, plan: dict) -> None:
        from .onboarding_release import verify
        value = self._telegram_command(plan, 'probe').get('native_probe')
        if self.config.code is None:
            raise OnboardingError('receiving_code_configuration_required')
        expected = verify(self.config.code, plan['release_digest'], uid=os.geteuid())['profile']['skills']
        if (not isinstance(value, dict) or value.get('skill_errors') != 0
                or value.get('model_turns_started') != 0 or value.get('skills_force_reload') is not True
                or not isinstance(value.get('enabled_skills'), list)
                or not set(expected) <= set(value['enabled_skills'])):
            raise OnboardingError('native_telegram_probe_failed')

    def _telegram_binding(self, plan: dict) -> dict:
        """Observe the installed owner binding without returning private IDs."""
        program = ('import json,hashlib,os,stat;from pathlib import Path;'
                   'p=Path("/home/agent/.local/state/daimon-onboarding/telegram/binding.json");'
                   's=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and not s.st_mode&0o077;'
                   'v=json.loads(p.read_bytes());'
                   'd=hashlib.sha256(json.dumps({"human":v["human_id"]},sort_keys=True,separators=(",",":")).encode()).hexdigest();'
                   'print(json.dumps(dict(plan_digest=v["plan_digest"],bot_id=v["bot_id"],'
                   'destination_digest=d,token_sha256=v["token_sha256"])))')
        value = json.loads(self._dispatch(plan, ['exec', self.instance(plan), '--',
                           'python3', '-B', '-I', '-c', program]))
        if not isinstance(value, dict):
            raise OnboardingError('invalid_onboarding_observation')
        return value

    def _decision(self, plan: dict) -> dict | None:
        if self.config.consent_uid is None or self.config.progress is None or self.config.code is None:
            raise OnboardingError("invalid_onboarding_host_configuration")
        onboarding_release.verify(self.config.code, plan["release_digest"], uid=os.geteuid())
        from .onboarding_custody import CustodyPolicy
        custody = CustodyPolicy(self.config.custody_policy) if self.config.custody_policy is not None else None
        if custody is not None and custody.value['revoked']:
            return None
        proposal = onboarding_consent.review(plan, (self.config.code / "inheritance.md").read_text(),
            custody=custody.review() if custody is not None else None)
        reviews = onboarding_consent.Reviews(self.config.progress, worker_uid=os.geteuid())
        try:
            existing = reviews.read(plan["name"], owner=plan["owner"])
        except FileNotFoundError:
            existing = None
        if existing != proposal:
            reviews.publish(proposal)
        if self.config.consent_state is None:
            raise OnboardingError("invalid_onboarding_host_configuration")
        from .onboarding_approvals import decision
        return decision(self.config, proposal)

    def _guest_paths(self, plan: dict) -> tuple[Path, Path, dict]:
        if self.config.code is None or self.config.inputs is None or self.config.views is None:
            raise OnboardingError("receiving_code_configuration_required")
        onboarding_release.verify(self.config.code, plan["release_digest"], uid=os.geteuid())
        source = self.config.inputs / plan["name"]
        manifest = self.input_cache.verify(source, plan["seed_digest"])
        view = self.config.views / digest(plan) / "input"
        guest_code = Path("/opt/daimon-onboarding") / plan["release_digest"]
        mounts = {
            "onboarding-code": dict(type="disk", source=str(self.config.code), path=str(guest_code), readonly="true", shift="true"),
            "onboarding-input": dict(type="disk", source=str(view), path="/home/agent/.onboarding-input", readonly="true", shift="true"),
        }
        if manifest.get('seed_mode') == 'new':
            _, _, runtime_mounts = self._runtime_paths(plan, guest_code)
            mounts.update(runtime_mounts)
        return source, guest_code, mounts

    def _receiving_base(self, plan: dict) -> Path:
        """Resolve an approved existing receiver without reopening its upload.

        Candidate maintenance consumes the guest's retained plan/genesis, not
        participant input or onboarding mounts. Host/identity grants, successor
        bytes, current admission and receiving identity remain independent
        requirements on the existing closed control routes.
        """
        if self.config.code is None or plan['release_digest'] != self.config.release_digest:
            raise OnboardingError('receiving_code_configuration_required')
        onboarding_release.verify(self.config.code, plan['release_digest'], uid=os.geteuid())
        return Path('/opt/daimon-onboarding') / plan['release_digest']

    def _runtime_selection(self, plan: dict) -> tuple[Path | None, str | None]:
        selected = (self.config.runtime_by_name or {}).get(plan['name'])
        return selected if selected is not None else (self.config.runtime_code, self.config.runtime_digest)

    def _runtime_paths(self, plan: dict, base: Path, *,
                       candidate: tuple[Path, str] | None = None) -> tuple[Path, list[str], dict]:
        """Context stays frozen; each body may retain its qualified generation."""
        runtime_code, runtime_digest = self._runtime_selection(plan) if candidate is None else candidate
        if runtime_code is None and runtime_digest is None:
            return base, [], {}
        if self.config.code is None or runtime_code is None or runtime_digest is None:
            raise OnboardingError('qualified_onboarding_runtime_required')
        onboarding_code_successor.verify(runtime_code, runtime_digest,
            self.config.code, plan['release_digest'], uid=os.geteuid())
        code = Path('/opt/daimon-onboarding-runtime') / runtime_digest
        mount = dict(type='disk', source=str(runtime_code), path=str(code), readonly='true', shift='true')
        return code, ['--runtime-code', str(code), '--runtime-digest', runtime_digest], {
            'runtime-' + runtime_digest[:55]: mount}

    def _mounted(self, plan: dict, mounts: dict, *, deadline_ns: int | None = None) -> bool:
        if deadline_ns is None:
            instances, _ = self._inventory()
        else:
            # A candidate observation needs instance devices, not home volumes.
            # Include this transport call in the same budget as owner status.
            instances = json.loads(self._dispatch(plan, ['list', '--format=json'], deadline_ns=deadline_ns))
            if (not isinstance(instances, list) or any(not isinstance(row, dict) for row in instances)
                    or sum(row.get('name') == self.instance(plan) for row in instances) != 1):
                raise OnboardingError('invalid_onboarding_environment_observation')
        row = next(row for row in instances if row.get("name") == self.instance(plan))
        devices = row.get("expanded_devices", {})
        for name, expected in mounts.items():
            if name in devices and devices[name] != expected:
                raise OnboardingError("foreign_receiving_mount_preserved")
        # Operational aliases may change while the exact qualified source,
        # destination and read-only fence remain the same. A conflicting
        # canonical device above is still preserved, never bypassed.
        return all(
            name in devices or any(actual == expected for actual in devices.values())
            for name, expected in mounts.items()
        )

    def _guest_command(self, plan: dict, action: str, stage: str, guest_code: Path) -> str:
        # Only qualified receiving code runs. No command from the seed or
        # inherited home, model output, or HTTP string reaches this argv.
        launcher = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                    "from clusterctl.onboarding_guest import main; raise SystemExit(main())")
        incoming = "/home/agent/.onboarding-input"
        if self.config.inputs is None:
            raise OnboardingError('receiving_code_configuration_required')
        source = self.config.inputs / plan['name']
        manifest = self.input_cache.verify(source, plan['seed_digest'])
        import_code = guest_code
        if manifest.get('seed_mode') == 'new':
            import_code, _, _ = self._runtime_paths(plan, guest_code)
        return self._dispatch(plan, ["exec", self.instance(plan), "--user", "1000", "--group", "1000",
            "--env", "HOME=/home/agent", "--", "python3", "-B", "-I", "-c", launcher, str(import_code),
            action, stage, "--home", "/home/agent", "--input", incoming,
            "--code", str(guest_code), "--plan", incoming + "/plan.json"])

    def _guest_observe(self, plan: dict, stage: str) -> Observation:
        if self._environment(plan).state != "complete":
            return Observation("waiting", reason="backend_unavailable")
        _, guest_code, mounts = self._guest_paths(plan)
        if not self._mounted(plan, mounts):
            return Observation("absent", safe_to_execute=True) if stage == "context" else Observation("waiting", reason="backend_unavailable")
        value = json.loads(self._guest_command(plan, "observe", stage, guest_code))
        if not isinstance(value, dict) or set(value) != {"state", "facts", "reason", "safe_to_execute"}:
            raise OnboardingError("invalid_onboarding_observation")
        observed = Observation(**value)
        observed.validate()
        return observed

    def _guest_execute(self, plan: dict, stage: str) -> None:
        if self._environment(plan).state != "complete":
            raise OnboardingError("qualified_guest_environment_required")
        source, guest_code, mounts = self._guest_paths(plan)
        if stage == "context":
            assert self.config.views is not None
            onboarding_mounts.prepare_view(source, self.config.views, plan)
            instances, _ = self._inventory()
            row = next(row for row in instances if row.get("name") == self.instance(plan))
            # Code first: its typed bootstrap owns just the new empty home.
            for name in ('onboarding-code', *[key for key in mounts if key.startswith('runtime-')], 'onboarding-input'):
                if name == "onboarding-input":
                    launcher = ("import sys; sys.path.insert(0, sys.argv[1]); "
                                "from clusterctl.onboarding_mounts import bootstrap_home; bootstrap_home()")
                    self._dispatch(plan, ["exec", self.instance(plan), "--", "python3", "-B", "-I", "-c", launcher, str(guest_code)])
                current = row.get("expanded_devices", {}).get(name)
                if current is not None and current != mounts[name]:
                    raise OnboardingError("foreign_receiving_mount_preserved")
                if current is None:
                    device = mounts[name]
                    self._dispatch(plan, ["config", "device", "add", self.instance(plan), name, "disk",
                        *[key + "=" + value for key, value in device.items() if key != "type"]])
            # Reconcile torn copies without replacing the frozen receiving SDK
            # or context, and never touch an already activated receiving body.
            from .onboarding_guest import reconcile_context_copy
            program = ('import json,sys;\n' + inspect.getsource(reconcile_context_copy)
                + '\nprint(json.dumps(reconcile_context_copy("/home/agent",'
                + '"/home/agent/.onboarding-input",json.loads(sys.argv[1]))))')
            result = json.loads(self._dispatch(plan, ['exec', self.instance(plan), '--user', '1000',
                '--group', '1000', '--', 'python3', '-B', '-I', '-c', program, json.dumps(plan)]))
            if set(result) != {'recovered'} or type(result['recovered']) is not int or result['recovered'] < 0:
                raise OnboardingError('invalid_onboarding_observation')
        self._guest_command(plan, "execute", stage, guest_code)

    def _ceremony(self, plan: dict):
        decision = self._decision(plan)
        if decision is None:
            raise OnboardingError("identity_authorization_required")
        if decision is not None and decision["matrix_identity_mode"] == "existing":
            from .onboarding_enrollment import ExistingEnrollment
            return ExistingEnrollment(self)
        if self.config.custody is None or self.config.custody_grants is None:
            raise OnboardingError("identity_authorization_required")
        return FirstCustody(self.config.custody, self.config.custody_grants)

    def _matrix_mount(self, plan: dict) -> dict:
        if self.config.views is None:
            raise OnboardingError("receiving_code_configuration_required")
        return dict(type="disk", source=str(self.config.views / digest(plan) / "matrix-public"),
                    path="/home/agent/.onboarding-matrix", readonly="true", shift="true")

    def _target_call(self, plan: dict, action: str, *, profile: dict | None = None,
                     peer_packet: dict | None = None, peer_being_ref: str | None = None,
                     candidate: tuple[Path, str] | None = None,
                     observation_timeout_seconds: float | None = None,
                     require_loaded: bool = False,
                     bootstrap_request: dict | None = None,
                     bootstrap_ready_sha256: str | None = None,
                     bootstrap_timeout_seconds: float | None = None,
                     control_file: Path | None = None, control_command: Path | None = None,
                     control_value: dict | None = None, identity_expires_at_ms: int | None = None) -> dict:
        """Probe prepared receiving code without changing active selectors.

        Candidate calls require the already verified public read-only mount.
        The receiving owner still verifies its exact code/SDK independently.
        A host timeout is uncertain observation, never proof of guest exit.
        """
        deadline_ns = None
        bootstrapping = action in {'receiving-bootstrap-freeze', 'receiving-bootstrap-stage', 'receiving-bootstrap-publish'}
        controlling = action in {'receiving-control-prepare', 'receiving-control-apply'}
        if (action == 'receiving-identity') != (identity_expires_at_ms is not None):
            raise OnboardingError('invalid_receiving_identity_request')
        if identity_expires_at_ms is not None and (type(identity_expires_at_ms) is not int
                or not 0 < identity_expires_at_ms < 2**53):
            raise OnboardingError('invalid_receiving_identity_request')
        if bootstrapping:
            if (candidate is None or bootstrap_timeout_seconds is None
                    or observation_timeout_seconds is not None
                    or not math.isfinite(bootstrap_timeout_seconds) or not 0 < bootstrap_timeout_seconds <= 60
                    or (action == 'receiving-bootstrap-freeze') != (bootstrap_request is None)
                    or (action == 'receiving-bootstrap-publish') != (bootstrap_ready_sha256 is not None)):
                raise OnboardingError('invalid_receiving_bootstrap_request')
            deadline_ns = time.monotonic_ns() + int(bootstrap_timeout_seconds * 1_000_000_000)
        elif any(item is not None for item in (bootstrap_request, bootstrap_ready_sha256, bootstrap_timeout_seconds)):
            raise OnboardingError('invalid_receiving_bootstrap_request')
        if controlling:
            if (control_file is None
                    or (action == 'receiving-control-prepare') != (control_command is not None or control_value is not None)
                    or control_command is not None and control_value is not None
                    or control_value is not None and not isinstance(control_value, dict)):
                raise OnboardingError('invalid_receiving_control_request')
        elif control_file is not None or control_command is not None or control_value is not None:
            raise OnboardingError('invalid_receiving_control_request')
        if observation_timeout_seconds is not None:
            if (action not in {'running', 'admitted-running', 'receiving-identity', 'receiving-control-prepare', 'receiving-control-apply'}
                    or not math.isfinite(observation_timeout_seconds)
                    or not 0 < observation_timeout_seconds <= 60):
                raise OnboardingError('receiving_host_deadline_required')
            deadline_ns = time.monotonic_ns() + int(observation_timeout_seconds * 1_000_000_000)
        if action == 'receiving-identity' and observation_timeout_seconds is None:
            raise OnboardingError('receiving_host_deadline_required')
        if require_loaded and action not in {'running', 'admitted-running'}:
            raise OnboardingError('qualified_onboarding_target_observer_required')
        if self.config.custody is None or self.config.custody_grants is None:
            raise OnboardingError("identity_authorization_required")
        if not self._ceremony(plan).authorize(plan):
            raise OnboardingError("identity_authorization_required")
        if candidate is None:
            _, guest_code, _ = self._guest_paths(plan)
        else:
            guest_code = self._receiving_base(plan)
        runtime_code, runtime_args, mounts = (self._runtime_paths(plan, guest_code) if candidate is None
            else self._runtime_paths(plan, guest_code, candidate=candidate))
        if candidate is not None:
            if (action not in {'sdk-observe', 'sdk-prepare', 'observe', 'running', 'admitted-running',
                    'receiving-control-prepare', 'receiving-control-apply', 'receiving-bootstrap-freeze',
                    'receiving-bootstrap-stage', 'receiving-bootstrap-publish', 'receiving-identity'}
                    or profile is not None or peer_packet is not None or peer_being_ref is not None
                    or not onboarding_code_successor.sdk_parameters(candidate[0], uid=os.geteuid())
                    or not self._mounted(plan, mounts, deadline_ns=deadline_ns)):
                raise OnboardingError('qualified_onboarding_candidate_mount_required')
        from .onboarding_service import code_command
        public = "/home/agent/.onboarding-matrix"
        peer_args = []
        if peer_packet is not None or peer_being_ref is not None:
            from daimon_matrix.canonical import canonical_bytes
            from . import onboarding_peer
            if (action != 'peer-accept' or profile is not None or self.config.peer is None
                    or peer_packet is None or peer_being_ref is None or self.config.views is None):
                raise OnboardingError('approved_onboarding_peer_required')
            approved = being_seed._read(self.config.peer)['source_being_ref']
            signer = onboarding_peer.native(Path(__file__).resolve().parents[1]).verify_identity(peer_packet['sender_identity'])
            if approved != peer_being_ref or signer.state.being_ref != approved:
                raise OnboardingError('approved_onboarding_peer_required')
            onboarding_mounts.prepare_matrix_public(self.config.views, plan, {'peer-offer.json': peer_packet})
            peer_args = ['--peer-packet', public + '/peer-offer.json', '--peer-packet-sha256',
                hashlib.sha256(canonical_bytes(peer_packet)).hexdigest(), '--peer-being-ref', approved]
        elif action == 'peer-accept':
            raise OnboardingError('approved_onboarding_peer_required')
        arguments = [action, "--home", "/home/agent", "--code", str(guest_code), *runtime_args,
            "--plan", "/home/agent/.onboarding-input/plan.json", "--genesis", public + "/genesis.json",
            "--activation", public + "/activation.json", "--credential-response", public + "/credential-response.json",
            *peer_args, *(['--public-profile-json', json.dumps(profile, separators=(',', ':'))] if profile is not None else [])]
        if require_loaded:
            arguments += ['--require-loaded']
        if control_file is not None:
            arguments += ['--control-file', str(control_file)]
        if control_command is not None:
            arguments += ['--control-command', str(control_command)]
        input_data = None
        if control_value is not None:
            input_data = json.dumps(control_value, sort_keys=True, separators=(',', ':'))
            if len(input_data.encode()) > being_seed.MAX_SELECTION:
                raise OnboardingError('invalid_receiving_control_request')
            arguments += ['--control-command', '-']
        if identity_expires_at_ms is not None:
            arguments += ['--identity-expires-at-ms', str(identity_expires_at_ms)]
        if bootstrap_request is not None:
            encoded = json.dumps(bootstrap_request, sort_keys=True, separators=(',', ':'))
            if len(encoded.encode()) > 131072:
                raise OnboardingError('invalid_receiving_bootstrap_request')
            arguments += ['--bootstrap-request-json', encoded]
        if bootstrap_ready_sha256 is not None:
            if not sha(bootstrap_ready_sha256):
                raise OnboardingError('invalid_receiving_bootstrap_request')
            arguments += ['--bootstrap-ready-sha256', bootstrap_ready_sha256]
        remaining = None
        if deadline_ns is not None:
            remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            arguments += ['--bootstrap-timeout-seconds' if bootstrapping else '--observation-timeout-seconds', str(remaining)]
        command = ["exec", self.instance(plan), "--user", "1000", "--group", "1000",
            "--env", "HOME=/home/agent", "--", *code_command(Path('/usr/bin/python3'), runtime_code,
                'clusterctl.onboarding_target', arguments)]
        dispatch: dict = {} if input_data is None else {'input_data': input_data}
        result = (self._dispatch(plan, command, **dispatch) if deadline_ns is None
            else self._dispatch(plan, command, timeout_seconds=remaining, deadline_ns=deadline_ns, **dispatch))
        value = json.loads(result)
        if not isinstance(value, dict):
            raise OnboardingError('invalid_onboarding_observation')
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        return value

    def _guest_service_call(self, plan: dict, action: str, *, candidate: tuple[Path, str],
                            timeout_seconds: float, request: dict | None = None,
                            owner_observation: dict | None = None) -> dict:
        """Named-unit root effects execute public Cluster code, never owner SDK.

        The caller holds the host operation/job locks and records uncertainty.
        This method does not create mounts or authorize a live interruption.
        """
        if (action not in {'bootstrap-inspect', 'bootstrap-validate', 'bootstrap-quiesce', 'bootstrap-select', 'bootstrap-start'}
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60
                or (action == 'bootstrap-inspect') != (request is None)
                or action != 'bootstrap-inspect' and owner_observation is not None):
            raise OnboardingError('receiving_guest_service_request_required')
        deadline_ns = time.monotonic_ns() + int(timeout_seconds * 1_000_000_000)
        if not self._ceremony(plan).authorize(plan):
            raise OnboardingError('identity_authorization_required')
        base = self._receiving_base(plan)
        code, runtime_args, mounts = self._runtime_paths(plan, base, candidate=candidate)
        if (not onboarding_code_successor.sdk_parameters(candidate[0], uid=os.geteuid())
                or not self._mounted(plan, mounts, deadline_ns=deadline_ns)):
            raise OnboardingError('qualified_onboarding_candidate_mount_required')
        arguments = ['--action', action, '--code', str(base), *runtime_args,
            '--plan', '/home/agent/.onboarding-input/plan.json']
        for flag, value, limit in (('--bootstrap-request-json', request, 65536),
                                   ('--owner-observation-json', owner_observation, 2 * 1024**2)):
            if value is not None:
                encoded = json.dumps(value, sort_keys=True, separators=(',', ':'))
                if len(encoded.encode()) > limit:
                    raise OnboardingError('receiving_guest_service_request_required')
                arguments += [flag, encoded]
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise OnboardingError('receiving_host_deadline_expired')
        arguments += ['--timeout-seconds', str(remaining)]
        from .onboarding_service import code_command
        command = ['exec', self.instance(plan), '--user', '0', '--group', '0', '--',
            *code_command(Path('/usr/bin/python3'), code, 'clusterctl.onboarding_service', arguments)]
        raw = self._dispatch(plan, command, timeout_seconds=remaining, deadline_ns=deadline_ns)
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get('installed') is False:
            raise OnboardingError('receiving_guest_service_observation_failed')
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        return value

    def _matrix_command(self, plan: dict, action: str) -> dict:
        value = self._target_call(plan, action)
        if (not isinstance(value, dict) or set(value) - {'group', 'receiving_controller'} != {"phase", "request", "receipt"}
                or value["phase"] not in {"absent", "prepared", "v7", "credential-pending", "v8-published", "v8", "peer-published"}):
            raise OnboardingError("invalid_onboarding_observation")
        return value

    def _matrix_execute(self, plan: dict, ceremony) -> bool:
        if self._environment(plan).state != "complete" or self.config.views is None:
            raise OnboardingError("qualified_guest_environment_required")
        code = Path("/opt/daimon-onboarding") / plan["release_digest"]
        _, _, runtime_mounts = self._runtime_paths(plan, code)
        if runtime_mounts and not self._mounted(plan, runtime_mounts):
            for name, mount in runtime_mounts.items():
                self._dispatch(plan, ['config', 'device', 'add', self.instance(plan), name, 'disk',
                    *[key + '=' + value for key, value in mount.items() if key != 'type']])
        root = ceremony.root / digest(plan)
        genesis = document(root / "genesis.json")
        onboarding_mounts.prepare_matrix_public(self.config.views, plan, {"genesis.json": genesis})
        mount = self._matrix_mount(plan)
        instances, _ = self._inventory()
        row = next(row for row in instances if row.get("name") == self.instance(plan))
        current = row.get("expanded_devices", {}).get("onboarding-matrix-public")
        if current is not None and current != mount:
            raise OnboardingError("foreign_receiving_mount_preserved")
        if current is None:
            self._dispatch(plan, ["config", "device", "add", self.instance(plan), "onboarding-matrix-public", "disk",
                                  *[key + "=" + value for key, value in mount.items() if key != "type"]])
        if self._sdk_successor(plan):
            # Dependency installation has its own resumable effect. It reads no
            # receiving custody and retains the previous content-addressed SDK.
            self._target_call(plan, 'sdk-prepare')
        # Lifecycle recovery may already have a live daemon. Its verified V8
        # publication is immutable; never reenter credential writer operations
        # merely because a later service/registry acknowledgement was lost.
        if self._matrix_command(plan, 'observe')['phase'] in {'v8', 'peer-published'}:
            return True
        target = self._matrix_command(plan, "prepare")
        activation = ceremony.authorize_target(plan, target["request"])
        if activation is None:
            return False
        onboarding_mounts.prepare_matrix_public(self.config.views, plan, {"activation.json": activation})
        self._matrix_command(plan, "activate")
        proposed = self._matrix_command(plan, "credential-prepare")
        response = ceremony.authorize_credential(plan, proposed["request"])
        if response is None:
            return False
        onboarding_mounts.prepare_matrix_public(self.config.views, plan, {"credential-response.json": response})
        self._matrix_command(plan, "credential-apply")
        return True

    def _sdk_successor(self, plan: dict) -> bool:
        runtime_code, _ = self._runtime_selection(plan)
        if runtime_code is None:
            return False
        marker = json.loads(onboarding_release.regular(
            runtime_code / onboarding_code_successor.MARKER, uid=os.geteuid()))
        return marker['schema'] in {onboarding_code_successor.SDK_SCHEMA,
                                   onboarding_code_successor.QUALIFIED_SDK_SCHEMA} or (
            marker['schema'] == onboarding_code_successor.TELEGRAM_SCHEMA and 'sdk_digest' in marker)

    def _dispatch(self, plan: dict, argv: list[str], *, timeout_seconds: float | None = None,
                  deadline_ns: int | None = None, input_data: str | None = None) -> str:
        # A revoked plan stops before the next concrete effect, including
        # revocation while an earlier long Incus operation was in flight.
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        if deadline_ns is not None:
            remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                raise OnboardingError('receiving_host_deadline_expired')
            timeout_seconds = remaining if timeout_seconds is None else min(remaining, timeout_seconds)
        options: dict = {} if timeout_seconds is None else {'timeout_seconds': timeout_seconds}
        if input_data is not None:
            options['input_data'] = input_data
        return self.run(argv, **options)
