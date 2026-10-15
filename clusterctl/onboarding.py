"""Durable onboarding execution, independent of a model conversation.

The host worker owns this store. HTTP intake may submit a request, but cannot
authorize a plan or execute a backend. Observations, not dispatch, finish steps.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Protocol, Any

from . import being_seed

SCHEMA = "cluster-onboarding-job/v1"
PLAN_SCHEMA = "cluster-onboarding-plan/v1"
STAGES = ("environment", "context", "memory", "matrix", "access", "telegram", "welcome", "acceptance")
REASONS = frozenset({
    "host_authorization_required", "capacity_required", "connection_data_required",
    "identity_authorization_required", "account_authorization_required",
    "human_contact_required", "uncertain_external_effect", "observed_state_conflict",
    "backend_unavailable", "verification_failed", "existing_identity_conflict", "hosted_checks_required",
    "telegram_idle_required",
})
FACTS = frozenset({
    "verified", "root_gib", "home_gib", "memory_stores", "memory_chapters", "skills",
    "identity_verified", "context_verified", "ssh_ready", "ssh_verified", "provider_verified", "browser_verified",
    "telegram_ready", "telegram_verified", "welcome_delivered", "human_contact_verified",
    "steering_verified", "topics_verified", "restart_verified", "cli_resume_verified",
    "matrix_delivery_verified", "browser_code_verified",
})
ACCEPTANCE = frozenset({
    "identity_verified", "ssh_verified", "provider_verified", "telegram_verified",
    "human_contact_verified", "steering_verified", "topics_verified",
    "restart_verified", "cli_resume_verified", "matrix_delivery_verified",
})
STAGE_FACTS: dict[str, dict[str, Any]] = {
    "environment": {"root_gib": 8, "home_gib": 22},
    "context": {"context_verified": True},
    "memory": {},
    "matrix": {"identity_verified": True},
    "access": {"ssh_ready": True, "provider_verified": True},
    "telegram": {"telegram_ready": True},
    "welcome": {"welcome_delivered": True},
    "acceptance": {},
}
STATES = frozenset({"ready", "running", "waiting", "attention-required", "complete"})


def private_directory(path: Path, *, create: bool = False) -> Path:
    being_seed._path(path)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OnboardingError("private_onboarding_directory_required")
    return path


class OnboardingError(ValueError):
    """Disclosure-safe worker refusal."""



# Explicit public operational codes only. Exception strings, paths, payloads and
# unknown future codes never become CLI diagnostics by matching a text pattern.
_DIAGNOSTIC_CODES = frozenset({
    'seed_operation_in_progress', 'qualified_runtime_module_required',
    'qualified_runtime_imports_required', 'qualified_runtime_context_required',
    'qualified_receiving_interpreter_required', 'private_onboarding_sdk_required',
    'installed_onboarding_sdk_changed', 'onboarding_sdk_digest_mismatch',
    'native_onboarding_sdk_refused', 'onboarding_observation_deadline_expired',
    'onboarding_observation_deadline_exceeded', 'onboarding_runtime_not_ready',
    'onboarding_admission_not_current', 'onboarding_daemon_origin_conflict',
    'onboarding_daemon_responder_conflict', 'onboarding_loaded_base_conflict',
    'qualified_onboarding_loaded_view_required', 'onboarding_service_operation_failed',
    'existing_onboarding_service_preserved', 'receiving_controller_loaded_bundle_conflict',
    'receiving_preservation_authorization_expired', 'receiving_matrix_deadline_expired',
    'onboarding_runtime_channel_closed',
    'onboarding_runtime_observation_unavailable', 'receiving_guest_bootstrap_identity_required',
})


def refusal_diagnostic(error: Exception, *, stage: str) -> dict:
    """Opt-in local CLI detail; never serialize arbitrary exception contents."""
    code = 'unclassified_refusal'
    if isinstance(error, (OnboardingError, being_seed.SeedError)):
        candidate = str(error)
        if candidate in _DIAGNOSTIC_CODES:
            code = candidate
    elif isinstance(error, FileNotFoundError):
        code = 'local_input_or_socket_missing'
    elif isinstance(error, PermissionError):
        code = 'local_access_refused'
    elif isinstance(error, TimeoutError):
        code = 'local_operation_timed_out'
    return dict(schema='cluster-onboarding-refusal/v1', stage=stage, code=code)


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_plan(value: Any) -> dict:
    expected = {"schema", "name", "owner", "seed_digest", "release_digest", "account_profile", "browser"}
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != PLAN_SCHEMA:
        raise OnboardingError("invalid_onboarding_plan")
    for name in ("name", "owner", "account_profile"):
        if not isinstance(value[name], str) or not being_seed.NAME.fullmatch(value[name]):
            raise OnboardingError("invalid_onboarding_plan")
    for name in ("seed_digest", "release_digest"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise OnboardingError("invalid_onboarding_plan")
    if type(value["browser"]) is not bool:
        raise OnboardingError("invalid_onboarding_plan")
    return dict(value)


@dataclass(frozen=True)
class Observation:
    state: Literal["absent", "complete", "waiting", "uncertain", "conflict"]
    facts: dict = field(default_factory=dict)
    reason: str | None = None
    # Only an authoritative observation can prove a dispatch is safe to repeat.
    safe_to_execute: bool = False

    def validate(self) -> None:
        if self.state not in {"absent", "complete", "waiting", "uncertain", "conflict"}:
            raise OnboardingError("invalid_onboarding_observation")
        if not isinstance(self.facts, dict) or set(self.facts) - FACTS:
            raise OnboardingError("invalid_onboarding_observation")
        if any(type(value) not in {bool, int} or type(value) is int and value < 0
               for value in self.facts.values()):
            raise OnboardingError("invalid_onboarding_observation")
        if self.reason is not None and self.reason not in REASONS:
            raise OnboardingError("invalid_onboarding_observation")
        if type(self.safe_to_execute) is not bool or self.state == "complete" and self.facts.get("verified") is not True:
            raise OnboardingError("invalid_onboarding_observation")


class Backend(Protocol):
    def authorize(self, plan: dict, plan_digest: str) -> bool:
        """Check the current host grant for these exact bytes; labels are insufficient."""

    def observe(self, plan: dict, stage: str, operation_id: str) -> Observation:
        """Observe the concrete effect without changing it."""

    def execute(self, plan: dict, stage: str, operation_id: str) -> None:
        """Execute a typed operation. stdout/errors never become public progress."""


class JobStore:
    def __init__(self, root: str | Path):
        self.root = being_seed._path(Path(root))

    def directory(self, name: str) -> Path:
        if not isinstance(name, str) or not being_seed.NAME.fullmatch(name):
            raise OnboardingError("invalid_onboarding_name")
        return being_seed._path(self.root / name)

    def _load(self, name: str) -> dict:
        private_directory(self.root)
        private_directory(self.directory(name))
        try:
            record = being_seed._read(self.directory(name) / "job.json")
        except FileNotFoundError:
            raise OnboardingError("onboarding_job_not_found") from None
        plan = validate_plan(record.get("plan"))
        if (set(record) != {"schema", "plan", "plan_digest", "state", "stage", "reason",
                            "created_ms", "updated_ms", "steps"}
                or record.get("schema") != SCHEMA or plan["name"] != name
                or record.get("plan_digest") != digest(plan)
                or not isinstance(record.get("steps"), dict)
                or set(record["steps"]) != set(STAGES)
                or record.get("state") not in STATES
                or record.get("reason") is not None and record["reason"] not in REASONS
                or any(type(record.get(key)) is not int or record[key] < 0
                       for key in ("created_ms", "updated_ms"))):
            raise OnboardingError("invalid_onboarding_job")
        pending = False
        for stage in STAGES:
            step = record["steps"][stage]
            if not isinstance(step, dict):
                raise OnboardingError("invalid_onboarding_job")
            if step.get("operation_id") != self.operation_id(record["plan_digest"], stage):
                raise OnboardingError("invalid_onboarding_job")
            if step.get("state") not in {"pending", "dispatching", "complete"}:
                raise OnboardingError("invalid_onboarding_job")
            if step["state"] == "complete":
                if (pending or set(step) != {"state", "operation_id", "facts", "completed_ms"}
                        or type(step["completed_ms"]) is not int or step["completed_ms"] < 0):
                    raise OnboardingError("invalid_onboarding_job")
                Observation("complete", step["facts"]).validate()
                self.validate_completion(plan, stage, step["facts"])
            else:
                if set(step) != {"state", "operation_id"} or pending and step["state"] != "pending":
                    raise OnboardingError("invalid_onboarding_job")
                pending = True
        first = next((s for s in STAGES if record["steps"][s]["state"] != "complete"), None)
        if record["stage"] != first or (record["state"] == "complete") != (first is None):
            raise OnboardingError("invalid_onboarding_job")
        return record

    @staticmethod
    def operation_id(plan_digest: str, stage: str) -> str:
        return hashlib.sha256((plan_digest + ":" + stage).encode()).hexdigest()

    def submit(self, plan: dict, backend: Backend | Callable[[], Backend]) -> dict:
        plan = validate_plan(plan)
        fingerprint = digest(plan)
        current = backend() if callable(backend) else backend
        if not current.authorize(plan, fingerprint):
            raise OnboardingError("host_authorization_required")
        directory = self.directory(plan["name"])
        private_directory(self.root, create=True)
        # Parent lock makes first publication atomic with competing submissions.
        with being_seed._locked(self.root):
            if callable(backend) and not backend().authorize(plan, fingerprint):
                raise OnboardingError("host_authorization_required")
            if (directory / "job.json").exists():
                record = self._load(plan["name"])
                if record["plan_digest"] != fingerprint:
                    raise OnboardingError("onboarding_plan_conflict")
                return self.project(record)
            private_directory(directory, create=True)
            record = {
                "schema": SCHEMA, "plan": plan, "plan_digest": fingerprint,
                "state": "ready", "stage": STAGES[0], "reason": None,
                "created_ms": int(time.time() * 1000), "updated_ms": int(time.time() * 1000),
                "steps": {stage: {"state": "pending", "operation_id": self.operation_id(fingerprint, stage)}
                          for stage in STAGES},
            }
            being_seed._write(directory / "job.json", record)
        return self.project(record)

    def _save(self, directory: Path, record: dict) -> None:
        record["updated_ms"] = int(time.time() * 1000)
        being_seed._write(directory / "job.json", record)

    def tick(self, name: str, backend: Backend | Callable[[], Backend]) -> dict:
        directory = self.directory(name)
        private_directory(self.root)
        private_directory(directory)
        with being_seed._locked(directory):
            record = self._load(name)
            if record["state"] == "complete":
                return self.project(record)
            backend = backend() if callable(backend) else backend
            if not backend.authorize(record["plan"], record["plan_digest"]):
                record.update(state="waiting", reason="host_authorization_required")
                self._save(directory, record)
                return self.project(record)
            stage = next(stage for stage in STAGES if record["steps"][stage]["state"] != "complete")
            step = record["steps"][stage]
            record.update(stage=stage, reason=None)
            try:
                observed = backend.observe(record["plan"], stage, step["operation_id"])
                observed.validate()
                if observed.state == "absent":
                    if not observed.safe_to_execute:
                        observed = Observation("uncertain", reason="uncertain_external_effect")
                    else:
                        step["state"] = "dispatching"
                        record["state"] = "running"
                        self._save(directory, record)
                        backend.execute(record["plan"], stage, step["operation_id"])
                        observed = backend.observe(record["plan"], stage, step["operation_id"])
                        observed.validate()
                if observed.state == "complete":
                    self.validate_completion(record["plan"], stage, observed.facts)
                    step.update(state="complete", facts=observed.facts, completed_ms=int(time.time() * 1000))
                    next_stage = next((s for s in STAGES if record["steps"][s]["state"] != "complete"), None)
                    record.update(state="complete" if next_stage is None else "ready", stage=next_stage, reason=None)
                else:
                    record.update(state="waiting" if observed.state in {"waiting", "absent"} else "attention-required",
                                  reason=observed.reason or ("observed_state_conflict" if observed.state == "conflict"
                                                            else "verification_failed"))
            except OnboardingError as error:
                record.update(state="attention-required", reason='existing_identity_conflict'
                              if str(error) == 'existing_identity_conflict' else "verification_failed")
            except Exception:
                # Keep dispatch intent and exact operation ID for reconciliation.
                # Private exception text, command output and credentials stay out.
                record.update(state="attention-required", reason="backend_unavailable")
            self._save(directory, record)
            return self.project(record)

    @staticmethod
    def validate_completion(plan: dict, stage: str, facts: dict) -> None:
        if any(type(facts.get(key)) is not type(value) or facts[key] != value
               for key, value in STAGE_FACTS[stage].items()):
            raise OnboardingError("verification_failed")
        if stage == "memory" and any(type(facts.get(key)) is not int
                                     for key in ("memory_stores", "memory_chapters")):
            raise OnboardingError("verification_failed")
        if stage == "acceptance" and not JobStore.accepted(plan, facts):
            raise OnboardingError("verification_failed")

    @staticmethod
    def accepted(plan: dict, facts: dict) -> bool:
        required = ACCEPTANCE | ({"browser_verified"} if plan["browser"] else set())
        return all(facts.get(key) is True for key in required)

    @staticmethod
    def project(record: dict) -> dict:
        return {
            "schema": SCHEMA, "name": record["plan"]["name"], "owner": record["plan"]["owner"],
            "plan_digest": record["plan_digest"], "state": record["state"], "stage": record["stage"],
            "reason": record["reason"] if record["reason"] in REASONS else None,
            "completed_steps": [stage for stage in STAGES if record["steps"][stage]["state"] == "complete"],
            "active": record["state"] == "complete", "updated_ms": record["updated_ms"],
        }

    def status(self, name: str, *, owner: str) -> dict:
        record = self._load(name)
        if owner != "*" and record["plan"]["owner"] != owner:
            raise OnboardingError("onboarding_job_not_found")
        return self.project(record)

    def names(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(path.name for path in self.root.iterdir()
                      if being_seed.NAME.fullmatch(path.name) and (path / "job.json").is_file())
