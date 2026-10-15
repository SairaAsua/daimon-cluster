"""Cluster-owned host boundary for the pinned :mod:`daimon_matrix` runtime.

Cluster owns physical body lifecycle, the embodiment registry, resource
fences, and portable storage.  Matrix owns identity, ledger semantics, local
scope resolution, and effect receipts.  This module is the deliberately small
adapter between those authorities; it does not duplicate Matrix protocol code.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.metadata
import json
import os
import shutil
import signal
import stat
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .embodiments import Registry, RegistryError
from .fences import FenceError, ResourceFenceStore

MATRIX_CONTRACT_COMMIT = "0dc0b555939b16a1150a220a366a6911a5ae9c28"
MATRIX_ROOT_SCHEMA = "dm.cluster-matrix-root/v1"
MATRIX_SNAPSHOT_SCHEMA = "dm.cluster-matrix-snapshot/v1"
MATRIX_RECOVERY_SNAPSHOT_SCHEMA = "dm.cluster-matrix-recovery-snapshot/v1"
MATRIX_STATUS_SCHEMA = "dm.cluster-matrix-status/v1"
_LOCK_NAME = ".daimon-matrixd.lock"
_MAX_PASSWORD_BYTES = 4096
_MAX_BUNDLE_BYTES = 4 * 1024 * 1024
_MAX_UNIX_SOCKET_BYTES = 107
_CLUSTERD_MATRIX_METHODS = frozenset(
    {
        "runtime.status",
        "scope.me",
        "scope.we",
        "scope.we.diff",
        "scope.we.sync-plan",
    }
)
_CURATOR_WORKER_METHODS = frozenset(
    {"curator.claim", "curator.complete", "curator.enqueue", "curator.inspect"}
)
_EFFECT_OBSERVATION_FIELDS = frozenset(
    {"intent", "observed_postcondition", "current_fence_evidence"}
)

EffectObserver = Callable[
    [Mapping[str, Any], Mapping[str, Any], int], Mapping[str, Any]
]


@dataclass(frozen=True)
class EffectObserverRoute:
    """One explicit effect-truth adapter binding.

    A route is selected by all three authority coordinates.  The namespace is
    the first component of ``resource_ref`` (for example ``wiki`` in
    ``wiki:page:home``); it is not a prefix or wildcard.
    """

    adapter: str
    work_kind: str
    resource_namespace: str
    observer: EffectObserver | None

    def __post_init__(self) -> None:
        for value in (self.adapter, self.work_kind, self.resource_namespace):
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 256
                or any(ord(character) < 0x21 for character in value)
            ):
                raise MatrixHostError("effect_observer_route_rejected")
        if ":" in self.resource_namespace:
            raise MatrixHostError("effect_observer_route_rejected")


class EffectObserverRouter:
    """Fail-closed router for concrete downstream effect observers."""

    def __init__(self, routes: Sequence[EffectObserverRoute] = ()) -> None:
        self._routes = tuple(routes)
        coordinates = [
            (route.adapter, route.work_kind, route.resource_namespace)
            for route in self._routes
        ]
        if len(coordinates) != len(set(coordinates)):
            raise MatrixHostError("effect_observer_route_ambiguous")

    def __call__(
        self,
        item: Mapping[str, Any],
        receipt: Mapping[str, Any],
        at_ms: int,
    ) -> Mapping[str, Any]:
        resource_ref = item.get("resource_ref")
        namespace = (
            resource_ref.split(":", 1)[0]
            if isinstance(resource_ref, str) and ":" in resource_ref
            else None
        )
        coordinate = (receipt.get("adapter"), item.get("work_kind"), namespace)
        matches = [
            route
            for route in self._routes
            if (route.adapter, route.work_kind, route.resource_namespace) == coordinate
        ]
        if len(matches) != 1 or not callable(matches[0].observer):
            raise MatrixHostError("effect_truth_unverifiable")
        try:
            observed = matches[0].observer(item, receipt, at_ms)
        except Exception as exception:
            raise MatrixHostError("effect_truth_unverifiable") from exception
        if not isinstance(observed, Mapping) or set(observed) != set(
            _EFFECT_OBSERVATION_FIELDS
        ):
            raise MatrixHostError("effect_truth_unverifiable")
        return observed


class MatrixHostError(RuntimeError):
    """Stable, disclosure-safe refusal at the Matrix hosting boundary."""


def _matrix_api() -> dict[str, Any]:
    """Load the optional, pinned dependency and reject a schema downgrade."""

    try:
        from daimon_matrix import cluster as cluster_api
        from daimon_matrix import (
            canonical,
            client,
            curator,
            daemon,
            memory_projection,
            native_egress,
            operator_bootstrap,
            operator_capabilities,
            operator_rebirth,
            publication,
            runtime,
            service,
        )
    except ImportError as exception:  # base clusterctl remains usable without it
        raise MatrixHostError("daimon_matrix_dependency_unavailable") from exception
    try:
        distribution = importlib.metadata.distribution("daimon-matrix")
        direct_url = json.loads(distribution.read_text("direct_url.json") or "null")
        installed_commit = direct_url["vcs_info"]["commit_id"]
    except (
        importlib.metadata.PackageNotFoundError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as exception:
        raise MatrixHostError("daimon_matrix_commit_unverifiable") from exception
    if installed_commit != MATRIX_CONTRACT_COMMIT:
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    expected = {
        "BODY_SNAPSHOT_SCHEMA": "dm.cluster-body-snapshot/v1",
        "FENCE_EVIDENCE_SCHEMA": "dm.cluster-resource-fence-evidence/v1",
        "FENCE_VERIFICATION_SCHEMA": "dm.cluster-resource-fence-verification/v1",
        "FENCE_POSITION_SCHEMA": "dm.cluster-resource-fence-position/v1",
        "EFFECT_RECEIPT_SCHEMA": "dm.cluster-effect-receipt/v1",
        "EFFECT_RECONCILIATION_SCHEMA": "dm.cluster-effect-reconciliation/v1",
    }
    if any(
        getattr(cluster_api, name, None) != value for name, value in expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V7", None) != "dm.runtime.bundle/v7":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(runtime, "BUNDLE_SCHEMA_V8", None) != "dm.runtime.bundle/v8":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if getattr(client, "CLIENT_CONFIG_SCHEMA_V3", None) != "dm.local.client-config/v3":
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    curator_expected = {
        "ITEM_SCHEMA": "dm.curator.item/v1",
        "CLAIM_SCHEMA": "dm.curator.claim/v1",
        "RESULT_SCHEMA": "dm.curator.result/v1",
        "ENQUEUE_SCHEMA": "dm.curator.enqueue-result/v1",
        "INSPECTION_SCHEMA": "dm.curator.inspection/v1",
    }
    if any(
        getattr(curator, name, None) != value
        for name, value in curator_expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if frozenset(getattr(curator, "WORK_KINDS", ())) != frozenset(
        {
            "memory-evaluation",
            "memory-proposal",
            "memory-projection",
            "publication",
        }
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if frozenset(getattr(curator, "COORDINATION_MODES", ())) != frozenset(
        {"queue-item", "resource-fence"}
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if frozenset(getattr(service, "CURATOR_METHODS", ())) != _CURATOR_WORKER_METHODS:
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    projection_expected = {
        "PROFILE_SCHEMA": "dm.memory-projection.profile/v1",
        "INTENT_SCHEMA": "dm.memory-projection.intent/v1",
        "RECEIPT_SCHEMA": "dm.memory-projection.receipt/v1",
        "RECONCILIATION_SCHEMA": "dm.memory-projection.reconciliation/v1",
        "REBUILD_PLAN_SCHEMA": "dm.memory-projection.rebuild-plan/v1",
        "REBUILD_RECEIPT_SCHEMA": "dm.memory-projection.rebuild-receipt/v1",
        "HMK_COMMIT": "f10fd5c3089c0962920314c97e14bc024feffa7a",
        "HMK_API_VERSION": "1.0.0",
        "HMK_SCHEMA_VERSION": 1,
        "PROJECTOR_ID": "matrix:personal-memory-projector",
        "PROJECTOR_VERSION": "1.0.0",
    }
    if any(
        getattr(memory_projection, name, None) != value
        for name, value in projection_expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    publication_expected = {
        "POLICY_SCHEMA": "dm.publication.policy/v1",
        "PROFILE_SCHEMA": "dm.publication.profile/v1",
        "PROPOSAL_SCHEMA": "dm.publication.proposal/v1",
        "REVIEW_SCHEMA": "dm.publication.review/v1",
        "REQUEST_SCHEMA": "dm.publication.request/v1",
        "CLAIM_SCHEMA": "dm.publication.claim/v1",
        "ACCEPTANCE_SCHEMA": "dm.publication.acceptance/v1",
        "RECONCILIATION_SCHEMA": "dm.publication.reconciliation/v1",
        "PROVIDER_REQUEST_SCHEMA": "dm.publisher.request/v1",
        "PROVIDER_PLAN_SCHEMA": "dm.publisher.plan/v1",
        "PROVIDER_RECEIPT_SCHEMA": "dm.publisher.receipt/v1",
        "COMPAII_STATE_COMMIT": "cf56e9de703f68f44b85fdf21f503d55a5557984",
        "HMK_COMMIT": "f10fd5c3089c0962920314c97e14bc024feffa7a",
        "PROVIDER_API_VERSION": "1.0.0",
        "PROVIDER_ADAPTER_ID": (
            "dm:adapter:v0:OnDIAMjSu2T_8EqLG_wxxygVXCPGXaTJsA41-IMcpSo"
        ),
        "PROVIDER_POLICY_HASH": (
            "800929a4d56687ca224c5df767ab05c4c259acc75904530848683a92e2484b88"
        ),
    }
    if any(
        getattr(publication, name, None) != value
        for name, value in publication_expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if (
        frozenset(getattr(operator_bootstrap, "STATUS_OBSERVER_METHODS", ()))
        != _CLUSTERD_MATRIX_METHODS
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if set(getattr(operator_capabilities, "OPERATOR_PROFILE_NAMES", ())) != set(
        getattr(service, "OPERATOR_CAPABILITY_PROFILES", ())
    ) or set(getattr(operator_capabilities, "HOST_PROFILE_NAMES", ())) != {
        "curator",
        "status",
    }:
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    rebirth_expected = {
        "REQUEST_SCHEMA": "dm.operator.embodiment-request/v1",
        "ACTIVATION_SCHEMA": "dm.operator.embodiment-activation/v1",
        "PREPARATION_SCHEMA": "dm.operator.rebirth-preparation/v1",
        "TARGET_PROFILE_SCHEMA": "dm.operator.rebirth-target-profile/v1",
        "RECOVERY_ACTIVATION_SCHEMA": "dm.operator.recovery-activation/v1",
    }
    if any(
        getattr(operator_rebirth, name, None) != value
        for name, value in rebirth_expected.items()
    ):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    if not callable(getattr(operator_rebirth, "restore_recovery_ledger", None)):
        raise MatrixHostError("daimon_matrix_contract_mismatch")
    return {
        "canonical": canonical,
        "client": client,
        "cluster": cluster_api,
        "curator": curator,
        "daemon": daemon,
        "memory_projection": memory_projection,
        "native_egress": native_egress,
        "operator_capabilities": operator_capabilities,
        "operator_rebirth": operator_rebirth,
        "publication": publication,
        "runtime": runtime,
        "service": service,
    }


def matrix_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return an opaque, stable per-embodiment root without leaking its ID."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise MatrixHostError("invalid_embodiment_id")
    # 128 opaque bits keep roots compact enough for sockaddr_un on normal
    # /var/lib deployments while retaining collision resistance at this scale.
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "matrix" / key


def matrix_client_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return the host-local clusterd capability root for one embodiment."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise MatrixHostError("invalid_embodiment_id")
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "matrix-clients" / key


def matrix_curator_client_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return the separate host-local root for one curator worker capability."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise MatrixHostError("invalid_embodiment_id")
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "matrix-curator-clients" / key


def _owner_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        if absolute.resolve(strict=True) != absolute:
            raise MatrixHostError("matrix_root_not_owner_only")
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise MatrixHostError("matrix_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise MatrixHostError("matrix_root_not_owner_only")
    return absolute


def _stable_owner_directory(path: Path) -> tuple[Path, int]:
    """Open an already validated directory and retain its exact inode."""

    absolute = _owner_directory(path)
    before = absolute.lstat()
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
        ):
            raise MatrixHostError("matrix_root_replaced")
        return Path(f"/proc/self/fd/{descriptor}"), descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _destination_parent(
    destination: str | Path, *, exists_code: str
) -> tuple[Path, Path, int]:
    """Return a stable owner-only parent for one new directory target."""

    target = Path(os.path.abspath(destination))
    if not target.name or Path(target.name).name != target.name:
        raise MatrixHostError(exists_code)
    requested_parent = target.parent
    try:
        resolved_parent = requested_parent.resolve(strict=True)
        before = requested_parent.lstat()
    except FileNotFoundError as exception:
        raise MatrixHostError(exists_code) from exception
    if (
        resolved_parent != requested_parent
        or stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise MatrixHostError(exists_code)
    descriptor = -1
    try:
        descriptor = os.open(
            requested_parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
        ):
            raise MatrixHostError(exists_code)
        try:
            os.stat(target.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MatrixHostError(exists_code)
        return target, Path(f"/proc/self/fd/{descriptor}"), descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _publish_directory_noreplace(
    parent_descriptor: int,
    temporary_name: str,
    target_name: str,
    *,
    exists_code: str,
) -> None:
    """Atomically publish a directory without replacing a concurrent target."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise MatrixHostError("matrix_directory_publication_unsupported")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(temporary_name),
        parent_descriptor,
        os.fsencode(target_name),
        1,  # Linux RENAME_NOREPLACE
    )
    if result == 0:
        os.fsync(parent_descriptor)
        return
    observed_errno = ctypes.get_errno()
    if observed_errno in {errno.EEXIST, errno.ENOTEMPTY}:
        raise MatrixHostError(exists_code)
    raise MatrixHostError("matrix_directory_publication_failed") from OSError(
        observed_errno, os.strerror(observed_errno)
    )


def _owner_file_descriptor(path: Path) -> int:
    """Open one stable owner-only regular file without following a symlink."""

    absolute = Path(os.path.abspath(path))
    try:
        before = absolute.lstat()
    except FileNotFoundError as exception:
        raise MatrixHostError("matrix_client_material_missing") from exception
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        raise MatrixHostError("matrix_client_material_not_owner_only")
    try:
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
        ):
            raise MatrixHostError("matrix_client_material_replaced")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _owner_file_bytes(path: Path, code: str, *, maximum_size: int) -> bytes:
    try:
        descriptor = _owner_file_descriptor(path)
    except (MatrixHostError, OSError) as exception:
        raise MatrixHostError(code) from exception
    try:
        info = os.fstat(descriptor)
        if not 1 <= info.st_size <= maximum_size:
            raise MatrixHostError(code)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > maximum_size:
                raise MatrixHostError(code)
            chunks.append(chunk)
        if size != info.st_size:
            raise MatrixHostError(code)
        return b"".join(chunks)
    except OSError as exception:
        raise MatrixHostError(code) from exception
    finally:
        os.close(descriptor)


def _owner_file_digest(
    path: Path, code: str, *, expected_size: int
) -> tuple[os.stat_result, str, int]:
    try:
        descriptor = _owner_file_descriptor(path)
    except (MatrixHostError, OSError) as exception:
        raise MatrixHostError(code) from exception
    try:
        info = os.fstat(descriptor)
        if info.st_size > expected_size:
            return info, "", info.st_size
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if size > expected_size:
                return info, "", size
        return info, digest.hexdigest(), size
    except OSError as exception:
        raise MatrixHostError(code) from exception
    finally:
        os.close(descriptor)


def _copy_owner_file(
    source: Path,
    destination: Path,
    code: str,
    *,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> tuple[str, int]:
    """Copy from one inode-stable owner-only descriptor and hash those bytes."""

    try:
        source_descriptor = _owner_file_descriptor(source)
    except (MatrixHostError, OSError) as exception:
        raise MatrixHostError(code) from exception
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if expected_size is not None and before.st_size != expected_size:
            raise MatrixHostError(code)
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(source_descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        after = os.fstat(source_descriptor)
        value = digest.hexdigest()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or size != before.st_size
            or (expected_sha256 is not None and value != expected_sha256)
        ):
            raise MatrixHostError(code)
        os.fsync(destination_descriptor)
        return value, size
    except OSError as exception:
        raise MatrixHostError(code) from exception
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _public_bundle(root: Path, bundle_name: str) -> dict[str, Any]:
    if (
        not isinstance(bundle_name, str)
        or not bundle_name
        or Path(bundle_name).name != bundle_name
    ):
        raise MatrixHostError("unsafe_matrix_bundle_name")
    path = root / bundle_name
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_BUNDLE_BYTES
        ):
            raise MatrixHostError("matrix_bundle_not_owner_only")
        value = json.loads(path.read_text(encoding="utf-8"))
    except MatrixHostError:
        raise
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exception:
        raise MatrixHostError("matrix_bundle_unreadable") from exception
    if not isinstance(value, dict) or value.get("schema") not in {"dm.runtime.bundle/v7", "dm.runtime.bundle/v8"}:
        raise MatrixHostError("matrix_bundle_rejected")
    return value


def _origin(value: Any) -> dict[str, str]:
    fields = {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or any(
            not isinstance(value[field], str) or not value[field] for field in fields
        )
    ):
        raise MatrixHostError("matrix_origin_rejected")
    return {field: value[field] for field in sorted(fields)}


class MatrixHostAdapter:
    """Exact injected readers/verifiers for one guarded embodiment."""

    def __init__(
        self,
        state_dir: str | Path,
        embodiment_id: str,
        *,
        fence_store: ResourceFenceStore | None = None,
        effect_observer_routes: Sequence[EffectObserverRoute] = (),
        clock: Any = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        self.state_dir = Path(os.path.abspath(state_dir))
        self.embodiment_id = embodiment_id
        self.registry = Registry(self.state_dir)
        self.fences = fence_store or ResourceFenceStore(self.state_dir)
        self.effect_observer = EffectObserverRouter(effect_observer_routes)
        self.clock = clock

    def require_origin(self, value: Mapping[str, Any]) -> dict[str, Any]:
        origin = _origin(value)
        if origin["embodiment_id"] != self.embodiment_id:
            raise MatrixHostError("matrix_embodiment_mismatch")
        try:
            record = self.registry.status(self.embodiment_id)
        except RegistryError as exception:
            raise MatrixHostError("matrix_registry_unavailable") from exception
        if (
            record.get("body_ref") != origin["body_ref"]
            or record.get("status") != "running"
            or record.get("current_incarnation_id") != origin["incarnation_id"]
        ):
            raise MatrixHostError("matrix_origin_registry_mismatch")
        return record

    def body_snapshot(
        self,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        evaluated_at_ms: int | None = None,
    ) -> dict[str, Any]:
        observed_at_ms = (
            int(self.clock()) if evaluated_at_ms is None else evaluated_at_ms
        )
        if (
            isinstance(observed_at_ms, bool)
            or not isinstance(observed_at_ms, int)
            or observed_at_ms < 0
        ):
            raise MatrixHostError("matrix_evaluation_time_rejected")
        self.require_origin(
            {
                "body_ref": body_ref,
                "embodiment_id": embodiment_id,
                "incarnation_id": incarnation_id,
                "principal_id": "cluster-internal-validation",
            }
        )
        try:
            held = self.fences.current_for_holder(embodiment_id, at_ms=observed_at_ms)
        except (FenceError, OSError) as exception:
            raise MatrixHostError("resource_fence_registry_unavailable") from exception
        return {
            "schema": "dm.cluster-body-snapshot/v1",
            "body_ref": body_ref,
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
            "observed_at_ms": observed_at_ms,
            "state": "running",
            "resource_fences": [
                {"resource_ref": item["resource_ref"], "epoch": item["epoch"]}
                for item in held
            ],
        }

    def fence_evidence(self, resource_ref: str) -> dict[str, Any] | None:
        observed_at_ms = int(self.clock())
        try:
            current = self.fences.verify_current(resource_ref, at_ms=observed_at_ms)
            record = self.registry.status(self.embodiment_id)
        except (FenceError, RegistryError, OSError) as exception:
            raise MatrixHostError("resource_fence_registry_unavailable") from exception
        if current is None:
            return None
        incarnation_id = record.get("current_incarnation_id")
        if (
            record.get("status") != "running"
            or current.get("holder_embodiment_id") != self.embodiment_id
            or not isinstance(incarnation_id, str)
        ):
            return None
        matrix = _matrix_api()["cluster"]
        return matrix.create_resource_fence_evidence(
            body_ref=record["body_ref"],
            holder_embodiment_id=self.embodiment_id,
            holder_incarnation_id=incarnation_id,
            resource_ref=current["resource_ref"],
            epoch=current["epoch"],
            observed_at_ms=observed_at_ms,
            expires_at_ms=current["created_ms"] + current["ttl_s"] * 1000,
            verification_ref=self.fences.proof_ref(current),
        )

    def verify_fence(self, evidence: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
        matrix = _matrix_api()["cluster"]
        try:
            current = self.fences.verify_current(
                str(evidence.get("resource_ref") or ""), at_ms=at_ms
            )
            record = self.registry.status(self.embodiment_id)
        except (FenceError, RegistryError, OSError) as exception:
            raise matrix.FenceVerificationUnavailable() from exception
        matches = bool(
            current is not None
            and record.get("status") == "running"
            and record.get("body_ref") == evidence.get("body_ref")
            and record.get("current_incarnation_id")
            == evidence.get("holder_incarnation_id")
            and current.get("holder_embodiment_id")
            == evidence.get("holder_embodiment_id")
            == self.embodiment_id
            and current.get("resource_ref") == evidence.get("resource_ref")
            and current.get("epoch") == evidence.get("epoch")
            and self.fences.proof_ref(current) == evidence.get("verification_ref")
        )
        return {
            "schema": "dm.cluster-resource-fence-verification/v1",
            "content_hash": evidence.get("content_hash"),
            "resource_ref": evidence.get("resource_ref"),
            "holder_embodiment_id": evidence.get("holder_embodiment_id"),
            "epoch": evidence.get("epoch"),
            "verified_at_ms": at_ms,
            "current": matches,
        }

    @staticmethod
    def create_effect_receipt(**fields: Any) -> dict[str, Any]:
        return _matrix_api()["cluster"].create_effect_receipt(**fields)

    def reconcile_effect(
        self,
        receipt: Mapping[str, Any],
        *,
        intent: Any,
        observed_postcondition: Mapping[str, Any] | None,
        at_ms: int | None = None,
    ) -> dict[str, Any]:
        matrix = _matrix_api()["cluster"]
        checked_at = int(self.clock()) if at_ms is None else at_ms
        position = receipt.get("resource_fence")
        evidence = None
        if isinstance(position, Mapping):
            evidence = self.fence_evidence(str(position.get("resource_ref") or ""))
        return matrix.reconcile_effect_receipt(
            receipt,
            intent=intent,
            observed_postcondition=observed_postcondition,
            at_ms=checked_at,
            current_fence_evidence=evidence,
            fence_verifier=self.verify_fence if evidence is not None else None,
        )

    def support_status(self) -> dict[str, Any]:
        return {
            "schema": MATRIX_STATUS_SCHEMA,
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
            "embodiment_id": self.embodiment_id,
            "resource_fences": self.fences.support_status(),
        }


def _matrix_client(
    state_dir: str | Path,
    embodiment_id: str,
    *,
    client_root: Path,
    required_methods: frozenset[str],
) -> Any:
    """Load one exact least-authority local client."""

    api = _matrix_api()
    adapter = MatrixHostAdapter(state_dir, embodiment_id)
    root = _owner_directory(matrix_root(state_dir, embodiment_id))
    bundle = _public_bundle(root, "runtime.json")
    origin = _origin(bundle.get("local_origin"))
    adapter.require_origin(origin)
    socket_name = bundle.get("socket")
    if (
        not isinstance(socket_name, str)
        or not socket_name
        or Path(socket_name).name != socket_name
        or len(os.fsencode(root / socket_name)) > _MAX_UNIX_SOCKET_BYTES
    ):
        raise MatrixHostError("matrix_socket_path_rejected")
    client_root = _owner_directory(client_root)
    key_descriptor = _owner_file_descriptor(client_root / "capability.key")
    try:
        key = api["client"].read_capability_key(key_descriptor)
    except Exception as exception:
        raise MatrixHostError("matrix_client_key_rejected") from exception
    try:
        config = api["client"].ClientConfig.load(client_root / "client.json", key)
    except Exception as exception:
        raise MatrixHostError("matrix_client_config_rejected") from exception
    if frozenset(config.capability.methods) != required_methods:
        raise MatrixHostError("matrix_client_authority_rejected")
    if dict(config.expected_server) != origin:
        raise MatrixHostError("matrix_client_origin_mismatch")
    if config.runtime_id != bundle.get(
        "runtime_id"
    ) or config.runtime_label != bundle.get("runtime_label"):
        raise MatrixHostError("matrix_client_runtime_mismatch")
    return api["client"].LocalClient(root / socket_name, config)


def matrix_client(state_dir: str | Path, embodiment_id: str) -> Any:
    """Load clusterd's read-only five-method Matrix status client.

    The descriptor and 32-byte capability key live outside the portable Matrix
    root.  Snapshots therefore carry encrypted Matrix custody and ledger state,
    but never the host-local capability used by clusterd's status projection.
    """

    return _matrix_client(
        state_dir,
        embodiment_id,
        client_root=matrix_client_root(state_dir, embodiment_id),
        required_methods=_CLUSTERD_MATRIX_METHODS,
    )


def matrix_curator_client(state_dir: str | Path, embodiment_id: str) -> Any:
    """Load a separate exact curator-worker capability for one embodiment."""

    return _matrix_client(
        state_dir,
        embodiment_id,
        client_root=matrix_curator_client_root(state_dir, embodiment_id),
        required_methods=_CURATOR_WORKER_METHODS,
    )


def matrix_client_factory(state_dir: str | Path) -> Any:
    """Build the production factory consumed by clusterd handlers."""

    absolute = Path(os.path.abspath(state_dir))

    def load(embodiment_id: str) -> Any:
        return matrix_client(absolute, embodiment_id)

    return load


def _required_snapshot_runtime_filenames(
    bundle: Mapping[str, Any], bundle_name: str
) -> set[str]:
    """Return V7 files whose absence makes the source incomplete.

    Optional stores are still copied whenever present. Their configured names
    are validated here so no suffix-based omission or unsafe path can hide
    existing state.
    """

    required = {bundle_name}

    def filename(value: Any) -> str:
        if not isinstance(value, str) or not value or Path(value).name != value:
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        return value

    required.add(filename(bundle.get("ledger")))
    keystore = bundle.get("keystore")
    if not isinstance(keystore, Mapping):
        raise MatrixHostError("matrix_snapshot_source_unsafe")
    required.add(filename(keystore.get("filename")))
    routing = bundle.get("routing")
    if routing is not None:
        if not isinstance(routing, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        required.add(filename(routing.get("filename")))
    peer = bundle.get("peer_transport")
    if peer is not None:
        if not isinstance(peer, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        for field in ("exchange_filename", "outbox_filename"):
            filename(peer.get(field))
        required.add("transport-custody.json")
    scopes = bundle.get("scopes")
    if scopes is not None:
        if not isinstance(scopes, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        relationship_name = scopes.get("relationships_filename")
        if relationship_name is not None:
            required.add(filename(relationship_name))
    species = bundle.get("species")
    if species is not None:
        if not isinstance(species, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        for field in ("cas_filename", "pointer_filename", "registry_filename"):
            filename(species.get(field))
    relationships = bundle.get("relationships")
    if relationships is not None:
        if not isinstance(relationships, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        filename(relationships.get("store_filename"))
    sources = bundle.get("sources")
    if sources is not None:
        if not isinstance(sources, Mapping):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        filename(sources.get("cas_filename"))
        known_beings = sources.get("known_beings")
        if not isinstance(known_beings, list):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        for known in known_beings:
            if not isinstance(known, Mapping):
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            required.add(filename(known.get("ledger_filename")))
    return required


def _snapshot_files(
    root: Path,
    bundle_name: str,
    *,
    custody_free: bool = False,
) -> tuple[dict[str, Any], list[Path]]:
    bundle = _public_bundle(root, bundle_name)
    socket_name = bundle.get("socket")
    excluded = {_LOCK_NAME, socket_name}
    configured_required_files = _required_snapshot_runtime_filenames(
        bundle, bundle_name
    )
    ledger_name = bundle["ledger"]
    assert isinstance(ledger_name, str)
    required_files = (
        {bundle_name, ledger_name} if custody_free else configured_required_files
    )
    sqlite_sidecars = {f"{ledger_name}-wal", f"{ledger_name}-shm"}
    if bundle.get("schema") in {"dm.runtime.bundle/v7", "dm.runtime.bundle/v8"}:
        # These paths are secret-bearing by contract. Exclude them before
        # interpreting public profile metadata, then require the complete exact
        # profile table so a truncated or relabelled bundle cannot weaken the
        # exclusion boundary.
        excluded.update(
            {"client.json", "client.key", "operator-clients", "host-clients"}
        )
        api = _matrix_api()
        operator_capabilities = api["operator_capabilities"]
        capabilities = bundle.get("capabilities")
        runtime_id = bundle.get("runtime_id")
        runtime_label = bundle.get("runtime_label")
        operator_roles = set(operator_capabilities.OPERATOR_PROFILE_NAMES)
        host_roles = set(operator_capabilities.HOST_PROFILE_NAMES)
        if (
            not isinstance(capabilities, list)
            or len(capabilities) != len(operator_roles) + len(host_roles)
            or not isinstance(runtime_id, str)
            or not runtime_id
            or not isinstance(runtime_label, str)
            or not runtime_label
        ):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        observed: set[tuple[str, str]] = set()
        for row in capabilities:
            if not isinstance(row, Mapping) or set(row) != {
                "descriptor",
                "profile",
                "runtime_id",
                "secret_slot",
            }:
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            profile = row.get("profile")
            if not isinstance(profile, Mapping) or row.get("runtime_id") != runtime_id:
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            role = profile.get("role")
            schema = profile.get("schema")
            if not isinstance(role, str) or not isinstance(
                row.get("descriptor"), Mapping
            ):
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            try:
                if schema == operator_capabilities.HOST_CAPABILITY_PROFILE_SCHEMA:
                    if role not in host_roles:
                        raise KeyError(role)
                    expected_profile = operator_capabilities.host_capability_profile(
                        role
                    )
                    expected_slot = operator_capabilities.host_capability_slot(
                        runtime_label, role
                    )
                else:
                    if role not in operator_roles:
                        raise KeyError(role)
                    expected_profile = (
                        operator_capabilities.operator_capability_profile(role)
                    )
                    expected_slot = operator_capabilities.operator_capability_slot(
                        runtime_label, role
                    )
            except (
                KeyError,
                operator_capabilities.OperatorCapabilityError,
            ) as exception:
                raise MatrixHostError("matrix_snapshot_source_unsafe") from exception
            identity = (str(expected_profile["schema"]), role)
            if (
                dict(profile) != expected_profile
                or row.get("secret_slot") != expected_slot
                or identity in observed
            ):
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            observed.add(identity)
            client_directory = profile.get("client_directory")
            config_name = profile.get("client_config_filename")
            key_name = profile.get("client_key_filename")
            if not all(
                isinstance(value, str) and value for value in (config_name, key_name)
            ):
                raise MatrixHostError("matrix_snapshot_source_unsafe")
            if client_directory == ".":
                excluded.update((config_name, key_name))
            elif isinstance(client_directory, str):
                parts = Path(client_directory).parts
                if (
                    len(parts) != 2
                    or parts[0] not in {"operator-clients", "host-clients"}
                    or not parts[1]
                ):
                    raise MatrixHostError("matrix_snapshot_source_unsafe")
                excluded.add(parts[0])
            else:
                raise MatrixHostError("matrix_snapshot_source_unsafe")
        expected_identities = {
            (
                operator_capabilities.operator_capability_profile(role)["schema"],
                role,
            )
            for role in operator_roles
        } | {
            (operator_capabilities.host_capability_profile(role)["schema"], role)
            for role in host_roles
        }
        if observed != expected_identities:
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        try:
            authority = api["operator_rebirth"].authority_from_runtime_bundle(bundle)
            origin = _origin(bundle.get("local_origin"))
            member = authority.validate_origin(origin, require_active=True)
            credential = authority.credentials[member["embodiment_credential_id"]]
            signing_key = credential["body"]["signing_key"]
            operator_capabilities.verify_operator_capability_binding(
                bundle.get("operator_capability_binding"),
                runtime_id=runtime_id,
                runtime_label=runtime_label,
                being_ref=authority.state.being_ref,
                origin=origin,
                signing_key=signing_key,
                capability_rows=capabilities,
            )
        except Exception as exception:
            raise MatrixHostError("matrix_snapshot_source_unsafe") from exception
    files: list[Path] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path.name in excluded or path.name in sqlite_sidecars:
            continue
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise MatrixHostError("matrix_snapshot_source_unsafe")
        files.append(path)
    observed_files = {path.name for path in files}
    if not required_files.issubset(observed_files) or (
        custody_free and observed_files != required_files
    ):
        raise MatrixHostError("matrix_snapshot_source_unsafe")
    return bundle, files


def create_portable_snapshot(
    root: str | Path, destination: str | Path, *, bundle_name: str = "runtime.json"
) -> dict[str, Any]:
    """Copy a quiesced Matrix root into a closed, hashed snapshot directory."""

    api = _matrix_api()
    source, source_descriptor = _stable_owner_directory(Path(root))
    try:
        target, target_parent, parent_descriptor = _destination_parent(
            destination, exists_code="matrix_snapshot_destination_exists"
        )
    except BaseException:
        os.close(source_descriptor)
        raise
    lock_descriptor: int | None = None
    temporary_name = f".{target.name}.snapshot-{uuid.uuid4()}"
    temporary = target_parent / temporary_name
    temporary_created = False
    try:
        lock_descriptor = api["daemon"].acquire_lock(source)
        bundle, files = _snapshot_files(source, bundle_name)
        os.mkdir(temporary_name, mode=0o700, dir_fd=parent_descriptor)
        temporary_created = True
        temporary.chmod(0o700)
        payload = temporary / "payload"
        payload.mkdir(mode=0o700)
        entries = []
        for path in files:
            copied = payload / path.name
            digest, size = _copy_owner_file(
                path, copied, "matrix_snapshot_source_replaced"
            )
            entries.append(
                {
                    "name": path.name,
                    "sha256": digest,
                    "size": size,
                }
            )
        manifest = {
            "schema": MATRIX_SNAPSHOT_SCHEMA,
            "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
            "bundle": bundle_name,
            "origin": _origin(bundle.get("local_origin")),
            "files": entries,
        }
        manifest_path = temporary / "snapshot.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        _publish_directory_noreplace(
            parent_descriptor,
            temporary_name,
            target.name,
            exists_code="matrix_snapshot_destination_exists",
        )
        temporary_created = False
        return manifest
    except BlockingIOError as exception:
        raise MatrixHostError("matrix_runtime_not_quiesced") from exception
    except BaseException:
        if temporary_created:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        os.close(parent_descriptor)
        os.close(source_descriptor)


def restore_portable_snapshot(
    snapshot: str | Path, destination: str | Path
) -> dict[str, Any]:
    """Verify and restore a portable snapshot to a fresh owner-only root."""

    source, source_descriptor = _stable_owner_directory(Path(snapshot))
    try:
        target, target_parent, parent_descriptor = _destination_parent(
            destination, exists_code="matrix_restore_destination_exists"
        )
    except BaseException:
        os.close(source_descriptor)
        raise
    temporary_name = f".{target.name}.restore-{uuid.uuid4()}"
    temporary = target_parent / temporary_name
    temporary_created = False
    try:
        manifest, _payload, verified = verify_portable_snapshot(
            source, _stable_root=True
        )
        os.mkdir(temporary_name, mode=0o700, dir_fd=parent_descriptor)
        temporary_created = True
        temporary.chmod(0o700)
        rows = {row["name"]: row for row in manifest["files"]}
        for path, name in verified:
            copied = temporary / name
            row = rows[name]
            _copy_owner_file(
                path,
                copied,
                "matrix_snapshot_payload_replaced",
                expected_size=row["size"],
                expected_sha256=row["sha256"],
            )
        _publish_directory_noreplace(
            parent_descriptor,
            temporary_name,
            target.name,
            exists_code="matrix_restore_destination_exists",
        )
        temporary_created = False
    except BaseException:
        if temporary_created:
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    finally:
        os.close(parent_descriptor)
        os.close(source_descriptor)
    return manifest


def verify_portable_snapshot(
    snapshot: str | Path,
    *,
    _stable_root: bool = False,
    _custody_free: bool = False,
) -> tuple[dict[str, Any], Path, list[tuple[Path, str]]]:
    """Verify a full or explicitly custody-free snapshot without restoring it."""

    source = Path(snapshot) if _stable_root else _owner_directory(Path(snapshot))
    try:
        manifest_raw = _owner_file_bytes(
            source / "snapshot.json",
            "matrix_snapshot_manifest_unreadable",
            maximum_size=16 * 1024 * 1024,
        )
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise MatrixHostError("matrix_snapshot_manifest_unreadable") from exception
    expected_schema = (
        MATRIX_RECOVERY_SNAPSHOT_SCHEMA
        if _custody_free
        else MATRIX_SNAPSHOT_SCHEMA
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"schema", "matrix_contract_commit", "bundle", "origin", "files"}
        or manifest.get("schema") != expected_schema
        or manifest.get("matrix_contract_commit") != MATRIX_CONTRACT_COMMIT
        or not isinstance(manifest.get("files"), list)
    ):
        raise MatrixHostError("matrix_snapshot_manifest_rejected")
    _origin(manifest.get("origin"))
    payload = source / "payload"
    if _stable_root:
        try:
            payload_info = payload.lstat()
        except FileNotFoundError as exception:
            raise MatrixHostError("matrix_root_missing") from exception
        if (
            stat.S_ISLNK(payload_info.st_mode)
            or not stat.S_ISDIR(payload_info.st_mode)
            or payload_info.st_uid != os.geteuid()
            or stat.S_IMODE(payload_info.st_mode) & 0o077
        ):
            raise MatrixHostError("matrix_root_not_owner_only")
    else:
        payload = _owner_directory(payload)
    verified: list[tuple[Path, str]] = []
    names: set[str] = set()
    for row in manifest["files"]:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"name", "sha256", "size"}
            or not isinstance(row["name"], str)
            or Path(row["name"]).name != row["name"]
            or row["name"] in names
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
        ):
            raise MatrixHostError("matrix_snapshot_manifest_rejected")
        path = payload / row["name"]
        try:
            _info, digest, size = _owner_file_digest(
                path,
                "matrix_snapshot_payload_unreadable",
                expected_size=row["size"],
            )
        except MatrixHostError as exception:
            raise MatrixHostError("matrix_snapshot_payload_unreadable") from exception
        if size != row["size"] or digest != row["sha256"]:
            raise MatrixHostError("matrix_snapshot_payload_rejected")
        names.add(row["name"])
        verified.append((path, row["name"]))
    if {path.name for path in payload.iterdir()} != names:
        raise MatrixHostError("matrix_snapshot_payload_rejected")
    try:
        bundle, portable_files = _snapshot_files(
            payload,
            manifest["bundle"],
            custody_free=_custody_free,
        )
    except (MatrixHostError, KeyError, TypeError) as exception:
        raise MatrixHostError("matrix_snapshot_payload_rejected") from exception
    if (
        _origin(bundle.get("local_origin")) != _origin(manifest.get("origin"))
        or {path.name for path in portable_files} != names
    ):
        raise MatrixHostError("matrix_snapshot_payload_rejected")
    return manifest, payload, verified


def _password_reader(descriptor: int) -> Any:
    used = False

    def read() -> bytearray:
        nonlocal used
        if used:
            raise MatrixHostError("password_descriptor_reused")
        used = True
        try:
            value = os.read(descriptor, _MAX_PASSWORD_BYTES + 1)
        finally:
            os.close(descriptor)
        if not value or len(value) > _MAX_PASSWORD_BYTES:
            raise MatrixHostError("invalid_password_descriptor")
        return bytearray(value)

    return read


def _diagnostic(code: str) -> None:
    value = {"schema": "dm.cluster-matrix-host-diagnostic/v1", "code": code}
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--embodiment-id", required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--guardian-pid", type=int)
    parser.add_argument("--visibility-installation", type=Path)
    parser.add_argument("--provision-visibility", action="store_true")
    parser.add_argument(
        "--production-fence-verifier",
        action="store_true",
        help="verify Cluster's production fence database without signing custody",
    )
    args = parser.parse_args(argv)
    if args.provision_visibility and (
        args.visibility_installation is not None or args.ready_fd is not None
    ):
        _diagnostic("matrix_visibility_provision_never_serves")
        return 2
    lock_descriptor: int | None = None
    stopping = threading.Event()
    guardian: threading.Thread | None = None
    try:
        if args.guardian_pid is not None:
            if args.guardian_pid <= 1 or os.getppid() != args.guardian_pid:
                raise MatrixHostError("matrix_guardian_missing")

            def require_guardian() -> None:
                while not stopping.wait(0.02):
                    if os.getppid() != args.guardian_pid:
                        os.kill(os.getpid(), signal.SIGKILL)

            guardian = threading.Thread(
                target=require_guardian,
                name=f"matrix-guardian-{args.guardian_pid}",
                daemon=True,
            )
            guardian.start()
        api = _matrix_api()
        fence_store = (
            ResourceFenceStore.production_verifier(args.state_dir)
            if args.production_fence_verifier
            else None
        )
        adapter = None if args.provision_visibility else MatrixHostAdapter(
            args.state_dir, args.embodiment_id, fence_store=fence_store
        )
        root = _owner_directory(matrix_root(args.state_dir, args.embodiment_id))
        bundle = _public_bundle(root, args.bundle)
        origin = _origin(bundle.get("local_origin"))
        if args.provision_visibility:
            record = Registry(args.state_dir).status(args.embodiment_id)
            if (origin["embodiment_id"] != args.embodiment_id
                    or record.get("body_ref") != origin["body_ref"]
                    or record.get("status") != "stopped"
                    or record.get("current_incarnation_id") is not None):
                raise MatrixHostError("matrix_visibility_requires_stopped_body")
        else:
            assert adapter is not None
            adapter.require_origin(origin)
        socket_name = bundle.get("socket")
        if (
            not isinstance(socket_name, str)
            or not socket_name
            or Path(socket_name).name != socket_name
            or len(os.fsencode(root / socket_name)) > _MAX_UNIX_SOCKET_BYTES
        ):
            raise MatrixHostError("matrix_socket_path_rejected")
        lock_descriptor = api["daemon"].acquire_lock(root)
        def clock() -> int:
            return time.time_ns() // 1_000_000
        visibility_options = {}
        if args.visibility_installation is not None:
            visibility_options["egress_factory"] = api["daemon"]._visibility_factory(
                args.visibility_installation, clock=clock
            )
        elif args.provision_visibility:
            controller = api["native_egress"].closed_visibility(
                clock=clock, catalog_mode="migrate"
            )
            # Native composition initializes base tables. Refuse incompatible
            # existing visibility journals before that composition writes DDL.
            catalogs = []
            peer = bundle.get("peer_transport")
            if peer is not None:
                catalogs.extend([
                    ("runtime-peer-responses", peer["exchange_filename"]),
                    ("runtime-peer-requests", peer["outbox_filename"]),
                ])
            if bundle.get("routing") is not None:
                catalogs.append(("runtime-route-requests", bundle["ledger"]))
            for catalog_id, filename in catalogs:
                path = api["runtime"]._safe_file(root, filename, must_exist=False)
                if path.exists():
                    controller._preflight_migration(path, catalog_id)
            visibility_options["egress"] = controller
        runtime = api["runtime"].load_runtime(
            root,
            args.bundle,
            _password_reader(args.password_fd),
            clock=clock,
            body_reader=None if adapter is None else adapter.body_snapshot,
            curator_fence_verifier=None if adapter is None else adapter.verify_fence,
            curator_effect_observer=None if adapter is None else adapter.effect_observer,
            **visibility_options,
        )
        if args.provision_visibility:
            runtime.egress.migrate_registered_catalogs(
                version=api["native_egress"].VISIBILITY_SCHEMA_VERSION
            )
            runtime.egress.validate_registered_catalogs()
            _diagnostic("matrix_visibility_provisioned")
            return 0

        def request_stop(_number: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        api["daemon"].serve_forever(
            runtime, stop=stopping, ready_descriptor=args.ready_fd
        )
        return 0
    except Exception as exception:  # noqa: BLE001 - one closed process boundary
        code = exception.args[0] if exception.args else "matrix_host_startup_refused"
        _diagnostic(code if isinstance(code, str) else "matrix_host_startup_refused")
        return 1
    finally:
        stopping.set()
        if lock_descriptor is not None:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EffectObserverRoute",
    "EffectObserverRouter",
    "MATRIX_CONTRACT_COMMIT",
    "MATRIX_RECOVERY_SNAPSHOT_SCHEMA",
    "MATRIX_SNAPSHOT_SCHEMA",
    "MATRIX_STATUS_SCHEMA",
    "MatrixHostAdapter",
    "MatrixHostError",
    "create_portable_snapshot",
    "main",
    "matrix_client",
    "matrix_client_factory",
    "matrix_client_root",
    "matrix_curator_client",
    "matrix_curator_client_root",
    "matrix_root",
    "restore_portable_snapshot",
    "verify_portable_snapshot",
]
