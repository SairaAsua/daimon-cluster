"""Private portable-context intake, independent of Matrix custody and Incus.

The preserved context utility is an exact upstream snapshot, not another archive
implementation. Preparation is not enrollment or an observed running body.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import BinaryIO

TOOL_COMMIT = "3a4ab6cdc5cb29712e44eabc063b1a53e8528db2"
TOOL_HASHES = {
    "export_being.py": "9cf5761d2031eda3549f6097ce4747c0a21b402836426b2c2e4187687d857aa4",
    "receive_being.py": "29241c7e2254796cab7cf42eac47099f4ff44504afef4e562bc36591d9222bcc",
    "install_codex_identity.py": "cb98a8a5e1c04777b78b19ea9755116998d371ed541d14a4cf7eb34b47f5b8b0",
    "protected_being.py": "53fc6db90a70556b38b3fa377655754e5785f9bf26fd0c090bfa43ba6e053fe9"
}
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,30}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}\Z")
MAX_UPLOAD = 2 * 1024**3
MAX_RECORD = 65536
MAX_SELECTION = 2 * 1024**2
MAX_PREPARATION = 16 * 1024**2
PREPARATION_TIMEOUT = 3600
MAX_SEEDS = 200
MAX_OWNER_SEEDS = 8
SCHEMA = "cluster-being-seed/v1"
PHASES = {"awaiting-upload", "uploaded", "preparing", "prepared", "attention-required"}


class SeedError(ValueError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.status = status


def _path(path: Path) -> Path:
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise SeedError("seed_symlink_path_refused")
    return path


def _read(path: Path, *, limit: int = MAX_RECORD) -> dict:
    _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise SeedError("private_seed_record_required")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise SeedError("invalid_seed_record")
    return value


def _write(path: Path, value: dict, *, limit: int = MAX_RECORD) -> None:
    _path(path)
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) > limit:
        raise SeedError("seed_record_too_large")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _directory(state_dir: str | Path, name: str) -> Path:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise SeedError("invalid_seed_name")
    return _path(Path(state_dir) / "being-seeds" / name)


def _record(state_dir: str | Path, name: str, owner: str) -> tuple[Path, dict]:
    directory = _directory(state_dir, name)
    try:
        record = _read(directory / "record.json")
    except FileNotFoundError as exc:
        raise SeedError("seed_not_found", 404) from exc
    if owner != "*" and record.get("created_by") != owner:
        raise SeedError("seed_not_found", 404)
    if record.get("schema") != SCHEMA or record.get("name") != name:
        raise SeedError("invalid_seed_record")
    if record.get("phase") == "awaiting-upload" and (directory / "source.archive").exists():
        # A crash may publish bytes before publishing metadata. Reads expose
        # that ambiguity; neither retry nor repair may replace those bytes.
        record = {**record, "phase": "attention-required"}
    return directory, record


@contextlib.contextmanager
def _locked(directory: Path, *, shared: bool = False):
    fd = os.open(_path(directory / "lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SeedError("seed_operation_in_progress", 409) from exc
        yield
    finally:
        os.close(fd)


def _fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def verified_tools() -> Path:
    root = Path(__file__).resolve().parents[1] / "support/being-seed-tools"
    for filename, expected in TOOL_HASHES.items():
        raw = _path(root / "tools" / filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise SeedError("pinned_seed_tool_mismatch", 503)
    return root


def tool(name: str, arguments: list[str], *, timeout: int = 600) -> dict:
    root = verified_tools()
    launcher = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                f"from tools.{name} import main; raise SystemExit(main())")
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-c", launcher, str(root), *arguments],
            capture_output=True, timeout=timeout, check=False,
        )
        value = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, ValueError) as exc:
        raise SeedError("seed_tool_incomplete", 409) from exc
    if result.returncode or not isinstance(value, dict):
        # No upstream stderr, archive contents or private paths in the API.
        raise SeedError("seed_verification_or_preparation_refused")
    return value


def create(state_dir: str | Path, spec: dict, *, owner: str, key: str) -> dict:
    if not isinstance(spec, dict) or set(spec) - {"name", "label", "mode", "browser", "soul"}:
        raise SeedError("invalid_seed_request")
    if (spec.get("mode") not in {"import", "new"}
            or not isinstance(spec.get("label"), str) or not LABEL.fullmatch(spec["label"])
            or type(spec.get("browser", False)) is not bool):
        raise SeedError("invalid_seed_request")
    try:
        uuid.UUID(key)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SeedError("seed_idempotency_key_required") from exc
    if spec["mode"] == "new":
        soul = spec.get("soul")
        if not isinstance(soul, str) or not soul.strip() or len(soul.encode()) > 24000 or "\0" in soul:
            raise SeedError("new_seed_initial_soul_required")
    elif "soul" in spec:
        raise SeedError("import_seed_preserves_original_soul")
    directory = _directory(state_dir, spec.get("name", ""))
    parent = directory.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.stat().st_uid != os.geteuid() or parent.stat().st_mode & 0o077:
        raise SeedError("private_seed_directory_required")
    fingerprint = _fingerprint({"spec": spec, "owner": owner, "key": key})
    with _locked(parent):
        if directory.exists():
            _, old = _record(state_dir, spec["name"], owner)
            if old.get("request_fingerprint") != fingerprint:
                raise SeedError("seed_name_or_request_conflict", 409)
            return project(old)
        key_digest = hashlib.sha256(key.encode()).hexdigest()
        owned = 0
        for existing in parent.glob("*/record.json"):
            old = _read(existing)
            owned += old.get("created_by") == owner
            if old.get("created_by") == owner and old.get("idempotency_digest") == key_digest:
                raise SeedError("seed_idempotency_key_reuse", 409)
        if owned >= MAX_OWNER_SEEDS:
            raise SeedError("owner_seed_intake_capacity_reached", 409)
        if len(list(parent.glob("*/record.json"))) >= MAX_SEEDS:
            raise SeedError("seed_intake_capacity_reached", 409)
        directory.mkdir(mode=0o700)
        record = {
            "schema": SCHEMA, "name": spec["name"], "label": spec["label"],
            "mode": spec["mode"], "created_by": owner,
            "request_fingerprint": fingerprint, "created_ms": int(time.time() * 1000),
            "idempotency_digest": key_digest,
            "phase": "awaiting-upload", "browser_requested": spec.get("browser", False),
            "tool_commit": TOOL_COMMIT,
        }
        if spec["mode"] == "new":
            _write(directory / "initial-context.json", {"soul": spec["soul"]})
            record["phase"] = "uploaded"
        _write(directory / "record.json", record)
    return project(record)


def _retryable_upload(directory: Path, record: dict) -> bool:
    """Retry interrupted intake only; never touch published or prepared context."""
    if (record.get("mode") != "import" or record.get("phase") != "attention-required"
            or any(record.get(key) is not None for key in
                   ("archive_sha256", "archive_size", "preparation_fingerprint"))):
        return False
    partials = 0
    for path in directory.iterdir():
        if path.name == "transfer" or re.fullmatch(r"\.transfer-[0-9a-f]{32}", path.name):
            from .onboarding_transfer import _packet_at
            try:
                _packet_at(path, record)
            except (OSError, ValueError):
                return False
            continue
        if path.name in {"record.json", "connections.json", "lock"}:
            continue
        if not re.fullmatch(r"upload-[0-9a-f]{32}\.partial", path.name):
            return False
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            return False
        partials += 1
    return partials > 0


def _partial_digest(path: Path) -> tuple[int, str]:
    fd = os.open(_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise SeedError("private_upload_partial_required", 409)
        return info.st_size, hashlib.file_digest(stream, "sha256").hexdigest()


def _resume_partial(directory: Path, record: dict) -> tuple[Path | None, int, str]:
    candidates = sorted(directory.glob("upload-*.partial"),
                        key=lambda p: (-p.lstat().st_size, p.name))
    for path in candidates:
        if not re.fullmatch(r"upload-[0-9a-f]{32}\.partial", path.name):
            raise SeedError("private_upload_partial_required", 409)
        size, digest = _partial_digest(path)
        if 0 < size <= record["upload_size"]:
            # A complete but corrupt attempt cannot be extended or published.
            if size == record["upload_size"] and digest != record["upload_sha256"]:
                continue
            return path, size, digest
    return None, 0, hashlib.sha256(b"").hexdigest()


def upload_progress(state_dir: str | Path, name: str, *, owner: str) -> dict:
    """Owner-only durable offset. The client verifies its exact local prefix."""
    directory, _ = _record(state_dir, name, owner)
    with _locked(directory):
        _, record = _record(state_dir, name, owner)
        if record["mode"] != "import":
            raise SeedError("new_seed_has_no_source_archive", 409)
        if record.get("archive_sha256") is not None:
            return dict(complete=True, offset=record["archive_size"],
                        size=record["archive_size"], sha256=record["archive_sha256"],
                        prefix_sha256=record["archive_sha256"])
        if record["phase"] != "awaiting-upload" and not _retryable_upload(directory, record):
            raise SeedError("seed_upload_not_resumable", 409)
        size, digest = record.get("upload_size"), record.get("upload_sha256")
        if size is None or digest is None:
            return dict(complete=False, offset=0, size=None, sha256=None,
                        prefix_sha256=hashlib.sha256(b"").hexdigest())
        _, offset, prefix = _resume_partial(directory, record)
        return dict(complete=False, offset=offset, size=size, sha256=digest,
                    prefix_sha256=prefix)


def upload(state_dir: str | Path, name: str, *, owner: str,
           stream: BinaryIO, length: int, sha256: str, offset: int | None = None,
           total: int | None = None, prefix_sha256: str | None = None) -> dict:
    directory, _ = _record(state_dir, name, owner)
    resume = offset is not None or total is not None or prefix_sha256 is not None
    if resume:
        if (type(offset) is not int or type(total) is not int
                or not 0 <= offset <= total or length != total - offset
                or not isinstance(prefix_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", prefix_sha256)):
            raise SeedError("seed_upload_resume_headers_required")
        size = total
    else:
        size = length
    if (not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or type(length) is not int or not 0 < size <= MAX_UPLOAD):
        raise SeedError("bounded_archive_and_sha256_required", 413)
    with _locked(directory):
        _, record = _record(state_dir, name, owner)
        if record["mode"] != "import":
            raise SeedError("new_seed_has_no_source_archive", 409)
        if record.get("archive_sha256") == sha256 and record.get("archive_size") == size:
            return project(record)
        if record["phase"] != "awaiting-upload" and not _retryable_upload(directory, record):
            raise SeedError("seed_archive_already_present", 409)
        if (record.get("upload_sha256", sha256) != sha256
                or record.get("upload_size", size) != size):
            raise SeedError("seed_upload_retry_requires_same_archive", 409)
        # Upstream permits at most 5 GiB of expanded payload. Reserve space
        # for preserved and working copies plus uploaded archive copies.
        if shutil.disk_usage(directory).free < 10 * 1024**3 + 3 * size:
            raise SeedError("seed_staging_storage_required", 409)
        path = None
        if resume and offset:
            if record.get("upload_sha256") != sha256 or record.get("upload_size") != size:
                raise SeedError("seed_upload_retry_requires_same_archive", 409)
            path, actual, prefix = _resume_partial(directory, record)
            if actual != offset or prefix != prefix_sha256 or path is None:
                raise SeedError("seed_upload_resume_offset_changed", 409)
        elif resume and prefix_sha256 != hashlib.sha256(b"").hexdigest():
            raise SeedError("seed_upload_resume_prefix_mismatch", 409)
        record.update(upload_sha256=sha256, upload_size=size)
        _write(directory / "record.json", record)
        if path is None:
            path = directory / ("upload-" + uuid.uuid4().hex + ".partial")
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        else:
            fd = os.open(_path(path), os.O_RDWR | os.O_NOFOLLOW)
        digest = hashlib.sha256()
        try:
            with os.fdopen(fd, "r+b") as destination:
                if resume and offset:
                    while chunk := destination.read(1024 * 1024):
                        digest.update(chunk)
                    if destination.tell() != offset or digest.hexdigest() != prefix_sha256:
                        raise SeedError("seed_upload_resume_offset_changed", 409)
                remaining = length
                read = getattr(stream, "read1", stream.read)
                try:
                    while remaining:
                        chunk = read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise SeedError("incomplete_seed_upload")
                        destination.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                finally:
                    destination.flush()
                    os.fsync(destination.fileno())
            if digest.hexdigest() != sha256:
                raise SeedError("seed_archive_hash_mismatch")
            from .onboarding_transfer import MAGIC
            with path.open("rb") as incoming:
                protected = incoming.read(len(MAGIC)) == MAGIC
            if protected:
                from .onboarding_transfer import _packet
                _, _, recipient_digest = _packet(directory, record)
                record["transfer_recipient_sha256"] = recipient_digest
            os.link(path, directory / "source.archive")
            record.update(phase="uploaded", archive_sha256=sha256, archive_size=size)
        except (OSError, SeedError):
            record["phase"] = "attention-required"
            _write(directory / "record.json", record)
            raise
        _write(directory / "record.json", record)
        path.unlink()
    return project(record)


def discovery(state_dir: str | Path, name: str, *, owner: str) -> dict:
    directory, record = _record(state_dir, name, owner)
    with _locked(directory):
        if record["mode"] != "import" or record["phase"] not in {"uploaded", "prepared"}:
            raise SeedError("seed_discovery_requires_uploaded_archive", 409)
        selection_path = directory / "discovery.json"
        if not selection_path.exists():
            from .onboarding_transfer import arguments
            protected_args = arguments(directory, record)
            tool("receive_being", ["discover", "--archive", str(directory / "source.archive"),
                                  "--sha256", record["archive_sha256"],
                                  "--output", str(selection_path), *protected_args])
        return _read(selection_path, limit=MAX_SELECTION)


def queue_prepare(state_dir: str | Path, name: str, selection: dict | None, *, owner: str) -> dict:
    """Persist the owner's exact selection for the existing service worker.

    This records no consent, credentials or inferred identity. Publication is
    bounded and fast; the private archive is processed outside the HTTP request.
    """
    directory, record = _record(state_dir, name, owner)
    if record["mode"] == "import":
        required = {"schema", "being_label", "memory_coverage", "soul", "memory", "skills"}
        if (not isinstance(selection, dict) or not required <= set(selection)
                or set(selection) - required - {"discovery"}
                or selection["schema"] != "dm.being-receiving-selection/v1"
                or selection["being_label"] != record["label"]
                or selection["memory_coverage"] not in {"owner-selected", "complete-authorized"}
                or not isinstance(selection["soul"], str) or not selection["soul"]
                or any(not isinstance(selection[key], list) for key in ("memory", "skills"))):
            raise SeedError("explicit_receiving_selection_required")
    elif selection is not None:
        raise SeedError("new_seed_has_no_historical_selection")
    fingerprint = _fingerprint({"selection": selection})
    with _locked(directory):
        _, record = _record(state_dir, name, owner)
        if record["phase"] == "prepared" and record.get("preparation_fingerprint") == fingerprint:
            return project(record)
        if record["phase"] != "uploaded":
            raise SeedError("seed_preparation_preserves_existing_attempt", 409)
        request = dict(schema="cluster-being-seed-preparation-request/v1", owner=owner,
            archive_sha256=record.get("archive_sha256"), selection=selection)
        path = directory / "preparation-request.json"
        if path.exists():
            if _read(path, limit=MAX_SELECTION) != request:
                raise SeedError("seed_preparation_preserves_existing_attempt", 409)
        else:
            _write(path, request, limit=MAX_SELECTION)
        record["preparation_queued"] = True
        _write(directory / "record.json", record)
        return project(record)


def process_preparation(state_dir: str | Path, name: str, *, owner: str) -> dict | None:
    """Run only a durable owner request; retries preserve installed context."""
    directory, record = _record(state_dir, name, owner)
    try:
        request = _read(directory / "preparation-request.json", limit=MAX_SELECTION)
    except FileNotFoundError:
        return None
    if (set(request) != {"schema", "owner", "archive_sha256", "selection"}
            or request["schema"] != "cluster-being-seed-preparation-request/v1"
            or request["owner"] != owner
            or request["archive_sha256"] != record.get("archive_sha256")
                and not (record["mode"] == "new" and request["archive_sha256"] is None)):
        raise SeedError("invalid_seed_preparation_request")
    return prepare(state_dir, name, request["selection"], owner=owner)


def prepare(state_dir: str | Path, name: str, selection: dict | None, *, owner: str) -> dict:
    directory, _ = _record(state_dir, name, owner)
    with _locked(directory):
        _, record = _record(state_dir, name, owner)
        fingerprint = _fingerprint({"selection": selection})
        if record["phase"] == "prepared" and record.get("preparation_fingerprint") == fingerprint:
            return project(record)
        if (record["phase"] in {"preparing", "attention-required"}
                and record.get("preparation_fingerprint") == fingerprint
                and (directory / "received/preparation.json").exists()):
            # The native tool durably publishes its final marker before the
            # intake record. Reconcile that crash window without running the
            # tool again or replacing subsequent receiving writes.
            report = _read(directory / "received/preparation.json", limit=MAX_PREPARATION)
            if (report.get("archive_sha256") != record.get("archive_sha256")
                    or record["mode"] == "import" and report.get("selection") != selection):
                raise SeedError("seed_preparation_preserves_existing_attempt", 409)
            return _complete_preparation(directory, record, report)
        interrupted = (record["mode"] == "import"
            and record["phase"] in {"preparing", "attention-required"}
            and record.get("preparation_fingerprint") == fingerprint
            and record.get("preparation_queued") is True)
        if interrupted:
            # No readiness marker was published: this context has never been
            # installed. Preserve every partial byte before a bounded retry.
            if int(record.get("preparation_attempts", 1)) >= 3:
                raise SeedError("seed_preparation_retry_limit", 409)
            partial = directory / "received"
            if partial.exists():
                _path(partial)
                os.rename(partial, directory / ("uncompleted-receiving-" + uuid.uuid4().hex))
        elif record["phase"] != "uploaded":
            raise SeedError("seed_preparation_preserves_existing_attempt", 409)
        if record["mode"] == "import" and not isinstance(selection, dict):
            raise SeedError("explicit_receiving_selection_required")
        if record["mode"] == "new" and selection is not None:
            raise SeedError("new_seed_has_no_historical_selection")
        record.update(phase="preparing", preparation_fingerprint=fingerprint,
            preparation_attempts=int(record.get("preparation_attempts", 1 if interrupted else 0)) + 1)
        _write(directory / "record.json", record)
        try:
            if record["mode"] == "new":
                source = directory / "initial-source"
                source.mkdir(mode=0o700)
                soul = _read(directory / "initial-context.json")["soul"]
                fd = os.open(source / "SOUL.md", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(soul.encode())
                plan = directory / "export-plan.json"
                tool("export_being", ["discover", "--being", record["label"],
                                     "--context-root", str(source), "--output", str(plan)])
                exported = tool("export_being", ["export", "--plan", str(plan),
                                                "--output", str(directory / "generated.tgz"),
                                                "--writers-stopped"])
                os.rename(directory / "generated.tgz", directory / "source.archive")
                record["archive_sha256"] = exported["sha256"]
                tool("receive_being", ["discover", "--archive", str(directory / "source.archive"),
                                      "--sha256", record["archive_sha256"],
                                      "--output", str(directory / "discovery.json")])
                selection = _read(directory / "discovery.json", limit=MAX_SELECTION)
            assert isinstance(selection, dict)
            _write(directory / "selection.json", selection, limit=MAX_SELECTION)
            from .onboarding_transfer import arguments
            protected_args = arguments(directory, record)
            tool("receive_being", ["prepare", "--archive", str(directory / "source.archive"),
                                  "--sha256", record["archive_sha256"],
                                  "--selection", str(directory / "selection.json"),
                                  "--output", str(directory / "received"), *protected_args],
                 timeout=PREPARATION_TIMEOUT)
            report = _read(directory / "received/preparation.json", limit=MAX_PREPARATION)
            return _complete_preparation(directory, record, report)
        except (SeedError, OSError, ValueError, KeyError, TypeError):
            record["phase"] = "attention-required"
            _write(directory / "record.json", record)
            raise SeedError("seed_preparation_requires_attention", 409) from None


def _complete_preparation(directory: Path, record: dict, report: dict) -> dict:
    if report.get("schema") != "dm.being-receiving-preparation/v1" or not report.get("ready_for_context_install"):
        raise SeedError("seed_preparation_marker_missing")
    counts = [row["sqlite"]["table_counts"].get("chapters") for row in report["memory"]]
    record.update(phase="prepared", prepared_ms=int(time.time() * 1000),
        memory_coverage="empty-new" if record["mode"] == "new" else report["memory_coverage"],
        memory_stores=len(counts),
        memory_chapters=sum(counts) if all(type(c) is int for c in counts) else None,
        skills=len(report["selection"]["skills"]))
    _write(directory / "record.json", record)
    return project(record)


def connections(state_dir: str | Path, name: str, value: dict, *, owner: str) -> dict:
    directory, _ = _record(state_dir, name, owner)
    allowed = {"telegram_bot_token", "telegram_chat_id", "telegram_topic_id", "ssh_public_key"}
    if not isinstance(value, dict) or not value or set(value) - allowed:
        raise SeedError("invalid_seed_connection_fields")
    if "telegram_bot_token" in value and not re.fullmatch(r"[0-9]{6,15}:[A-Za-z0-9_-]{30,80}", str(value["telegram_bot_token"])):
        raise SeedError("invalid_telegram_bot_token")
    for field in ("telegram_chat_id", "telegram_topic_id"):
        if field in value and (type(value[field]) is not int or value[field] == 0):
            raise SeedError("invalid_telegram_destination")
    if "ssh_public_key" in value and not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{40,1600}(?: [^\r\n]{0,80})?", str(value["ssh_public_key"])):
        raise SeedError("ssh_public_key_required")
    with _locked(directory):
        _, record = _record(state_dir, name, owner)
        old = _read(directory / "connections.json") if (directory / "connections.json").exists() else {}
        old.update(value)
        _write(directory / "connections.json", old)
        record["connection_fields"] = sorted(old)
        _write(directory / "record.json", record)
        return project(record)


def project(record: dict, *, retryable_upload: bool = False) -> dict:
    """Closed read model: no identity text, paths, credentials or raw errors."""
    if (record.get("phase") not in PHASES or not NAME.fullmatch(str(record.get("name", "")))
            or not LABEL.fullmatch(str(record.get("label", "")))):
        raise SeedError("invalid_seed_record")
    fields = {"telegram_bot_token", "telegram_chat_id", "telegram_topic_id", "ssh_public_key"}
    supplied = set(record.get("connection_fields", [])) & fields
    return {
        "schema": SCHEMA, "name": record["name"], "label": record["label"],
        "mode": record["mode"] if record.get("mode") in {"import", "new"} else "unknown",
        "phase": record["phase"], "tool_commit": TOOL_COMMIT,
        "upload_retryable": record["phase"] == "awaiting-upload" or retryable_upload,
        "created_ms": record.get("created_ms") if type(record.get("created_ms")) is int else None,
        "prepared_ms": record.get("prepared_ms") if type(record.get("prepared_ms")) is int else None,
        "archive_sha256": record.get("archive_sha256") if re.fullmatch(r"[0-9a-f]{64}", str(record.get("archive_sha256", ""))) else None,
        "memory_coverage": record.get("memory_coverage") if record.get("memory_coverage") in {"owner-selected", "complete-authorized", "empty-new"} else "not-verified",
        **{field: record.get(field) if type(record.get(field)) is int else None
           for field in ("memory_stores", "memory_chapters", "skills")},
        "browser": "requested; not accepted" if record.get("browser_requested") is True else "not requested",
        "ssh": "key supplied; not accepted" if "ssh_public_key" in supplied else "key required",
        "telegram": "data supplied; not accepted" if {"telegram_bot_token", "telegram_chat_id"} <= supplied else "bot data required",
        "pending": ["context installation", "native memory acceptance", "signed embodiment enrollment",
                    "dedicated SSH", "fresh provider login", "Telegram acceptance"],
        "protected_history": bool(record.get("transfer_recipient_sha256")),
        "preparation_queued": record.get("preparation_queued") is True and record["phase"] != "prepared",
        "active": False,
    }


def status(state_dir: str | Path, name: str, *, owner: str = "*") -> dict:
    directory, record = _record(state_dir, name, owner)
    return project(record, retryable_upload=_retryable_upload(directory, record))


def list_seeds(state_dir: str | Path, *, owner: str = "*") -> list[dict]:
    parent = _path(Path(state_dir) / "being-seeds")
    if not parent.exists():
        return []
    rows = []
    for path in sorted(parent.iterdir()):
        if not NAME.fullmatch(path.name):
            continue
        try:
            rows.append(status(state_dir, path.name, owner=owner))
        except (SeedError, OSError, ValueError, TypeError):
            continue
        if len(rows) >= MAX_SEEDS:
            break
    return rows
