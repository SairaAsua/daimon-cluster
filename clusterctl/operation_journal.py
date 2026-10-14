"""Durable intent journal for substrate mutations and logical convergence."""

from __future__ import annotations

import copy
import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import time
import threading
import uuid
from pathlib import Path
from typing import Any

JOURNAL_SCHEMA = "cluster-operation-journal/v1"
INTENT_SCHEMA = "cluster-operation-intent/v1"
_UNSET = object()
TERMINAL_STATES = frozenset({"completed", "compensated"})
UNSAFE_STATES = frozenset({"degraded"})
OPEN_STATES = frozenset(
    {
        "planned",
        "runtime-dispatching",
        "runtime-applied",
        "logical-committed",
        "idempotency-persisted",
        "audited",
        "degraded",
    }
)
_STAGE_ORDER = {
    "planned": 0,
    "runtime-dispatching": 1,
    "runtime-applied": 2,
    "logical-committed": 3,
    "idempotency-persisted": 4,
    "audited": 5,
    "completed": 6,
    "compensated": 6,
    "degraded": 7,
}


class JournalError(RuntimeError):
    pass


class JournalConflict(JournalError):
    pass


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def intent_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class OperationJournal:
    """Owner-only SQLite journal with one open mutation per exact target."""

    def __init__(self, state_dir: str | Path, *, initialize: bool = True):
        self.path = Path(state_dir) / "operation-journal.sqlite3"
        self._owners = threading.local()
        if initialize:
            self._initialize()
        else:
            self._open_existing()

    @classmethod
    def existing(cls, state_dir: str | Path) -> OperationJournal | None:
        path = Path(state_dir) / "operation-journal.sqlite3"
        return None if not path.is_file() else cls(state_dir, initialize=False)

    def _connect(self, *, query_only: bool = False) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        if query_only:
            connection.execute("PRAGMA query_only=ON")
        return connection

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
        ):
            raise JournalError("operation journal parent is not owner-controlled")
        self.path.parent.chmod(0o700)
        lock_path = self.path.parent / ".operation-journal-init.lock"
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise JournalError(
                    "operation journal init lock is not owner-controlled"
                )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._initialize_locked()
        except OSError as exc:
            raise JournalError("cannot lock operation journal initialization") from exc
        finally:
            if "descriptor" in locals():
                os.close(descriptor)

    def _initialize_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
        ):
            raise JournalError("operation journal parent is not owner-controlled")
        self.path.parent.chmod(0o700)
        if self.path.is_symlink():
            raise JournalError("operation journal symlink is forbidden")
        try:
            connection = self._connect()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata(
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS operations(
                    operation_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    target TEXT NOT NULL,
                    idempotency_key TEXT,
                    intent_hash TEXT NOT NULL,
                    intent_json TEXT NOT NULL,
                    expected_precondition_json TEXT NOT NULL,
                    intended_transition_json TEXT NOT NULL,
                    audit_identity_json TEXT NOT NULL,
                    audit_event_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    runtime_observation_json TEXT,
                    logical_observation_json TEXT,
                    result_json TEXT,
                    last_error TEXT,
                    created_ms INTEGER NOT NULL,
                    updated_ms INTEGER NOT NULL
                ) STRICT;
                CREATE INDEX IF NOT EXISTS operations_idempotency
                    ON operations(idempotency_key)
                    WHERE idempotency_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS operations_target_state
                    ON operations(target,state,updated_ms);
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(name,value) VALUES('schema',?)",
                (JOURNAL_SCHEMA,),
            )
            schema = connection.execute(
                "SELECT value FROM metadata WHERE name='schema'"
            ).fetchone()
            if schema is None or schema["value"] != JOURNAL_SCHEMA:
                raise JournalError("unsupported operation journal schema")
        except sqlite3.Error as exc:
            raise JournalError("cannot initialize operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()
        self._secure_files()

    def _open_existing(self) -> None:
        parent = self.path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
        ):
            raise JournalError("operation journal parent is not owner-controlled")
        self._secure_files()
        try:
            connection = self._connect(query_only=True)
            schema = connection.execute(
                "SELECT value FROM metadata WHERE name='schema'"
            ).fetchone()
            if schema is None or schema["value"] != JOURNAL_SCHEMA:
                raise JournalError("unsupported operation journal schema")
        except sqlite3.Error as exc:
            raise JournalError("cannot open operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def _secure_files(self) -> None:
        for path in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
        ):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise JournalError("operation journal is not owner-controlled")
            try:
                path.chmod(0o600)
            except FileNotFoundError:
                continue

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        try:
            for field in (
                "intent_json",
                "expected_precondition_json",
                "intended_transition_json",
                "audit_identity_json",
                "runtime_observation_json",
                "logical_observation_json",
                "result_json",
            ):
                raw = value.pop(field)
                value[field.removesuffix("_json")] = (
                    None if raw is None else json.loads(raw)
                )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise JournalError("operation journal row is corrupt") from exc
        return value

    def plan(
        self,
        *,
        operation: str,
        target: str,
        idempotency_key: str | None,
        intent: dict[str, Any],
        expected_precondition: dict[str, Any],
        intended_transition: dict[str, Any],
        audit_identity: dict[str, Any],
        operation_id: str | None = None,
        allow_terminal_successor: bool = False,
    ) -> dict[str, Any]:
        closed_intent = {"schema": INTENT_SCHEMA, **copy.deepcopy(intent)}
        digest = intent_hash(closed_intent)
        identifier = operation_id or f"operation:{uuid.uuid4()}"
        timestamp = now_ms()
        try:
            connection = self._connect()
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key is not None:
                existing = connection.execute(
                    "SELECT * FROM operations WHERE idempotency_key=? "
                    "ORDER BY created_ms DESC,operation_id DESC LIMIT 1",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    decoded = self._decode(existing)
                    if (
                        decoded["operation"] != operation
                        or decoded["target"] != target
                        or decoded["intent"].get("runtime_call")
                        != closed_intent.get("runtime_call")
                    ):
                        raise JournalConflict(
                            "idempotency identity is bound to different operation bytes"
                        )
                    if decoded["state"] not in TERMINAL_STATES:
                        if decoded["state"] == "degraded":
                            raise JournalConflict(
                                "degraded operation requires explicit repair"
                            )
                        if decoded["intent_hash"] != digest:
                            raise JournalConflict(
                                "pending idempotency identity has different state bytes"
                            )
                        connection.commit()
                        return decoded
                    if not allow_terminal_successor:
                        raise JournalConflict(
                            "terminal idempotency identity cannot be reused"
                        )
            open_rows = connection.execute(
                "SELECT * FROM operations WHERE target=? AND state IN "
                "('planned','runtime-dispatching','runtime-applied','logical-committed',"
                "'idempotency-persisted','audited','degraded') "
                "ORDER BY created_ms,operation_id",
                (target,),
            ).fetchall()
            if open_rows:
                exact = [
                    row
                    for row in open_rows
                    if row["operation"] == operation and row["intent_hash"] == digest
                ]
                if len(exact) == 1 and open_rows[0]["state"] != "degraded":
                    connection.commit()
                    return self._decode(exact[0])
                raise JournalConflict(
                    "target has a pending, contradictory or degraded operation"
                )
            connection.execute(
                """
                INSERT INTO operations VALUES(
                    ?,?,?,?,?,?,?,?,?,?,'planned',NULL,NULL,NULL,NULL,?,?
                )
                """,
                (
                    identifier,
                    operation,
                    target,
                    idempotency_key,
                    digest,
                    canonical_bytes(closed_intent).decode(),
                    canonical_bytes(expected_precondition).decode(),
                    canonical_bytes(intended_transition).decode(),
                    canonical_bytes(audit_identity).decode(),
                    str(uuid.uuid4()),
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (identifier,)
            ).fetchone()
            assert row is not None
            return self._decode(row)
        except sqlite3.Error as exc:
            if "connection" in locals():
                connection.rollback()
            raise JournalError("cannot persist operation intent") from exc
        except Exception:
            if "connection" in locals():
                connection.rollback()
            raise
        finally:
            if "connection" in locals():
                connection.close()
            self._secure_files()

    def get(self, operation_id: str) -> dict[str, Any] | None:
        try:
            connection = self._connect(query_only=True)
            row = connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            return None if row is None else self._decode(row)
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    @contextlib.contextmanager
    def mutation_lock(self, operation_id: str):
        """Own an operation through its external effect and journal mutation.

        Kernel ownership is shared by every advance, including abandonment.
        Nested advances by this same controller/thread reuse its ownership;
        competing instances/processes never break a live lock by age.
        """
        process_id = os.getpid()
        owned: set[str] = (getattr(self._owners, 'operations', set())
                           if getattr(self._owners, 'process_id', None) == process_id else set())
        if operation_id in owned:
            yield
            return
        name = hashlib.sha256(operation_id.encode()).hexdigest()
        path = self.path.parent / ('.operation-' + name + '.lock')
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise JournalError('operation mutation lock is not owner-controlled')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise JournalConflict('operation mutation is in progress') from exc
            self._owners.operations = owned | {operation_id}
            self._owners.process_id = process_id
            try:
                yield
            finally:
                self._owners.operations = owned
        finally:
            os.close(descriptor)

    def advance(self, operation_id: str, state: str, *,
                runtime_observation: dict[str, Any] | None = None,
                logical_observation: dict[str, Any] | None = None,
                result: dict[str, Any] | None = None, last_error: str | None = None,
                expected_runtime_observation: object = _UNSET) -> dict[str, Any]:
        with self.mutation_lock(operation_id):
            return self._advance(operation_id, state,
                runtime_observation=runtime_observation,
                logical_observation=logical_observation, result=result,
                last_error=last_error, expected_runtime_observation=expected_runtime_observation)

    def _advance(
        self,
        operation_id: str,
        state: str,
        *,
        runtime_observation: dict[str, Any] | None = None,
        logical_observation: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        last_error: str | None = None,
        expected_runtime_observation: object = _UNSET,
    ) -> dict[str, Any]:
        if state not in _STAGE_ORDER:
            raise JournalError("invalid operation journal state")
        try:
            connection = self._connect()
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise JournalError("unknown operation journal id")
            current = str(row["state"])
            if (expected_runtime_observation is not _UNSET
                    and self._decode(row)['runtime_observation'] != expected_runtime_observation):
                raise JournalConflict("runtime observation changed during reconciliation")
            if current in TERMINAL_STATES and current != state:
                raise JournalConflict("terminal operation cannot advance")
            if current == "degraded" and state != "degraded":
                raise JournalConflict("degraded operation requires explicit repair")
            if state != "degraded" and _STAGE_ORDER[state] < _STAGE_ORDER[current]:
                raise JournalConflict("operation journal stage cannot regress")
            connection.execute(
                """
                UPDATE operations SET
                    state=?,
                    runtime_observation_json=COALESCE(?,runtime_observation_json),
                    logical_observation_json=COALESCE(?,logical_observation_json),
                    result_json=COALESCE(?,result_json),
                    last_error=?,updated_ms=?
                WHERE operation_id=?
                """,
                (
                    state,
                    None
                    if runtime_observation is None
                    else canonical_bytes(runtime_observation).decode(),
                    None
                    if logical_observation is None
                    else canonical_bytes(logical_observation).decode(),
                    None if result is None else canonical_bytes(result).decode(),
                    last_error,
                    now_ms(),
                    operation_id,
                ),
            )
            connection.commit()
            updated = connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            assert updated is not None
            return self._decode(updated)
        except sqlite3.Error as exc:
            if "connection" in locals():
                connection.rollback()
            raise JournalError("cannot advance operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()
            self._secure_files()

    def open_operations(self) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in OPEN_STATES)
        try:
            connection = self._connect(query_only=True)
            rows = connection.execute(
                f"SELECT * FROM operations WHERE state IN ({placeholders}) "
                "ORDER BY created_ms,operation_id",
                tuple(sorted(OPEN_STATES)),
            ).fetchall()
            return [self._decode(row) for row in rows]
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def open_for_target(self, target: str) -> dict[str, Any] | None:
        try:
            connection = self._connect(query_only=True)
            row = connection.execute(
                "SELECT * FROM operations WHERE target=? AND state IN "
                "('planned','runtime-dispatching','runtime-applied','logical-committed',"
                "'idempotency-persisted','audited','degraded') "
                "ORDER BY created_ms,operation_id LIMIT 1",
                (target,),
            ).fetchone()
            return None if row is None else self._decode(row)
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def latest_for_target(self, target: str) -> dict[str, Any] | None:
        """Return the newest operation for an exact durable target identity."""

        try:
            connection = self._connect(query_only=True)
            row = connection.execute(
                "SELECT * FROM operations WHERE target=? "
                "ORDER BY created_ms DESC,operation_id DESC LIMIT 1",
                (target,),
            ).fetchone()
            return None if row is None else self._decode(row)
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def latest_for_idempotency_key(self, key: str) -> dict[str, Any] | None:
        """Return the newest operation bound to a caller idempotency key."""

        try:
            connection = self._connect(query_only=True)
            row = connection.execute(
                "SELECT * FROM operations WHERE idempotency_key=? "
                "ORDER BY created_ms DESC,operation_id DESC LIMIT 1",
                (key,),
            ).fetchone()
            return None if row is None else self._decode(row)
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def latest_completed_for_result(
        self, operation: str, field: str, value: str
    ) -> dict[str, Any] | None:
        """Return the newest completed operation with one exact result field."""

        if not field or not field.replace("_", "").isalnum():
            raise JournalError("operation journal result field is invalid")
        try:
            connection = self._connect(query_only=True)
            row = connection.execute(
                "SELECT * FROM operations WHERE operation=? AND state='completed' "
                "AND json_extract(result_json,?)=? "
                "ORDER BY created_ms DESC,operation_id DESC LIMIT 1",
                (operation, f'$."{field}"', value),
            ).fetchone()
            return None if row is None else self._decode(row)
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def list_all(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise JournalError("operation journal limit is out of range")
        try:
            connection = self._connect(query_only=True)
            rows = connection.execute(
                "SELECT * FROM operations ORDER BY created_ms DESC,operation_id LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._decode(row) for row in rows]
        except sqlite3.Error as exc:
            raise JournalError("cannot read operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def validate(self) -> int:
        """Verify SQLite structure and every persisted JSON row."""
        try:
            connection = self._connect(query_only=True)
            check = connection.execute("PRAGMA quick_check").fetchone()
            if check is None or check[0] != "ok":
                raise JournalError("operation journal integrity check failed")
            rows = connection.execute("SELECT * FROM operations").fetchall()
            for row in rows:
                self._decode(row)
            return len(rows)
        except sqlite3.Error as exc:
            raise JournalError("cannot validate operation journal") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def authorize_repair(self, operation_id: str, resume_state: str) -> dict[str, Any]:
        if resume_state not in {"runtime-dispatching", "runtime-applied"}:
            raise JournalError("repair resume state is not bounded")
        try:
            connection = self._connect()
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise JournalError("unknown operation journal id")
            if row["state"] != "degraded":
                raise JournalConflict(
                    "only a degraded operation needs repair authority"
                )
            connection.execute(
                "UPDATE operations SET state=?,last_error=NULL,updated_ms=? "
                "WHERE operation_id=?",
                (resume_state, now_ms(), operation_id),
            )
            connection.commit()
            repaired = connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            assert repaired is not None
            return self._decode(repaired)
        except sqlite3.Error as exc:
            if "connection" in locals():
                connection.rollback()
            raise JournalError("cannot authorize operation repair") from exc
        finally:
            if "connection" in locals():
                connection.close()
            self._secure_files()
