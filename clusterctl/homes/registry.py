"""One revisioned resource authority for all homes; local manifests are inputs.

Sessions and grants share the same protected store, not credentials or roles.
Publication commits are compare-and-swap, with immutable ownership/history.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import re

from .policy import validate_audience


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def projection_digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def immutable_record(entry):
    return {k: v for k, v in entry.items() if k not in ("versions", "decision")}


def version_digest(entry):
    return projection_digest(
        {k: v for k, v in immutable_record(entry).items() if k != "version_ref"}
    )


class Registry:
    def __init__(self, sessions):
        self.sessions = sessions
        with closing(sessions.connect()) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS publications(
              home TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL,
              digest TEXT NOT NULL, projection TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS home_owners(
              home TEXT PRIMARY KEY, owner TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS publication_history(
              home TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL,
              projection TEXT NOT NULL, PRIMARY KEY(home,revision));
            CREATE TABLE IF NOT EXISTS resources(
              ref TEXT PRIMARY KEY, home TEXT NOT NULL, owner TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resource_versions(
              resource TEXT NOT NULL, version TEXT NOT NULL, document TEXT NOT NULL,
              PRIMARY KEY(resource,version));
            CREATE TABLE IF NOT EXISTS reader_rosters(
              tribe TEXT PRIMARY KEY, founder TEXT NOT NULL, revision INTEGER NOT NULL,
              document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reader_roster_history(
              tribe TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL,
              PRIMARY KEY(tribe,revision));
            """)
            db.execute(
                "INSERT OR IGNORE INTO home_owners SELECT home,owner FROM publications"
            )

    @staticmethod
    def _bind_home(db, home, owner):
        row = db.execute(
            "SELECT owner FROM home_owners WHERE home=?", (home,)
        ).fetchone()
        if row and row["owner"] != owner:
            raise ValueError("home_publication_owner_conflict")
        db.execute("INSERT OR IGNORE INTO home_owners VALUES(?,?)", (home, owner))

    def bind_home(self, home, owner):
        """Withdrawal removes routing, never the immutable home identity."""
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._bind_home(db, home, owner)
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def register(
        self, *, home, owner, state, expected_revision, known_actor, known_tribe
    ):
        if (
            not isinstance(state, dict)
            or state.get("schema") != 1
            or not isinstance(state.get("entries"), list)
            or len(state["entries"]) > 4096
            or type(expected_revision) is not int
        ):
            raise ValueError("invalid_home_publication")
        references = set()
        records = []
        for entry in state["entries"]:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("title"), str)
                or not 1 <= len(entry["title"]) <= 1024
                or not isinstance(entry.get("summary"), str)
                or len(entry["summary"]) > 8192
                or entry.get("kind") not in ("link", "artifact")
            ):
                raise ValueError("invalid_home_resource_metadata")
            from .applications import application
            application(entry)
            reference = entry.get("artifact_ref")
            if (
                not isinstance(reference, str)
                or not re.fullmatch("[a-f0-9]{32}", reference)
                or reference in references
            ):
                raise ValueError("invalid_home_resource_reference")
            references.add(reference)
            validate_audience(entry, known_actor=known_actor, known_tribe=known_tribe)
            versions = entry.get("versions", [])
            if not isinstance(versions, list) or len(versions) > 4096:
                raise ValueError("invalid_home_resource_versions")
            for version in versions:
                if (
                    not isinstance(version, dict)
                    or version.get("artifact_ref") != reference
                ):
                    raise ValueError("invalid_home_version_reference")
                # Old targets may have been revoked; they remain historical
                # evidence and cannot create a new current authorization.
                validate_audience(
                    version, known_actor=lambda _: True, known_tribe=lambda _: True
                )
            for version in [entry, *versions]:
                record = immutable_record(version)
                if record.get("version_ref") != version_digest(record):
                    raise ValueError("invalid_home_immutable_version")
                records.append((reference, record["version_ref"], canonical(record)))
        serialized, digest = canonical(state), projection_digest(state)
        if len(serialized.encode()) > 8 * 1024 * 1024:
            raise ValueError("home_publication_too_large")
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._bind_home(db, home, owner)
                old = db.execute(
                    "SELECT * FROM publications WHERE home=?", (home,)
                ).fetchone()
                if old and old["owner"] != owner:
                    raise ValueError("home_publication_owner_conflict")
                if old and old["digest"] == digest:
                    db.commit()
                    return {
                        "revision": old["revision"],
                        "digest": digest,
                        "status": "unchanged",
                    }
                revision = old["revision"] if old else 0
                if revision != expected_revision:
                    raise ValueError("home_publication_revision_conflict")
                for reference in references:
                    resource = db.execute(
                        "SELECT home,owner FROM resources WHERE ref=?", (reference,)
                    ).fetchone()
                    if resource and (resource["home"], resource["owner"]) != (
                        home,
                        owner,
                    ):
                        raise ValueError("home_resource_owner_conflict")
                    db.execute(
                        "INSERT OR IGNORE INTO resources VALUES(?,?,?)",
                        (reference, home, owner),
                    )
                for reference, version, document in records:
                    previous = db.execute(
                        "SELECT document FROM resource_versions WHERE resource=? AND version=?",
                        (reference, version),
                    ).fetchone()
                    if previous and previous["document"] != document:
                        raise ValueError("home_immutable_version_conflict")
                    db.execute(
                        "INSERT OR IGNORE INTO resource_versions VALUES(?,?,?)",
                        (reference, version, document),
                    )
                revision += 1
                db.execute(
                    "INSERT INTO publication_history VALUES(?,?,?,?)",
                    (home, revision, digest, serialized),
                )
                db.execute(
                    "INSERT OR REPLACE INTO publications VALUES(?,?,?,?,?)",
                    (home, owner, revision, digest, serialized),
                )
                db.commit()
                return {"revision": revision, "digest": digest, "status": "registered"}
            except BaseException:
                db.rollback()
                raise

    def current(self, home, *, observed_state):
        """Return committed metadata only when the serving content agrees."""
        with closing(self.sessions.connect()) as db:
            row = db.execute(
                "SELECT * FROM publications WHERE home=?", (home,)
            ).fetchone()
            if not row or row["digest"] != projection_digest(observed_state):
                return None
            return {
                "revision": row["revision"],
                "owner": row["owner"],
                "state": json.loads(row["projection"]),
            }

    def revision(self, home):
        with closing(self.sessions.connect()) as db:
            row = db.execute(
                "SELECT revision FROM publications WHERE home=?", (home,)
            ).fetchone()
            return row[0] if row else 0

    def version(self, *, home, resource, version):
        with closing(self.sessions.connect()) as db:
            row = db.execute(
                "SELECT v.document FROM resource_versions v JOIN resources r ON r.ref=v.resource "
                "WHERE r.home=? AND v.resource=? AND v.version=?",
                (home, resource, version),
            ).fetchone()
            return json.loads(row[0]) if row else None

    def roster(self, *, tribe, founder, document, expected_revision, known_human):
        if (
            set(document) != {"readers", "revoked", "expires_at_ms"}
            or type(document["revoked"]) is not bool
            or not isinstance(document["readers"], list)
            or len(document["readers"]) > 256
            or any(
                not isinstance(r, str) or not known_human(r)
                for r in document["readers"]
            )
            or len(set(document["readers"])) != len(document["readers"])
            or (
                document["expires_at_ms"] is not None
                and (
                    type(document["expires_at_ms"]) is not int
                    or document["expires_at_ms"] <= 0
                )
            )
            or type(expected_revision) is not int
        ):
            raise ValueError("invalid_home_reader_roster")
        with closing(self.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                old = db.execute(
                    "SELECT * FROM reader_rosters WHERE tribe=?", (tribe,)
                ).fetchone()
                revision = old["revision"] if old else 0
                if old and old["founder"] != founder:
                    raise ValueError("home_roster_founder_changed")
                if revision != expected_revision:
                    raise ValueError("home_roster_revision_conflict")
                row = {
                    **document,
                    "founder_principal_id": founder,
                    "revision": revision + 1,
                }
                serialized = canonical(row)
                db.execute(
                    "INSERT INTO reader_roster_history VALUES(?,?,?)",
                    (tribe, revision + 1, serialized),
                )
                db.execute(
                    "INSERT OR REPLACE INTO reader_rosters VALUES(?,?,?,?)",
                    (tribe, founder, revision + 1, serialized),
                )
                db.commit()
                return row
            except BaseException:
                db.rollback()
                raise

    def rosters(self):
        with closing(self.sessions.connect()) as db:
            return {
                row["tribe"]: json.loads(row["document"])
                for row in db.execute("SELECT * FROM reader_rosters")
            }
