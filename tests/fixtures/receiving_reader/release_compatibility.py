"""Public receiving requirements, not an installer or an authority grant.

The owning controller binds this data to its existing approved content digest,
verifies exact artifacts, and obtains actual receiving evidence separately.
No runtime, custody, inbox, network or persistent state is opened here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from typing import Any

from .canonical import canonical_bytes

RELEASE_SCHEMA = "dm.receiving-release/v1"
READER_SCHEMA = "dm.receiving-reader/v1"
RESULT_SCHEMA = "dm.receiving-compatibility/v1"
GROUP_PROFILE = "membership-group/v1"

_WIRES = sorted(
    {
        "dm.messaging.application/v3",
        "dm.tribe.conversation/v1",
        "dm.tribe.direct-conversation/v1",
        "dm.tribe.intake-result/v1",
        "dm.communication.message/v1",
        "dm.communication.resolution/v1",
        "dm.communication.receipt/v2",
        "dm.sealed-delivery/v1",
        "dm.transport-request/v1",
        "dm.transport-response/v1",
        "dm.messaging.operator-binding/v1",
    }
)
_FEATURES = sorted(
    {
        "membership-group/v1",
        "root-history/v1",
        "semantic-body-legs/v3",
        "confirmed-visibility-before-egress/v1",
        "exact-carrier-retry/v1",
        "per-receiver-artifacts/v1",
        "durable-group-intake/v1",
        "deferred-receipt-observation/v1",
        "bounded-numeric-http/v1",
        "owned-transport-reply/v1",
        "bounded-group-fanout/v1",
        "membership-direct/v1",
        "signed-roster-cas/v1",
    }
)
_CONTRACT_FIELDS = {
    "profile",
    "interpreter",
    "wire_read",
    "wire_write",
    "store_versions",
    "capabilities",
    "pending_inspection",
    "pending_transmission",
}
_ARTIFACTS = {
    "matrix_sdk",
    "receiving_code",
    "worker",
    "owner_client",
    "telecodex",
}


class ReleaseCompatibilityError(ValueError):
    """Stable public error codes, without input values or private material."""


def _closed(value: Any, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReleaseCompatibilityError("release_contract_invalid")
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9:._/-]{1,240}", value
    ):
        raise ReleaseCompatibilityError("release_contract_invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ReleaseCompatibilityError("release_contract_invalid")
    return value


def _names(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        raise ReleaseCompatibilityError("release_contract_invalid")
    checked = [_text(item) for item in value]
    if checked != sorted(set(checked)):
        raise ReleaseCompatibilityError("release_contract_invalid")
    return checked


def _artifacts(value: Any, *, shared: bool) -> None:
    if (
        not isinstance(value, dict)
        or not value
        or not set(value) <= _ARTIFACTS
        or (shared and "matrix_sdk" not in value)
        or (not shared and "matrix_sdk" in value)
    ):
        raise ReleaseCompatibilityError("release_contract_invalid")
    for digest in value.values():
        _digest(digest)


def _contract(value: Any) -> Mapping[str, Any]:
    contract = _closed(value, _CONTRACT_FIELDS)
    _text(contract["profile"])
    interpreter = _closed(contract["interpreter"], {"implementation", "version"})
    _text(interpreter["implementation"])
    version = interpreter["version"]
    if (
        not isinstance(version, list)
        or len(version) != 3
        or any(type(part) is not int or not 0 <= part <= 1000 for part in version)
    ):
        raise ReleaseCompatibilityError("release_contract_invalid")
    for field in ("wire_read", "wire_write", "capabilities", "pending_inspection"):
        _names(contract[field])
    stores = contract["store_versions"]
    if not isinstance(stores, dict) or not 1 <= len(stores) <= 32:
        raise ReleaseCompatibilityError("release_contract_invalid")
    for name, versions in stores.items():
        _text(name)
        if (
            not isinstance(versions, list)
            or not 1 <= len(versions) <= 32
            or any(type(v) is not int or not 1 <= v <= 1000 for v in versions)
            or versions != sorted(set(versions))
        ):
            raise ReleaseCompatibilityError("release_contract_invalid")
    if contract["pending_transmission"] != "original-binding-unexpired":
        raise ReleaseCompatibilityError("release_contract_invalid")
    return contract


def describe_reader() -> dict[str, Any]:
    """Describe this qualified SDK's group codec; never claim loaded readiness.

    Versioned store metadata is covered here. Unversioned SQL layouts, integrity,
    bindings, pending records and authority closure still require actual preflight.
    """
    return {
        "schema": READER_SCHEMA,
        "contract": {
            "profile": GROUP_PROFILE,
            "interpreter": {
                "implementation": sys.implementation.name,
                "version": list(sys.version_info[:3]),
            },
            "wire_read": list(_WIRES),
            "wire_write": list(_WIRES),
            "store_versions": {"communication": [4], "visibility_catalog": [1]},
            "capabilities": list(_FEATURES),
            "pending_inspection": [
                "dm.tribe.delivery/v1",
                "dm.tribe.direct-delivery/v1",
                "dm.tribe.intake-reconciliation/v1",
            ],
            "pending_transmission": "original-binding-unexpired",
        },
    }


def validate_release(value: Any, *, expected_digest: str) -> dict[str, Any]:
    """Validate the canonical manifest digest pinned by the approved operation.

    A digest argument or provenance field is not approval. The authenticated
    owning controller must supply it from its protected approved selection.
    The enclosing operation's digest names a different object.
    """
    document = _closed(
        value,
        {
            "schema",
            "artifacts",
            "provenance",
            "contract",
            "authorities",
            "required_receivers",
        },
    )
    if document["schema"] != RELEASE_SCHEMA:
        raise ReleaseCompatibilityError("release_contract_invalid")
    if hashlib.sha256(canonical_bytes(value)).hexdigest() != _digest(expected_digest):
        raise ReleaseCompatibilityError("release_digest_mismatch")
    _artifacts(document["artifacts"], shared=True)
    provenance = _closed(
        document["provenance"], {"matrix_revision", "qualification_sha256"}
    )
    if not isinstance(provenance["matrix_revision"], str) or not re.fullmatch(
        r"[0-9a-f]{40}", provenance["matrix_revision"]
    ):
        raise ReleaseCompatibilityError("release_contract_invalid")
    _digest(provenance["qualification_sha256"])
    _contract(document["contract"])
    authorities = _closed(document["authorities"], {"current", "candidate"})
    for rows in authorities.values():
        if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
            raise ReleaseCompatibilityError("release_contract_invalid")
        refs = []
        for row in rows:
            _closed(row, {"being_ref", "control_head", "manifest_hash"})
            refs.append(_text(row["being_ref"]))
            _text(row["control_head"])
            _digest(row["manifest_hash"])
        if refs != sorted(set(refs)):
            raise ReleaseCompatibilityError("release_contract_invalid")
    receivers = document["required_receivers"]
    if not isinstance(receivers, list) or not 1 <= len(receivers) <= 256:
        raise ReleaseCompatibilityError("release_contract_invalid")
    identities = []
    for row in receivers:
        fields = {"being_ref", "embodiment_id", "expected_selection_sha256"}
        if isinstance(row, dict) and "artifacts" in row:
            fields.add("artifacts")
            _artifacts(row["artifacts"], shared=False)
            if "per-receiver-artifacts/v1" not in document["contract"]["capabilities"]:
                raise ReleaseCompatibilityError("release_contract_invalid")
        _closed(row, fields)
        identities.append((_text(row["being_ref"]), _text(row["embodiment_id"])))
        _digest(row["expected_selection_sha256"])
    if identities != sorted(set(identities)):
        raise ReleaseCompatibilityError("release_contract_invalid")
    return copy.deepcopy(dict(document))


def selected_artifacts(
    release: Any, *, being_ref: str, embodiment_id: str, expected_digest: str
) -> dict[str, str]:
    """Resolve the exact frozen receiver selection; absent roles stay unchanged.

    This is public selection data, not an installation, original-base verification
    or evidence that any selected component is actually loaded.
    """
    document = validate_release(release, expected_digest=expected_digest)
    for row in document["required_receivers"]:
        if (row["being_ref"], row["embodiment_id"]) == (being_ref, embodiment_id):
            return {**document["artifacts"], **row.get("artifacts", {})}
    raise ReleaseCompatibilityError("release_receiver_missing")


def assess_reader(release: Any, reader: Any, *, expected_digest: str) -> dict[str, Any]:
    """Compare declared code support only. This result never enables egress."""
    document = validate_release(release, expected_digest=expected_digest)
    descriptor = _closed(reader, {"schema", "contract"})
    if descriptor["schema"] != READER_SCHEMA:
        raise ReleaseCompatibilityError("reader_contract_invalid")
    supported = _contract(descriptor["contract"])
    required = document["contract"]
    missing = []
    for field in ("profile", "interpreter", "pending_transmission"):
        if required[field] != supported[field]:
            missing.append(field + "_unsupported")
    for field in ("wire_read", "wire_write", "capabilities", "pending_inspection"):
        if not set(required[field]) <= set(supported[field]):
            missing.append(field + "_unsupported")
    if any(
        not set(versions) <= set(supported["store_versions"].get(name, []))
        for name, versions in required["store_versions"].items()
    ):
        missing.append("store_versions_unsupported")
    return {
        "schema": RESULT_SCHEMA,
        "release_digest": expected_digest,
        "reader_sha256": hashlib.sha256(canonical_bytes(reader)).hexdigest(),
        "compatible": not missing,
        "reasons": sorted(missing),
        "receiving_readiness": "unobserved",
    }


if __name__ == "__main__":
    print(json.dumps(describe_reader(), sort_keys=True))
