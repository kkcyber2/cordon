"""The differential oracle.

The only thing that distinguishes "the endpoint returned 200" from "the endpoint
leaked someone else's data" is a comparison. This module performs that comparison
over recorded responses -- it never sends anything itself, so the decision logic is
fully testable and a real run only has to supply the bodies.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

# Fields that identify *whose* record this is. If a response that should have been
# refused instead carries a different owner's marker, the object was disclosed.
OWNER_KEYS = (
    "owner_id", "ownerId", "user_id", "userId", "account_id", "accountId",
    "tenant_id", "tenantId", "customer_id", "customerId", "email", "ssn",
)


@dataclass(frozen=True)
class Observation:
    """One recorded response to one request made as one identity."""

    identity: str          # "owner" | "attacker" | "anonymous"
    status: int
    body: str
    object_id: str = ""

    @property
    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


@dataclass
class Verdict:
    confirmed: bool
    severity: str
    reason: str
    leaked_fields: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "severity": self.severity,
            "reason": self.reason,
            "leaked_fields": self.leaked_fields,
            "evidence": self.evidence,
        }


REFUSED = {401, 403, 404}
_OK = range(200, 300)


def _fields(obj: Any) -> set[str]:
    if isinstance(obj, Mapping):
        return set(obj.keys())
    if isinstance(obj, list) and obj and isinstance(obj[0], Mapping):
        return set(obj[0].keys())
    return set()


def _owner_markers(obj: Any) -> dict[str, str]:
    """Pull owner-identifying values out of a response body."""
    out: dict[str, str] = {}
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            if k in OWNER_KEYS and isinstance(v, (str, int)):
                out[k] = str(v)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, Mapping):
                out.update(_owner_markers(item))
    return out


def compare_without_auth(owner: Observation, anonymous: Observation) -> Verdict:
    """
    Was an object served to a caller with no credentials?

    Refusal in any recognised form is correct. A 2xx carrying the object is not,
    and a 2xx carrying the *owner's* identifying fields is conclusive.
    """
    if anonymous.status in REFUSED:
        return Verdict(False, "none", f"anonymous request refused ({anonymous.status})")
    if anonymous.status in _OK:
        leaked = sorted(_fields(anonymous.json) & set(OWNER_KEYS))
        if leaked:
            return Verdict(
                True,
                "error",
                "the object was served to an unauthenticated caller, including "
                f"owner-identifying field(s): {', '.join(leaked)}",
                leaked,
                {"anonymous_status": anonymous.status, "object_id": owner.object_id},
            )
        if anonymous.body.strip() and anonymous.body == owner.body:
            return Verdict(
                True, "error",
                "the anonymous response is byte-identical to the owner's response",
                [], {"anonymous_status": anonymous.status},
            )
        if anonymous.body.strip():
            # A body that is not obviously the record could be an error document
            # returned with 200, which is common and not a finding.
            return Verdict(
                False, "none",
                f"200 but the body does not resemble the owner's record "
                f"({len(anonymous.body)} bytes vs {len(owner.body)})",
                [], {"anonymous_status": anonymous.status},
            )
    return Verdict(False, "none", f"no disclosure (status {anonymous.status})")


def compare_across_identities(owner: Observation, attacker: Observation) -> Verdict:
    """
    Did identity B receive identity A's object?

    This is the real BOLA oracle. A 200 alone proves nothing -- plenty of APIs
    return 200 with `{"error": "..."}`. The test is whether the attacker's body
    matches the owner's body, or carries the owner's markers.
    """
    if attacker.status in REFUSED:
        return Verdict(False, "none", f"attacker request refused ({attacker.status})")

    if attacker.status not in _OK:
        return Verdict(False, "none", f"unexpected status {attacker.status}, not a disclosure")

    if attacker.body.strip() == owner.body.strip() and owner.body.strip():
        return Verdict(
            True, "error",
            "the attacker received a byte-identical copy of the owner's object",
            sorted(_fields(attacker.json) & set(OWNER_KEYS)),
            {"attacker_status": attacker.status, "object_id": owner.object_id},
        )

    owner_marks = _owner_markers(owner.json)
    attacker_marks = _owner_markers(attacker.json)
    shared = {k: v for k, v in attacker_marks.items() if owner_marks.get(k) == v and v}

    if shared:
        return Verdict(
            True, "error",
            "the attacker's response carries the owner's identifiers: "
            + ", ".join(f"{k}={v}" for k, v in sorted(shared.items())),
            sorted(shared),
            {"attacker_status": attacker.status, "object_id": owner.object_id},
        )

    # Same shape, different content: almost always the attacker's *own* object,
    # which means authorization held.
    attacker_fields = _fields(attacker.json)
    owner_fields = _fields(owner.json)
    if attacker_fields and attacker_fields == owner_fields:
        return Verdict(
            False, "none",
            "same schema but different content -- the attacker received their own "
            "object, so ownership is being enforced",
            [], {"attacker_status": attacker.status},
        )

    return Verdict(False, "none", "response does not resemble the owner's object")


def identity_required(owner_status: int, attacker_status: int) -> bool:
    """Is a second identity necessary to prove the bug here?"""
    return owner_status in _OK and attacker_status in _OK


def is_sequential(value: str) -> bool:
    return value.isdigit()


def summarise(verdicts: Sequence[Verdict]) -> dict:
    confirmed = [v for v in verdicts if v.confirmed]
    return {
        "tested": len(verdicts),
        "confirmed": len(confirmed),
        "severity": "error" if any(v.severity == "error" for v in confirmed) else "none",
    }
