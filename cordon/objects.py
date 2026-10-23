"""Object-identifier analysis.

Broken object-level authorization is the most common serious bug in real APIs and
the one static scanners handle worst, because the bug is not in the code -- it is
in what the code *permits*. Two users, one object, different owners: nothing in a
single request looks wrong.

This module does the part that can be done without a target: it finds the
identifiers in a request that are worth testing, classifies how guessable they
are, and explains what a differential test would need to prove.

Pure functions. No network.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Iterable, Sequence

# Parameters whose names suggest they name a specific object. This list is the
# whole value of the heuristic: `id` alone is noise, but `invoice_id` on a GET is
# exactly where BOLA lives.
_ID_NAME = re.compile(
    r"(?:^|_)(?:id|ids|uuid|guid|ref|key|no|num|number)$|"
    r"(?:^|_)(?:account|user|customer|order|invoice|document|file|project|"
    r"tenant|org|team|member|payment|card|message|thread|ticket|record)"
    r"(?:_?id)?$",
    re.IGNORECASE,
)

_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Identifiers that are opaque and unguessable: testing them by incrementing is
# pointless, and claiming otherwise would be dishonest.
UUID_V4, UUID_ANY, SEQUENTIAL, HASH, SLUG, UNKNOWN = (
    "uuid_v4", "uuid", "sequential", "hash", "slug", "unknown",
)


@dataclass(frozen=True)
class Identifier:
    """One candidate object reference found in a request."""

    name: str
    value: str
    kind: str            # uuid_v4 | uuid | sequential | hash | slug | unknown
    guessable: bool      # can a neighbouring value be predicted?
    reason: str

    @property
    def testable(self) -> bool:
        """Only guessable identifiers can be attacked by substitution alone."""
        return self.guessable


def classify_value(value: str) -> tuple[str, bool, str]:
    """Work out what kind of identifier this is and whether it can be walked."""
    v = value.strip()
    if not v:
        return UNKNOWN, False, "empty"

    if _UUID.match(v):
        # v4 UUIDs carry 122 random bits. Adjacent values are not reachable.
        version = v[14]
        if version == "4":
            return UUID_V4, False, "v4 UUID: 122 random bits, neighbours are unreachable"
        return UUID_ANY, False, f"UUID v{version}: not sequentially enumerable"

    if re.fullmatch(r"\d{1,12}", v):
        n = int(v)
        return SEQUENTIAL, True, f"integer {n}: neighbours are trivially predictable"

    if re.fullmatch(r"[0-9a-f]{16,64}", v, re.IGNORECASE):
        return HASH, False, "hex digest: not enumerable without knowing the input"

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}", v):
        return SLUG, True, "slug-like: may be guessable or leaked elsewhere"

    return UNKNOWN, False, "unrecognised format"


def looks_like_object_reference(name: str) -> bool:
    """Does this parameter name suggest it selects one specific object?"""
    return bool(_ID_NAME.search(name))


def find_identifiers(params: Iterable[tuple[str, str]]) -> list[Identifier]:
    """
    Extract the parameters worth testing from a request's key/value pairs.

    Only *named* object references are returned: a parameter called `q` holding
    "42" is a search term, not an object id, and testing it would waste requests
    and generate noise.
    """
    out: list[Identifier] = []
    for name, value in params:
        if not looks_like_object_reference(name):
            continue
        kind, guessable, reason = classify_value(value)
        out.append(Identifier(name=name, value=value, kind=kind,
                              guessable=guessable, reason=reason))
    return out


def neighbour_values(value: str, span: int = 3) -> list[str]:
    """
    The values a substituted-identifier attack would try.

    For an integer id this is id±1..span. For anything else we return nothing,
    because there is no honest way to guess a neighbour of a random token.
    """
    kind, guessable, _ = classify_value(value)
    if kind != SEQUENTIAL or not guessable:
        return []
    n = int(value)
    out = []
    for delta in range(1, span + 1):
        for candidate in (n + delta, n - delta):
            if candidate >= 0:
                out.append(str(candidate))
    return out


@dataclass(frozen=True)
class DifferentialPlan:
    """What a two-identity test would have to look like to prove BOLA."""

    identifier: Identifier
    method: str
    path: str
    proven: bool
    explanation: str


def plan_differential(
    identifier: Identifier,
    method: str,
    path: str,
    have_second_identity: bool,
) -> DifferentialPlan:
    """
    Describe the test that would actually prove (or disprove) the bug.

    The oracle is a comparison, not a status code: a 200 is not evidence on its
    own. The owner and the non-owner must both request the same object id, and the
    finding exists when the non-owner receives the *owner's data* rather than a
    403/404.
    """
    if not identifier.guessable:
        return DifferentialPlan(
            identifier, method, path, False,
            f"{identifier.name} is a {identifier.kind}; substitution cannot reach a "
            "neighbouring object. Test it by capturing a second id from a different "
            "account instead of guessing.",
        )
    if not have_second_identity:
        return DifferentialPlan(
            identifier, method, path, True,
            f"Plan: as user A request {method} {path}, note the body. As user B request "
            f"the same path with {identifier.name}=<A's id>. Vulnerable if B receives "
            "A's object (200 + owner's fields), not if B receives 403/404.",
        )
    return DifferentialPlan(
        identifier, method, path, True,
        f"As user B, request {method} {path} with {identifier.name} set to a value "
        "belonging to user A. Compare the response body against A's own response.",
    )


def unauthenticated_probe(identifier: Identifier, method: str, path: str) -> DifferentialPlan:
    """
    The cheaper half of the test: does the object render with no credentials at all?

    This catches the cases where authz is skipped entirely rather than misapplied,
    and it needs only one identity (none).
    """
    testable = identifier.guessable or identifier.kind in (UUID_V4, UUID_ANY, HASH)
    return DifferentialPlan(
        identifier, method, path, testable,
        f"Request {method} {path} with no Authorization header. A body containing "
        "object data is an unauthenticated disclosure; a 401/403 is correct.",
    )


def rank_candidates(ids: Sequence[Identifier]) -> list[Identifier]:
    """Most worth testing first: guessable object refs, then opaque ones."""
    return sorted(
        ids,
        key=lambda i: (not i.guessable, i.kind != SEQUENTIAL, i.name),
    )


def parse_path_params(path: str) -> list[Identifier]:
    """
    Pull `{id}`-style path segments out of a route template.

    `/api/invoices/{invoice_id}` is a BOLA site; `/api/invoices` is not.
    """
    out: list[Identifier] = []
    for seg in path.split("/"):
        m = re.fullmatch(r"\{(\w+)\}", seg) or re.fullmatch(r":(\w+)", seg)
        if not m:
            continue
        name = m.group(1)
        if not looks_like_object_reference(name):
            continue
        out.append(Identifier(name=name, value="", kind=UNKNOWN,
                              guessable=False, reason="path template parameter"))
    return out


def normalize_uuid(value: str) -> str | None:
    """Canonicalise a UUID, or None when it is not one."""
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError):
        return None
