"""Route + policy analysis.

Reads an OpenAPI document (or a plain route list) and reports every endpoint that
*names an object but declares no authorization requirement*. That combination is
the precondition for BOLA; whether the bug is real still needs the differential
test from objects.py, and this module is careful to say so.

Pure functions over parsed data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .objects import Identifier, find_identifiers, parse_path_params

# Security scheme types that actually constrain the caller. `apiKey` on a header
# is authentication; `oauth2`/`openIdConnect` carry scopes that say what the token
# is allowed to do. An endpoint with none of these is open to anyone.
AUTH_SCHEMES = {"http", "apiKey", "oauth2", "openIdConnect", "mutualTLS"}


@dataclass(frozen=True)
class Endpoint:
    """One operation from the spec, reduced to what this analysis needs."""

    method: str
    path: str
    operation_id: str
    # None means "the operation did not declare security" (inherit global).
    # An empty tuple means "the operation explicitly declares NO security" --
    # which is a real, reportable state and must not be confused with absence.
    security: tuple[dict, ...] | None
    global_security: tuple[dict, ...]
    parameters: tuple[tuple[str, str], ...]   # (name, example value or "")

    @property
    def effective_security(self) -> tuple[dict, ...]:
        """
        OpenAPI semantics: an operation-level `security` *overrides* the global
        one, and an explicit empty list means "no auth".

        `security is None` (absent) and `security == ()` (explicitly empty) must be
        distinguished: collapsing them to a truthiness test makes an endpoint that
        deliberately opts out of auth silently inherit the global rule, which
        hides exactly the finding this tool exists to report.
        """
        if self.security is not None:
            return self.security
        return self.global_security

    @property
    def authenticated(self) -> bool:
        return any(req for req in self.effective_security)

    @property
    def has_scopes(self) -> bool:
        return any(scopes for req in self.effective_security for scopes in req.values())

    @property
    def identifier_names(self) -> list[str]:
        names = [i.name for i in find_identifiers(self.parameters)]
        names += [i.name for i in parse_path_params(self.path)]
        # de-duplicate, order-preserving
        seen, out = set(), []
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    @property
    def names_an_object(self) -> bool:
        return bool(self.identifier_names)


@dataclass
class Finding:
    """A route worth testing, with the reason stated in plain language."""

    method: str
    path: str
    kind: str                 # unauthenticated_object | unauthenticated | no_scopes
    severity: str             # error | warning | note
    objects: list[str]
    reason: str
    test_plan: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "kind": self.kind,
            "severity": self.severity,
            "objects": self.objects,
            "reason": self.reason,
            "test_plan": self.test_plan,
            **({"extra": self.extra} if self.extra else {}),
        }


def _security(spec: Mapping[str, Any]) -> tuple[dict, ...]:
    sec = spec.get("security")
    if not isinstance(sec, list):
        return ()
    return tuple(s for s in sec if isinstance(s, dict))


def load_endpoints(spec: Mapping[str, Any]) -> list[Endpoint]:
    """Flatten an OpenAPI 3 document into Endpoint records."""
    global_sec = _security(spec)
    paths = spec.get("paths") or {}
    out: list[Endpoint] = []

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Path-level parameters apply to every operation beneath them.
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if not isinstance(op, dict):
                continue

            params: list[tuple[str, str]] = []
            for p in list(shared) + list(op.get("parameters") or []):
                if not isinstance(p, dict) or "name" not in p:
                    continue
                example = ""
                schema = p.get("schema") or {}
                if isinstance(schema, dict):
                    for key in ("example", "default"):
                        if key in schema:
                            example = str(schema[key])
                            break
                    if not example and isinstance(schema.get("enum"), list) and schema["enum"]:
                        example = str(schema["enum"][0])
                params.append((p["name"], example))

            declared = op.get("security")
            out.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    operation_id=op.get("operationId", "") or f"{method.upper()} {path}",
                    security=None if "security" not in op else _security(op),
                    global_security=global_sec,
                    parameters=tuple(params),
                )
            )
    return out


def audit(endpoints: Iterable[Endpoint]) -> list[Finding]:
    """
    Report the endpoints that can plausibly host broken object access.

    Three distinct findings, because they mean different things:

    * `unauthenticated_object` — names an object and requires no auth at all. The
      most serious: one request, no credentials, someone else's record.
    * `unauthenticated` — no auth, no obvious object. Still worth a look, lower
      severity, and easy to dismiss wrongly, so it stays a note.
    * `no_scopes` — authenticated but the token is not scoped to this object. The
      classic BOLA precondition: a valid token for the wrong tenant passes.
    """
    findings: list[Finding] = []

    for ep in endpoints:
        if not ep.authenticated:
            if ep.names_an_object:
                findings.append(
                    Finding(
                        method=ep.method,
                        path=ep.path,
                        kind="unauthenticated_object",
                        severity="error",
                        objects=ep.identifier_names,
                        reason=(
                            f"{ep.method} {ep.path} takes "
                            f"{', '.join(ep.identifier_names)} and declares no security "
                            "requirement, so any caller can request any object by id."
                        ),
                        test_plan=(
                            f"GET the path with no Authorization header and an id that "
                            "belongs to another account. A 200 carrying that record is "
                            "an unauthenticated disclosure."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        method=ep.method,
                        path=ep.path,
                        kind="unauthenticated",
                        severity="note",
                        objects=[],
                        reason=f"{ep.method} {ep.path} declares no security requirement.",
                        test_plan="Confirm the route is meant to be public.",
                    )
                )
        elif ep.names_an_object and not ep.has_scopes:
            findings.append(
                Finding(
                    method=ep.method,
                    path=ep.path,
                    kind="no_scopes",
                    severity="warning",
                    objects=ep.identifier_names,
                    reason=(
                        f"{ep.method} {ep.path} names "
                        f"{', '.join(ep.identifier_names)} but its security requirement "
                        "carries no scopes, so a token for any tenant satisfies it."
                    ),
                    test_plan=(
                        "Authenticate as tenant B and request tenant A's id. The server "
                        "must check ownership of the object, not just the validity of "
                        "the token."
                    ),
                )
            )

    order = {"error": 0, "warning": 1, "note": 2}
    findings.sort(key=lambda f: (order[f.severity], f.path, f.method))
    return findings


def summary(findings: Iterable[Finding]) -> dict:
    counts = {"error": 0, "warning": 0, "note": 0}
    by_kind: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_kind[f.kind] = by_kind.get(f.kind, 0) + 1
    return {"total": sum(counts.values()), "by_severity": counts, "by_kind": by_kind}
