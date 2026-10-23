"""CLI: audit an OpenAPI document for broken object-level authorization.

    cordon audit openapi.json
    cordon audit openapi.json --json
    cordon audit openapi.json --sarif out.sarif
    cordon verify --owner a.json --attacker b.json

Exit codes: 0 clean, 1 findings at error severity, 2 usage/data error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import sarif
from .oracle import Observation, compare_across_identities, compare_without_auth
from .routes import audit, load_endpoints, summary


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cordon: cannot read {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"cordon: {path} is not a JSON object")
    if "paths" not in data:
        raise SystemExit(f"cordon: {path} has no 'paths' -- is it an OpenAPI document?")
    return data


def cmd_audit(args) -> int:
    spec = _load(args.spec)
    endpoints = load_endpoints(spec)
    findings = audit(endpoints)
    stats = summary(findings)

    if args.json:
        print(json.dumps(
            {
                "document": args.spec,
                "title": (spec.get("info") or {}).get("title", ""),
                "endpoints": len(endpoints),
                "summary": stats,
                "findings": [f.as_dict() for f in findings],
            },
            indent=2,
        ))
    else:
        title = (spec.get("info") or {}).get("title", args.spec)
        print(f"{title} — {len(endpoints)} operation(s) analysed\n")
        if not findings:
            print("no authorization gaps found.")
        else:
            for f in findings:
                head = {
                    "error": "UNAUTHENTICATED OBJECT",
                    "warning": "NO OBJECT SCOPES",
                    "note": "UNAUTHENTICATED",
                }[f.severity]
                print(f"  [{head}] {f.method} {f.path}")
                print(f"    {f.reason}")
                if f.objects:
                    print(f"    objects: {', '.join(f.objects)}")
                print(f"    test: {f.test_plan}")
                print()
            sev = stats["by_severity"]
            print(f"{stats['total']} finding(s): "
                  f"{sev.get('error', 0)} error, {sev.get('warning', 0)} warning, "
                  f"{sev.get('note', 0)} note")

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(sarif.dumps(sarif.build(findings, args.spec)))
        print(f"SARIF written to {args.sarif}", file=sys.stderr)

    return 1 if any(f.severity == "error" for f in findings) else 0


def cmd_verify(args) -> int:
    """
    Run the differential oracle over two recorded responses.

    Supply --owner (as the legitimate user) and either --attacker (a second
    identity) or --anonymous (no credentials at all).
    """
    owner = _observation("owner", args.owner)
    verdicts = []

    if args.anonymous:
        verdicts.append(compare_without_auth(owner, _observation("anonymous", args.anonymous)))
    if args.attacker:
        verdicts.append(compare_across_identities(owner, _observation("attacker", args.attacker)))

    if not verdicts:
        raise SystemExit("cordon: give --attacker or --anonymous")

    confirmed = [v for v in verdicts if v.confirmed]
    if args.json:
        print(json.dumps({"verdicts": [v.as_dict() for v in verdicts]}, indent=2))
    else:
        for v in verdicts:
            mark = "VULNERABLE" if v.confirmed else "not vulnerable"
            print(f"{mark}: {v.reason}")
            if v.leaked_fields:
                print(f"  leaked: {', '.join(v.leaked_fields)}")
    return 1 if confirmed else 0


def _observation(identity: str, path: str) -> Observation:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise SystemExit(f"cordon: cannot read {path}: {exc}")
    status = 200
    body = raw
    # Accept either a bare body or a {"status":..,"body":..} recording.
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and {"status", "body"} <= set(parsed):
        status = int(parsed["status"])
        body = parsed["body"] if isinstance(parsed["body"], str) else json.dumps(parsed["body"])
    return Observation(identity=identity, status=status, body=body)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cordon", description="Broken object-level authorization auditor")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit an OpenAPI document")
    a.add_argument("spec")
    a.add_argument("--json", action="store_true")
    a.add_argument("--sarif", default=None, metavar="PATH")
    a.set_defaults(func=cmd_audit)

    v = sub.add_parser("verify", help="compare recorded responses to prove BOLA")
    v.add_argument("--owner", required=True, help="recording as the legitimate user")
    v.add_argument("--attacker", help="recording as a different authenticated user")
    v.add_argument("--anonymous", help="recording with no credentials")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
