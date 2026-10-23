"""SARIF 2.1.0 for cordon findings."""
from __future__ import annotations

import json
from typing import Sequence

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULES = {
    "unauthenticated_object": {
        "id": "CORDON-BOLA-001",
        "name": "UnauthenticatedObjectAccess",
        "shortDescription": {"text": "Object addressed without authentication"},
        "fullDescription": {
            "text": "The operation names an object identifier and declares no security "
                    "requirement, so an unauthenticated caller can address any record."
        },
        "defaultConfiguration": {"level": "error"},
    },
    "no_scopes": {
        "id": "CORDON-BOLA-002",
        "name": "UnscopedObjectAccess",
        "shortDescription": {"text": "Object addressed by an unscoped credential"},
        "fullDescription": {
            "text": "The operation names an object identifier but its security requirement "
                    "declares no scopes, so a credential for any tenant satisfies it."
        },
        "defaultConfiguration": {"level": "warning"},
    },
    "unauthenticated": {
        "id": "CORDON-AUTH-003",
        "name": "UnauthenticatedEndpoint",
        "shortDescription": {"text": "Endpoint without authentication"},
        "fullDescription": {"text": "The operation declares no security requirement."},
        "defaultConfiguration": {"level": "note"},
    },
}


def build(findings: Sequence, target: str, version: str = "1.0.0") -> dict:
    used = {f.kind for f in findings}
    results = []
    for f in findings:
        rule = RULES.get(f.kind)
        if rule is None:
            continue
        results.append(
            {
                "ruleId": rule["id"],
                "level": f.severity if f.severity in ("error", "warning", "note") else "warning",
                "message": {"text": f"{f.method} {f.path}: {f.reason}"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": target}}}
                ],
                "properties": {"objects": f.objects, "test_plan": f.test_plan},
            }
        )

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cordon",
                        "version": version,
                        "informationUri": "https://github.com/kkcyber2/cordon",
                        "rules": [RULES[k] for k in RULES if k in used],
                    }
                },
                "results": results,
            }
        ],
    }


def dumps(log: dict) -> str:
    return json.dumps(log, indent=2) + "\n"
