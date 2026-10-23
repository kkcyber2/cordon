"""Tests for identifier classification, route auditing and the differential oracle."""
from __future__ import annotations

import json

import pytest

from cordon import sarif
from cordon.objects import (
    HASH,
    SEQUENTIAL,
    SLUG,
    UUID_V4,
    classify_value,
    find_identifiers,
    looks_like_object_reference,
    neighbour_values,
    normalize_uuid,
    parse_path_params,
    plan_differential,
    rank_candidates,
    unauthenticated_probe,
)
from cordon.oracle import (
    Observation,
    compare_across_identities,
    compare_without_auth,
    identity_required,
    summarise,
)
from cordon.routes import audit, load_endpoints, summary


# ------------------------------------------------------------------ identifiers
def test_uuid_v4_is_not_guessable():
    kind, guessable, reason = classify_value("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
    assert kind == UUID_V4
    assert guessable is False
    assert "neighbours" in reason


def test_integer_is_guessable():
    kind, guessable, _ = classify_value("1042")
    assert kind == SEQUENTIAL
    assert guessable is True


def test_hex_digest_is_not_guessable():
    kind, guessable, _ = classify_value("d41d8cd98f00b204e9800998ecf8427e")
    assert kind == HASH
    assert guessable is False


def test_empty_is_unknown_and_not_guessable():
    kind, guessable, reason = classify_value("   ")
    assert kind == "unknown"
    assert guessable is False
    assert reason == "empty"


def test_object_reference_names_are_recognised():
    for name in ("id", "invoice_id", "userId", "tenant_id", "account", "order_id", "document"):
        assert looks_like_object_reference(name), name


def test_non_reference_names_are_ignored():
    for name in ("q", "page", "limit", "sort", "search", "lang", "foo"):
        assert not looks_like_object_reference(name), name


def test_find_identifiers_only_returns_object_names():
    params = [("q", "shoes"), ("invoice_id", "42"), ("page", "2")]
    ids = find_identifiers(params)
    assert len(ids) == 1
    assert ids[0].name == "invoice_id"
    assert ids[0].guessable is True


def test_find_identifiers_keeps_uuid_but_flags_untestable():
    ids = find_identifiers([("user_id", "3f2504e0-4f89-41d3-9a0c-0305e82c3301")])
    assert len(ids) == 1
    assert ids[0].testable is False


def test_neighbours_of_an_integer():
    assert neighbour_values("10", span=2) == ["11", "9", "12", "8"]


def test_no_neighbours_for_a_uuid():
    assert neighbour_values("3f2504e0-4f89-41d3-9a0c-0305e82c3301") == []


def test_neighbours_never_go_negative():
    assert all(int(v) >= 0 for v in neighbour_values("1", span=3))


def test_rank_puts_guessable_first():
    ids = find_identifiers([
        ("user_id", "3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
        ("order_id", "77"),
    ])
    ranked = rank_candidates(ids)
    assert ranked[0].name == "order_id"


def test_parse_path_params_extracts_id_templates():
    ids = parse_path_params("/api/invoices/{invoice_id}/lines")
    assert [i.name for i in ids] == ["invoice_id"]


def test_parse_path_params_handles_colon_style():
    ids = parse_path_params("/api/users/:userId")
    assert [i.name for i in ids] == ["userId"]


def test_parse_path_params_ignores_non_object_segments():
    assert parse_path_params("/api/{version}/status") == []


def test_normalize_uuid():
    assert normalize_uuid("3F2504E0-4F89-41D3-9A0C-0305E82C3301").startswith("3f2504e0")
    assert normalize_uuid("not-a-uuid") is None


def test_differential_plan_refuses_to_guess_a_random_token():
    ids = find_identifiers([("doc_id", "3f2504e0-4f89-41d3-9a0c-0305e82c3301")])
    plan = plan_differential(ids[0], "GET", "/docs/{doc_id}", have_second_identity=True)
    assert plan.proven is False
    assert "capturing a second id" in plan.explanation


def test_differential_plan_states_the_oracle_explicitly():
    ids = find_identifiers([("invoice_id", "42")])
    plan = plan_differential(ids[0], "GET", "/invoices/{invoice_id}", have_second_identity=False)
    assert plan.proven is True
    assert "403/404" in plan.explanation


def test_unauthenticated_probe_is_testable_for_a_uuid():
    ids = find_identifiers([("doc_id", "3f2504e0-4f89-41d3-9a0c-0305e82c3301")])
    assert unauthenticated_probe(ids[0], "GET", "/docs").proven is True


# ----------------------------------------------------------------------- routes
def _spec(paths, security=None):
    doc = {"openapi": "3.0.0", "info": {"title": "T"}, "paths": paths}
    if security is not None:
        doc["security"] = security
    return doc


def test_load_endpoints_flattens_operations():
    spec = _spec({
        "/a": {"get": {"operationId": "getA"}, "post": {"operationId": "postA"}},
    })
    eps = load_endpoints(spec)
    assert {(e.method, e.path) for e in eps} == {("GET", "/a"), ("POST", "/a")}


def test_operation_security_overrides_global():
    spec = _spec(
        {"/open": {"get": {"security": [], "parameters": [{"name": "id", "in": "query"}]}}},
        security=[{"bearer": []}],
    )
    ep = load_endpoints(spec)[0]
    # An explicit empty list means "no auth", which must not inherit the global rule.
    assert ep.authenticated is False


def test_global_security_applies_when_operation_is_silent():
    spec = _spec({"/x": {"get": {}}}, security=[{"bearer": []}])
    ep = load_endpoints(spec)[0]
    assert ep.security is None
    assert ep.authenticated is True


def test_explicit_empty_security_is_not_confused_with_absent():
    """Regression: a falsy empty list used to inherit the global rule and hide
    an endpoint that deliberately disables auth."""
    spec = _spec({"/x": {"get": {"security": []}}}, security=[{"bearer": []}])
    ep = load_endpoints(spec)[0]
    assert ep.security == ()
    assert ep.authenticated is False


def test_unauthenticated_object_is_an_error():
    spec = _spec({"/invoices/{invoice_id}": {"get": {}}})
    findings = audit(load_endpoints(spec))
    assert len(findings) == 1
    assert findings[0].kind == "unauthenticated_object"
    assert findings[0].severity == "error"
    assert "invoice_id" in findings[0].objects


def test_unscoped_authenticated_object_is_a_warning():
    spec = _spec(
        {"/orders/{order_id}": {"get": {"security": [{"bearer": []}]}}},
    )
    findings = audit(load_endpoints(spec))
    assert findings[0].kind == "no_scopes"
    assert findings[0].severity == "warning"


def test_scoped_object_route_is_clean():
    spec = _spec(
        {"/orders/{order_id}": {"get": {"security": [{"oauth2": ["orders:read"]}]}}},
    )
    assert audit(load_endpoints(spec)) == []


def test_unauthenticated_route_without_an_object_is_a_note():
    spec = _spec({"/health": {"get": {}}})
    findings = audit(load_endpoints(spec))
    assert findings[0].kind == "unauthenticated"
    assert findings[0].severity == "note"


def test_findings_sort_errors_first():
    spec = _spec({
        "/health": {"get": {}},
        "/invoices/{invoice_id}": {"get": {}},
        "/orders/{order_id}": {"get": {"security": [{"bearer": []}]}},
    })
    findings = audit(load_endpoints(spec))
    assert findings[0].severity == "error"
    assert findings[-1].severity == "note"


def test_summary_counts():
    spec = _spec({"/invoices/{invoice_id}": {"get": {}}, "/health": {"get": {}}})
    stats = summary(audit(load_endpoints(spec)))
    assert stats["total"] == 2
    assert stats["by_severity"]["error"] == 1
    assert stats["by_kind"]["unauthenticated_object"] == 1


def test_parameter_examples_are_captured():
    spec = _spec({
        "/d": {"get": {"parameters": [
            {"name": "doc_id", "in": "query", "schema": {"example": 7}}
        ]}}
    })
    ep = load_endpoints(spec)[0]
    assert ("doc_id", "7") in ep.parameters


# ----------------------------------------------------------------------- oracle
def _obs(identity, status, body, oid=""):
    return Observation(identity=identity, status=status, body=json.dumps(body) if not isinstance(body, str) else body, object_id=oid)


OWNER = _obs("owner", 200, {"id": 5, "owner_id": "alice", "total": 120})


def test_anonymous_refusal_is_not_a_finding():
    v = compare_without_auth(OWNER, _obs("anonymous", 401, {"error": "auth required"}))
    assert v.confirmed is False


def test_anonymous_disclosure_with_owner_fields_is_confirmed():
    v = compare_without_auth(OWNER, _obs("anonymous", 200, {"id": 5, "owner_id": "alice"}))
    assert v.confirmed is True
    assert v.severity == "error"
    assert "owner_id" in v.leaked_fields


def test_anonymous_identical_body_is_confirmed():
    v = compare_without_auth(OWNER, Observation("anonymous", 200, OWNER.body))
    assert v.confirmed is True


def test_anonymous_200_error_document_is_not_a_finding():
    v = compare_without_auth(OWNER, _obs("anonymous", 200, {"message": "please log in"}))
    assert v.confirmed is False


def test_bola_confirmed_when_attacker_gets_identical_body():
    v = compare_across_identities(OWNER, Observation("attacker", 200, OWNER.body))
    assert v.confirmed is True
    assert "byte-identical" in v.reason


def test_bola_confirmed_by_shared_owner_marker():
    attacker = _obs("attacker", 200, {"id": 5, "owner_id": "alice", "total": 999})
    v = compare_across_identities(OWNER, attacker)
    assert v.confirmed is True
    assert "owner_id=alice" in v.reason


def test_bola_refused_is_not_confirmed():
    v = compare_across_identities(OWNER, _obs("attacker", 403, {"error": "forbidden"}))
    assert v.confirmed is False


def test_attacker_receiving_their_own_object_is_not_a_finding():
    """Same shape, different owner: authorization is working."""
    attacker = _obs("attacker", 200, {"id": 9, "owner_id": "bob", "total": 40})
    v = compare_across_identities(OWNER, attacker)
    assert v.confirmed is False
    assert "ownership is being enforced" in v.reason


def test_identity_required_helper():
    assert identity_required(200, 200) is True
    assert identity_required(200, 404) is False


def test_summarise_verdicts():
    good = compare_across_identities(OWNER, _obs("attacker", 403, {"e": 1}))
    bad = compare_across_identities(OWNER, Observation("attacker", 200, OWNER.body))
    s = summarise([good, bad])
    assert s["tested"] == 2
    assert s["confirmed"] == 1
    assert s["severity"] == "error"


# ----------------------------------------------------------------------- sarif
def test_sarif_is_valid():
    spec = _spec({"/invoices/{invoice_id}": {"get": {}}})
    findings = audit(load_endpoints(spec))
    log = sarif.build(findings, "openapi.json")
    assert log["version"] == "2.1.0"
    result = log["runs"][0]["results"][0]
    assert result["ruleId"] == "CORDON-BOLA-001"
    assert result["level"] == "error"
    assert log["runs"][0]["tool"]["driver"]["name"] == "cordon"


def test_sarif_serialises():
    spec = _spec({"/x/{id}": {"get": {}}})
    text = sarif.dumps(sarif.build(audit(load_endpoints(spec)), "s.json"))
    assert json.loads(text)["version"] == "2.1.0"


def test_sarif_empty_is_valid():
    log = sarif.build([], "s.json")
    assert log["runs"][0]["results"] == []


# ------------------------------------------------------------------------- cli
def test_cli_audit_exit_1_on_error(tmp_path):
    spec = _spec({"/invoices/{invoice_id}": {"get": {}}})
    p = tmp_path / "o.json"
    p.write_text(json.dumps(spec))
    from cordon.cli import main
    assert main(["audit", str(p)]) == 1


def test_cli_audit_exit_0_when_clean(tmp_path):
    spec = _spec({"/orders/{order_id}": {"get": {"security": [{"oauth2": ["o"]}]}}})
    p = tmp_path / "o.json"
    p.write_text(json.dumps(spec))
    from cordon.cli import main
    assert main(["audit", str(p)]) == 0


def test_cli_audit_json_is_parseable(tmp_path, capsys):
    spec = _spec({"/invoices/{invoice_id}": {"get": {}}})
    p = tmp_path / "o.json"
    p.write_text(json.dumps(spec))
    from cordon.cli import main
    main(["audit", str(p), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["endpoints"] == 1
    assert out["findings"][0]["kind"] == "unauthenticated_object"


def test_cli_rejects_non_openapi(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    from cordon.cli import main
    with pytest.raises(SystemExit):
        main(["audit", str(p)])


def test_cli_verify_confirms_bola(tmp_path):
    owner = tmp_path / "a.json"
    owner.write_text(json.dumps({"status": 200, "body": {"id": 1, "owner_id": "alice"}}))
    attacker = tmp_path / "b.json"
    attacker.write_text(json.dumps({"status": 200, "body": {"id": 1, "owner_id": "alice"}}))
    from cordon.cli import main
    assert main(["verify", "--owner", str(owner), "--attacker", str(attacker)]) == 1


def test_cli_verify_clears_a_refused_request(tmp_path):
    owner = tmp_path / "a.json"
    owner.write_text(json.dumps({"status": 200, "body": {"id": 1, "owner_id": "alice"}}))
    attacker = tmp_path / "b.json"
    attacker.write_text(json.dumps({"status": 403, "body": {"error": "no"}}))
    from cordon.cli import main
    assert main(["verify", "--owner", str(owner), "--attacker", str(attacker)]) == 0
