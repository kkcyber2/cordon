# cordon

Finds broken object-level authorization (BOLA/IDOR) in an API before your users do.

```
$ cordon audit openapi.json
Storefront API — 34 operation(s) analysed

  [UNAUTHENTICATED OBJECT] GET /invoices/{invoice_id}
    GET /invoices/{invoice_id} takes invoice_id and declares no security
    requirement, so any caller can request any object by id.
    test: GET the path with no Authorization header and an id that belongs to
          another account. A 200 carrying that record is an unauthenticated
          disclosure.

1 finding(s): 1 error, 0 warning, 0 note
```

## Why this exists

BOLA is consistently the #1 or #2 bug class in the OWASP API Security Top 10, and
it is the one static scanners are worst at. The reason is structural: **there is
no vulnerable line of code.** The handler is correct. The query is parameterised.
The bug is that a valid token for tenant B is accepted on a route that addresses
tenant A's record — and nothing in a single request looks wrong.

So cordon does not try to find a bad line. It does two narrower things well:

1. **audit** — finds the routes where the *precondition* exists: an endpoint that
   names an object and does not constrain who may address it.
2. **verify** — the differential oracle, which is the only test that can actually
   prove the bug: did identity B receive identity A's object?

## The bug this tool found in itself

An endpoint declaring `"security": []` means *no authentication*. An endpoint with
no `security` key inherits the document's global rule. Collapsing those two with a
truthiness check (`if self.security:`) makes an endpoint that deliberately opts out
of auth silently inherit the global rule — **hiding the exact finding the tool
exists to report.** `None` (absent) and `()` (explicitly empty) are now distinct,
and `test_explicit_empty_security_is_not_confused_with_absent` pins it.

## Install

```bash
pip install -e .
```

Python 3.10+, no runtime dependencies.

## Usage

```bash
cordon audit openapi.json                  # human report
cordon audit openapi.json --json           # machine report
cordon audit openapi.json --sarif out.sarif

cordon verify --owner a.json --attacker b.json     # two identities
cordon verify --owner a.json --anonymous c.json    # no credentials
```

Exit codes: `0` clean, `1` error-severity findings, `2` bad input.

## What the three findings mean

| Finding | Severity | Meaning |
|---|---|---|
| `unauthenticated_object` | error | Names an object, requires no auth at all. One curl, no credentials, someone else's record. |
| `no_scopes` | warning | Authenticated, but the token carries no scopes. The classic BOLA precondition: a valid token for the wrong tenant passes. |
| `unauthenticated` | note | No auth, no obvious object. Usually fine — a health check — but worth a glance. |

Severity here is about the *vulnerability*. Whether the object is actually
reachable still needs `cordon verify`.

## The oracle

A 200 is not evidence. Plenty of APIs return `200 {"error":"..."}`. cordon
compares bodies:

- **byte-identical** to the owner's response → confirmed;
- **carries the owner's identifiers** (`owner_id`, `tenant_id`, `email`, …) →
  confirmed, and the field is named in the report;
- **same schema, different content** → the attacker received *their own* object,
  so ownership is being enforced. **Not** a finding.

That last case matters. Without it, every well-built API would be reported as
vulnerable.

## Identifier classification

Not every id can be walked, and pretending otherwise wastes requests and burns
credibility:

- integer `1042` → **guessable**, neighbours are `1043`, `1041`, …
- UUID v4 → **not guessable**; 122 random bits. Test it by *capturing* a second id,
  not by guessing.
- hex digest, opaque slug → not enumerated.

## Tests

```bash
python -m pytest tests/ -q     # 49 tests
```

## License

MIT — see [LICENSE](LICENSE).

---

Built by **KK (Conan Sultan Khan)** · [github.com/kkcyber2](https://github.com/kkcyber2) · kkdev9715@gmail.com
