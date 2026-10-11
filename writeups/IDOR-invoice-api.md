# IDOR — Insecure Direct Object Reference

| Field | Value |
|---|---|
| **Severity** | High |
| **Class** | OWASP A01:2021 — Broken Access Control |
| **CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| **Environment** | Sanitized lab reproduction |
| **Date** | 2026-10 |

> **Reproduction notice.** This report is a sanitized, reconstructed lab
> reproduction. It documents the vulnerability class, the manual validation
> technique, and the remediation — not a live client finding. No real target
> data, credentials, or infrastructure details are included.

---

## Summary

The application exposes a set of invoice records addressed by a sequential
integer identifier. The endpoint authenticates the user, but performs **no
authorization check** on whether the requested object belongs to them. Any
authenticated user can enumerate identifiers and read every other customer's
invoices, including billing addresses and partial payment details.

The finding is trivially exploitable — no tools required beyond a browser and a
counter.

---

## Affected Endpoint

```
GET /api/v2/invoices/{id}
```

**Authorization model:** authentication only (valid session cookie required)
**Required authorization:** object-level ownership check — *absent*

---

## Reproduction

Authenticated as user `testbuyer01`, who owns invoices 1000–1002.

**Step 1 — baseline (legitimate request):**

```
GET /api/v2/invoices/1000
Cookie: session=<valid>

200 OK
{
  "id": 1000,
  "amount": 249.00,
  "currency": "USD",
  "status": "paid",
  "shipping_address": { "line1": "...", "country": "..." }
}
```

**Step 2 — access a record owned by another user:**

```
GET /api/v2/invoices/1001
Cookie: session=<valid for testbuyer01>

200 OK
{
  "id": 1001,
  "amount": 1899.50,
  "currency": "USD",
  "status": "pending",
  "shipping_address": { "line1": "...", "country": "..." }
}
```

The session is valid and belongs to `testbuyer01`, but invoice `1001` belongs to
`testbuyer02`. The API returns it without objection.

**Step 3 — enumerate sequentially:**

Because identifiers are sequential and response codes do not change, the whole
customer invoice set is retrievable:

```
for id in range(1000, 1100):
    r = requests.get(f"{BASE}/api/v2/invoices/{id}", cookies=session)
    if r.status_code == 200:
        log(id, r.json())
```

All 100 requests return `200 OK`.

---

## Evidence

| Invoice ID | Owner | Retrieved as | Status |
|---|---|---|---|
| 1000 | testbuyer01 | testbuyer01 | 200 (legitimate) |
| 1001 | testbuyer02 | testbuyer01 | **200 — unauthorized** |
| 1002 | testbuyer01 | testbuyer01 | 200 (legitimate) |
| 1003 | testbuyer02 | testbuyer01 | **200 — unauthorized** |
| 1042 | testbuyer07 | testbuyer01 | **200 — unauthorized** |

Identifiers `1099`+ returned `404`, confirming a bounded sequential range of
~100 records.

---

## Impact

- **Confidentiality:** full exposure of the customer invoice set — amounts,
  billing addresses, order history.
- **Scale:** a single authenticated (or, in this lab, self-registered) account
  reads the entire dataset. No rate limiting was observed.
- **Amplification:** invoice numbers leak order volume, which feeds directly into
  enumeration of the order and fulfilment endpoints in the same API.
- **PII context:** shipping addresses are personal data. Under GDPR this is a
  reportable personal data breach once it involves data outside the data
  subject's own account.

**Business impact:** regulatory exposure, customer notification obligation,
loss of trust, and a straightforward pre-auth-req chain into account takeover
via the order-delivery flow.

---

## Root Cause

The handler loads the object by primary key and returns it. There is no
comparison between the object's owner and the authenticated principal.

```python
# vulnerable
@app.route("/api/v2/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.to_dict())          # no ownership check
```

`@login_required` answers *"who is this?"*. It never answers *"may this person
see this?"*. Those are different questions, and only the first was asked.

---

## Remediation

**1. Scope every query to the authenticated principal.**

Never fetch by raw ID and check afterwards — scope at the database level so an
unauthorized object is indistinguishable from one that does not exist.

```python
# fixed
@app.route("/api/v2/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        user_id=g.current_user.id,        # ownership enforced in the query
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

**2. Return `404`, not `403`,** for objects the user does not own. A `403`
confirms the object exists, which is itself an enumeration oracle. `404` is the
correct response.

**3. Add an authorization check to every object endpoint.** Audit the API for
all routes taking an object identifier, not just this one. IDOR is rarely a
single endpoint.

**4. Replace sequential identifiers with UUIDv4** for objects that are
user-visible. This is *defence in depth* — it does not fix the missing
authorization check, but it raises the cost of enumeration.

**5. Rate limit and alert** on high-volume sequential access to object
endpoints from a single principal.

---

## Verification After Fix

```bash
# As testbuyer01, request an invoice owned by testbuyer02
curl -i -b cookies.txt $BASE/api/v2/invoices/1001

# Expected: 404 Not Found  (identical to a genuinely missing record)
```

Compare the response for an unauthorized record against a nonexistent ID
(`/invoices/99999`). Both must be indistinguishable — same status, same body,
same response time.

---

## Takeaway

Authentication is not authorization. Every endpoint that accepts an object
identifier needs an explicit decision about who may act on that object, and
that decision belongs in the data access layer — not in the view.
