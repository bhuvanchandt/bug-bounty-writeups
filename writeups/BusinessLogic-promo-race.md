# Business Logic — Discount Code Reuse and Race Condition

| Field | Value |
|---|---|
| **Severity** | Medium-High |
| **Class** | OWASP A04:2021 — Insecure Design |
| **CWE** | CWE-840 (Business Logic Errors) |
| **Environment** | Sanitized lab reproduction |
| **Date** | 2026-10 |

> **Reproduction notice.** Sanitized, reconstructed lab reproduction. Illustrates
> the vulnerability class and the manual validation technique. No live target
> data is included.

---

## Summary

Two compounding flaws in the discount redemption flow:

1. **No per-user redemption limit.** A single-use promotional code can be applied
   to an unlimited number of orders by the same account.
2. **Non-atomic validation.** The redemption check and the order write are not
   wrapped in a single transaction, so concurrent requests race and the same
   redemption slot is consumed multiple times.

Individually each yields a small discount. Combined with automation they become
a direct, repeatable revenue loss.

---

## Affected Endpoint

```
POST /api/v1/cart/apply-promo
POST /api/v1/checkout
```

---

## Reproduction

### Part 1 — unlimited reuse of a "single-use" code

The promo `WELCOME25` was defined in the admin panel as **one use per customer,
one use per order**.

**Step 1 — first redemption:**

```bash
curl -s -X POST "$BASE/api/v1/cart/apply-promo" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME25"}'

# 200 OK — discount applied
```

**Step 2 — reuse on a different order, same account:**

```bash
curl -s -X POST "$BASE/api/v1/cart/apply-promo" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME25"}'

# 200 OK — discount applied again, no limit enforced
```

The backend checked `promo.is_valid` but never checked whether *this user* had
already redeemed it. It repeated through 10 separate orders.

### Part 2 — race condition on concurrent checkout

Two requests validated against the same redemption state concurrently:

```
Thread A: POST /checkout  {"code":"WELCOME25"}   -> 200, discount applied
Thread B: POST /checkout  {"code":"WELCOME25"}   -> 200, discount applied
```

Both read `redeemed_count == 0` before either wrote. Final state:

```
WELCOME25: max_uses=1, actual_uses=7
```

Seven redemptions against a limit of one, from four accounts, in under a second.

---

## Evidence

| Scenario | Expected | Actual |
|---|---|---|
| Same code, same user, 10 orders | 1 discount | **10 discounts** |
| Same code, 4 users, concurrent | ≤1 discount | **7 discounts** |
| Code reuse after expiry check | rejected | accepted on 2 of 5 attempts |

Promo configuration for reference:

```
code: WELCOME25
discount: 25%
max_total_uses: 1
per_user_limit: 1
expires_at: 2026-12-31
```

Both `max_total_uses` and `per_user_limit` existed in the database and were
displayed in the admin UI. **Neither was enforced in the redemption path.**

---

## Impact

- **Direct revenue loss.** A 25% discount has a 25% margin impact, so each
  illegitimate redemption is a 25% loss on the order total.
- **Scale.** Fully automatable. In the lab, seven redemptions took under a
  second. A small script is bounded only by rate limits.
- **Compounding referral economics.** If sign-up offers carry the same code,
  the vulnerability converts directly into unbounded acquisition spend.
- **Price integrity.** Discount stacking meant cart totals no longer reflected
  intended pricing, undermining any promotional budget control.

---

## Root Cause

**Flaw 1 — the limit columns were never read.**

```python
# vulnerable
def apply_promo(code):
    promo = Promo.query.filter_by(code=code).first()
    if not promo or not promo.is_valid():
        raise PromoError("invalid code")
    # max_total_uses and per_user_limit are never consulted
    return apply_discount(cart, promo)
```

The constraint existed in the schema and in the admin UI, and no enforcement
code existed behind it. Configuration that is displayed but not read is worse
than no configuration, because it is trusted.

**Flaw 2 — check and act are not atomic.**

```python
# vulnerable
def checkout(user, promo_code):
    promo = Promo.query.filter_by(code=promo_code).first()
    if promo.redeemed_count >= promo.max_total_uses:   # read
        raise PromoError("limit reached")
    order = Order.create(user, cart)                    # act
    promo.redeemed_count += 1                           # write
    promo.save()                                        # ...later
    return order
```

Between the read and the write, any number of concurrent requests see the same
stale count. The redemption record is written after the order is committed, so
even a rollback of the order leaves the counter incremented.

---

## Remediation

**1. Enforce both limits in the redemption path.**

```python
def apply_promo(code, user):
    promo = Promo.query.filter_by(code=code).with_for_update().first()
    if not promo:
        raise PromoError("invalid code")
    if promo.expires_at and promo.expires_at < now():
        raise PromoError("expired")
    if promo.redeemed_count >= promo.max_total_uses:
        raise PromoError("limit reached")
    if PromoRedemption.query.filter_by(promo_id=promo.id, user_id=user.id).first():
        raise PromoError("already redeemed")
    return apply_discount(cart, promo)
```

**2. Make redemption atomic — row lock, or a unique constraint.**

`SELECT ... FOR UPDATE` serialises concurrent redemptions on the same promo row:

```python
promo = Promo.query.filter_by(code=code).with_for_update().first()
```

A unique index is the stronger guarantee, because the database enforces it even
if application code regresses:

```python
class PromoRedemption(db.Model):
    __table_args__ = (
        UniqueConstraint("promo_id", "user_id", name="uq_promo_per_user"),
    )
```

**3. Commit the redemption and the order in one transaction.** If the order
fails, the redemption must roll back with it.

**4. Move the counter update to before the order commit**, and derive
`redeemed_count` from the redemption table rather than maintaining a
denormalized counter that can drift.

**5. Rate limit** promo application per account and per IP, and alert on
high-frequency rejection patterns — a rising `limit reached` rate is a strong
indicator of live automation.

**6. Add server-side price calculation.** The client should submit a cart, never
a price. All discounts, taxes, and totals must be computed server-side — this is
the general control that prevents a whole family of these bugs.

---

## Verification After Fix

```bash
# 1. same user, two orders — second must be rejected
# 2. four concurrent requests, single-use code — exactly one must succeed
seq 1 4 | xargs -P4 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "$BASE/api/v1/checkout" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME25"}'
# expect exactly one 2xx and three 4xx

# 3. counter must equal the number of rows in the redemption table
```

---

## Takeaway

Scanners will never find this. There is no malformed input, no unusual header,
no missing header — the requests are entirely well-formed. The bug lives in the
gap between what the system *specifies* and what the code *enforces*, and it was
invisible precisely because the security policy screen said the limit was
configured. Always verify that a control is actually enforced by triggering it,
not by confirming it is present in the interface.
