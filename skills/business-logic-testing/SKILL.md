---
name: business-logic-testing
description: "Test an authorized web application for business-logic flaws and race conditions — the classes scanners cannot find. Model invariants (conservation of value, uniqueness, monotonicity, exclusivity), build an Actor x Action x Resource matrix, abuse state machines (skip/reorder/replay steps, limit-slicing), find numeric bugs (float-vs-decimal rounding, cross-currency refund arbitrage, negative amounts), stale feature gates, and saga gaps; prove concurrency bugs (double-spend, lost update, idempotency-key reuse) with controlled parallel requests. Use when the user mentions 'business logic testing,' 'race condition,' 'double spend,' 'TOCTOU,' 'concurrency bug,' 'idempotency,' 'coupon reuse,' 'workflow bypass,' 'limit bypass,' 'negative amount,' 'refund arbitrage,' 'parallel request attack,' or 'logic flaw.'"
allowed-tools: Read, Grep, Glob
---

# Business Logic Testing — Invariants, State-Machine Abuse, Race Conditions

The vulnerability classes scanners cannot find. A scanner matches syntax; a logic flaw is a mismatch between what the app *is supposed to guarantee* and what its code actually enforces under adversarial or concurrent use. This skill is the dynamic counterpart to `owasp-audit`'s source-side race patterns (TOCTOU, atomic queue claim, reserve-then-act) and the depth behind `web-pentest` Phase 8.

Work invariant-first: name the guarantee, then try to break it. A finding is not "I sent a weird request" — it is "I violated a stated invariant and proved durable state changed."

## Authorization Check

Concurrency and logic testing mutates real state. Before sending anything:

1. Written authorization naming this specific application and that **business-logic and concurrency testing** are in scope.
2. **Prefer a staging or test-mode environment.** Use payment test mode (e.g. Stripe test keys), seeded test tenants, and disposable accounts you own. Never exercise a production money flow, inventory ledger, or third-party billing API unless the written scope explicitly names it.
3. A **request-count cap** agreed in advance. Concurrency proofs need tens of parallel requests, not thousands — name the ceiling and stay under it.
4. Accounts you control for every role and tenant you will test (owner, non-owner, admin, two tenants).

If any of these is missing, stop and ask. See **Boundaries** below.

Sending live requests is deliberately outside this skill's pre-approved tools (`Read, Grep, Glob` only) — the human runs the parallel requests, or approves each tool invocation, so a throughput test never fires unattended.

## Step 1 — Model the invariants

Before touching a request, write down what the system promises. Four families cover most money and workflow bugs:

- **Conservation of value.** Money, credits, points, inventory, and quota are neither created nor destroyed except through an authorized path. A $10 refund must remove exactly $10 of credit; redeeming a coupon must decrement its remaining uses.
- **Uniqueness.** A coupon redeems once per rule; a username, invite, or idempotency key is claimed by exactly one principal; an order is fulfilled once.
- **Monotonicity.** Some counters only move one way — a used voucher never returns to unused, a shipped order never returns to pending, a consumed one-time token never re-validates.
- **Exclusivity.** A seat, a lock, a lease, or a "pending approval" row is held by one actor at a time; two parties cannot both own the same mutually-exclusive resource.

For each invariant, note **where it is enforced** (a DB unique constraint? an application `if`? only the UI?) and **what proves a violation** (a ledger that no longer sums to zero, two rows where one should exist). An invariant enforced only in the UI or only in a single handler is the lead.

## Step 2 — Actor x Action x Resource matrix

Enumerate the grid and look for the cells the app forgot:

- **Actors:** anonymous, authenticated user, resource owner, non-owner, admin, two separate tenants, a user mid-workflow.
- **Actions:** create, read, update, delete, approve, cancel, refund, redeem, transfer, advance-state.
- **Resources:** each object with a lifecycle or a balance — order, invoice, coupon, subscription, document, approval request, wallet.

Fill each cell with the expected outcome (allow / deny), then test the deny cells and the state-sensitive allow cells. The interesting failures: a non-owner reaching an owner action (overlaps IDOR/BOLA — see `web-pentest` Phase 4), an actor performing an action valid only in a different state, or the same actor performing a once-only action twice.

## Step 3 — State-machine abuse

Draw the intended state graph (cart -> checkout -> paid -> shipped; draft -> submitted -> approved). Then attack the edges:

- **Skip a step.** Call the step-4 endpoint directly without completing step 2. Can you reach `paid` without a charge, or `approved` without a reviewer?
- **Reorder steps.** Apply a discount after the total is locked; change the shipping address after payment authorization but before capture.
- **Replay a step.** Re-POST a terminal transition. Does "confirm" run twice? Does a one-time token validate again?
- **Limit-slicing.** A limit checked per-request but not in aggregate: split one over-limit action into many under-limit ones (withdraw the daily max in several smaller transfers; exceed a per-upload cap across many uploads that share no running total).
- **Approve your own request.** Tamper with `approver_id` / `reviewer_id` so the requester and approver are the same principal.

Each of these is a candidate for the concurrency amplifier in Step 6 — a window that is hard to hit sequentially is trivial to hit with parallel requests.

## Step 4 — Numeric and value issues

- **Float vs. decimal.** Prices or balances stored or computed as floats accumulate rounding error. Probe amounts like `0.1 + 0.2`, long-fraction quantities, and values near rounding boundaries; watch for a cent appearing or vanishing.
- **Rounding direction.** A per-line-item round that always rounds in the customer's favor, summed over many items, leaks value. Many small items can be cheaper than the honest total.
- **Negative and zero amounts.** Can you order quantity `-1`, transfer a negative sum (crediting yourself), or apply a discount larger than the subtotal to drive the total below zero?
- **Cross-currency refund arbitrage.** Pay in a currency that converts one way, refund in another (or at a later rate), and keep the spread. Test when charge and refund use different rate snapshots or different currencies.
- **Type / precision coercion.** Scientific notation (`1e3`), extra precision, leading zeros, or integer overflow at the boundary of the money type.

## Step 5 — Stale authorization and saga gaps

- **Stale feature gates and roles.** After a downgrade, cancellation, or role change, does the old capability keep working until a cache expires? Test the gated action immediately after revoking the entitlement, and with a token minted before the change.
- **Event-driven saga gaps.** Multi-service workflows coordinated by events (order -> payment -> inventory -> fulfillment) have no single transaction. Look for: a step that commits before a prior step's compensation can run, a compensation (refund, release-inventory) that never fires on partial failure, and a consumer that is not idempotent so a redelivered event double-applies. The dynamic tell is a state that is internally inconsistent across services after an interrupted or duplicated flow.

## Step 6 — Concurrency methodology

Most logic invariants are enforced with a check-then-act sequence that is safe sequentially and unsafe in parallel. The goal is to land N requests inside the same check-then-act window so the check passes N times before any act commits.

Patterns to hunt (source-side equivalents live in `owasp-audit` A06/A02/A08):

- **Idempotency key scoped to the path, not the principal.** If the key is keyed by `(endpoint, key)` rather than `(principal, endpoint, key)`, another user's key — or a replay of your own — reuses a completed result. Submit two different operations under one key; submit one key across two accounts.
- **Cache-before-commit.** The app writes a "reserved/pending" marker to a cache, then commits to the DB. Two requests both read "available" from the stale cache before either commit lands.
- **Lost update (read-modify-write).** `balance = read(); write(balance - amount)` with no atomic decrement or version check — concurrent writers each start from the same read and the last write wins, losing the others' effect.
- **Saga compensation timing.** Fire the parallel burst during the window between a forward step and its compensation.
- **Redis locks without `NX`/`EX` or fencing tokens.** A lock set without atomic acquire-and-expire, or without a fencing token, lets two holders believe they own it (one acquires, the other sets over it; or a GC-paused holder acts after its lease expired).
- **READ COMMITTED anomalies.** The default isolation level permits non-repeatable reads and write skew — two transactions each read a constraint as satisfied and both write, violating it. Uniqueness enforced by `SELECT ... then INSERT` (instead of a DB UNIQUE constraint) breaks here.
- **Upsert races.** "Insert if absent else update" implemented in app code (not an atomic `INSERT ... ON CONFLICT`) double-inserts under concurrency.

**Landing the requests on the same window.** The web-request equivalent of a starter pistol:

- **HTTP/2 single-packet attack.** Put the final frame of many requests into one TCP packet so the server receives them simultaneously, removing network jitter from the race.
- **Last-byte synchronization (HTTP/1.1).** Send all but the last byte of each request ahead of time over kept-alive connections, then release the last bytes together.
- **Connection warming.** Send a throwaway request first so TLS/connection setup and any lazy initialization are already done before the timed burst.

Tooling, a worked Turbo Intruder config, and a minimal `httpx`/`curl --parallel` runner are in [references/concurrency.md](references/concurrency.md) — all scoped to authorized-test use and the agreed request cap.

## Validation and false positives — per class

Hold every candidate to the evidence bar before it becomes a finding. Use the verdict vocabulary: a candidate is `confirmed`, `needs_validation`, or `rejected` (see [references/verification.md](references/verification.md)). Severity attaches only to `confirmed` findings; calibrate with [references/severity-calibration.md](references/severity-calibration.md).

**General validation standard (all classes):** *1 request is correctly denied, then N concurrent requests succeed where only 1 should — and the durable state change is proven* (ledger no longer sums correctly, two rows where uniqueness required one, a counter past its monotone bound, a balance that moved further than any single authorized action allows). A changed response code alone is not proof; read the persisted state back.

| Class | Confirmed when | Likely false positive |
|---|---|---|
| Double-spend / coupon reuse | Coupon with N uses redeemed > N times; refunded value exceeds charged; inventory oversold — proven by reading the balance/count back | The op is genuinely idempotent — enforced ETag/`If-Match`, or a DB UNIQUE/`ON CONFLICT` collapses the duplicates so only one commits |
| Lost update | Sum of concurrent deltas does not equal the net change in the durable balance | An atomic decrement or a version/`WHERE balance >= amount` guard rejected all but one |
| Idempotency-key reuse | A second distinct operation (or another principal) reused a key and got the first result, or a replay double-applied | Keys correctly scoped to principal + request body hash; replays return the cached result without re-applying the side effect |
| State-machine skip/reorder/replay | A terminal/forbidden state reached without its precondition, persisted | The transition was rejected server-side; only the UI advanced |
| Limit-slicing | Aggregate exceeds the limit across sliced requests, durably | A running server-side total caught the aggregate |
| Numeric (negative/rounding/arbitrage) | Final persisted balance reflects created or destroyed value | Input validation rejected it; the "discrepancy" was display formatting only |
| Stale gate / saga gap | A revoked capability still performed a durable action, or services left inconsistent after an interrupted/duplicated flow | A short, documented cache TTL that closes on its own with no durable effect |

**The two false-positive traps to always rule out:**

1. **Truly idempotent operations.** An enforced ETag/`If-Match`, a DB UNIQUE constraint, or `INSERT ... ON CONFLICT DO NOTHING` means the duplicates collapse to one commit — the parallel requests *look* accepted (all 200) but only one took effect. Always read the durable state, never trust the status code.
2. **Visual-only glitches.** A doubled toast, an optimistic UI that shows two items, or a transient count before a refetch is not a finding if the server state is correct. No durable state change, no finding — record it as a **hardening note** at most, never a severity.

A candidate you could not land under the agreed request cap is `needs_validation` with a `validation_plan` (the exact burst to run in staging), not a confirmed finding.

## Output Format

Report with the shared findings vocabulary; see [references/findings-format.md](references/findings-format.md) for the `findings.json` record and how to validate/export it.

```markdown
# Business Logic & Race Condition Test Report
## Target / environment: [app + staging vs prod, test-mode confirmation]
## Authorization: [scope reference, request-count cap]

### Invariant register
| Invariant | Family | Enforced where | Violation proof |

### Findings
#### [verdict] [Title]
**Invariant violated:** [conservation / uniqueness / monotonicity / exclusivity]
**Endpoint(s):** `METHOD /path`
**Preconditions:** [accounts, state, concurrency needed]
**Reproduction:** [the controlled burst — count, sync method; or the step sequence]
**Durable-state proof:** [the balance/row/counter read back that shows the violation]
**Verdict:** confirmed | needs_validation (+ blockers, validation_plan) | rejected (+ ruled_out_by {control, location})
**Severity:** [only if confirmed — see severity-calibration.md]

### Hardening notes (not findings)
[Visual-only glitches, defense-in-depth gaps with no traced durable impact]
```

## Boundaries

- Refuse to run concurrency or logic tests against a **production money flow, inventory ledger, or live third-party billing API** without explicit written scope naming it. Default to staging / test mode.
- Refuse to exceed the agreed request-count cap or to turn a proof into a sustained load — a controlled double-spend proof is a dozen requests, not a stress test (that is a DoS; see `web-pentest` Boundaries).
- **Never touch third-party systems** (the payment provider's own API, upstream SaaS) as a target — they are out of scope by default even when the app in scope calls them.
- Proof of concept is the minimum burst that demonstrates the violation, not a reusable exploit for repeated extraction.
- If a test moves real money or real inventory, stop and report; do not "clean up" by issuing compensating transactions that mutate more state.

## Cross-references

- `owasp-audit` A06/A02/A08 — source-side race patterns: TOCTOU, atomic queue claim (`UPDATE ... WHERE status='pending' RETURNING`), reserve-then-act, external-resource-create TOCTOU. Read the code to locate the check-then-act window this skill proves dynamically.
- `web-pentest` Phase 8 (business logic) and its "Combined white-box + black-box mode" — when source and a running instance are both available, code findings point to the exact window to race.
- `api-audit` — idempotency, BOLA, and API-level object/function authorization.
- `finding-triage` — close each candidate to a disposition with contextual severity.

## References

- Strix (Apache-2.0) — `vulnerabilities/race_conditions.md` and `vulnerabilities/business_logic.md` (https://github.com/usestrix/strix). Techniques paraphrased, not copied. This skill deliberately does **not** adopt Strix's never-refuse / never-question-authorization posture: authorization, staging preference, and request caps are enforced here.
- PortSwigger Web Security Academy — race conditions (single-packet attack) and business-logic labs.
- OWASP Web Security Testing Guide (WSTG) — Business Logic Testing section.
