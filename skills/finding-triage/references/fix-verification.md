# Fix verification and regression hunt

A merged pull request is a claim that the bug is gone. This is the check of that claim. Run it for every **Fix now**
finding before its record gets `disposition: Fixed`, and again whenever a later audit finds the same fingerprint.

The bar is simple to state. **A fix is verified when the original claim, re-checked against the fixed code, would now
close as `rejected`,** with `ruled_out_by` pointing at the fix: a named control, on every path an attacker can reach,
before the sink, failing closed. Anything less is a partial fix, and the record stays open.

Do the checks in order. Each one can send the fix back.

## 1. Re-run the original check against the fix

Use the same check that confirmed the finding, unchanged. Don't swap it for one the fix was written to pass.

- **Reproduced findings** (`"reproduced": true`). Re-run the recorded PoC, test or request against a build with the
  fix, in the environment the original ran in or another one you're authorized to test. Expect the refusal: 403 or
  404 instead of 200, the payload rendered inert, the job rejected. Then send the legitimate baseline request and
  confirm it still works. A fix that breaks the feature gets reverted, and the bug comes back with the revert.
- **Static-only findings.** Walk the recorded `trace[]` again hop by hop on the fixed code. Find the hop where the
  fix now stops the attack, and check it the way a verifier checks a control: every path, before the sink, fails
  closed. In Claude Code, hand the original record and the fixed code to the `finding-verifier` subagent. It should
  come back `rejected` with the fix as `ruled_out_by`. If it comes back `confirmed` or `needs_validation`, the fix is
  incomplete.
- **Needs a deployed fact** (a WAF rule, an IdP setting, a header the origin sends). The fix isn't verified until
  that fact is checked against the deployment. Run the original `validation_plan`, or write one and hand it over.

Record the command or the test that ran, when, against which commit, and the observed result.

## 2. Variant check: sibling paths

A bug in one handler is usually a pattern. Look for the same mistake where the fix didn't reach.

- **Other callers of the sink.** Grep for every call of the function, query helper or template the trace ends in.
  Each caller is a path the fix has to cover or that needs its own guard.
- **Parallel entrypoints to the same data.** The REST route and the server action or GraphQL resolver that write the
  same table; `v1` next to `v2`; the HTTP handler and the queue worker; `PUT` next to `PATCH`; the bulk endpoint next
  to the single one; the admin import next to the user form.
- **The same pattern elsewhere.** The same unsafe call or missing check in other files: `grep -rnE` for the call
  shape, or `rg` with a type filter. Example for a missing owner filter:

  ```bash
  rg -n --type ts 'findUnique\(\{\s*where:\s*\{\s*id' src/
  grep -rnE 'findUnique\(\{ *where: *\{ *id' src/ --include='*.ts'
  ```

What to do with what you find:

- **Same root cause, and the fix's shared code now covers it** (the guard moved into the helper every caller uses).
  Confirm that with step 1 for that path too. No new record.
- **Same root cause, not covered.** The fix is incomplete. Send it back before setting `Fixed`.
- **Same pattern, separate root cause** (another handler with its own missing check). It's a new candidate with its own
  fingerprint. List it under "Related candidates" and hand it to the owning audit skill, or triage it separately. It
  doesn't block this record.

## 3. Confirm the fix didn't just move the sink

Some fixes make the original trace stop working without removing the bug. Re-trace from every entrypoint that reached
the old sink, not just the one in the PoC. Watch for:

| Shape | What it looks like | What to check |
|---|---|---|
| Moved, not removed | Escaping added in one template; the same value is rendered raw in another, or in an email or PDF | Every place the tainted value is output or used |
| Guard on the wrong layer | Validation added in the client, the form or the API gateway config only | That the server enforces it on the path that reaches the sink |
| Guard on one path | Ownership check added to the route; the background job or bulk endpoint calls the service directly | The control sits in the shared function, or on every path |
| Denylist for a known payload | The PoC string is blocked; a different encoding or case gets through | That the fix is an allow-list, a parameterized API or a type, not a pattern match on the PoC |
| Fails open | The new check is inside `try`/`catch` that continues, or reads an env var that may be unset | What happens on error and when the setting is missing |
| Behind a flag | The fix ships behind a feature flag or config that defaults off | The default in the code, and the value in every deployed environment |
| Sink swapped for a sibling | `exec` replaced with `spawn` and `shell: true`; `innerHTML` replaced with `insertAdjacentHTML` | That the replacement is actually safe with the same input |
| Moved the trust problem | The ID now comes from a header or a cookie instead of the URL | Whether the new source is any less attacker-controlled |

Any of these means the fix is partial. Record what you found and send it back.

## 4. Regression test

The fix needs a test that sends the adversarial input to the vulnerable path and asserts it's refused, so the bug can't
quietly come back.

- It exercises the real path (the route, the job, the resolver), not only a unit test of the new helper.
- It asserts the refusal and the absence of the side effect: no refund issued, no row written, nothing rendered raw.
- It fails on the commit before the fix. Run it there if you can. If you can't, say why in the writeup.
- It runs in CI. A test that's skipped or not collected protects nothing.
- For a variant the shared fix covers, one test per distinct entrypoint, not one per fingerprint.

If the project has no test harness for that layer, record the gap in the writeup and keep the step 1 check as the
regression check. Don't block `Fixed` on building a harness, but do name who owns adding one.

## 5. Ship, then set `Fixed`

`Fixed` means the fix is live and was checked. The rule from Step 4 of the skill still applies: a decision to fix is
not a fix.

- While the fix is planned, in review, merged but not deployed, or deployed to only some environments: leave
  `disposition` unset. The record stays open and `to-sarif.mjs` keeps alerting.
- Set `disposition: "Fixed"` only when steps 1–4 passed **and** the change has shipped to every environment the
  finding applied to.
- Don't change `verdict` or `severity`. The record is still a confirmed finding of that severity; the disposition
  says it's closed.
- Keep the `fingerprint` exactly as it was, even if the fix moved or renamed the code. Re-runs match on it.
- Re-run the validator after editing: `node references/validate-findings.mjs findings.json`.

### What to record

Put the fix details in `ext` on the confirmed record (flat keys, see `findings-format.md`). The producing skill's own
`ext` keys stay as they are.

| `ext` key | Value |
|---|---|
| `fixed_in` | The fixing commit SHA, or the release tag if it shipped across several commits |
| `fix_verified_on` | The date the step 1 check passed against the shipped fix, `YYYY-MM-DD` |
| `regression_test` | Repo-relative path of the regression test, or an array of paths. Leave it out if there isn't one, and say why in the writeup |

```json
{
  "fingerprint": "api-audit/CWE-639/src/routes/orders.ts/refundOrder",
  "verdict": "confirmed",
  "skill": "api-audit",
  "title": "Refund endpoint lets any user refund another user's order (IDOR)",
  "cwe": "CWE-639",
  "owasp_category": "API1:2023",
  "location": { "file": "src/routes/orders.ts", "line": 88 },
  "trace": [
    { "kind": "entrypoint", "file": "src/routes/orders.ts", "line": 84, "description": "POST /api/orders/:id/refund reads :id" },
    { "kind": "propagation", "file": "src/services/orders.ts", "line": 41, "description": "findOrder(id) has no owner filter" },
    { "kind": "sink", "file": "src/services/payments.ts", "line": 17, "description": "refund issued" }
  ],
  "evidence": [{ "file": "src/services/orders.ts", "line": 41, "description": "WHERE id = $1, no user_id predicate" }],
  "counterevidence": "requireAuth only authenticates; no policy on this route. Fix check: findOrder now takes userId and every caller (route, bulk refund job) passes the session user; the original PoC returns 404 on the fixed build.",
  "confidence": "high",
  "reproduced": true,
  "severity": {
    "likelihood": { "score": "high", "reason": "Open signup; sequential ids" },
    "impact": { "score": "high", "reason": "Refunds another customer's payment" },
    "overall": "high"
  },
  "conditions": [{ "kind": "authentication_level", "description": "Any user account" }],
  "disposition": "Fixed",
  "ext": { "fixed_in": "4f2c9e1", "fix_verified_on": "2026-10-27", "regression_test": "tests/api/orders.refund.test.ts" }
}
```

In the Fix writeup, fill in the Verification section with the step 1 result and add the variant check and the
"didn't move the sink" check in a line each.

## On re-runs: suppression and regressions

The `Fixed` record stays in `findings.json` so the next audit knows about it.

- **Same fingerprint, fix still in place.** The audit re-checks it (the audit skills re-verify carried-forward
  records). If the claim still closes as `rejected` against the fix, the record stays `Fixed` and isn't re-raised.
- **Same fingerprint, the bug is back.** That's a regression. Reopen the record: clear `disposition`, remove
  `fixed_in` and `fix_verified_on`, and set `ext.regressed_after` to the old `fixed_in` value. Add the new evidence,
  then triage it again from Step 2. Severity starts where it was; re-calibrate only with new evidence. Then find out
  why the regression test didn't catch it.
- **Different fingerprint, same pattern.** It's a variant, not a regression. It's a new candidate.

## Sources

Paraphrased, not copied:

- Trail of Bits skills (CC BY-SA 4.0): [post-patch-validation](https://github.com/trailofbits/skills/tree/main/plugins/post-patch-validation),
  [regression-hunt](https://github.com/trailofbits/skills/tree/main/plugins/regression-hunt) and
  [patching-bugs](https://github.com/trailofbits/skills/tree/main/plugins/patching-bugs) (re-run the reproduction
  against the patch, hunt for variants and regressions, prove the patch holds)
- Strix (Apache-2.0): [analysis/fix_verification.md](https://github.com/usestrix/strix/blob/main/strix/skills/analysis/fix_verification.md)
  (a fix is checked against the original exploit and the surrounding paths before it's closed)
