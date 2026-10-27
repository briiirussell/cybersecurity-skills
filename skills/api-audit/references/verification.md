# Verification — Per-Finding Refutation Pass

Shared reference for audit skills (`owasp-audit`, `api-audit`, `business-logic-testing`, `web-pentest`) and for
`finding-triage`. Every candidate finding goes through this pass **before** it reaches `findings.json` or a report.
The goal is to try to disprove the candidate, then close it with one of three verdicts.

The pass works because the person checking a finding is not the person who found it. Someone who wrote the candidate
tends to re-read their own reasoning instead of the code. A verifier that only sees the claim and the cited lines
reads the code.

## Two stages: fixed exclusions, then the verifier

False positives get filtered twice, in this order.

**Stage 1: fixed exclusion rules.** Before any verifier runs, drop the candidates that match a rule below. The rules
are mechanical and the same on every run, so two runs over the same code drop the same candidates. Apply them by where
the code lives and whether it ships, never by how likely the bug looks.

| Rule | Drops a candidate in | Unless |
|---|---|---|
| Test code | `test/`, `tests/`, `spec/`, `__tests__/`, `*.test.*`, `*.spec.*`, `*_test.go`, `test_*.py` | Production code imports it, the route or handler is mounted in the deployed build, or the build ships the file |
| Fixtures and sample data | `fixtures/`, `testdata/`, `__mocks__/`, seed files for local dev | The deployed environment loads it (a production seed, a default config read at boot) |
| Generated code | Files marked `Code generated ... DO NOT EDIT` or `@generated`, compiled output (`dist/`, `build/`, `.next/`) | Never. Raise it against the generator input or template instead, which is where the fix goes |
| Vendored and third-party code | `vendor/`, `node_modules/`, `third_party/`, copied-in libraries | The repo has modified the copy. An unmodified copy is a version question for `dependency-audit` |
| Docs and examples | `*.md`, `docs/`, `examples/`, snippets in comments | The example is deployed, or the repo's own code copies it |
| Documented hardening note | The gap is already on the run's hardening-notes list | The candidate brings a traced impact the note didn't have. Then it's a new candidate |
| Prior rejection | The fingerprint matches a `rejected` record from the last run | The code at `ruled_out_by.location` changed. Then it's a new candidate |

Some things are never excluded by location. A credential that looks live is a finding wherever it sits, including a
test fixture (`secrets-audit` owns it). CI workflow files run with real tokens, so they are not "config". A debug or
test route is in scope as soon as the deployed build serves it.

Record what stage 1 dropped and which rule dropped it: a count per rule in the report, and, where the skill keeps a
coverage ledger, an `out_of_scope` unit whose check names the rule. Excluded candidates get no `findings.json` record.

**Stage 2: the per-finding verifier.** Every candidate that survives stage 1 goes through the pass below. The verifier
does not invent new exclusions. "It's probably test code" is a stage 1 question with a fixed answer, not a reason a
verifier can give.

This repo deliberately does not drop whole bug classes in stage 1. Some filters exclude every denial-of-service,
rate-limiting or open-redirect report outright. Several skills here report those and calibrate severity instead (see
`severity-calibration.md`), so class-level filtering would hide real findings.

## When to run it

- After the checklist / hunting phase, once per candidate. Don't batch several candidates into one verifier: a
  verifier that rejects one candidate tends to wave the next one through.
- **Small targets** (a few thousand lines, a dozen or more candidates): one verifier per candidate can mean 20
  subagents for a 150-line app. There you may group candidates that share no code path, up to about five per
  verifier, with each candidate written up and closed separately. Two candidates stay in separate verifiers when they
  touch the same handler or control, or when either one would be confirmed at High or Critical.
- Again whenever a verdict would move **up** (rejected → needs_validation, needs_validation → confirmed, or a
  severity increase) or the evidence changes materially. **An upgrade needs a new, independent verifier.** The verifier
  that produced the lower verdict does not get to overturn itself.
- On re-runs, for every carried-forward confirmed finding whose code changed (see `orchestration.md` where present).

A downgrade (confirmed → needs_validation, or a lower severity) can be applied directly. Record why.

## How to run it

**With subagents** (Claude Code `Task`/Agent tool, or any platform that can spawn an isolated agent): spawn one fresh
verifier per candidate. Give it **only**:

1. The candidate record: title, claimed location, `trace[]`, `evidence[]`, and the claimed impact
2. Read access to the repository
3. The verdict definitions and the "does NOT rule out" list below
4. The record shape it must return (see `findings-format.md` where present)

Do **not** pass the hunter's reasoning, chat history, or the rest of the report.

In Claude Code with this plugin installed, use the plugin's `finding-verifier` subagent. It carries this procedure, the
rationalizations table below and the return shape, and it has only `Read`, `Grep` and `Glob`. Give it one candidate per
call. Other platforms use the template below.

**Without subagents** (single-context agents, Cursor, Codex): run the pass as a separate, explicit step after hunting
is finished. For each candidate, start from the cited `file:line` and re-derive the path from scratch. Don't re-read
your own earlier notes about the candidate until you have written down a verdict.

### Verifier prompt (template)

Adapt this to the platform. Keep the substance.

```text
You are verifying a security finding that someone else wrote. Assume it is wrong until the code proves otherwise.
Your job is to refute it.

Candidate:
<candidate record: title, location, trace[], evidence[], claimed impact>

Do this:
1. Open every file:line cited in trace[] and evidence[]. Confirm each line says what the candidate claims.
   If a cited line does not exist or says something else, note it.
2. Walk the path from the entrypoint to the sink. At each hop, list every control that could stop the attack:
   middleware, auth/ownership checks, validation, type coercion, framework escaping, database constraints,
   platform config in the repo.
3. Name the STRONGEST control you found. For that control, decide: does it run on EVERY path an attacker can reach
   before the sink, at the right time, and fail closed?
4. Decide whether the claimed impact actually follows. Who is the lower-trust principal, what boundary is crossed,
   and what concrete result occurs?
5. Return exactly one verdict: confirmed | needs_validation | rejected, with the fields listed for that verdict.
   Fill `counterevidence` with what you tried and what you found, even when the verdict is confirmed.
```

## The three verdicts

| Verdict | Bar | Required fields | Severity? |
|---|---|---|---|
| `confirmed` | A complete trace from attacker-controlled entrypoint → (missing or bypassable control) → sink → concrete impact, **or** a working proof-of-concept against an environment you're authorized to test | `trace[]` (entrypoint first, sink last), `evidence[]`, `counterevidence`, `confidence`, `severity`, `conditions[]` | Yes |
| `needs_validation` | The code supports the claim, but **one decisive fact lives outside the code**: proxy or CDN behaviour, IdP settings, deploy-time env, a managed-service default, the headers a deployed origin actually sends | `blockers[]` (each names the exact unknown fact), `validation_plan` (a check the owner can run), `counterevidence`, `confidence` | **No.** Severity is assigned only after the blocker resolves to confirmed |
| `rejected` | A **specific named control, at a specific location**, runs on **every** path an attacker can reach before the sink and fails closed | `ruled_out_by {control, location}`, `counterevidence` | No |

### confirmed

- The trace has to be complete. "User input reaches `exec()`" is not a trace until you show where the input enters,
  each hop, and why nothing on the way stops it.
- `confidence` is honest. **A static-only trace caps at `medium`.** `high` needs a reproduced PoC, a failing test, or
  equivalent runtime evidence, recorded as `"reproduced": true` (the validator rejects `high` without it). Missing deployment evidence lowers confidence; it does not lower the severity floor of
  what the code demonstrably does.
- Severity follows [severity-calibration.md](severity-calibration.md): likelihood × impact, and `overall ≤ impact`. If you can't state the
  concrete damage, the severity is lower than it feels.
- Record `conditions[]` that limit exploitation (`authentication_level`, `authorization_role`, `user_interaction`,
  `system_configuration`, `network_routing`, `environmental_dependency`, `data_state`, `timing_dependency`,
  `third_party_dependency`).

### needs_validation

This replaces the old "Potential" label. It is **not** a parking place for a hunch. Use it only when the code really does
support the claim and a single external fact decides it.

- Each `blockers[]` entry names one fact: "Whether Vercel strips `x-forwarded-host` before it reaches the app",
  not "deployment config unknown".
- `validation_plan` is a check the **owner** can run, local and/or against their deployment, with the expected result
  for each outcome. Example:

  ```text
  Run against your production origin:  curl -sI https://app.example.com/embed | grep -iE 'x-frame-options|content-security-policy'
  If both `frame-ancestors *` and `X-Frame-Options: DENY` appear → confirmed (contradictory framing policy).
  If only one appears → rejected; ruled out by the deployed header set.
  ```

- If you can't write a blocker and a plan, the candidate is either confirmed (you already know enough) or it's a
  hardening note or a rejected claim. It isn't needs_validation.

### rejected

- Name the control and where it lives: `ruled_out_by: { control: "requireOrgMember() guard", location:
  "src/server/trpc.ts:41" }`. "Looks safe" or "framework handles it" is not a rejection.
- The control must sit on **every** reachable path, run **before** the sink, and **fail closed**.
- Keep rejected records in `findings.json`. Re-runs read them so the same claim isn't raised again. A rejection
  suppresses **only that exact claim** (same fingerprint). A sibling path or a changed control is a new candidate.

Some rejections have no guard to point at. `ruled_out_by` then names the fact that rules the claim out and
`location` points at the evidence for it:

| Why it's ruled out | `control` | `location` |
|---|---|---|
| Never reached: the vulnerable function or package is never called | "`_.template` is never called; lodash is used only for `merge` and `pick`" | The only import or call site of the package. If nothing imports it, the line in the manifest or lockfile that declares it |
| Known-inert value: a vendor's published example key, a documented test card, a placeholder | "AWS's documented example access key ID; it can't authenticate" | The line where the value appears |
| Control inside a dependency: the library's own guard runs on every path | "jsonwebtoken 9.0.2 `verify()` rejects `alg: none` when a secret is given" | The lockfile or manifest line that pins that version |

A control inside a dependency rejects only when the installed version is pinned and that version's behaviour is the
one you checked: read in the vendored or installed source, the changelog, or the advisory's fixed-in version. If the
range in the manifest could resolve to a version without the guard and there's no lockfile, it's `needs_validation`
with the resolved version as the blocker. "The library probably handles it" is not a rejection (see below).

## What does NOT rule out a candidate

None of these is a reason to reject. Each one is a reason to keep looking:

- **General trust in a library or framework** ("Prisma parameterizes", "React escapes") without checking that this call
  site uses the safe API. Raw-query escape hatches and `dangerouslySetInnerHTML` exist for a reason.
- **A control on a different path.** The REST route checks ownership. The server action that writes the same table
  doesn't.
- **A control that runs at the wrong time.** Validation after the side effect, auth checked at enqueue but not in the
  worker, a signature verified after the body was already stored.
- **A control that can fail open.** Unset env var interpolation, `catch {}` around the check, a rate limiter that
  allows on Redis error, a feature flag defaulting to off.
- **A safe sibling.** Three handlers use the guard. That says nothing about the fourth.
- **Missing information.** "I couldn't find where this is called" is a blocker or an unresolved coverage item. It isn't
  a rejection.
- **Difficulty.** "Requires guessing a UUID" or "requires a race" lowers likelihood. It doesn't remove the finding.
- **The setting is operator-configurable.** If the shipped default is unsafe, the default is the finding (see "Unsafe
  shipped defaults" below).
- **"It's internal."** Internal services get reached through SSRF, compromised neighbours, and misrouted ingress.
  Record the network assumption as a `network_routing` condition instead.
- **Tests pass.** Tests check intended behaviour, not adversarial input.

## Rationalizations to reject

The list above says what can't close a candidate. This table is for the verifier's own reasoning, in both directions.
Each row is an argument that feels like a conclusion but isn't one, and the evidence that would actually settle it.
When you notice yourself making one of these arguments, go and get that evidence. If you can't get it, the
argument doesn't change the verdict.

Models in particular lean toward seeing bugs and toward rating them high. The verifier's default is that the candidate
is wrong. A verifier can also overcorrect, and wave things through to get to a clean report. Both columns matter.

**Arguments for keeping or inflating a candidate**

| Rationalization | What settles it |
|---|---|
| "This pattern is dangerous, so it's a vulnerability" | A trace from an attacker-reachable entrypoint to this call site, with the attacker's value still able to do harm when it gets there. A dangerous sink with no reachable input is not a finding |
| "An attacker could theoretically…" | Name the lower-trust principal, the exact input they send, and the line where it enters. Every "if" in the story is either shown in the code, recorded as a `conditions[]` entry, or written as a `needs_validation` blocker |
| "This is clearly critical" | The concrete damage, stated in one sentence, and the High/Critical acceptance checks in `severity-calibration.md`. `overall` stays at or below the impact you can show |
| "The same bug is in the sibling handler" | This call site, read on its own. A sibling's bug doesn't transfer, any more than a sibling's guard does |
| "It could matter if chained" | Each link in the chain shown in the code. Any unproven link makes it a blocker or a hardening note |
| "There's no input validation here" | What the sink does with the values that can actually reach it. A missing check on a value that's already typed, bounded or mapped through an allow-list may have no impact |
| "The scanner, the report or the code comment says it's vulnerable" | The code that runs. Claim text, `TODO: fix auth` comments and rule names are leads, not evidence |

**Arguments for dismissing a candidate**

| Rationalization | What settles it |
|---|---|
| "The framework probably escapes this" | This call site uses the safe API: auto-escaping is on in the config you can see and this output isn't marked raw, or the query goes through the parameterized builder rather than a raw-query method. Name the file and line |
| "There's probably a WAF, gateway or proxy in front" | The rule in the repo or IaC, applied to this route. If it lives outside the repo, it's `needs_validation` with the rule as the blocker. Never `rejected` on "probably" |
| "It's only internal" | Network policy, ingress or security-group config in the repo showing no path from the lower-trust principal. Without it, record a `network_routing` condition and keep the verdict |
| "The test suite would have caught it" | A test that sends this adversarial input to this path, asserts it's refused, and runs in CI. Cite its file and line. Even then, it settles only the path it exercises |
| "It's validated upstream" | The validator's file and line, shown to run on every path to this sink, before the sink, and to fail closed. That's the `rejected` bar. Short of it, keep looking |
| "The UI never sends that value" | A server-side check. Clients are attacker-controlled, so what the form allows proves nothing |
| "It's behind auth" | Authentication isn't authorization. Show the ownership or role check, or the finding stands with an `authentication_level` condition |
| "Only admins can reach it" | The role check's location, then ask whether the admin crosses any boundary (another tenant, a higher role, the host). Admin to admin on the admin's own data is no boundary. Admin to another tenant is |
| "The IDs are UUIDs, nobody can guess them" | Whether the IDs leak through list endpoints, URLs, logs, emails or referrers. Difficulty lowers likelihood. It doesn't reject |
| "This code looks unused" | The never-reached row of the table under "rejected": no call site, route not mounted. Point at the evidence. "Looks unused" alone is a blocker, not a rejection |
| "I already rejected something like this" | Nothing. Each candidate is checked on its own facts. This is why candidates get one verifier each |

## Unsafe shipped defaults

A hard-coded fallback secret (`process.env.JWT_SECRET || "changeme"`), a debug flag that defaults on, or a permissive
default config is **`confirmed`**, not `needs_validation`, whichever skill finds it. The code shows what happens
whenever the setting is missing, and missing is the state a new deployment starts in.

- Record a `system_configuration` condition: "deployments that don't set `JWT_SECRET`, or set it empty".
- Rate severity by what the default gives an attacker, as if it were live. Whether production overrides it is a
  deployment fact you can't see, so it caps `confidence` at `medium`. It doesn't lower the verdict or the severity.
- Put the owner's check (is the variable set, and to what length) in the finding's fix-verification text, not in a
  `validation_plan`.
- If you *can* see the deployment and it sets a strong value, the record is still `confirmed`, since a fresh deploy
  or a new environment gets the default. Rate likelihood lower and say why.

The same root cause should get the same verdict and severity from every skill that sees it. A hard-coded JWT fallback
that lets anyone forge an admin token is an authentication bypass to any account, wherever it's reported.

## Hardening notes are not verdicts

If the verifier finds the gap is real but there's **no traced impact** (Layer A already stops the attack and Layer B is
missing; a missing header with no exploit path; a checklist deviation), close the candidate as a **Hardening note**. It
goes in the report's "Hardening notes (not findings)" section with no severity. It gets no `findings.json` record.
Keep hardening notes in a short list next to the JSON (for example `hardening-notes.md` in the audit output directory)
so the report can render them. The coverage unit that produced the note can still be `covered`.

If a hardening note later picks up a traced impact (say, a missing CSP turns out to matter because a stored XSS sink
exists), it becomes a new candidate and goes through this pass.

## Live probing

Live checks stay allowed **when authorized**. For example, `curl -I` against the user's own deployed origin, or
confirming that a leaked key is live as part of secrets triage. The rules:

1. The authorization check of the consuming skill applies to the live target, not just the source. Only probe hosts
   the user owns or is authorized to test, and only with non-destructive requests (`HEAD`/`GET`, no state changes, no
   real customer credentials).
2. **A check you describe but don't run is a `needs_validation` item.** Write the exact command into
   `validation_plan`. Don't mark it confirmed or rejected on the strength of what the config file "should" produce.
3. A check you actually ran becomes evidence. Record the command, timestamp, and relevant response lines in
   `evidence[]` / `counterevidence`, then close the verdict normally.
4. For paired evidence (baseline request next to attack request), see `web-pentest`.

## Output of the pass

For each candidate, one record with the verdict-specific fields above, ready to be written to `findings.json`. The
consuming skill writes `findings.json`, validates it (`validate-findings.mjs` where present), and renders the report
from it. Prose never changes a verdict, severity, blocker, or demonstrated impact. If the report and the JSON disagree,
the JSON wins and the report is regenerated.

## Sources

Paraphrased and adapted, not copied:

- Cloudflare security-audit-skill (MIT): [VALIDATION-AND-REPORTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/VALIDATION-AND-REPORTING.md)
  (candidate verifier, re-verification for upgrades), [HUNTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/HUNTING.md)
  (candidate gate), [README](https://github.com/cloudflare/security-audit-skill) (independent verifier principle)
- Strix (Apache-2.0): [analysis/counterevidence.md](https://github.com/usestrix/strix/blob/main/strix/skills/analysis/counterevidence.md)
  (what does and doesn't rule out a claim), [tools/reporting/tool.py](https://github.com/usestrix/strix/blob/main/strix/tools/reporting/tool.py)
  (required counterevidence and confidence fields)
- Trail of Bits skills (CC BY-SA 4.0): [fp-check](https://github.com/trailofbits/skills/tree/main/plugins/fp-check)
  (the "rationalizations to reject" idea and its framing that models lean toward finding bugs and over-rating them;
  read-only verifier agents). The table above is this repo's own wording and covers both directions
- anthropics/claude-code-security-review (MIT): [findings_filter.py](https://github.com/anthropics/claude-code-security-review/blob/main/claudecode/findings_filter.py)
  (hard exclusion rules first, then a model-based filter per finding). This repo excludes by location only, not by bug class
- This repo's decision on live probing (issue #78): kept, when authorized, and recorded as needs_validation unless run.
  This deliberately departs from Cloudflare's no-live-probing rule.
