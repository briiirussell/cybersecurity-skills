# Orchestration — Modes, Run Profiles, Hunters, and Re-runs

Shared reference for `owasp-audit` and `api-audit`. Use it when an audit is too big for one pass, or when the user asks
for a full audit. It assumes the recon and ledger from [recon-and-coverage.md](recon-and-coverage.md), the verdicts from [verification.md](verification.md),
and the record format in [findings-format.md](findings-format.md).

A single audit pass finds a fraction of what repeated, independent passes find. Cloudflare reports that one run
surfaced roughly half of what several runs found together. Splitting the work and repeating it is how you close that
gap. The evidence bar stays the same.

## Operating modes

| Mode | When | Output |
|---|---|---|
| **Guidance** (default) | The user asks a question, wants a quick look at a file or feature, or wants to know how to secure something | Conversational answer. Findings still follow the verdict rules. No ledger required |
| **Full audit** | The user explicitly asks for an audit / security review of a codebase, a PR, or a release | Recon → ledger → hunting → verification → critic → `findings.json` → report |

If the request is ambiguous ("can you check this for security issues?" on a whole repo), ask one question first: *"Do
you want a quick guidance pass, or a full audit with a coverage ledger and a findings.json report?"* Then proceed.

## Run profiles

Ask which profile, or pick one and say so. The report header names the profile.

| Profile | Hunting | Critic | Verification | Typical use |
|---|---|---|---|---|
| `quick` | One wave over the highest-priority units | One critic wave; leftovers become `deferred` | One independent verifier per candidate | Pre-launch smoke check, small app, time-boxed |
| `standard` | Waves until every in-scope unit is `covered`, `candidate`, `not_applicable`, or justified `deferred` | Repeat until a wave adds nothing high-value | One verifier per candidate, and a new one for any upgrade | Default full audit |
| `deep` | As standard, plus a Wildcard and an Obvious-things hunter, plus a second independent hunter on high-value boundaries | Repeat until a critic wave returns **no** missing units | As standard; also re-verify every confirmed high/critical with a second verifier | Pre-raise diligence, regulated data, after an incident |

**Profiles change breadth and redundancy, never the evidence bar.** A `quick` run doesn't get to confirm anything on a
weaker trace. It just covers less and says so: a `quick` run with deferred units is reported as **partial**.

## Coordinator and hunters

With subagents (Claude Code's Agent/Task tool, or similar), split the work:

- **Coordinator** (the main agent): runs recon, owns `architecture.md`, `coverage.json`, and `findings.json`, assigns
  units, runs critics and verifiers, renders the report. **Only the coordinator writes shared state.** Hunters return
  results; the coordinator merges them.
- **Hunters**: isolated subagents, each assigned a batch of ledger units (group by surface × boundary so one hunter sees
  a whole boundary, for example "every surface that crosses tenant isolation").

**Assignment order:** unauthenticated surfaces first, then high-value boundaries (tenant isolation, admin, payments,
paid third-party work, file handling), then changed code (recent commits, the diff), then everything else.

### Hunter prompt (template)

Give every hunter the same structure. Paraphrase freely, but keep each part:

```text
Role: You are a security hunter reviewing assigned units of <project>. You find candidates. You do not close them.
      An independent verifier will try to refute everything you report.

Architecture (verbatim): <architecture.md>

Your units: <list of coverage unit ids with surface, boundary, category>

Attack classes for these units: <the relevant checklist blocks from the consuming skill, e.g. owasp-audit A01 + A06>

Exclusions (do not report): <out_of_scope units with reasons; prior rejected fingerprints with ruled_out_by>

Method: For each unit, read the entrypoint and follow data to every sink. Name the control at each hop with file:line.
        Check sibling paths that write the same data. Record what you checked even when nothing is wrong.

Candidate gate: Report a candidate only if you can name the lower-trust principal, the input they control, the control
                that should stop them, the boundary crossed, the affected resource, and a concrete result. Gaps with no
                traced impact go in hardening[]. Unknowns that need deployment facts go in candidates[] with blockers.

Output: one JSON object, nothing else (shape below).
```

### Hunter result

```json
{
  "units": [
    { "id": "...", "status": "covered|candidate|blocked|not_applicable",
      "reviewed_paths": ["..."], "checks": [{ "invariant": "...", "method": "...", "result": "..." }],
      "unresolved": [] }
  ],
  "candidates": [
    { "title": "...", "owasp_category": "A01", "cwe": "CWE-639", "location": { "file": "...", "line": 0 },
      "trace": [{ "kind": "entrypoint|propagation|sink", "file": "...", "line": 0, "description": "..." }],
      "evidence": [{ "file": "...", "line": 0, "description": "..." }],
      "claimed_impact": "...", "blockers": [] }
  ],
  "hardening": [ { "unit": "...", "note": "..." } ],
  "uncovered": [ { "surface": "...", "why": "found while hunting, not in my units" } ]
}
```

The coordinator merges `units` into `coverage.json`, sends each candidate to its own verifier ([verification.md](verification.md)), adds
`uncovered` items as new `planned` units, and appends `hardening` to `hardening-notes.md`.

### Special hunters (`deep`, optional in `standard`)

- **Wildcard.** Gets the architecture and the whole surface list but **no attack-class assignment**. Asked: "What would
  you attack first, and why?" Good at business-logic and cross-feature issues the checklist doesn't name. Pair with
  `business-logic-testing` when a running instance is available.
- **Obvious things.** Literal and thorough: hard-coded secrets, debug flags, `eval`, disabled TLS verification, wildcard
  CORS, default credentials, admin routes without auth. It still has to trace impact. "`VERIFY_NONE` exists" is a
  hardening note until it reaches something that matters.

## Sequential fallback (no subagents)

On platforms without subagents (Cursor, Codex, or a single long session), run the same phases in order and keep the
isolation as best you can:

1. Recon → write `architecture.md` and `coverage.json` (all `planned`).
2. Hunt unit-batch by unit-batch in the assignment order. After each batch, update the ledger **before** starting the
   next one, so the ledger, not your memory, holds what's done.
3. Finish **all** hunting before verifying. Then verify each candidate from its cited lines, without re-reading your
   hunting notes first (see [verification.md](verification.md)).
4. Run the critic as a separate step that reads only `architecture.md`, `coverage.json`, and the code.
5. Write and validate `findings.json`, then render the report.

If context runs low, stop at a unit boundary, mark the remaining units `deferred`, and report the run as partial. Don't
compress the evidence bar to finish.

## Re-runs and carry-forward

At the start of every full audit, look for a prior `security-audit/findings.json` and `coverage.json`.

| Prior record | Code at its trace/evidence locations | Action |
|---|---|---|
| `confirmed` | Unchanged | Carry forward by fingerprint. Re-verify (a quick verifier pass that the cited lines still say the same thing). Keep the disposition |
| `confirmed` | Changed | Revalidate with a fresh verifier. If the fix landed, close it as `Fixed` and keep the record. If the change moved code, update locations; the fingerprint stays the same |
| `needs_validation` | Any | Ask whether the owner ran the `validation_plan`. If yes, close on their result. If no, carry forward unchanged |
| `rejected` | Unchanged control | Suppress **that exact claim** (same fingerprint). Don't re-raise it |
| `rejected` | Control changed or removed | The rejection no longer holds. It's a new candidate |
| `covered` unit | Reviewed paths unchanged | Optionally skip in `quick`; re-review in `standard`/`deep` (different hunters find different things) |
| `covered` unit | Reviewed paths changed | Back to `planned` |

Find changes with `git diff --name-only <prior-audit-commit>..HEAD` (record the commit in `architecture.md` on every
run). Fingerprints identify the root cause, never line numbers, severity, or verdict, so they survive edits. A rejected
fingerprint suppresses only itself. A sibling with the same pattern on a different path is a different fingerprint.

## Cost and budget

Subagent fan-out multiplies token cost. Before a `standard` or `deep` run on a large repo, tell the user roughly how
many units and hunters you plan to use and confirm. If the budget runs out mid-run, the remaining units become
`deferred` and the report says partial.

## Sources

Paraphrased and adapted, not copied:

- Cloudflare security-audit-skill (MIT): [SKILL.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SKILL.md)
  (operating modes, run profiles, cost budget, coverage and prior runs), [HUNTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/HUNTING.md)
  (hunter prompt, structured hunter result), [ATTACK-CLASSES.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/ATTACK-CLASSES.md)
  (Wildcard and Obvious-things hunters), [README](https://github.com/cloudflare/security-audit-skill) (single run vs repeated runs)
