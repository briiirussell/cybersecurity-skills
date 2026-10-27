# Independent verification during triage

How finding-triage uses the per-finding verifier from [verification.md](verification.md). The audit skills run it
before a finding reaches `findings.json`. Triage runs it again at the points below, because a triage decision is
often the first time anyone other than the finder has looked.

## When to run it

- **Before confirming at High or Critical.** The High/Critical acceptance checks ask whether counterevidence was
  searched for. A fresh verifier is how you search.
- **Before moving a verdict up.** `rejected` → `needs_validation`, `needs_validation` → `confirmed`, or a higher
  severity. The person or agent that wrote the lower verdict doesn't get to overturn it.
- **Before writing a scanner finding up as a false positive.** The verifier has to land on `rejected` with a named
  control, or the false-positive template has nothing to put in "Ruled out by".
- **When a `rejected` record's control moved.** Re-verify the claim from scratch rather than editing the old record.

A downgrade (lower severity, confirmed → needs_validation) doesn't need a verifier. Record why.

## Stage 1 first

Scanner output and bulk imports go through the fixed exclusion rules in [verification.md](verification.md) ("Two
stages") before anything else: test code, fixtures, generated and vendored code, docs and examples, known hardening
notes, prior rejections whose control hasn't changed. Note which rule dropped each one. Don't spend a verifier on a
finding in `dist/`. Raise it against the source that generates it.

## Turning a finding into a candidate

The verifier takes a candidate record, not a scanner blob. Restate the finding (Step 1) into these fields:

| Field | From a `findings.json` record | From a scanner, advisory or report |
|---|---|---|
| `fingerprint`, `skill` | As recorded | Build one: `finding-triage/<cwe-or-rule>/<file>/<function or resource>` |
| `title` | As recorded | Your Step 1 restatement in one line |
| `location` | As recorded | The flagged `file:line`, repo-relative |
| `trace[]` | As recorded | What the scanner's data-flow output gives you, or `[]` |
| `evidence[]` | As recorded | The flagged line and anything the report quotes |
| claimed impact | From the record's title and severity reasons | The scanner's or reporter's claim, unedited |

Pass the claim as it was made, including any severity it came with. The verifier's job is to test that claim, so
don't soften it first.

## Running it

**Claude Code with this plugin installed.** Hand the candidate to the `finding-verifier` subagent. It has `Read`,
`Grep` and `Glob` only, never runs code, and treats comments and the claim text as things to check. Send one finding
per call and nothing else: no triage notes, no chat history, no draft disposition.

**Cursor, Codex and other tools** (they don't get plugin subagents). Run the same pass inline as a separate step:

1. Finish and set aside your own notes on the finding.
2. Open [verification.md](verification.md) and follow "Verifier prompt (template)" from the cited `file:line`,
   re-deriving the path from scratch.
3. Before choosing a verdict, go through its "Rationalizations to reject" table, both halves.
4. Write the verdict down before re-reading your earlier notes.

## Using the result

- The verifier returns one record. Validate it before merging it into `findings.json`:
  `node references/validate-findings.mjs findings.json`.
- **It agrees with you.** Carry on to Step 3 or Step 4. Copy its `counterevidence` into the writeup's "Why this
  severity" or "Why it's not real".
- **It disagrees.** The JSON record wins over your draft. If you think it's wrong, the fix is new evidence and a
  second fresh verifier, not an edit to its record.
- **It returns `needs_validation`.** Triage can't rate it yet. Put the blocker and plan in the "Needs validation"
  table and hand the plan to the owner.
- **It says hardening note.** No record. It goes in the "Hardening notes" list.

A verifier that only reads code caps `confirmed` at `medium` confidence. If triage then reproduces the bug (with
authorization, per the skill's Authorization section), record the reproduction in `evidence[]`, set
`"reproduced": true`, and raise confidence.
