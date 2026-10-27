# Examples

Each folder here is one real run of a skill against the same small app, so you can see what you get before you install anything.

The target is [`target/`](target/): notes-api, a ~150-line Express API I wrote with planted bugs and dependencies pinned to versions with known advisories. It's deliberately vulnerable. Don't deploy it. Its README doesn't list the bugs, so the runs couldn't read the answers.

| Skill | Run | Result | Files |
|---|---|---|---|
| [owasp-audit](../skills/owasp-audit/) | full audit, standard profile | 8 confirmed (4 high, 2 medium, 2 low), 3 needs validation, 7 rejected, 12 hardening notes | [report](owasp-audit/report.md) · [findings.json](owasp-audit/findings.json) · [findings.sarif](owasp-audit/findings.sarif) · [coverage.json](owasp-audit/coverage.json) · [architecture](owasp-audit/architecture.md) · [hardening notes](owasp-audit/hardening-notes.md) |
| [api-audit](../skills/api-audit/) | full REST audit | 7 confirmed (1 critical, 3 high, 1 medium, 2 low), 1 needs validation, 4 rejected | [report](api-audit/report.md) · [findings.json](api-audit/findings.json) · [findings.sarif](api-audit/findings.sarif) · [coverage.json](api-audit/coverage.json) |
| [dependency-audit](../skills/dependency-audit/) | `npm audit` + reachability | 49 advisories in 10 packages: 2 reachable (high), 7 need a production fact, 40 never called. Plus 1 app bug (high) | [report](dependency-audit/report.md) · [findings.json](dependency-audit/findings.json) · [findings.sarif](dependency-audit/findings.sarif) · [npm-audit.json](dependency-audit/npm-audit.json) |
| [secrets-audit](../skills/secrets-audit/) | source + posture (no git history) | 0 confirmed, 1 needs validation, 4 rejected | [report](secrets-audit/report.md) · [findings.json](secrets-audit/findings.json) · [findings.sarif](secrets-audit/findings.sarif) |
| [finding-triage](../skills/finding-triage/) | two scanner alerts, one at a time ([input](finding-triage/input.md)) | semgrep SQLi alert: false positive. ZAP error-disclosure alert: confirmed, Medium → Low | [report](finding-triage/report.md) · [findings.json](finding-triage/findings.json) · [findings.sarif](finding-triage/findings.sarif) |

## How they were made

- **The runs:** on 2026-10-26, Claude Code (Opus) ran each skill as a separate agent, following that skill's `SKILL.md` and references.
  - **Reviews:** static and read-only. Nothing was deployed or exploited, so no finding is `reproduced` and confirmed confidence tops out at medium.
  - **Scanner output:** the dependency run used real `npm audit` output, saved next to the report. The finding-triage alerts were written for the example in each tool's format. They weren't captured from a real scan, and the report says so.
- **Independence:** each run saw only the target, never the other examples.
- **Editing:** I didn't edit findings. The agents wrote `findings.json` and `coverage.json`. Where the harness wouldn't let an agent write a markdown file, I saved its report text as given.
- **SARIF:** generated with `node shared/to-sarif.mjs findings.json --include-needs-validation`.

`scripts/test/examples.test.mjs` runs on every PR and checks that:

- every `findings.json` and `coverage.json` validates;
- every file and line a record points at exists in `target/`;
- every `findings.sarif` matches what `to-sarif.mjs` produces today.

So these double as regression fixtures for the shared formats.

## Worth noticing

**The same bug, three verdicts.** The JWT secret falls back to a hard-coded default (`src/config.js:5`), and each run handled it differently:

| Run | Verdict | Severity |
|---|---|---|
| api-audit | confirmed | critical |
| owasp-audit | confirmed | high |
| secrets-audit | needs validation | none |

secrets-audit asks "is it set in production?" first. The other two treat a default that ships unsafe as a finding whatever production does. That's a real difference in how the skills apply the rules, not a typo, and it's the kind of thing these examples exist to surface.

**What every run agreed on:**

- the SQL injection in `/search`
- the `ORDER BY` allow-list being safe
- the `_.merge` mass assignment in `PATCH /notes/:id`
- lodash 4.17.15's `merge` not being a prototype-pollution path

**Rejections carry weight.** dependency-audit closed 40 of 49 advisories as unreachable, naming the call site or control each time. That's most of the value of the run.

**Where the skills were awkward to follow.** Each run reported where the skill's instructions were unclear. That feedback is collected in [#159](https://github.com/briiirussell/cybersecurity-skills/issues/159), for example the coverage-ledger id example that the validator rejects.

## Re-running

Point a skill at `examples/target/` and compare. The runs aren't deterministic: wording, grouping and the odd severity will differ. Missing one of the confirmed findings above, though, is worth a [field report](https://github.com/briiirussell/cybersecurity-skills/issues/new?template=field-report.yml).
