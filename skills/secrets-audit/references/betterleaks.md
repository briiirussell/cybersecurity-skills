# Betterleaks

Companion to `secrets-audit` "Tooling" and "Triaging a found secret". [Betterleaks](https://github.com/betterleaks/betterleaks)
is an MIT-licensed secrets scanner from gitleaks' original author and maintainers. Three things make it the default
here:

- **Fewer false positives on generic secrets.** It scores how unlike ordinary text a string is ("rare, not random"),
  so `password = "…"` and `API_KEY=…` lines are less noisy than with entropy-only tools.
- **Built-in liveness and blast radius.** `validate` makes the provider's read-only identity call. `analyze` resolves
  the identity, account and permissions behind a live key. Those are triage steps 2 and 4.
- **Value fingerprints.** Each finding carries a SHA-256 of the exact value, so the same key found in five places, or
  by gitleaks and trufflehog too, dedupes to one.

Checked on 2026-10-30 against the README, the v2 migration guide and `docs/scanning.md`.

## Which version

The latest stable release is **v1.9.0**. v2 is at release candidate (`v2.0.0-rc.6`, 2026-10-30), and the README warns
that package managers and the Docker `latest` tag may still install v1. Run `betterleaks version` first. The commands
below are v2; use the v1 column when it reports 1.x, and run `betterleaks <command> --help` once rather than guessing.

| Purpose | v1.9.0 | v2 |
|---|---|---|
| Filesystem scan | `betterleaks dir <path>` | `betterleaks fs <path>` (or `filesystem`) |
| Validate during a scan | `--validation` | `-v` / `--validate` |
| Identity and permissions | — | `-a` / `--analyze` (implies `-v`) |
| JSON report | `--report-format=json --report-path f` | `-o report.json` (`.jsonl` for JSON Lines) |
| Validate one known rule | `validate --rule-id ID` | `validate --rule ID` |
| List rules that can validate | `validate --list` | `config show ids --validation` (also `--analysis`) |
| Config file | `.betterleaks.toml` read automatically | **Not** read automatically: pass `--config` |
| SARIF, CSV, JUnit reports | Yes | **Removed** (use `to-sarif.mjs` on `findings.json`) |
| Container images | — | `betterleaks container <image>` |

`-v` meant `--verbose` in v1 and means `--validate` in v2. On a v1 install, don't pass `-v` from a v2 example.

## Safety rules

These follow from the skill's Authorization section.

1. **Detection only, stated on the command line.** Validation is off by default, but `BETTERLEAKS_VALIDATE=true` or
   `BETTERLEAKS_ANALYZE=true` in a dotfile or CI environment turns it on silently. Every scan passes
   `--validate=false --analyze=false` (v2), so a stray variable can't make the agent use a found key.
2. **`-v`, `-a`, `validate` and `analyze` only after asking.** They send the found key to its provider, which counts as
   using it. None is pre-approved, and the lint fails a grant that would allow one.
3. **Always `--redact`, and write the report to a file with `-o`.** Never `-o -` or terminal output inside an agent
   session: whatever prints lands in the session transcript, one of the places this skill tells people to scrub.
   Summarize the report by rule id and file. Don't print matching lines.
4. **Remote sources still use the network** in detection-only mode (cloning, the GitHub API, image pulls). When the user
   wants no outbound traffic, scan only with `fs`, a local `git` repo, or `stdin`.
5. **Never `revoke`.** Rules can carry revocation calls. Revoking before the replacement is deployed breaks
   production (triage step 5), and revocation is the owner's call. Scans never run revocation on their own.
6. **Keep the value out of the command line.** To check one key, re-scan the file it's in with `-v` rather than
   piping the value into `validate`. A value typed into a command lands in the transcript and in shell history.

## Commands

```bash
mkdir -p .security/out
# Default scan: full git history, detection only, redacted, report to a file
betterleaks git . --validate=false --analyze=false --redact -o .security/out/betterleaks.json
# Working tree only (untracked files, build output)
betterleaks fs . --validate=false --analyze=false --redact -o .security/out/betterleaks-fs.json
# Which rules can check liveness / resolve identity
betterleaks config show ids --validation
betterleaks config show ids --analysis
# After the user says yes: check liveness for the keys in one file (step 2), or identity and permissions (step 4)
betterleaks fs config/payments.ts -v --redact -o .security/out/validate.json
betterleaks fs config/payments.ts -a --redact -o .security/out/analyze.json
```

`betterleaks validate --rule <id> --simple` and `betterleaks analyze --rule <id>` read a single value from stdin. Use
them only when the value comes from a pipe out of the file that holds it, never typed or echoed.

If the repo already has a `.gitleaks.toml` or a gitleaks pre-commit hook, keep gitleaks as well. Betterleaks still
honours `gitleaks:allow` comments.

## Reading the report

A v2 JSON report is one object: `schema_version`, `findings`, and `scan` (run metadata). A `.jsonl` report has one
`{"finding": …}` line per finding and a final `{"scan": …}` line, so skip that last line when you read it.

| Field | Meaning |
|---|---|
| `rule_id` | Detector, for example `github-pat` |
| `location.path`, `location.start_line` | Where it was found |
| `attributes["git.sha"]`, `attributes["git.author_name"]` | Commit and author for history findings |
| `match.fingerprint` | SHA-256 of the exact value (64 hex characters), or `hmac-sha256:<hex>` with `--hmac-key` |
| `rule_hash` | Which version of the rule matched |
| validation / `analysis.status` | `valid`, `invalid` or `unknown` when `-v` / `-a` ran |

**Use HMAC fingerprints for anything that leaves the machine** (CI artifacts, issues, PR comments). A plain SHA-256 of
a short or low-entropy token can be brute-forced from the published hash. Pass `--hmac-key`, or set
`BETTERLEAKS_FINGERPRINT_HMAC_KEY` from a secret store.

## Verdicts and `ext` keys

| Result | Verdict |
|---|---|
| `valid`, and the identity or permissions reach production data or money | `confirmed`, `reproduced: true`. Severity follows the key type and blast radius |
| `invalid` | `rejected`: revoked or sandbox-only. `ruled_out_by` names the validation result and the date |
| `unknown`, or validation not run | `needs_validation`. `unknown` is not `invalid` |

The `findings.json` fingerprint stays `secrets-audit/<provider>-<key type>/<file>/<variable>`. Betterleaks data goes in
`ext`:

| Key | Example |
|---|---|
| `detector` | `"github-pat"` |
| `validation` | `"valid"`, `"invalid"`, `"unknown"`, `"not checked"` |
| `identity` | `"octocat (user)"`, redacted where it names a person outside the team |
| `capabilities` | `["repo", "workflow"]` |
| `value_fingerprint` | `"hmac-sha256:3f9e…"` (prefer the HMAC form) |
| `scanner` | `"betterleaks@2.0.0-rc.6"` |

## After rotation: confirm the old key is dead

Once the new key is deployed and the old one revoked (triage step 5), re-run the `-v` scan on the place the old value
was found. Expect `invalid`. A `valid` result means the revoke didn't take, or the value was rotated somewhere else.

## Sources

- [Betterleaks README](https://github.com/betterleaks/betterleaks), the
  [v2 migration guide](https://github.com/betterleaks/betterleaks/blob/main/docs/v2_migration.md) and
  [scanning guide](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md)
- The author's write-ups: [Regex is (almost) all you need](https://lookingatcomputer.substack.com/p/regex-is-almost-all-you-need),
  [Rare Not Random](https://lookingatcomputer.substack.com/p/rare-not-random)
- Proposed by @coreyhaines31 in issue #214
