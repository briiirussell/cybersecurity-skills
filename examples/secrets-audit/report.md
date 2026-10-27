# Secrets Audit Report
## Scope: notes-api (`examples/target`): all 12 files, including `.env.example` and `package-lock.json`. Static review only; no credential was tested against a provider.
## Date: 2026-10-26

Rendered from [`findings.json`](findings.json): 5 records (0 confirmed, 1 needs validation, 4 rejected). It passes `node shared/validate-findings.mjs`.

**Not covered in this run:**

- **Git history.** The target has no repository of its own (it sits inside this repo and was just written), so the history part of the skill didn't apply. On a real checkout it would be `trufflehog git file://. --since-commit=<first-commit>` plus `git log -p -S "AKIA" --all` and the same for each prefix. The parent repo's history wasn't scanned.
- **Things that aren't in the repo:** Docker images, CI logs, frontend bundles, crash reporters, backups, agent configs. The target has none of them, and there are no user-level agent files in scope, so there's no `findings.user.json`.

### Live leaked secrets found

None. The only provider-format keys in the tree are AWS's published example pair (see Rejected).

| Provider | Key type (publishable / restricted / secret) | Redacted value | Location | First seen (commit / date) | Verified live? | Rotation status |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

### Needs validation

| Provider | Location | Blocker | Check for the owner to run |
|---|---|---|---|
| App JWT (HS256 signing secret) | `src/config.js:5` (`jwtSecret`) | Is `JWT_SECRET` set to a non-empty, high-entropy value in every deployed environment, and has it ever run on the default? | In each deployment run `node -e 'console.log((process.env.JWT_SECRET\|\|"").length)'`. Expect 32+; 0 means the default is in effect. Confirm in the secret store that the value isn't the default from `src/config.js:5`. On staging, sign an HS256 token for a test user you own with the default and call `GET /api/notes`; expect 401. |

`secrets-audit/jwt-hmac-default/src/config.js/jwtSecret`: `config.js:5` falls back to a hardcoded 8-character default when `JWT_SECRET` is unset. Because it uses `||`, an empty string also selects the default, and `.env.example:3` ships `JWT_SECRET=` empty. Nothing at startup rejects a missing or default secret.

If the default is live, any internet client can sign a token with any `sub` (`auth.js:27–28`). User ids are sequential (`db.js:8`), and `requireAdmin` looks up the role for that `sub` (`auth.js:36`), so the forged token would also reach `/api/admin/*`.

If the check fails, set a new secret (this logs everyone out), treat every token issued so far as forgeable, and review admin user-deletion activity. Confidence: medium. The code is unambiguous; what production sets is not in the repo.

### Rejected (do not re-raise)

| Fingerprint | Location | Ruled out by |
|---|---|---|
| `secrets-audit/aws-access-key-id/.env.example/AWS_ACCESS_KEY_ID` | `.env.example:6` (`AWS_ACCESS_KEY_ID`, `AKIA…MPLE`) | AWS's documented example key ID: it's the sample value in the AWS CLI user guide and the STS `get-access-key-info` reference, so it can't authenticate. Nothing in the repo reads it (no AWS SDK, no S3 code). |
| `secrets-audit/aws-secret-access-key/.env.example/AWS_SECRET_ACCESS_KEY` | `.env.example:7` (`AWS_SECRET_ACCESS_KEY`, `wJal…EKEY`) | AWS's documented example secret: the sample paired with the key ID above in the AWS CLI `aws configure` docs. |
| `secrets-audit/error-response-secret-leak/src/app.js/errorHandler` | `src/app.js:17` | The handler returns only `err.message` and `err.stack`. No error path carries `config.jwtSecret` or `process.env`: the secret is used only at `auth.js:18` and `auth.js:27`, and verify errors are caught at `auth.js:30`. There is no crash reporter. The stack-trace disclosure itself belongs to `owasp-audit`. |
| `secrets-audit/generic-high-entropy/package-lock.json/integrity` | `package-lock.json:21` (first of 105) | All 105 hits from the 40-character sweep are `sha512` integrity digests. Every `resolved` URL is `registry.npmjs.org` with no userinfo, and there's no `_authToken`. |

### Hardening notes (not findings)

- **No `.gitignore`.** A `.env` created from `.env.example`, or the SQLite file at the default `./notes.db` (password hashes), would be committed by `git add .`. Add `.env*` with `!.env.example`, and `*.db`. Effort: minutes.
- **`.env.example` uses realistic AWS key formats.** AWS's example pair is allowlisted by gitleaks but still trips naive scanners and teaches copy-paste of key-shaped values. Leave them empty, as `JWT_SECRET=` already is. Effort: minutes.
- **No startup check on required secrets.** Failing fast when `JWT_SECRET` is missing, short, or the default would close the needs-validation item whatever the deployment sets. Effort: small.

### Secrets-management posture

| Category | Status | Notes |
|---|---|---|
| Secrets hardcoded in source | ⚠️ | One hardcoded fallback (`jwtSecret`, `src/config.js:5`). No provider keys in source. |
| Storage tier | ⚠️ Environment variables only | `src/config.js` reads `process.env` only. There's no `dotenv` dependency and no secrets-manager client, so secrets come from whatever starts the process, which isn't in the repo. |
| `.env` committed / ignored | ⚠️ | No `.env` in the tree, but no `.gitignore` protects one either. |
| Agent configs | 🟢 N/A | No `.mcp.json`, `.cursor/`, `.vscode/mcp.json`, `.claude/` or `.gemini/` files. |
| Git history clean | Not assessed | No repository history for the target (see Scope). |
| Runtime fetch vs build-time embed | 🟢 | Nothing is embedded at build; there's no build step, Dockerfile or frontend bundle. |
| Long-lived cloud keys for workloads | ⚠️ Implied | `.env.example:5–7` says backups go to S3 using an IAM user access key pair. The backup code isn't in the repo (`backupBucket`, `src/config.js:7`, is never used), so its IAM scope can't be checked. Prefer an instance or task role, or workload identity (`iam-audit`). |
| Rotation cadence / automation | Not assessed | Nothing in the repo defines rotation. Rotating `JWT_SECRET` invalidates every session, since there's no key-ID or dual-key support. |
| Access logging, IAM scoping, cross-environment isolation, break-glass | Not assessed | These live in the deployment, not the repo. |
| Secrets in logs / error responses | 🟢 | Checked: the error path carries no secret (see Rejected). |

### Recommendations

| Priority | Item | Owner | Deadline |
|---|---|---|---|
| 1 | Run the `JWT_SECRET` check above in every environment. If any of them uses the default, set a new secret, then review admin user deletions. | Maintainer | Before next deploy |
| 2 | Remove the `\|\| <default>` fallback and fail at startup when `JWT_SECRET` is missing or shorter than 32 bytes. | Maintainer | Next release |
| 3 | Add a `.gitignore` covering `.env*` (keeping `!.env.example`) and `*.db`. | Maintainer | Next release |
| 4 | Blank the AWS values in `.env.example`, and move backups to role-based credentials when the backup job is added to the repo. | Maintainer | When backups land |
| 5 | Add gitleaks as a pre-commit hook and in CI, and run the history scan once the target has its own repository. | Maintainer | Next release |
