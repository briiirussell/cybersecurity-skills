# Cybersecurity Skills Versions

Current versions of all skills. Agents can compare against local versions to check for updates.

| Skill | Version | Last Updated |
|-------|---------|--------------|
| agent-supply-chain-audit | 1.12.0 | 2026-11-18 |
| ai-risk-management | 1.1.3 | 2026-10-30 |
| api-audit | 1.3.0 | 2026-11-18 |
| breach-patterns | 1.2.0 | 2026-11-18 |
| business-logic-testing | 1.1.0 | 2026-10-30 |
| cicd-security | 1.3.1 | 2026-11-18 |
| cloud-audit | 1.4.0 | 2026-11-18 |
| container-audit | 1.4.0 | 2026-11-18 |
| control-audit | 1.2.1 | 2026-10-30 |
| crypto-audit | 1.1.2 | 2026-10-27 |
| csf-mapping | 1.0.3 | 2026-10-27 |
| dependency-audit | 1.8.0 | 2026-11-18 |
| disk-forensics | 1.0.2 | 2026-10-27 |
| finding-triage | 1.4.0 | 2026-11-18 |
| fuzzing-harness | 1.0.1 | 2026-10-27 |
| hipaa-audit | 1.1.1 | 2026-10-27 |
| iam-audit | 1.2.0 | 2026-10-27 |
| incident-triage | 1.12.0 | 2026-11-18 |
| log-watch | 1.1.0 | 2026-11-18 |
| malware-triage | 1.0.0 | 2026-10-27 |
| mobile-audit | 1.1.1 | 2026-10-27 |
| native-code-review | 1.0.1 | 2026-10-27 |
| osint-recon | 1.0.2 | 2026-10-26 |
| owasp-audit | 1.9.0 | 2026-11-18 |
| patch-sweep | 1.9.0 | 2026-11-18 |
| pci-audit | 1.2.0 | 2026-11-18 |
| personal-opsec | 1.4.0 | 2026-11-18 |
| privacy-engineering | 1.1.0 | 2026-10-27 |
| prompt-injection | 1.2.1 | 2026-10-27 |
| recon | 1.0.1 | 2026-10-26 |
| red-team-engagement | 1.0.1 | 2026-10-26 |
| scanner-pipeline | 1.1.0 | 2026-10-30 |
| secrets-audit | 1.9.0 | 2026-11-18 |
| security-comms | 1.0.3 | 2026-10-26 |
| security-start | 1.0.0 | 2026-10-27 |
| siem-detection | 1.1.0 | 2026-11-18 |
| soc-operations | 1.0.4 | 2026-10-26 |
| threat-hunting | 1.4.0 | 2026-11-18 |
| threat-modeling | 1.0.4 | 2026-10-26 |
| variant-analysis | 1.0.0 | 2026-10-27 |
| vuln-research | 1.0.4 | 2026-10-27 |
| web-pentest | 1.4.0 | 2026-11-18 |

## Recent Changes

### 1.99.2 (2026-11-18)

README: mention HoneyWarden. Docs only.

**Added**
- A line under "Built by" pointing to [HoneyWarden](https://honeywarden.com), Bri's security startup for small SaaS teams, for readers who want these kinds of checks automated.

### 1.99.1 (2026-11-18)

evals/README: current trigger-eval results and misses. Docs only.

**Fixed**
- The results section quoted v1.69.0. It now gives v1.99.0's numbers (should-fire 276/288, 95.8%; top-3 99.3%; near-miss 224/225, 99.6%; most similar pair 0.34) and lists today's misses. New since v1.69.0: a pasted branch protection export going to cicd-security, "new admin user at 3am" going to log-watch, and the Better Auth reachability question going to vuln-research. Fixed since v1.69.0: the MOVEit/SolarWinds checklist prompt and the service-account-key near-miss.

### 1.99.0 (2026-11-18)

patch-sweep adds a web server / reverse-proxy track: host packages, container images and Kubernetes ingress controllers, with nginx2root (nginx 1.31.9 / 1.30.7) as the worked example. patch-sweep 1.9.0.

**Added**
- patch-sweep `references/web-servers.md`: where front proxies hide (distro packages, images by digest, ingress controllers that bundle nginx, managed platforms), the affected test (version in range plus the config precondition, read with `nginx -T`), the distro tracker rule from `linux-hosts.md` instead of `nginx -v`, stopgaps with verify / persist / removal date and the old-worker check, rebuild-and-redeploy with digests before and after, and a board that keeps `patched (rebuilt image digest X)` apart from `host patched, image not rebuilt`.
- Worked example: the five nginx2root CVEs (CVE-2026-123007, -123633, -121810, -123634, -113425) with nginx.org ranges, config preconditions and stopgaps, plus the five other CVEs fixed in the same release. NGINX Plus fixed builds from F5's NVD records, Ubuntu and Debian status, ingress-nginx (archived, `controller-v1.15.1` bundles 1.27.1, `use-http2: "false"` meanwhile), and the kernel SCTP half of the chain (`install sctp /bin/false`, no kernel CVE ID yet). Checked 2026-11-18 against nginx.org, NVD, the fix commit, the Ubuntu and Debian trackers, Wiz, Aikido and Xint. Where Aikido's first-affected versions differ from nginx.org, nginx.org's are used. KEV and EPSS are `not checked`; nothing is taken from public exploit repos.
- Description trigger phrase 'nginx CVE across all our servers and ingress' and one should-fire trigger prompt.

**Changed**
- patch-sweep Step 4 and Step 5: short pointers to the front-proxy track.

Proposed by @coreyhaines31 in #301.

### 1.98.0 (2026-11-18)

web-pentest and api-audit: keep test-account secrets out of the model prompt, and give the model structured identities instead. web-pentest 1.4.0, api-audit 1.3.0.

**Added**
- web-pentest and api-audit: "Supplying test credentials". Do not put a test-account password, session cookie, or API key in the model prompt, a chat message, or an instruction file the agent or skill reads. The model sees `identity-A` / `identity-B` with role, tenant, and markers; code or the operator's tooling logs in and attaches the credential. Do not stage secrets in a sandbox or workspace that runs target code. A credential that reaches the prompt is treated as exposed and rotated after the test.
- Credit to usestrix/strix at commit 1152d53 (Apache-2.0). Its instructions docs say instructions become part of the prompt and warn against secrets in a workspace file; checked 2026-11-18. Strix's credential examples are not copied. HoneyWarden #82 is the pattern to prefer, not a required runtime.
- Description trigger phrases: web-pentest 'test accounts without pasting passwords into the prompt', api-audit 'structured identities for a BOLA test'. One should-fire trigger prompt each; should-fire top-1 is 264/276.

**Changed**
- web-pentest prerequisites: credentials stay out of the model prompt. The #76 paired owner-vs-non-owner rule and the authorization gate are unchanged.

Proposed by @coreyhaines31 in #300.

### 1.97.0 (2026-11-18)

dependency-audit checks Python startup hooks and the shape of a release before a bump ships (Microsoft `agent-framework` PyPI compromise, 2026-11-17). dependency-audit 1.8.0.

**Added**
- dependency-audit `references/python-startup-hooks.md`, with a one-line pointer in Step 4. It finds `.pth` import lines, `sitecustomize.py` and `usercustomize.py` with `find`, not by starting the interpreter, since starting it runs the hooks. It lists the normal importers (editable installs, `distutils-precedence.pth`, coverage, a distro `sitecustomize.py`) and how to diff a bumped wheel's top-level entries. The grep matches what `site` actually executes: lines that start with `import` and a space or tab. Tested locally with python3 3.13 in a venv.
- Release-shape checks for a Python bump, marked needs_validation: wheel-only when earlier releases shipped an sdist too, no matching upstream tag or release, new top-level `.pth` or `.py` files, and a meta-package out of step with its `-core` sibling.
- Exposure window: floor-only ranges for packages that run code at install or start are noted, with hash-pinned lockfiles and a cooldown as the fix. A confirmed bad install means remove the hook and module, rebuild, pin, and rotate every credential that user, runner or container could read, not just upgrade.
- Worked example: `agent-framework` 1.26.1 (20:35 UTC) and 1.26.2 (21:08 UTC), last safe 1.26.0, with the two `.pth` names, what was collected, and 1.26.2's GitHub Actions OIDC addition. Checked 2026-11-18 against Wiz, Socket, Aikido and the PyPI JSON API. Removal time is given as each vendor reported it (21:20 vs 21:30 UTC). Root cause is not confirmed. No CVE. Hashes and the webhook URL are left in the sources.
- Two dependency-audit trigger prompts.

Proposed by @coreyhaines31 in #299.

### 1.96.0 (2026-11-18)

agent-supply-chain-audit flags instruction files that say "don't read it, just run it", and repo files that run a command when the folder opens or the tests run (Bitdefender, SafeDep Miasma GitHub arm). agent-supply-chain-audit 1.12.0.

**Added**
- Step 2 check for anti-inspection and auto-run directives: an `AGENTS.md` / `CLAUDE.md` / rule that forbids reading a file and asks for it to run is confirmed, Critical, whatever reason it gives. Greps and portable equivalents in `references/content-checks.md`. Bitdefender Labs (2026-11-17) reported 22 malicious GitHub links with such lines for `scripts/setup.js`.
- BH5 repo auto-run triggers, no agent needed: `.vscode/tasks.json` `"runOn": "folderOpen"` (BH5a), `package.json` scripts that run a hidden file (BH5b), Composer / `Gemfile` / dev container commands (BH5c). BH5d: several triggers across tools that run the same file is DO-NOT-INSTALL on its own. From SafeDep's Miasma GitHub-arm write-up (one commit, five triggers, one `.github/setup.js`) and its config-files follow-up.
- Step 0: for any third-party repo, read agent config, hooks, `.vscode/tasks.json` and `package.json` scripts before opening it in an agent or editor.
- Description trigger phrase: `is this repo safe to open`. Two trigger evals.

**Changed**
- Step 1 inventory lists `.vscode/tasks.json`. Severity anchors name anti-inspection directives and BH5d (Critical) and BH5a–BH5c (High).

Facts checked on 2026-11-18 against the Bitdefender Labs post and both SafeDep posts. Vendor research, not re-verified. No CVE.

**Changed**
- agent-supply-chain-audit: Web-to-agent bridges (WB1–WB4) moved to `references/web-to-agent-bridges.md`, with a short summary left in Step 4, and the description lists fewer instruction-file names, to stay under the 500-line and 1024-character limits.

Proposed by @coreyhaines31 in #298.

### 1.95.0 (2026-11-18)

breach-patterns, pci-audit and incident-triage: OPTIMJACK, attacker code in Optimizely Web Project JavaScript served to 178 organisations (2026-11-16), and who can publish code through a vendor dashboard. breach-patterns 1.2.0, pci-audit 1.2.0, incident-triage 1.12.0.

**Added**
- breach-patterns `references/third-party-scripts.md`: an OPTIMJACK incident section next to Polymarket. Checked 2026-11-18 against Report URI, StepSecurity, Hudson Rock's InfoStealers write-up and Optimizely's status page. No CVE. The IoC and wallet list is linked, not copied.
- TP7, who can change what the vendor serves: edit and publish rights on tag manager and experimentation dashboards, SSO and MFA, write tokens, a reviewed audit log, and whether custom code is needed. Medium, high on logged-in or checkout pages. Pattern 11 points to it.
- pci-audit: 6.4.3 under Req 6 and 11.6.1 under Req 11, a "vendor snippet on the checkout page" common finding, and the PCI SSC e-skimming information supplement in References. Description trigger phrases: `payment page scripts`, `PCI 6.4.3`, `PCI 11.6.1`.
- incident-triage `references/vendor-breach-notice.md`: a script-vendor section. Assume you served malware for the window, read your own copy of the vendor code, audit write access, rotate non-`HttpOnly` cookie secrets, treat card data typed into your own forms as exposed, and decide on customer notice (Report URI's checklist). The SKILL.md vendor-breach line points to it. Description unchanged.

**Changed**
- TP5: allowlisting the vendor host did nothing. A restrictive `script-src` without `'strict-dynamic'` or `'unsafe-eval'` blocked the loader on 24 of the crawled organisations, and `connect-src` stopped the data theft on 17 more but not the in-page address swap. The published counts sum to 159 of 256 crawled hosts, and the page says so.
- TP6: search a served snippet for `atob(`, `eval(` and runtime script tags as well as the IoC domain, and compare against an archived copy, since a clean fetch now says nothing about earlier. The TP1 grep adds `optimizely|kissmetrics|storifyme|minute-ly`.
- breach-patterns description mentions OPTIMJACK and adds `Optimizely compromise` and `tag manager hacked`. Its opening line now says "turn it into a checklist". One trigger prompt each for breach-patterns and pci-audit (should-fire top-1 262/274 to 264/276). `e-skimming` was dropped as a pci-audit phrase because it pulled an `owasp-audit` prompt to pci-audit.
- Corrections to the issue draft. Optimizely did publish a statement: its status page says a flaw in the Web Experimentation signup flow was exploited. It still hasn't said how that reached unrelated projects. StepSecurity cites Helme counting 26 payload builds on 16 November, not "at least four" edits. The archived-copy advice is ours, not StepSecurity's. Hudson Rock names the earlier-wave vendor minute-ly, not Minute Media. The PCI SSC standard PDF could not be read (403); the 6.4.3 and 11.6.1 lines are paraphrased from PCI SSC's own blog summaries and say so, with no quoted requirement text.

Proposed by @coreyhaines31 in #297.

### 1.94.0 (2026-11-18)

Change control for committed agent config, an incident-triage step for it after a developer compromise, and a lookalike agent CLI check (GTIG AI Threat Tracker, November 2026; GHSA-vp2q-gp5r-xh5j). agent-supply-chain-audit 1.11.0, incident-triage 1.11.0, dependency-audit 1.7.0, cicd-security 1.3.1.

**Added**
- agent-supply-chain-audit `references/change-control.md`, CC1–CC3, with a short pointer in Step 3:
  - CC1: committed agent config (`.claude/`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.cursor/`, `.gemini/settings.json`, `.github/copilot-instructions.md`, `.vscode/mcp.json`) under CODEOWNERS with required code-owner review. No owner on a branch that takes direct pushes is medium, high where developers hold production or deploy credentials. Last match wins in CODEOWNERS, so read the whole file.
  - CC2: read-only `git log` over the last 90 days for added hook commands, `apiKeyHelper`, `statusLine`, and `env` overrides. A change nobody accounts for is needs_validation. A disowned change, or one that downloads and runs something, is critical and goes to `incident-triage`.
  - CC3 (optional): a required `pull_request` check that flags hook-key changes. No guard is a hardening note.
- agent-supply-chain-audit IN5: an agent CLI under a lookalike scope. `@claudecode/cli` is malware (all versions, no fix). The official package is `@anthropic-ai/claude-code`. Critical if installed.
- incident-triage `references/dev-tool-compromise.md` section 4: after a developer machine or token is compromised, check every repo that identity could push to for new agent config since the first suspicious activity, and review new PATs, OAuth apps, GitHub Apps and keys, including ones named after AI tools. Rotate before anyone reopens those repos in an agent.
- dependency-audit Step 4 and `references/source-redirection.md` §2: the same lookalike agent CLI check for `package.json`, lockfiles, global installs and install docs.
- Description trigger phrases: `CODEOWNERS for .claude` (agent-supply-chain-audit), `lookalike Claude Code package` (dependency-audit). Three should-fire trigger prompts.

**Changed**
- cicd-security: the inventory row for agent config and `references/checks.md` point to CC1–CC3. Cross-reference only.

Facts checked 2026-11-18 against GTIG's AI Threat Tracker (2026-11-16, MIDNIGHT NEPTUNE paragraph), GHSA-vp2q-gp5r-xh5j and OSV MAL-2026-19243. GTIG's account is vendor research, not re-verified. GTIG names no hook event or file contents, and none are added. No CVE. No SOMBERMEME IOCs.

Proposed by @coreyhaines31 in #296.

### 1.93.0 (2026-11-18)

incident-triage and secrets-audit: Cursor's November 2026 incident report on the vendor-breach playbook, with agent traces and support tickets as secrets locations. incident-triage 1.10.0, secrets-audit 1.9.0, agent-supply-chain-audit 1.10.0.

**Added**
- incident-triage `references/vendor-breach-notice.md`: a Cursor row. A key Cursor issued to Fireworks was exposed there; a shared bucket of non-Privacy-Mode agent traces was copied; unredacted credentials in traces reached Cursor SaaS tools, support data, and a credential that wrote the trojanized Claude Code extension to the cache serving Cursor's marketplace (Open VSX was never affected). Cursor's forensics, as reported, not re-verified. No CVE.
- A "Cursor, October 2026" section with six steps: agent traces are a secrets location; support tickets are a secrets location; ask about your vendor's vendors (two hops); confirm listed keys are revoked at the issuer; read "not notified" for exactly what it covers (agent traces only); a clean upstream registry does not clear a cache or mirror.
- secrets-audit vendor-held inventory: two classes, agent sessions and traces kept by the vendor or its subprocessors when privacy or zero-retention mode is off, and credentials sent to support. Description trigger phrases `agent traces` and `credentials sent to support`.
- agent-supply-chain-audit `references/ide-extensions.md`: the malicious builds were written to Cursor's marketplace cache, not Open VSX. EX3 now asks whether an extension comes through a cache, mirror, or proxy, and says to check publisher and version against upstream. Two-line pointer in SKILL.md.
- One trigger prompt each for incident-triage and secrets-audit (should-fire top-1 264/276).

**Not claimed**
- Which Fireworks incident exposed the key (Cursor does not say), which SaaS tools were reached, or that Cursor belongs to Wiz's "Black October" campaign. BleepingComputer reports that framing from Wiz and does not place Cursor in it.

Facts checked 2026-11-18 against Cursor's incident report (2026-11-13) and Oct 30 notice, BleepingComputer, and The Hacker News. The @cursor_ai post on X was not read.

Proposed by @coreyhaines31 in #295.

### 1.92.0 (2026-11-18)

threat-hunting and log-watch: hunt agent-speed AWS intrusions as a burst, not as single calls (AntiFox / ARTEX, November 2026). threat-hunting 1.4.0, log-watch 1.1.0.

**Added**
- threat-hunting: catalog section "Agent-speed cloud intrusions (AWS)". Denial bursts with the successes listed separately, one source using many identities, secret and storage pairs, EC2 role sessions used off-AWS, `FilterLogEvents` secret mining, anonymous S3 probing, public Cognito pools, and a scripting user agent from a new hosting ASN (never alone). A web-shell lead pulls the app's credentials and hunts them forward from the compromise time.
- threat-hunting: perishable IOC appendix in `references/agent-speed-aws.md` (Arctic Wolf and Datadog, November 2026), marked as leads. Remediation points at `cloud-audit`, `iam-audit`, and `incident-triage` instead of copying their checks.
- log-watch D11, opt-in: a principal's denial burst, or `GetSecretValue` / a decrypting `GetParameter` from a source IP or ASN not in that principal's baseline. The plan says to confirm `lookup-events` actually returns those reads (management events only, 90 days) before enabling it, and that S3 object reads will not be in that API.

Proposed by @coreyhaines31 in #271.

### 1.91.0 (2026-11-18)

cicd-security treats a valid GitHub Actions workflow lockfile as a pin for the step-level `uses:` it covers, and states what a lockfile does not cover. cicd-security 1.3.0.

**Added**
- `unpinned-action`: a readable, well-formed `.github/workflows/actions.lock` entry that records a commit pins that step-level `uses:`. A missing, unreadable, renamed, symlinked, or malformed lockfile counts as no coverage. The inventory column omits lockfile-pinned refs.
- Gaps that stay uncovered: job-level reusable workflow calls, mutable tools installed in a `run:` step (including `gh-actions-lock` itself), `docker://` tags, and `uses: ./…`. A lockfile is not a verdict that the locked commit is safe. `impostor-commit` is still not a pin.
- `sha_pinning_required` and the Require lockfile policy are separate checks. A lockfile satisfies SHA pinning for onboarded workflows. Bare `gh actions-lock` is not an audit command; it writes the file. `gh actions-lock --verify` is the read.
- zizmor v1.32.0 (2026-11-02) is the first release with experimental lockfile support. Older runs still flag locked tags. Record the version used.
- Description trigger phrases: `actions.lock`, `workflow lockfile`.

Facts checked against GitHub's changelog (2026-10-28) and lockfile docs on 2026-11-15, and against zizmor's v1.32.0 release notes.

Proposed by @coreyhaines31 in #270.

### 1.90.0 (2026-11-18)

agent-supply-chain-audit checks MCP reference server versions, and patch-sweep treats a date-to-semver switch as an explicit pin (#269). agent-supply-chain-audit 1.9.0, patch-sweep 1.8.0.

**Added**
- agent-supply-chain-audit MS1: `mcp-server-git` or `mcp-server-fetch` below 2026.11.11, and `@modelcontextprotocol/server-filesystem` on a date version (2025.1.14 through 2026.8.31) or below semver 2.3.0. Git is high (repo `.git/config` runs a program during a read-only tool, GHSA-6hqx-gqrx-c5r2). Fetch is low. Filesystem is medium. Unpinned `npx -y` / `uvx` is needs_validation, because 2.3.0 ranks below the old date versions. Pin `@2.3.0` explicitly. No CVE ids, none reported exploited, as of 2026-11-12.
- MS2: a tool that runs `git` on a repository it did not set up should clear repo-defined config (`GIT_CONFIG_COUNT` overrides, `--no-ext-diff --no-textconv`, refuse Git older than 2.31). `git status` on a freshly cloned untrusted repo is not a read.
- patch-sweep Step 4: after a package moves from date versions to semver, "latest" is not the fixed release. Check the installed version and pin it.

**Changed**
- agent-supply-chain-audit: the MCP client checks (MC1–MC3) moved to `references/mcp-client.md`, with a short summary left in Step 4, to keep SKILL.md under 500 lines. The Medium anchor row now reads as one list: AP2/AP3 and WB1+WB2 rate high on a machine with production or deploy credentials.

Proposed by @coreyhaines31 in #269.

### 1.89.0 (2026-11-18)

cicd-security rates a stolen write token as its own check, and incident-triage gets a dated sweep for the wfx campaign (November 2026). cicd-security 1.2.0, incident-triage 1.9.0.

**Added**
- cicd-security check 13, `compromised-writer`. Assume one maintainer or bot credential is stolen and rate what one push can reach with no review: secrets and `id-token: write` without environment reviewers, bots that can bypass rulesets, `npm install` without `--ignore-scripts`, shell scripts CI already runs, and `on: push` with no branch filter. Critical only when that push reaches publish credentials, cloud OIDC, or org secrets with no human gate. Otherwise a hardening note.
- Step 5 reads ruleset `bypass_actors` and records the manual Applications check. The wfx campaign's Fly.io GitHub App attribution is stated as StepSecurity reported it: no evidence of a Fly.io infrastructure breach, and how the tokens were obtained is unknown.
- incident-triage `references/dev-tool-compromise.md`: a wfx section (2026-11-10 onward) with the probe pull request, commit messages, file and branch patterns, the run-number gap check, rotation and persistence removal, and the IOC table from StepSecurity (2026-11-12), including the switch to Telegram-only exfil. Aikido's 4,837 accounts / 61,764 repositories and the 1,806 and 1,835 run figures are both cited. No CVE.

Facts checked against Aikido and StepSecurity on 2026-11-15.

Proposed by @coreyhaines31 in #268.

### 1.88.0 (2026-11-18)

incident-triage and secrets-audit: Notion / Fireworks transcript exposure on the vendor-breach playbook. incident-triage 1.8.0, secrets-audit 1.8.0.

**Added**
- Fireworks and Notion rows. Notion was not the breached party: Fireworks, its classification vendor, was. Checked 2026-11-11 against Notion's advisory and help center and both Fireworks bulletins. No CVE.
- Notion's "unattributable" definition, quoted: unlabeled chats, not non-identifying text. Enterprise zero-data-retention covers the API requests that generate Notion AI responses, not stored chat history or Insights. A contractual commitment from Fireworks did not prevent retention on the Insights endpoints.
- Five steps: inventory AI subprocessors and secondary copies; record what a zero-data-retention claim does and does not cover; do not treat unlabeled transcripts as harmless; the first "no customer data" bulletin can expand; no notice means follow the vendor's current guidance and keep watching.
- secrets-audit vendor-held inventory has a second table for the subprocessor, the feature that re-sends stored chats, and both sides of the retention claim.

Proposed by @coreyhaines31 in #267. Based on the vendor-breach playbook in #251, after the Railway row in #262.

### 1.87.0 (2026-11-18)

cicd-security rates an agent step by the credentials on the runner, not by the sandbox. cicd-security 1.1.0.

**Added**
- `agent-prompt-injection` is critical when a lower-trust actor can trigger the agent and any release, publish, `contents: write`, or `id-token: write` workflow restores an Actions cache. Record it once, with propagation carrier `actions-cache`. A read-only `permissions:` block does not clear it: the runner still holds `ACTIONS_RUNTIME_TOKEN`.
- `cache-poisoning` lists an AI agent job triggered by issues, pull requests, or comments as an untrusted cache writer, next to `pull_request_target`.
- A named incident, openai/codex issue-labeler (November 2026), in `references/worked-examples.md` and `references/ai-agents-in-ci.md`. Facts are as reported by Depi Research Team's Bugcrowd disclosure and The Defiant, read 2026-11-15. OpenAI fixed it. No malicious release is reported to have reached users. No CVE is named. The escape method is not reproduced, and the researcher's download figures are omitted.

Proposed by @coreyhaines31 in #266.

### 1.86.0 (2026-11-18)

agent-supply-chain-audit checks the MCP client, not only the servers it loads, and patch-sweep includes editor forks (#265). agent-supply-chain-audit 1.8.0, patch-sweep 1.7.0.

**Added**
- agent-supply-chain-audit MC1: VS Code below 1.145.3 is high. The 10 November 2026 release fixes MCP elicitation command links (CVE-2026-120779, CNA CVSS 9.6, E:U), install-link RCE, legacy SSE RCE, a network workspace trust bypass, and a serve-web downgrade. None are reported exploited, and none are in CISA KEV. A fork (Cursor, Windsurf, VSCodium, others) is needs_validation until its release notes name the upstream build. Fork status was not confirmed on 2026-11-11.
- MC2: flag `"type": "sse"` and `/sse` URLs. On an unpatched client that is part of the MC1 high. On a patched client it is a hardening note to move to Streamable HTTP.
- MC3: approving a one-click MCP install link without reading the command and inputs, and opening an HTTP(S) workspace file from an untrusted source. Hardening notes.
- patch-sweep Step 4: an editor/MCP-client advisory is swept on developer machines for the upstream product and every installed fork.

Proposed by @coreyhaines31 in #265.

### 1.85.0 (2026-11-18)

finding-triage, api-audit, and web-pentest: agent-report source class, and redacting HTTP transcripts before a model reads them. finding-triage 1.4.0, api-audit 1.2.0, web-pentest 1.3.0.

**Added**
- finding-triage: record a source class (scanner, manual audit, production/operator, agent-generated). Volume and multi-agent agreement do not raise severity and do not skip the six-element gate. A valid finding that only holds on a deployment the customer does not run stays Low or becomes a hardening note, and is not relabeled a false positive. Production evidence outweighs novel or agentic discovery for priority. The Puma-maintainer note is kept as an anecdote, with no hit-rate claim. The independent read still runs before High or Critical on an agent-written report.
- api-audit and web-pentest: before a model sees a Burp, ZAP, HAR, or curl transcript, replace cookies, `Authorization`, `Set-Cookie`, JWTs, and secret fields with stable identity markers so owner-vs-non-owner evidence still works. The credential swap stays outside the model. HoneyWarden #82 is named as the product analogue, not a dependency.

Proposed by @coreyhaines31 in #264.

### 1.84.0 (2026-11-18)

cloud-audit: a private overlay is a path to Postgres or Redis, not least privilege. cloud-audit 1.4.0.

**Added**
- DB6 says SSH, a VPC, or Tailscale is how admins reach `5432` / `6379` / `3306` / `27017`, and that this is not the privilege model. A leaked database URL still works from every node on a default-open overlay.
- DB7 reads the Tailscale ACL or grants policy (or the VPC security group) and flags a default-open or overly broad rule. Medium, or High when any node on the overlay could use a leaked URL. A tight policy is a note. Cites Tailscale's ACL and grants docs.

Proposed by @coreyhaines31 in #263. `personal-opsec` does not recommend Tailscale, so it is unchanged.

### 1.83.0 (2026-11-18)

incident-triage and secrets-audit: Railway's October 2026 final RCA, added to the vendor-breach playbook. incident-triage 1.7.0, secrets-audit 1.7.0.

**Added**
- A Railway row on the vendor-breach table, citing the final RCA (2026-11-10) and the Oct 22 preliminary note. Marked as Railway's forensics, not re-verified. No CVE. The "at most 1.85%" figure is an upper bound, not a victim count. "Abliterated models" / ARTEX-like language is Railway citing Wiz.
- Five tightenings: the issuer may act before you are told; inventory CI, build history, caches, GitHub App / OAuth / BYOK tokens, and agent keys; rotate at the issuer; do not treat env-var renaming as a control; keep upper bounds honest.
- secrets-audit vendor-held inventory lists those extra classes, and says renaming a variable is not a control.

Proposed by @coreyhaines31 in #262. Based on the vendor-breach playbook in #251.

### 1.82.0 (2026-11-18)

personal-opsec checks outbound SSH agent forwarding to hosts that run coding agents (#261). personal-opsec 1.4.0, agent-supply-chain-audit 1.7.1.

**Added**
- personal-opsec C9: read-only check of `ForwardAgent` under `Host *` and other wildcards, `ssh -G` per agent host, `ssh-add -l` fingerprints only, and the Codex forwarded-agent socket. Medium when a wildcard forwards the agent to an agent host; high when that agent holds a key that can push to production. The fix is a host-specific `ForwardAgent no` before any `Host *` block.
- The worked case is ChatGPT desktop Codex Remote SSH, build 26.1103.60933, as reported on 2026-11-09. The app does not enable forwarding itself. A user's own `ForwardAgent yes` is what links `SSH_AUTH_SOCK` to `~/.codex/app-server-control/forwarded-ssh-agent.sock`. No CVE. The closed PR #28131 is not a hidden flag.
- agent-supply-chain-audit credential-reads row now also matches `SSH_AUTH_SOCK` and `forwarded-ssh-agent.sock`.

Proposed by @coreyhaines31 in #261.

### 1.81.0 (2026-11-18)

secrets-audit and personal-opsec: Claude Code "don't ask again" allow rules can store a secret in `.claude/settings.local.json`. secrets-audit 1.6.0, personal-opsec 1.3.4.

**Added**
- secrets-audit counts inline credentials in `permissions.allow` (connection strings, bearer tokens, known key prefixes, `PGPASSWORD`, `--password`) and checks whether `.claude/settings.local.json` is tracked, only covered by a global git exclude, or named in the project `.gitignore`. Counts only. Do not print the matching line.
- A tracked or historically committed secret is rated like any other committed secret. An untracked copy covered only by global excludes is `needs_validation`, fixed by adding the path to the project `.gitignore`. If a real credential was saved there, rotate it, then remove it from the file and from history. Allow rules should be patterns such as `Bash(psql:*)`, with the secret in an env var or a secrets manager.
- Apiiro's 2026-11-05 counts (104,185 public copies, 1,122 with a secret, 215 missed by gitleaks and TruffleHog together) are cited as reported, not re-counted. Claude Code issues #13106 and #5544 were closed without a fix. No CVE.
- personal-opsec C3 asks whether Claude Code is current. v2.1.317 asks before putting the signed-in account email in the User-Agent. A fuller removal from model context was announced and was not verified shipped as of 2026-11-09.

Proposed by @coreyhaines31 in #260.

### 1.80.0 (2026-11-18)

dependency-audit, owasp-audit, and patch-sweep: Better Auth Expo authorization-proxy account takeover (CVE-2026-121802 / GHSA-4wq4-2ppv-q3hg / GHSA-hv45-wgqh-c9j5). dependency-audit 1.6.0, owasp-audit 1.9.0, patch-sweep 1.6.0.

**Added**
- dependency-audit: version floors for `better-auth` and `@better-auth/expo` (1.7.16, or 1.8.0-beta.5 on the beta line), the `expo()` reachability check, and the rule that a below-floor lockfile still bumps both packages when the plugin is absent. After the bump, rotate the application secret. Facts re-checked 2026-11-15 against the vendor advisory; not on CISA KEV.
- owasp-audit A07: flag custom auth that signs caller-supplied state with the application secret, or that uses one secret for email-verification links and the session cookie cache, with this advisory as the worked example.
- patch-sweep: fleet bump of both packages. Apps that register `expo()` are urgent; the rest are same-week. A row stays open until the secret is rotated wherever the proxy was reachable.

Proposed by @coreyhaines31 in #258.

### 1.79.0 (2026-11-18)

agent-supply-chain-audit adds a worked incident for an install-time worm that poisons coding-agent config, and personal-opsec points at it (#257). agent-supply-chain-audit 1.7.0, personal-opsec 1.3.3.

**Added**
- agent-supply-chain-audit: strutil-core 1.0.1 (RubyGems, 2026-11-06, Socket). A testmetest / Miasma / Shai-Hulud descendant. It runs at `gem install`, can poison MCP servers, session hooks, and instruction files, and can republish to RubyGems, npm, and PyPI. No public dependents and no confirmed victims. PyPI sibling pystr-codec. `paleasbest.top` is an IOC for this incident only, not a standing blocklist. Do not reproduce the payload. If it ran, rebuild the host and rotate credentials. Uninstalling the gem is not cleanup.
- personal-opsec Part C: after an unexpected RubyGems, PyPI, or npm install on a machine that runs coding agents, re-diff agent config and rotate tokens. The playbook stays in agent-supply-chain-audit.

Proposed by @coreyhaines31 in #257.

### 1.78.0 (2026-11-18)

dependency-audit and patch-sweep: undici cache and redirect batch, fixed in 7.30.2 and 8.12.4. dependency-audit 1.5.0, patch-sweep 1.5.0.

**Added**
- dependency-audit: the six 2026-11-05 advisories (CVE-2026-116592 high, plus five medium), lockfile and `redirect()`+`cache()` checks, and the Node releases that vendor the patched undici. Facts re-checked 2026-11-15. Not on CISA KEV. Node 22's undici 6.x is outside this batch; Node 24.22.3 and 26.13.1 are the patched vendor lines.
- patch-sweep: bump or override anything below 7.30.2 / 8.12.4, including the copy Node vendors for `fetch`. Stock `fetch()` is lower priority for the high advisory and still gets the bump. Normal cadence unless one cache is shared across tenants.

Proposed by @coreyhaines31 in #256.

### 1.77.0 (2026-11-18)

threat-hunting, incident-triage, and siem-detection: hunt high-severity outcomes whose parent is a coding agent (Elastic Threat Command, November 2026). threat-hunting 1.3.0, incident-triage 1.6.0, siem-detection 1.1.0.

**Added**
- threat-hunting: "Agent-parented high-severity outcomes" (AP1–AP5). Credential-store access, free reverse tunnels, persistence, quarantine stripping, and permission-bypass sessions, keyed on ancestry (`claude`, Cursor, Codex, ChatGPT). Claude Code reading its own `Claude Code-credentials` keychain item is allow-listed. A tunnel alone needs validation. Two readings stay written down.
- incident-triage: do not close because the parent is vendor-signed. Read the session transcript (human prompt versus a file, hook, MCP result, or remote session — #234, #253, #254), rotate what the session could read, then reuse the dev-machine persistence checks from #223.
- siem-detection: the same five outcomes as rule ideas. GenAI child-process volume alone is context, not a finding.

Proposed by @coreyhaines31 in #255.

### 1.76.0 (2026-11-18)

agent-supply-chain-audit inventories web-to-agent bridges, and the response skills know what to look for afterward (#254). agent-supply-chain-audit 1.6.0, incident-triage 1.5.0, personal-opsec 1.3.2, log-watch 1.0.3.

**Added**
- agent-supply-chain-audit WB1–WB4. A remote-control or web-session feature, a browser extension that can run on the agent's site, one account on both a personal browser and a work machine, and an approval rendered in a page a script can operate. WB1 and WB2 together are medium, and high when the machine holds production or deploy credentials. Word it as an exposure. The ThisBash report (Forever Security, 2026-11-04; The Register, 2026-11-05) has no CVE and no reported exploitation. Remote Control and Cowork are vendor-unconfirmed. Chromium extension manifest paths are in `references/locations.md`.
- personal-opsec K8 and C2 point at WB1–WB4.
- incident-triage dev-tool playbook: prompts the user did not type, a global package install, a new LaunchAgent, and a new `authorized_keys` entry lined up with a session nobody was present for. No exact-prompt IOCs.
- log-watch hands that shape to incident-triage. It is not a starter detection.

Proposed by @coreyhaines31 in #254.

### 1.75.0 (2026-11-18)

agent-supply-chain-audit records who installed each plugin, hook, and MCP server (#253). agent-supply-chain-audit 1.5.0, personal-opsec 1.3.1.

**Added**
- Inventory column **Installed by** (`user`, `vendor app`, `repo`, or `unknown`) plus install time. Read-only commands for Codex `[marketplaces]` / `[plugins]` / `[hooks.state]`, Claude Code `enabledPlugins` and `installed_plugins.json`, and Copilot CLI settings. Paths are in `references/locations.md`.
- AP1–AP5. An app-added plugin or marketplace, a self-approved `trusted_hash`, a session-start instruction that steers broad work, a remote MCP server added with the plugin, and leftovers after removal. Medium until the user confirms. Escalates on a machine that holds production credentials or deploy keys. The trust record shows an approval was stored, not who stored it. Do not call the vendor malicious.
- Worked report: Postman desktop auto-install, checked 2026-11-04. One user's evidence (12.33.4, then 12.35.1), not reproduced on a clean Mac. No fix and no CVE as of that date. Nothing in the reporting says data left the machine.
- personal-opsec C2 asks which desktop apps may change agent config. LD3 points at AP1 and AP4.

Proposed by @coreyhaines31 in #253.

### 1.74.0 (2026-11-18)

owasp-audit and patch-sweep: Rails Active Storage ImageMagick and FFmpeg advisories (GHSA-f3w6-w445-fwh9 / CVE-2026-122006, GHSA-v924-7rp8-4mxh / CVE-2026-126186). owasp-audit 1.8.0, patch-sweep 1.4.0.

**Added**
- owasp-audit Rails playbook, check 6: `:mini_magick` plus untrusted uploads plus a host policy that does not deny the coders, the traps that keep the shipped policy from loading, the FFmpeg analyzer workaround, and when to rotate secrets. Facts re-checked 2026-11-15. Not on CISA KEV. Fixed gems are 8.0.5.2 and 8.1.4.1. Rails 8.0's security window ended 2026-11-07; 7.2's ended 2026-08-10.
- patch-sweep: the same two advisories beside the libvips case. The bump is not done until ImageMagick loads the shipped policy. Disk-service apps that were reachable while vulnerable rotate `secret_key_base` and the other secrets the process can read before the row closes. Changing `secret_key_base` logs everyone out.

Proposed by @coreyhaines31 in #252.

### 1.73.0 (2026-11-18)

incident-triage and secrets-audit: a playbook for when a vendor you use was breached. incident-triage 1.4.0, secrets-audit 1.5.0.

**Added**
- incident-triage `references/vendor-breach-notice.md`, linked from Step 1. For a SaaS or platform that says an attacker reached its systems, while your own code and machines may be fine. Inventory what you handed the vendor, rotate the highest-value keys at the issuer (new, then revoke old), check the issuer's logs, rotate on the first notice of unauthorized access to credentials, treat "revoked for you" as partial, verify any "rotate now" email against the vendor's status page, and log the clock for Step 6.
- Dated rows for GitBook (2026-11-02), Northflank (2026-10-30), Bubble (2026-10-26), Allium (2026-10-25) and Warp (2026-10-23, disclosed 2026-10-26), each with what that vendor told customers. The "AI agents" attribution is marked vendor-reported, not confirmed. Warp's "rotate anything pasted into an agent session" advice is marked as coming from write-ups, not from Warp. No CVE is claimed.
- secrets-audit: a vendor-held secrets inventory (class, issuer, rotation tested?) so that inventory step is a lookup. "Rotation tested?" ties to the existing "rotation never tested" finding.

**Not in this change**
- breach-patterns Pattern 12 (a developer platform's control plane holds your secrets) was left out. The issue marked it optional.

Proposed by @coreyhaines31 in #251.

### 1.72.0 (2026-11-18)

Installer and interview-homework entry points from Binance's 2026-11-03 preliminary report (#250). agent-supply-chain-audit 1.4.0, incident-triage 1.3.0, threat-hunting 1.2.0, personal-opsec 1.3.0.

**Added**
- agent-supply-chain-audit IN1–IN4. An agent or CLI installed from a search result (critical when the source cannot be shown), Homebrew's git remote and `which brew` (critical when the remote is not Homebrew/brew), long-lived deploy tokens on a laptop (high when they can ship to production; existence only, no values), and agent tools that can act on another person's machine without a per-call approval (medium to high, a design check).
- The report is cited as reported. The sequence is a translation plus CoinDesk and The Block, not Binance's own copy of the 2026-11-03 report. Left unfilled, because the report does not say: the tool's name, how the installer was tampered with, the malicious component's name, and how the internal AI tools were abused.
- incident-triage dev-tool playbook: tampered installer, and an interview homework repo. "No alert" is not a clean result.
- threat-hunting developer-workstation catalog: the same two patterns.
- personal-opsec: open a take-home only in a throwaway VM, read install scripts and instruction files first, take installers from the vendor's own page, and keep deploy tokens off the interview machine.

Proposed by @coreyhaines31 in #250.

### 1.71.0 (2026-11-18)

secrets-audit, personal-opsec, cloud-audit, and container-audit: limit what a leaked key or database URL can do. secrets-audit 1.4.0, personal-opsec 1.2.2, cloud-audit 1.3.0, container-audit 1.4.0.

**Added**
- secrets-audit step 4 asks whether a pay-per-use key has a hard spend cap scoped to that key, project, or non-default workspace. `references/spend-caps.md` has the provider table (OpenRouter per-key `limit`, OpenAI and Anthropic monthly and not daily), SC1–SC3, and the OpenRouter check. Reading the cap asks first. Docs checked 2026-10-30. A daily cap on OpenAI or Anthropic is not what those docs say.
- personal-opsec C5 points at the same table.
- cloud-audit self-hosted VPS checks DB1–DB4 and DB6 (`references/self-hosted-vps.md`): public listeners, Docker published ports that skip ufw, Postgres `listen_addresses`, Redis bind / protected mode / auth. DB5 (Supabase and Neon allowlists) is in `references/paas.md`. Confirmed severities match the exposure. A compose file that is not shown to be deployed stays `needs_validation`.
- container-audit: the compose published-port grep, and a checklist line that `"5432:5432"` binds every interface.

Northflank's October 2026 status page is the reason the cap and the closed database matter. No CVE was assigned as of 2026-11-02.

Proposed by @coreyhaines31 in #249.

### 1.70.1 (2026-11-18)

README: install steps for OpenCode and oh-my-pi (`omp`). No skill changes.

**Added**
- Option 1 says which agents read `SKILL.md` natively through `npx skills`, with an OpenCode example (`-g -a opencode`).
- Option 7: oh-my-pi. `omp` isn't an `npx skills` target; it loads project `.agents/skills/` and `.claude/skills/`, plus `~/.omp/agent/skills/` and `.omp/skills/`. The git submodule option is now Option 8.

Contributed by @Robinbinu in #247.

### 1.70.0 (2026-10-30)

breach-patterns: Pattern 11, a compromised third-party script acting inside logged-in sessions (Polymarket via DebugBear, 2026-10-29). breach-patterns 1.1.0, business-logic-testing 1.1.0.

**Added**
- breach-patterns Pattern 11 and `references/third-party-scripts.md` (TP1–TP6), for vendor scripts SRI can't pin: real-user monitoring, tag managers, chat, A/B testing, session replay. The checks are third-party scripts by page type, whether each can be pinned, a step-up on sensitive actions, credentials exposed to page scripts, CSP allowlists as an exfil channel, and change detection. Greps and a live CSP check are included. The incident facts were checked against BleepingComputer, Ohey and SecurityWeek, and the page says the defenses are our recommendations.
- Two corrections to the issue draft. Only email-login accounts had positions sold; browser-wallet accounts had them transferred out, with a signature request per batch. No source says email-login users saw no prompt. How the DebugBear file was replaced isn't public.
- breach-patterns: a coverage table row, Pattern 2 now points to Pattern 11, and the description mentions the incident. Added a trigger prompt (should-fire 219/229 → 220/230).
- business-logic-testing Step 5: "Sensitive actions without fresh intent". Replay withdrawals, payouts, account changes and API key creation with only the existing session; if that works, any script on the page can do it.

Proposed by @coreyhaines31 in #243.

### 1.69.2 (2026-10-30)

Resolved the "(verify)" markers: every one was checked against a primary source on 2026-10-30 and replaced with a dated, sourced fact. ai-risk-management 1.1.3, control-audit 1.2.1, log-watch 1.0.2.

**Fixed**
- **ai-risk-management: Colorado was out of date.** SB 24-205 never took effect as written. After the delay to 30 June 2026, SB26-189 (signed 14 May 2026) repealed and re-enacted it as an automated decision-making technology law:
  - developer duties start 1 January 2027;
  - Attorney General rules are due by the same date;
  - the AG must give 60 days' notice and a chance to cure before enforcing, until 2030;
  - there's no private right of action.
- ai-risk-management: the EU Digital Omnibus on AI is in force (27 July 2026, OJ L 2026/1744). That confirms the Annex III date of 2 December 2027 and the Annex I date of 2 August 2028. The December 2025 order is named as EO 14365, with what it actually does, and the skill now says to check whether its Task Force has acted against a given state law.
- control-audit (NIST 800-53 / FedRAMP):
  - 5.1.1 is dated 7 November 2023 and added IA-13 (checked in NIST's OSCAL catalog history), and 5.2.0 is still current.
  - FedRAMP's own wording on certification classes ("loosely align", "not a direct correlation") replaces the secondary sources.
  - The CR26 Rev5 minimum control lists are counted from FedRAMP's machine-readable rules: 155 for Class B, 322 for C, 409 for D.
  - NIST's 800-53 to ISO/IEC 27001:2022 crosswalk and AICPA's TSC to 800-53 mapping are both confirmed.
- control-audit (SOC 2): the attestation-standards project (AT-C 105/205/210) has exposure drafts from February and March 2026, comments closed 30 June, and a proposed effective date of 15 June 2029. There's no final standard yet.
- control-audit (ISO 27001): the AICPA's TSC to ISO 27001 mapping is dated May 2018, so it covers the 2013 edition.
- log-watch: the GitHub audit-log actions are named. `personal_access_token` covers fine-grained token access in the org log, and `public_key.create` covers SSH and deploy keys. Token creation is in each user's security log, not the org log.

### 1.69.1 (2026-10-30)

evals/README: current trigger-eval results and misses. Docs only.

**Fixed**
- The results section quoted v1.50.1. It now gives v1.69.0's numbers (should-fire 219/229, 95.6%; top-3 98.7%; near-miss 219/221, 99.1%; most similar pair 0.40) and lists today's misses: pasted code, DPIA prompts going to threat-modeling, near-synonyms in neighbouring descriptions, and the budget and jailbreak prompts. It also notes that the incident-triage, prompt-injection and fuzzing-harness misses listed at v1.50.1 were fixed in v1.52.1–v1.52.3.

### 1.69.0 (2026-10-30)

agent-supply-chain-audit checks where agents get launched (#234). agent-supply-chain-audit 1.3.0, personal-opsec 1.2.1.

**Added**
- **Launch directories and folder trust** (`references/launch-directories.md`). In October 2026, Forever Security found a planted `AGENTS.md` in a customer's `~/Downloads` that told Codex to add a server to the machine-wide `~/.codex/config.toml` and install `function-color` (the MALFEX campaign). It's cited from The Hacker News, Help Net Security and BleepingComputer, with the disagreement between them noted.
  - **Folder trust per agent:** Codex `projects.<path>.trust_level` and Claude Code's trust prompt.
  - **A read-only inventory** of instruction files and project settings in `~/Downloads`, `~/Desktop`, `$HOME` and `/tmp`.
  - **LD1–LD4:**
    - LD1, a trusted catch-all folder;
    - LD2, an instruction file nobody wrote;
    - LD3, a machine-wide server or base URL the user doesn't recognize (rotate the login token);
    - LD4, a package from a known campaign.
    - LD2–LD4 are Critical and go to `incident-triage`.
  - Hardening notes.
- An Inventory row and a `locations.md` row for folder trust.
- personal-opsec C2 asks where agents are launched from.

**Departures from the issue draft**
- **Codex trust is per exact path, both ways.** A comment on openai/codex#19426 (Codex 0.163.0) reports that an `untrusted` parent didn't stop a child folder's `AGENTS.md` from loading. So the fix for LD1 is not launching agents in Downloads, not just setting the folder to untrusted.
- The reports disagree on the Claude Code code-execution rate (about a fifth in Help Net, about half in BleepingComputer). Both are named.

### 1.68.0 (2026-10-30)

owasp-audit's Next.js playbook adds the 2026-10-14 security release (#233). owasp-audit 1.7.0.

**Added**
- **Three advisories in section 6** of `references/frameworks/nextjs.md`, fixed in 16.4.1 and 15.5.28:
  - GHSA-673q-mjm6-r5xr: `use cache` RCE, no CVE, no workaround, 16.x only per GitHub.
  - GHSA-2464-fhr4-w9xw / CVE-2026-96889: Image Optimization RCE with SVG on glibc Linux; the workaround is `sharp` 0.35.5 or later.
  - GHSA-p3m5-59mp-jv5r / CVE-2026-94482: Server Action CPU DoS.
- **Match on GHSA id and fixed version, not CVE.** GitHub's records carry no CVE for two of the three. NVD describes CVE-2026-96889 as a librsvg bug (7.8, local vector). GitHub published all three eight days after the release.
- **A resolved-`sharp` check:** what the app actually installs, the image optimizer and SVG settings, `use cache` use, and recording the runtime's libc.
- A pointer to `patch-sweep` for Node.js runtime advisories such as the Brotli decoder RCE (CVE-2026-111497).

**Changed**
- The first column of the advisory table is now `Advisory`, and the "checked" date is 2026-10-30.

**Fixed (against the issue draft)**
- GHSA-673q's only affected range in GitHub's record is 16.0.0–16.4.0, so it's listed as fixed in 16.4.1 only.

### 1.67.0 (2026-10-30)

incident-triage gets a compromised-developer-machine playbook, threat-hunting a dev-tool backdoor hunt (#223). incident-triage 1.2.0, threat-hunting 1.1.0, personal-opsec 1.2.0.

**Added**
- **Dev-tool compromise** (`incident-triage/references/dev-tool-compromise.md`), for when an IDE extension, MCP server, npm `postinstall`, skill or plugin turns out to be malicious:
  - **Scope:** was it installed in the window, did it activate, do the IOCs match?
  - **Contain before cleaning:** cut access, collect evidence first (uninstalling doesn't remove the persistence), rotate from a clean machine.
  - **A read-only sweep** for macOS, Linux and Windows: attacker SSH keys, vendor-named LaunchAgents, scheduled tasks and `@reboot` cron entries, Remote Login, live reverse tunnels.
  - **Fleet and downstream scope.** A tunnel only gave a shell where an SSH server was running.
  - **Recovery hand-offs.**
- **Dated IOCs** for the malicious `Anthropic.claude-code` 2.1.312 and 2.1.313 builds in Cursor's marketplace (2026-10-29), taken from Cursor's notice as updated 2026-10-30 11:30 PT:
  - network indicators;
  - SSH key comment and fingerprints;
  - dropped files and persistence on all three OSes;
  - `extension.js` and VSIX hashes;
  - the remediation scripts, and how to run each.
  - It notes where sources disagree: whether 2.1.312 was malicious, and 2.1.314 as the fixed version.
- **threat-hunting: "Developer workstations"** in the hunt catalog. It's pattern-based rather than tied to one incident: `authorized_keys` on laptops, vendor-impersonating user persistence, executable hidden scripts in `~/.config`, reverse tunnels, Remote Login turned on, a changed `extension.js`.
- **personal-opsec C8, inbound remote access:** Remote Login off unless needed, `authorized_keys` absent or reviewed, and an alert on any change to it.
- **incident-triage:** the new incident type, plus pre-approved `launchctl list` and `shasum -a 256`.

**Departures from the issue draft**
- No source says "don't uninstall first". The playbook says to collect evidence before removing anything, and that uninstalling alone isn't enough (Cursor).
- Turning on SSH failed unless Cursor ran with admin rights (Cursor), so scoping asks whether an SSH server was already running.
- `ssh-keygen -lf:*`, `plutil -p:*` and `crontab -l` aren't pre-approved: `ssh-keygen -R` edits `known_hosts`, and `plutil` can write files. They prompt.
- The full attacker public key isn't reprinted. The comment and fingerprint identify it.

### 1.66.0 (2026-10-30)

agent-supply-chain-audit audits IDE extensions (#222). agent-supply-chain-audit 1.2.0, personal-opsec 1.1.1.

**Added**
- **IDE extensions as a first-class item** (`references/ide-extensions.md`):
  - **Folders and marketplaces** for Cursor, VS Code, VS Code Insiders, Windsurf, VSCodium, remote and SSH servers, and JetBrains.
  - **A read-only inventory from each `extensions.json`.** Its fields were checked against real registries: id, version, `source` (`gallery` or `vsix`), publisher, install time.
  - **Every version folder on disk**, because IDEs keep old builds after an update.
- **EX1–EX6:**
  - EX1, known-bad version on disk, starting with `anthropic.claude-code` 2.1.312 and 2.1.313 from Cursor's marketplace (2026-10-29), sourced from Cursor's notice;
  - EX2, auto-update on for high-privilege extensions;
  - EX3, the same id from a different marketplace;
  - EX4, code prepended to `extension.js`;
  - EX5, unverified publisher or typosquat;
  - EX6, no extension policy.
  - EX1 and EX4 are Critical and go to `incident-triage` before anything is cleaned up.
- Severity anchors, a fingerprint shape, an Inventory row, trigger phrases ("audit my IDE extensions"), and one trigger-eval prompt.
- personal-opsec C2 includes IDE extensions in the "what's connected" pass.

**Changed**
- `locations.md` no longer just names `~/.cursor/extensions/` as out of scope; it points to the EX checks.

### 1.65.0 (2026-10-30)

dependency-audit and container-audit find runtime defaults that widen a kernel CVE's reach (#221). dependency-audit 1.4.0, container-audit 1.3.0.

**Added**
- **Runtime exposure** (new shared file `runtime-exposure.md`, copied into both skills), with Go and MPTCP as the worked example for CVE-2026-98432:
  - Go's `multipathtcp` values. Since Go 1.24 the default is `2`, which turns MPTCP on for listeners.
  - **The default follows the main module's `go` line, not the toolchain**, so a `go 1.23` module built with Go 1.25 keeps MPTCP off.
  - Source checks (go.mod, `//go:debug`, `SetMultipathTCP`, a GODEBUG setting in the deploy config) and the authoritative binary check: `go version -m` reading `DefaultGODEBUG`.
  - An exposure table, and a `needs_validation` finding shape that hands off to `patch-sweep`.
- **Containers share the host kernel.** Rebuilding an image can't fix a kernel CVE, so the image is recorded as "not the fix location".
  - **MPTCP is per network namespace, and every new namespace starts with it on** (`net/mptcp/ctrl.c`). Turning it off on the host doesn't reach containers, so it's checked per container with `nsenter`.
  - Compose and Kubernetes per-workload settings. `net.mptcp.enabled` isn't in the kubelet's safe set, so it needs `--allowed-unsafe-sysctls`.
  - `hostNetwork`, and pulling Go binaries out of images without running them.
- dependency-audit Step 3 and container-audit's runtime checklist point to it.

### 1.64.0 (2026-10-30)

patch-sweep adds a Linux hosts and kernel CVE track (#220). patch-sweep 1.3.0.

**Added**
- **Linux hosts and kernel CVEs** (`patch-sweep/references/linux-hosts.md`) for VPSes, EC2, bare metal, nodes and relays, self-hosted runners and Kubernetes nodes:
  - **Inventory:** host listing from AWS, DigitalOcean, Hetzner and GCP, then asking about the rest. Each host row records the running and installed kernel.
  - **Affected test:** read the running kernel package against the **distro tracker** (Debian, Ubuntu, Red Hat, Amazon Linux, SUSE, OSV), never `uname -r` against upstream version numbers, because distros backport fixes under their own versions. A fix that's installed but not yet rebooted into still counts as affected.
  - **Mitigations:** livepatch, sysctls (and that many are per network namespace), host-firewall rules through the host's own manager, app-level switches. Each needs verify and persist lines and a removal date.
  - **Patching:** update, reboot in the owner's window, confirm, re-check mitigations. Notes for Kubernetes node pools and Lightning nodes.
  - A **host board** with its sort order, and prevention items.
- **Worked example: CVE-2026-98432**, dated 2026-10-30:
  - the IPv4 TCP use-after-free and its second trigger path;
  - exploitation (Anthropic's MPTCP exploit; not in KEV; EPSS 0.0045);
  - CVSS 9.8 versus Red Hat and Amazon's 8.1;
  - every upstream fixed branch, including 5.10 and 5.15;
  - status for Debian, Ubuntu, Red Hat, Amazon Linux and SUSE;
  - exposure checks (`net.mptcp.enabled`, `ss -Mltnp`, `tcp_migrate_req`) and five mitigations.
- **Pre-approved, read-only:** `aws ec2 describe-instances`, `doctl compute droplet list`, `hcloud server list`, `gcloud compute instances list`.

**Departures from the issue draft**
- The IP-options nftables rule is labelled as our reasoning from the fix, not a vendor mitigation. No vendor publishes it, and Red Hat says no mitigation meets its criteria.
- The draft said running programs see errors after MPTCP is turned off. No source says that, so it was dropped.
- Added the request-socket migration path from the fix description.
- Amazon Linux 2's extra kernels and part of the SUSE product line are still pending, not shipped.

### 1.63.0 (2026-10-30)

patch-sweep covers the browsers that agents and test suites download (#219). patch-sweep 1.2.0.

**Added**
- **Browser runtimes in a sweep** (`patch-sweep/references/browser-runtimes.md`), for an advisory set that includes a Chrome or Chromium CVE:
  - **Inventory** of four asset types:
    - lockfiles that pin Playwright, Puppeteer or `@sparticuz/chromium`, with how to map each version to its Chromium (`playwright install --dry-run`, Puppeteer's `PUPPETEER_REVISIONS`);
    - CI images and install steps;
    - production services that render HTML in a headless browser (`npm ls --omit=dev`);
    - operator machines, through personal-opsec C7.
  - **Affected test.** The usual three-part test, mapped to browsers: platform, what the browser loads, and what launched it. A macOS-only CVE doesn't affect Linux CI, but the same Chrome release usually fixes renderer bugs that do. Server-side renderers count as loading untrusted content, and `--no-sandbox` is flagged whatever the version.
  - **Patch table and board:** Playwright, Puppeteer, `@sparticuz/chromium`, CI images pinned by digest, operator machines (restart sessions after updating). A separate board puts production renderers first.
  - **Prevention:** grouped dependency bumps, a weekly CI-image Chromium check, operator reminders.

### 1.62.0 (2026-10-30)

agent-supply-chain-audit checks the browser each extension launches (#218). agent-supply-chain-audit 1.1.0.

**Added**
- **RT1, bundled browser is behind** (`references/browser-runtimes.md`):
  - A recognizer table for extensions that bring Chromium: Playwright MCP, Puppeteer servers, agent-browser, `chrome-devtools-mcp`'s executable-path overrides, skills that tell users to install a browser, and computer-use servers that hold Accessibility themselves.
  - A grep that finds them.
  - The severity ladder. Below a known-exploited or sandbox-escape fix: High with untrusted browsing from an app holding Accessibility, Medium with untrusted URLs alone, Low for localhost only. More than 2 majors behind with no named CVE: `needs_validation`. Remote browser services are out of scope.
- **RP1 and RT1 together.** A pinned browser server needs an update budget. Once its Chromium is more than one major behind stable, bumping the pin is a security fix, so the inventory records the pin date.
- **BH4:** `PLAYWRIGHT_BROWSERS_PATH`, `PUPPETEER_EXECUTABLE_PATH`, `AGENT_BROWSER_EXECUTABLE_PATH` and `--executablePath` choose which binary runs. A target in the repo or `/tmp` is its own finding.
- The inventory gains a **Runtime** column, and there are cross-references to `personal-opsec` C7 and `patch-sweep`.

### 1.61.0 (2026-10-30)

personal-opsec checks the Chromium builds that agent tools download (#217). personal-opsec 1.1.0.

**Added**
- **C7, agent browser runtimes.** Playwright, Puppeteer, agent-browser and the browser MCP servers download their own Chromium, and it never updates on its own. C7 lists every cached build and whether it's running, compares each with Chrome for Testing stable, and asks which apps hold Accessibility, Input Monitoring or Screen Recording.
  - **Below a known-exploited or sandbox-escape fix:** High if it's launched with Accessibility or browses untrusted sites, Medium if it only loads localhost.
  - **More than 2 majors behind stable:** Medium.
  - **Accessibility on its own:** a hardening note.
  - **Worked example: CVE-2026-106378**, a macOS GPU-process sandbox escape. It was fixed in Chrome 155 per the pwn.ai write-up. On 2026-10-30 it wasn't in CISA KEV (EPSS 0.003).
- **Local checks** (`references/local-checks.md`):
  - An inventory loop. On macOS it reads versions from the app bundle with `defaults read`, which runs nothing.
  - A `pgrep` count of running builds.
  - Project-local browser paths to Glob.
  - How to ask for the Accessibility grants without requesting Full Disk Access.
  - An update-and-clean table for Playwright, Puppeteer, agent-browser and the MCP servers.
- P0 and P1 entries, and a hand-off to agent-supply-chain-audit.
- **Pre-approved:** `defaults read` and `pgrep -fl`. A browser's `--version` runs the binary, so it prompts.

**Fixed (against the issue draft)**
- `npx playwright uninstall` removes the current install's browsers, not unused revisions; Playwright already removes unneeded builds on its own. The table now says so.
- agent-browser's docs don't name its download folder, so the loop searches `~/.agent-browser` and the table points to its config.
- agent-browser updates with `agent-browser upgrade`.

### 1.60.0 (2026-10-30)

scanner-pipeline adds Betterleaks, with a converter for its reports (#216). scanner-pipeline 1.1.0, secrets-audit 1.3.1.

**Added**
- **Betterleaks in the pipeline.** It's a secrets option alongside gitleaks: the two use the same rule ids and both honour `gitleaks:allow`. The default command is detection-only and silent, and it's pre-approved as an exact rule.
- **`betterleaks-to-findings.mjs`** (`scanner-pipeline/references/`). Betterleaks v2 dropped SARIF, so this converts a v2 JSON or JSONL report to `findings.json`; `to-sarif.mjs` then exports it.
  - It builds one record per rule and value, so the same key in several files is one finding with one evidence entry per place.
  - The fingerprint is the existing dedupe key, `secret:<rule>:<value hash[:12]>`, taken from `match.fingerprint`. It still works on `--redact` reports and with HMAC fingerprints.
  - Every record is imported as `needs_validation`.
  - It refuses a report that isn't redacted, and paths that aren't repo-relative.
  - Six tests run against real output from 2.0.0-rc.6.
- **Fleet secrets in one process:** `betterleaks github … https://github.com/<org>` replaces the clone loop. It prompts.
- **Betterleaks in CI**, written up for when v2 is stable:
  - pin the image by digest;
  - never validate in CI, since on a fork's PR that would send planted keys out;
  - read `.betterleaks.toml` from the base branch, so a PR can't switch off its own rules;
  - use HMAC fingerprints;
  - convert, then upload SARIF.

**Changed**
- The secrets dedupe note is honest now. gitleaks `--redact` and trufflehog with `Raw` stripped don't keep the value, so they can't produce the value hash; Betterleaks can.

**Fixed**
- secrets-audit: every Betterleaks command now passes `--silent`. Running 2.0.0-rc.6 showed it prints every finding to the terminal even when `-o` is set. With `--redact` the values are masked, but paths and commit authors still landed in the transcript. The safety rule now says so.

### 1.59.0 (2026-10-30)

secrets-audit scans for secrets beyond the repo (#215). secrets-audit 1.3.0, container-audit 1.2.1.

**Added**
- **Beyond the repo** (`secrets-audit/references/beyond-the-repo.md`): Betterleaks v2 commands for the places keys leak outside git:
  - GitHub issues, PRs, discussions, Actions logs and artifacts, releases and their assets, and gists, with the exact `--include` values from Betterleaks' scanning guide.
  - GitLab issues, MRs, releases and CI jobs.
  - Container images by digest. The scan reports files a later layer deleted or replaced, and names the layer that hid them.
  - A second pass over agent transcripts that catches generic secrets. Only counts and locations are read back, never the matching lines.
  - Hugging Face repos, discussions and PRs, and S3/R2 buckets.
- **Cleanup by surface.** A table for each place a key can leak: how to clean it up, and whether it can be purged at all. Examples: a comment's edit history, run logs, artifacts, secret gists that are only unlisted, deleted image layers. Rotation still comes first.
- **`ext.surface`** records where each key was found: `repo-head`, `git-history`, `issue`, `pr`, `actions-log`, `image-layer`, `transcript`, `bucket` and others.
- **Authorization:** remote sources only for accounts the user owns and names, with their own token. None of these commands is pre-approved.

**Changed**
- container-audit points image-layer secrets to secrets-audit.

### 1.58.0 (2026-10-30)

secrets-audit uses Betterleaks as its main scanner (#214). secrets-audit 1.2.0.

**Added**
- **Betterleaks** (`secrets-audit/references/betterleaks.md`): the scanner from gitleaks' original author and maintainers. It has fewer false positives on generic secrets, built-in liveness checks (`-v`), identity and permission analysis (`-a`), and value fingerprints that dedupe. The reference covers:
  - **Versions.** v1.9.0 is the latest stable release and v2 is at release candidate, so there's a flag table for both. In v2, `-v` means validate, where in v1 it meant verbose, and the config file isn't read unless you pass `--config`.
  - **Six safety rules.** Every scan is explicitly detection-only (`--validate=false --analyze=false`), so a stray `BETTERLEAKS_VALIDATE=true` can't make the agent use a key. `-v`, `-a`, `validate` and `analyze` run only after asking. Always `--redact`, and write the report to a file, never the terminal. Remote sources use the network even in detection-only mode. Never run `revoke`. Keep the value off the command line.
  - **Reading the report:** the JSON and JSONL report shapes, and HMAC fingerprints for anything that leaves the machine.
  - **Mapping to findings:** the verdict mapping (`unknown` is `needs_validation`, not `invalid`) and six `ext` keys.
- **Triage:**
  - Step 2 checks liveness by re-scanning the file with `-v`.
  - Step 4 gets identity and permissions from `-a`.
  - Step 5 confirms the old key is dead after rotation (`invalid` on a re-scan).
- **Pre-approved:** `betterleaks version`, `config show ids`, and the exact detection-only default scan. Liveness checks prompt.

**Changed**
- The Tooling table puts Betterleaks first, and keeps gitleaks for repos that already have a `.gitleaks.toml` or a pre-commit hook.

### 1.57.0 (2026-10-30)

Lint: secret scanners that check found keys must prompt. secrets-audit 1.1.5, scanner-pipeline 1.0.5. Groundwork for #214 and #216.

**Added**
- **Lint: credential checkers.** `grant-check.mjs` now fails any wildcard grant on `trufflehog` or `betterleaks`, and any exact rule that verifies (trufflehog without `--no-verification`; betterleaks with `-v`, `-a`, `validate` or `analyze`). Checking a found key sends it to the provider, which uses it, and the skills already say to ask first. A self-test covers it.

**Fixed**
- secrets-audit pre-approved `trufflehog git:*`, and scanner-pipeline pre-approved `trufflehog:*`. trufflehog verifies every candidate by default, so the agent could use a leaked key without asking, against secrets-audit's own Authorization rule. Both grants are gone, so trufflehog prompts.
- secrets-audit's trufflehog commands now pass `--no-verification` for detection, and the Tooling row says verification needs a yes first.

### 1.56.0 (2026-10-29)

container-audit checks the distro's own answer for OS-package CVEs (#207, part 5 of 5). container-audit 1.2.0, dependency-audit 1.3.2. This finishes #207.

**Added**
- **Vendor severity** (`container-audit/references/vendor-severity.md`). Trivy rates OS packages mostly by NVD. RHEL/UBI, Debian and Ubuntu backport fixes without changing the upstream version, so the skill now checks the vendor's state for the image's release first:
  - **Red Hat:** the Security Data API (`threat_severity`, per-product `fix_state`, and RHSA fixed versions).
  - **Debian and Ubuntu:** OSV's distro ecosystems, one query per package and version. Debian's tracker page gives per-CVE notes. Its full JSON export is 87 MB, so the skill doesn't use it for lookups.
- **Verdict mapping:**
  - "Not affected", or a backported fix already installed, is `rejected` with the vendor statement saved as evidence. That's the common trivy false positive on UBI images.
  - "Affected" or "Fix deferred" leaves the finding to the reachability rule.
  - "Will not fix" leaves it standing; the plan is a new base image or the owner's `Accepted Risk`. The vendor's call is input, not the decision.
- New `ext` keys: `vendor`, `vendor_severity`, `vendor_fix_state`, `vendor_advisory`. container-audit also gets `enrich-advisories.mjs`, so OS-package CVEs get KEV and EPSS too.
- `WebFetch` pre-approved for the Red Hat API; OSV queries are POSTs and prompt. docs/security-scanning.md and the SkillSpector baseline are updated.

**Fixed**
- dependency-audit's exploitation-signals reference linked to a 404 EPSS docs URL; it now points at `https://api.first.org/epss/`.

### 1.55.0 (2026-10-29)

A shared script that adds KEV and EPSS to findings, and SARIF that shows them (#207, part 4 of 5). dependency-audit 1.3.1, patch-sweep 1.1.1.

**Added**
- **`shared/enrich-advisories.mjs`** (copied into dependency-audit and patch-sweep). Usage: `node references/enrich-advisories.mjs findings.json -o findings.json`. For each record with an advisory id (the fingerprint's second segment, or `ext.advisory_ids`) it:
  - resolves CVE ids through OSV aliases
  - downloads the CISA KEV catalog once
  - batches EPSS 100 CVEs per call
  - writes the `ext` keys from dependency-audit's exploitation-signals reference

  It doesn't need any packages, and uses Node's built-in `fetch`. It sends advisory and CVE ids only. It never changes a verdict, severity or disposition, and it re-validates before writing. A failed lookup or `--offline` writes `not checked` and exits 1, so the gaps get reported. `--kev` takes a downloaded catalog.
  - Checked live against the example run's 27 records: 26 advisories enriched in about 5 seconds, and the output validates.
  - Tests use canned responses and need no network.
- **SARIF:** `to-sarif.mjs` tags KEV-listed results `kev` (on the rule and the result) and copies a numeric `ext.epss` to `properties.epss`, so code scanning shows both.

**Changed**
- dependency-audit's `references/exploitation-signals.md` leads with the script; the manual commands stay for checking one advisory by hand. patch-sweep Step 4 points to it, and patch-sweep now gets `validate-findings.mjs`, which the script imports.
- SkillSpector baseline: shared-copy rules for the script's OSV and EPSS calls, and the scanner's parse limit on it, each with a reason.

### 1.54.0 (2026-10-29)

patch-sweep orders the fleet by exploitation (#207, part 3 of 5). patch-sweep 1.1.0.

**Added**
- **Step 4: exploitation signals, once for the whole advisory set.** When the affected rows are known, look up each advisory in CISA KEV and EPSS once, not per repo, using dependency-audit Step 2b's commands. Offline: `not checked`, never from memory.
- **Status board `kev` column, and a sort order:** KEV first, then crit/high, then EPSS. A KEV-listed medium goes above an unexploited critical. The example board is reordered to match.
- **Step 5: a KEV-listed advisory with a slow patch path needs a mitigation entry before moving on.** A slow path is a major upgrade, a client approval, or a frozen branch. The entry is a control you applied, or a written reason none exists.
- `WebFetch` pre-approved for the public feeds; docs/security-scanning.md lists it.

**Changed**
- The board header's **Advisories** field records KEV (yes/no and date added) and EPSS next to the ids and fixed versions.

### 1.53.0 (2026-10-29)

dependency-audit ranks advisories by exploitation, and can find them without a scanner (#207, part 2 of 5). dependency-audit 1.3.0.

**Added**
- **Step 2b: Enrich with Exploitation Signals.** For every advisory, get its CVE id (OSV `aliases` maps a GHSA id), then check CISA KEV (one catalog download per run, matched on `cveID`) and EPSS (one call per 100 CVEs). Record KEV date added, due date and ransomware use, and the EPSS score, percentile and date. Offline, write `not checked`; never infer KEV status from memory. Advisories with no CVE are kept and marked "no CVE".
- **`references/exploitation-signals.md`.** It has the commands (KEV, EPSS, OSV, and GitHub's advisory API, whose EPSS is under `epss.percentage`) and three worked examples:
  - React Server Components CVE-2025-55182: KEV-listed, ransomware use Known
  - Next.js CVE-2025-29927: EPSS 0.992
  - a lodash medium: EPSS 0.003

  It also has the report column legend, and nine `ext` keys for `findings.json` (`advisory_ids`, `in_kev`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use`, `epss`, `epss_percentile`, `epss_date`, `reachability`), so no schema change is needed. Every endpoint was rechecked on 2026-10-29: KEV catalog 2026.10.29 has 1,764 entries.
- **No-scanner fallback.** Lockfile `name@version` pairs go to the OSV batch API, then OSV details, then KEV and EPSS. The report header says `Scanner: none (OSV API fallback)`. Because the batch call sends package names to OSV, a private repo with sensitive internal package names needs the owner's OK first.
- **`WebFetch` pre-approved** for the public feeds, as vuln-research has. The OSV batch POST goes through `curl` and prompts.

**Changed**
- **Known Vulnerabilities table:** new KEV and EPSS columns.
- **Prioritized Action Plan:** the order is now explicit:
  1. KEV-listed and runtime-reachable
  2. KEV-listed, build- or dev-only
  3. Critical/High with EPSS above 0.7
  4. the remaining Critical/High, by EPSS
  5. Medium
  6. Low
  - It ends with a "Signals not checked" line so a partial ordering is visible. The old plan opened with "actively exploited CVEs" without any step that checked.
- **Trimmed to fit SkillSpector's size limit.** The package-manager traps and the verify-after-fixing checklist are now short pointers to `references/fixing-safely.md`, which already had both in full.
- **SkillSpector baseline:** two E1 rules for the OSV and EPSS calls, each with a reason. docs/security-scanning.md lists the new grant.

### 1.52.5 (2026-10-29)

Exploitation signals in the shared severity calibration (#207, part 1 of 5). Shared doc only; the 22 skills that copy `severity-calibration.md` get it at build time.

**Added**
- **Exploitation signals** (`severity-calibration.md` §2). For a finding that rests on a published advisory, check CISA KEV (being exploited now) and EPSS (likelihood of exploitation in the next 30 days):
  - KEV-listed: likelihood is High.
  - EPSS above 0.7: High. 0.1 to 0.7: Medium. Below 0.1: use the CVSS exploitability metrics. These match vuln-research's cut points.
  - The signals change likelihood and the order of work, never severity above demonstrated impact.
  - KEV plus runtime reachability plus a traced path is the strongest case for High/Critical.
  - A KEV-listed CVE in a build- or dev-only package stays capped by impact but moves to the top of its band.
  - A failed lookup is recorded as `not checked`; KEV status is never inferred from memory.

Thanks to @coreyhaines31 for the issue.

### 1.52.4 (2026-10-27)

README skill map: the connector lines are now drawn from the column positions. Docs only.

**Fixed**
- The arrows above the family boxes were hand-drawn for an older layout. There were eight arrows for seven columns, so the last one pointed at nothing, and the joins above and below the boxes didn't line up. Now every arrow lands on a column, and both joins meet the trunk cleanly.

### 1.52.3 (2026-10-27)

prompt-injection description names indirect injection through what an agent reads (a malicious web page in a browsing agent; emails, documents or tickets reaching an agent that can act). prompt-injection 1.2.1.

**Changed**
- prompt-injection: description wording only. "Can a malicious web page hijack our browsing agent?" and "our agent reads incoming emails and can send replies" now route here instead of log-watch and threat-modeling. Offline trigger eval: should-fire 216 → 218 of 228. Its overlap with ai-risk-management drops from 0.45 to 0.40.

### 1.52.2 (2026-10-27)

incident-triage description names what a live incident looks like (ransomware on a file server, an attacker still in the network, an unexpected new admin user, a host compromised through a CVE). incident-triage 1.1.2.

**Changed**
- incident-triage: description wording only. All four of its trigger-eval misses now route here: two should-fire prompts that went to agent-supply-chain-audit and log-watch, and two near-misses that went to breach-patterns and patch-sweep. Offline trigger eval: should-fire 214 → 216 of 228, near-miss 217 → 219 of 221, nothing lost.

### 1.52.1 (2026-10-27)

fuzzing-harness description: says "fuzzer" and "file and packet parsers in C, C++, Rust, Go, Python or JS", so "write a fuzzer for our C packet parser" stops going to native-code-review. fuzzing-harness 1.0.1.

**Changed**
- fuzzing-harness: description wording only. Offline trigger eval: should-fire 213 → 214 of 228, nothing else moved.

### 1.52.0 (2026-10-27)

iam-audit gets a defender-side review of paths to Tier 0 in Active Directory and Entra ID (#138). iam-audit 1.2.0.

#138 asked for a new offensive skill, `ad-attack-paths`. This lands the part defenders need instead, inside iam-audit, which already owns AD and Entra: find every path from an ordinary user to Tier 0, and the change that closes it. Nothing is exploited. A live demonstration stays with authorized engagements under red-team-engagement.

**Added**
- **Active Directory and Entra ID: paths to Tier 0** (Mode 1), with `references/ad-tier0-paths.md`:
  - a Tier 0 inventory for on-prem AD and Entra / hybrid (DCs, AD CS, AD FS, DCSync rights, DC-linked GPOs, Entra Connect, privileged roles, Graph-permissioned apps)
  - getting the paths: prefer exports the team already has (BloodHound / AzureHound, PingCastle, Defender for Identity, Secure Score). New collection needs the directory owner's yes, every time, because it's noisy and may alert. Includes native read-only PowerShell queries for the common classes.
  - eleven exposure classes, each with what makes it a path and the fix that closes it: privileged nesting, control rights over Tier 0 objects, SPN service accounts, pre-authentication disabled, unconstrained delegation, certificate templates, local admin reuse, GPO edit rights, stale admins, the hybrid bridge, and app permissions
  - verdict rules: `confirmed` needs every edge shown in saved directory data and caps confidence at medium, because nothing is exercised. A path from Domain Users or all tenant users to domain or tenant control is critical. Fingerprints are `iam-audit/<class>/<directory>/<tier0-object>`, with new `ext` keys and a new `ad` provider value.
- **SkillSpector baseline.** Two narrow YR4 rules for the tool names in this section, each with a reason.

### 1.51.0 (2026-10-27)

The lint checks `#anchor` links (repo tooling). No skill changes.

**Added**
- **Anchor check.** `lint-skills.mjs` fails a markdown link whose `#anchor` names no heading in the target `.md` file, using GitHub's slug rules (lowercase, punctuation dropped, spaces to hyphens, `-1` / `-2` for repeated headings) plus explicit `<a id>` / `<a name>` targets. It checks SKILL.md, every skill's `references/` at any depth, and `shared/`. Renaming a heading, as the OWASP 2025 renumbering did, now breaks the build instead of quietly breaking links. All 58 existing anchor links resolve. A self-test covers it.

### 1.50.1 (2026-10-27)

Repo tooling and docs cleanups after the v1.37.0–v1.50.0 build. No skill changes.

**Added**
- **Lint: trailing-flag writers.** `grant-check.mjs` now fails any wildcard grant on `gh api`, `exiftool` or `floss`, however specific the prefix, because a trailing flag turns each into a write: `-X` / `-f` send a write request, `-TAG=` rewrites file metadata, and `--install-right-click-menu` changes the Windows registry. Use an exact rule or none. No current skill grants these, and a self-test covers it.

**Fixed**
- `evals/README.md`: skill count and current trigger-eval results (42 skills: should-fire 93.4%, near-miss 98.2%).
- The VERSIONS.md note for 1.50.0 said the router table has 37 rows; it has 36.

### 1.50.0 (2026-10-27)

New skill: security-start, a router for vague asks (#131). security-start 1.0.0.

**Added**
- **security-start 1.0.0.** For asks with no shape ("make this secure", "where do I start?"). It takes a quick read-only look at the repo, then asks at most three questions: what you have, what's happening, and who the result is for. Then it hands off to one to three skills from the catalog, in order. A 36-row table maps situations to a first skill and its follow-ups and covers all 41 other skills. An active incident skips the questions and goes straight to incident-triage. Routing to an offensive skill always comes with a note that it needs written authorization. It does no auditing itself and has no SessionStart hook, so it costs nothing in sessions that don't use it.
- **Doesn't steal triggers.** Its description claims only vague phrases and tells the model to use the named skill whenever the ask names a framework, target or tool. On the offline trigger eval it takes no other skill's prompts and wins all six of its own.
- README: new row, map cell, crossover line, and a "Not sure?" bullet at the top of "Where to start".

### 1.49.0 (2026-10-27)

control-audit adds NIST SP 800-53 Rev. 5 and FedRAMP (#140). control-audit 1.2.0. This finishes #140.

**Added**
- **NIST 800-53 and FedRAMP** (`references/nist-800-53.md`). It covers:
  - SP 800-53 Rev. 5 (Release 5.2.0), with the control families and the SP 800-53B Low / Moderate / High baselines
  - the SSP, SAR and POA&M artifacts, and OSCAL
  - FedRAMP's 2026 changes: the Consolidated Rules (mandatory from 1 January 2027), Classes A–D replacing Low/Moderate/High, the Rev5 certification sunset, and 20x Key Security Indicators
  - facts that rest only on secondary sources are marked "(verify)"
- Control enhancements are written with a dot in fingerprints (`AC-2(1)` → `AC-2.1`), because the validator doesn't allow parentheses.
- The skill's scope step and trigger phrases cover NIST 800-53 and FedRAMP.

### 1.48.0 (2026-10-27)

control-audit adds ISO/IEC 27001:2022 (#140). control-audit 1.1.0.

**Added**
- **ISO 27001** (`references/iso27001.md`): management-system clauses 4–10 and the Statement of Applicability. The 93 Annex A controls are grouped in the four themes, with the 11 controls that are new in 2022 marked. It also covers Amendment 1:2024 and the end of the 2013 transition on 31 October 2025. Control titles are paraphrased, not reproduced, because ISO text is copyrighted.
- The skill's scope step and trigger phrases cover ISO 27001.

### 1.47.0 (2026-10-27)

New skill: control-audit, starting with SOC 2 (#140). control-audit 1.0.0. Back-references: csf-mapping 1.0.3, pci-audit 1.1.1, hipaa-audit 1.1.1.

#140 asked whether SOC 2, ISO 27001 and NIST 800-53 / FedRAMP should be one skill or three. They're one skill, with a reference file per framework, because the workflow is the same and three skills would fight over the same trigger phrases. pci-audit and hipaa-audit stay separate because they review code.

**Added**
- **control-audit 1.0.0.** Control-level audit readiness:
  - scope the audit: framework, criteria, systems in scope, audit period, Type 1 vs Type 2
  - build the control inventory, and write an evidence request per control: what artifact, from whom, which sample period, and how it's tested (inquiry / observation / inspection / reperformance)
  - test what the repo and config can show, read-only, and hand technical checks to the owning skill (cloud-audit, iam-audit, siem-detection, ...)
  - record control gaps in the shared findings format. A gap is `confirmed` only with evidence that the control is missing or failing. Evidence held by a person or system the agent can't read goes to `needs_validation`, with the evidence request as the validation plan. An evidenced control is `rejected`.
  - rate severity by exposure, not audit-opinion risk; pure documentation gaps go in their own section
- **SOC 2** (`references/soc2.md`): the 2017 Trust Services Criteria with the 2022 revised points of focus (CC1–CC9 plus Availability, Confidentiality, Processing Integrity and Privacy), common evidence by criterion, and Type 1 vs Type 2.
- Output: a control matrix, an evidence-request list, findings and documentation gaps. Fingerprints are `control-audit/<framework>/<control id>/<scope>`, with `ext` keys for the framework, control id, test method and evidence request. Crosswalks go through csf-mapping.

**Changed**
- csf-mapping points readiness work for SOC 2 / ISO 27001 / FedRAMP to control-audit. pci-audit and hipaa-audit cross-reference it.
- README: new row, map cell, crossover line, and a "Where to start" mention.

### 1.46.0 (2026-10-27)

New skill: malware-triage (#139). malware-triage 1.0.0. Back-references: incident-triage 1.1.1, disk-forensics 1.0.2, threat-hunting 1.0.5, siem-detection 1.0.5.

**Added**
- **malware-triage 1.0.0.** Static triage of a suspicious file without running it. It covers:
  - **Safe handling first:** never execute the sample on the analyst's machine; work on a copy in an isolated VM. Private samples aren't uploaded to public services without the owner's yes, because that can tip off the attacker and leak data. Lookups by hash are fine.
  - **Identity and reputation:** hashes (SHA-256, imphash, ssdeep / TLSH) and reputation lookup by hash.
  - **Static analysis:** file type, entropy and packers, strings and FLOSS, and per-format triage for PE / .NET, ELF and Mach-O.
  - **Scripts and documents:** deobfuscating scripts and Office macros (PowerShell, JS, VBA via olevba), plus archives, ISO, LNK and OneNote containers.
  - **Behaviour:** capa capabilities mapped to MITRE ATT&CK.
  - **Indicators:** exported as defanged CSV or STIX 2.1.
  - **YARA rules:** tested against the sample and a goodware set.
  - **Hand-offs:** to siem-detection and threat-hunting.
- Dynamic analysis only points to a sandbox (CAPE, ANY.RUN, Joe Sandbox, Hybrid Analysis) and notes the privacy trade-off.
- **Output:** a Malware Triage Report, not `findings.json`. A verdict on a third-party file has no fix or disposition. The verdict is malicious / suspicious / likely benign / unknown, with confidence and a numbered evidence table, and "likely benign" is capped at medium confidence. Weaknesses the triage finds in the user's own systems go to the owning audit skill as findings.
- **Grants:** read-only commands only (`file`, `strings`, hashing, `yara`, `capa`, `olevba`, `readelf`, `objdump`, three `otool` forms). FLOSS and exiftool aren't pre-approved, because each has a flag that changes the system or the file.

**Changed**
- incident-triage, disk-forensics, threat-hunting and siem-detection point to malware-triage.
- README: new row, map cell, crossover line, and a "Where to start" mention.

### 1.45.0 (2026-10-27)

New skill: fuzzing-harness (#137). fuzzing-harness 1.0.0. Back-references: native-code-review 1.0.1, web-pentest 1.2.1, crypto-audit 1.1.2.

**Added**
- **fuzzing-harness 1.0.0.** Writes and runs fuzz harnesses and property-based tests for the code that handles untrusted bytes: parsers, decoders, serializers, deserializers, token and header parsing, protocol state machines.
  - **Ranks targets** by what they parse and where the input comes from.
  - **Harnesses:** libFuzzer, cargo-fuzz, Go native fuzzing, Atheris, Jazzer.js and Jazzer. Templates are in `references/harness-templates.md`.
  - **Property-based tests:** Hypothesis, fast-check and proptest, with useful properties: round-trip, invariants, differential against a reference, no crash on arbitrary input.
  - **Runs:** seed corpora and dictionaries, sanitizer builds, timeouts.
  - **Crashes:** each one is reproduced, minimized, deduped by stack and triaged into `findings.json`. A crash input that reproduces sets `reproduced: true`; `references/crash-triage.md` maps sanitizer reports to crash class and CWE. Each crash becomes a regression test.
  - **CI:** regression replay on every PR, short PR fuzz runs, ClusterFuzzLite, and OSS-Fuzz eligibility (`references/ci-integration.md`).
- Write is granted because harness, test, corpus and CI files are the main output. There are no Bash grants: installs, builds and fuzz runs execute the project's code, so they always prompt.
- An unfixed memory-safety crash input is never committed to a public repo, and public CI artifacts are treated as public.

**Changed**
- native-code-review hands dynamic confirmation to fuzzing-harness by name. web-pentest separates live HTTP fuzzing from code-level harnesses. crypto-audit points to it for round-trip and tamper-rejection property tests.
- README: new row, map cell and crossover line.

### 1.44.0 (2026-10-27)

New skill: native-code-review (#135). native-code-review 1.0.0. Back-references: crypto-audit 1.1.1, mobile-audit 1.1.1, vuln-research 1.0.4.

**Added**
- **native-code-review 1.0.0.** Memory-safety review of C, C++ and Rust source, parsers of untrusted input first. Each candidate is traced from where untrusted bytes enter to the memory operation that goes wrong. It covers:
  - out-of-bounds reads and writes
  - integer overflow, truncation and sign confusion that feed a size
  - use-after-free and double free
  - format strings, and uninitialized memory
  - Rust `unsafe` soundness (safety comments, `Send`/`Sync` impls, `transmute`, `set_len`, raw-pointer aliasing)
  - FFI boundaries
  - secrets not wiped from memory
- `references/bug-classes.md` has 11 bug classes, each with CWE ids, `rg` and portable grep patterns, and what rules a hit out or confirms it. The patterns were tested on sample C, C++ and Rust files. Also new: `references/rust-unsafe-checklist.md`, and `references/hardening-and-sanitizers.md` (OpenSSF compiler flags with minimum versions, `readelf` / `checksec` checks, ASan / UBSan / MSan / TSan and Miri runs).
- Calibration rules:
  - A missing hardening flag is always a hardening note, never a finding.
  - A missing wipe is a finding only when wiping is a documented guarantee or there's a traced leak path.
  - Unsound Rust in a published library's safe API is a finding even without an app-level path.
  - Titles never say "remote code execution" unless it was shown.
- Only `readelf` and `checksec file` are pre-approved. Building, tests, sanitizers, Miri and `cargo geiger` always prompt, because building runs the project's build scripts. Dynamic work stops at a sanitizer or Miri report.

**Changed**
- crypto-audit, mobile-audit (native libraries) and vuln-research (reachability for C, C++ and Rust libraries) point to native-code-review.
- README: new row, map cell and crossover line.

### 1.43.0 (2026-10-27)

New skill: variant-analysis (#136). variant-analysis 1.0.0. Back-references: finding-triage 1.3.1, scanner-pipeline 1.0.4, siem-detection 1.0.4.

**Added**
- **variant-analysis 1.0.0.** Starts from one confirmed finding and hunts its siblings:
  - pin down the original
  - write an exact-match rule, then widen it one element at a time
  - write the rule with tests: a Semgrep rule with `ruleid:` / `ok:` annotations and `semgrep --test`, a CodeQL query with a test pack and `.expected` file, or a nuclei v3 template for variants only visible over HTTP. The nuclei template only sends GET, needs both a status and a planted marker to match, and is checked against a known-bad and a known-fixed host first.
  - run it on one repo, or across the org via patch-sweep
  - close every hit with a verdict, linked to the original through `ext.variant_of`
  - hand the rule to scanner-pipeline so the bug can't come back
- Ships a tested Express IDOR rule (`references/rules/express-idor-param-lookup.yml` and its fixture; `semgrep --test` passes). The end-to-end example starts from the owasp-audit example's IDOR and finds one more hit in `examples/target`, rejected because `requireAdmin` guards it.
- Grants are exact Semgrep commands only (`--test`, `--validate`, one fixed `scan`), so `--autofix` is never pre-approved. CodeQL and nuclei always prompt. Write is granted because rule files are the main output.
- The CodeQL skeleton follows GitHub's docs but hasn't been compiled. The reference says to run `codeql test run` before trusting it.

**Changed**
- finding-triage, scanner-pipeline and siem-detection point to variant-analysis (siem-detection keeps log rules, variant-analysis takes rules over code and HTTP).
- README: new row, map cell and crossover line.

### 1.42.0 (2026-10-27)

New skill: cicd-security (#134). cicd-security 1.0.0. Back-references: dependency-audit 1.2.4, secrets-audit 1.1.4, scanner-pipeline 1.0.3, agent-supply-chain-audit 1.0.2, iam-audit 1.1.1.

**Added**
- **cicd-security 1.0.0.** Reviews CI the way you'd review authorization code. For every job, it asks one question: can someone with less trust than the job (a fork PR author, any commenter, a third-party action maintainer) change what it runs or reads, and what does the job hold when they do? It covers:
  - `pull_request_target` and `workflow_run` running untrusted code ("pwn requests"), including GitHub's December 2025 change to `pull_request_target`
  - expression injection from `${{ github.event.* }}` into `run:` steps
  - missing or broad `permissions:`
  - third-party actions not pinned to a commit SHA
  - OIDC trust policies with wildcard or missing `sub` conditions (AWS, GCP, Azure)
  - self-hosted runners on public repos, and secrets reaching forks
  - cache poisoning, and artifacts trusted across workflows
  - publish jobs without a protected identity
  - **AI agents in CI** (claude-code-action and similar): who can trigger them, what issue and PR text reaches them, and what token, tools and secrets they hold
  - GitLab CI and CircleCI equivalents, briefly
- Runs zizmor (`--offline`) and actionlint read-only, using exact grants only, because a wildcard would also allow `zizmor --fix` or `actionlint -init-config`. There's no `gh api` grant, because a trailing `-X` or `-f` can turn a read into a write.
- Writes `findings.json` with fingerprints `cicd-security/<class>/<workflow file>/<job>`, and `ext` keys for the trigger, job, lower-trust actor, token permissions and secrets in scope. Settings that live only on the platform (fork-PR approval, branch protection, cloud trust policies) go to `needs_validation`, along with the command that answers them. Worked examples cover each verdict.

**Changed**
- dependency-audit hands workflow security to cicd-security. Its Step 5 GitHub Actions bullets and Step 5b handoffs 1–4, 7 and 8 now point there. It keeps release-artifact identity and independent checksums, and drops the 'GitHub Actions security', 'cache poisoning' and 'OIDC trust policy' trigger phrases. A trigger-eval prompt about workflow review moves to cicd-security.
- secrets-audit, scanner-pipeline, agent-supply-chain-audit and iam-audit gain cross-references to cicd-security.
- README: new row, map cell, crossover line, and a "Where to start" mention.

### 1.41.0 (2026-10-27)

owasp-audit framework playbooks, part 3: Django and Rails (#132). owasp-audit 1.6.0. This finishes #132.

**Added**
- **Django** (`frameworks/django.md`): unscoped querysets and DRF object permissions, serializer and ModelForm mass assignment (`fields = '__all__'`), `**request` expansion into ORM filters (CVE-2025-64459), `raw()` / `extra()` / cursor SQL, `mark_safe`, and production settings (`DEBUG`, `SECRET_KEY`, allowed hosts).
- **Rails** (`frameworks/rails.md`): unscoped `find` and missing `authorize`, `permit!` and broad permit lists (and Rails 8 `params.expect`), interpolated SQL and `order()`, `html_safe` / `raw` and other output sinks, and credentials and production config.
- Mass assignment is tagged A08:2025 (CWE-915), following OWASP's mapping, or A01 when the assigned field is an owner or tenant key.

### 1.40.0 (2026-10-27)

owasp-audit framework playbooks, part 2: Firebase and Electron (#132). owasp-audit 1.5.0.

**Added**
- **Firebase** (`frameworks/firebase.md`): open and test-mode rules, `request.auth != null` as the only check, field allowlists on writes, Storage rules versus bucket IAM, Cloud Functions identity, and what API key restrictions and App Check do and don't protect.
- **Electron** (`frameworks/electron.md`): `webPreferences` (contextIsolation, nodeIntegration, sandbox, webSecurity), what the preload bridge exposes, IPC sender and argument checks, navigation and `shell.openExternal`, deep links, fuses, CVE-2025-55305, and update signing.

### 1.39.0 (2026-10-27)

owasp-audit gets framework playbooks, part 1: Next.js and Supabase (#132). owasp-audit 1.4.0.

**Added**
- **Framework detection.** Recon detects frameworks from package.json dependencies and config files, then loads only the matching playbook from `references/frameworks/`. Playbook findings use the normal Top 10:2025 categories, ledger units and findings format.
- **Next.js** (`frameworks/nextjs.md`): server actions as public POST endpoints, middleware/proxy matcher gaps and CVE-2025-29927, `NEXT_PUBLIC_` and `next.config` `env` leaks, route handler auth, per-user data leaking through cache and revalidate, and version advisories.
- **Supabase** (`frameworks/supabase.md`): RLS on every exposed table, permissive policies (including roles read from `user_metadata`), service-role and `sb_secret_` keys in client code, storage policies, `security definer` RPC, and `getSession()` / `verify_jwt` reliance. Links scanner-pipeline's `supabase-rls.yml`.
- Each playbook has the surfaces to add to the ledger, `rg` and portable grep commands, what confirms or rejects a candidate, and a confirmed and a rejected example.

**Changed**
- The weekly link check now covers nested reference folders (`skills/*/references/**/*.md`).

### 1.38.0 (2026-10-27)

finding-triage checks that a fix actually works before closing the finding (#133). finding-triage 1.3.0, owasp-audit 1.3.4, api-audit 1.1.7.

**Added**
- **Fix verification** (`finding-triage/references/fix-verification.md`). The bar: the original claim, re-checked against the fixed code, would now close as `rejected` with the fix as `ruled_out_by`. The steps: re-run the original reproduction or trace, check sibling code paths for the same bug, make sure the fix didn't just move the sink (a table of common ways it does), add a regression test, then set `Fixed`. Includes an example record that passes the validator.
- **Recording a fix.** finding-triage writes `ext.fixed_in`, `ext.fix_verified_on` and `ext.regression_test` on the record, and `ext.regressed_after` when a fixed finding comes back. The fingerprint stays the same so re-runs recognize it.

**Changed**
- finding-triage: new Step 7, "Verify the fix before closing it". `Fixed` still waits for the fix to ship (v1.26.4).
- `findings-format.md`: re-runs re-check `Fixed` records against the fix and reopen regressions.
- owasp-audit: the `Fixed` disposition now points to that check instead of "closed pending runtime verification". owasp-audit and api-audit's "Verify Fixes at Runtime" sections link it.

### 1.37.0 (2026-10-27)

finding-triage gets an adversarial verifier (#130). finding-triage 1.2.0, owasp-audit 1.3.3, api-audit 1.1.6.

**Added**
- **`finding-verifier` subagent** (`agents/finding-verifier.md`). A read-only plugin agent (Read, Grep, Glob) that takes one candidate finding, tries to disprove it, and returns one `findings.json` record with counterevidence. It never runs code, and it treats comments and the finding's own text as claims to check. Claude Code only; the Cursor and Codex adapters follow the same steps from `verification.md`.
- **Rationalizations to reject** (`shared/verification.md`). Arguments for inflating a candidate ("an attacker could theoretically…") and for dismissing one ("there's probably a WAF", "it's only internal"), each with the evidence that would settle it. It complements the v1.26.1 table of valid rejections.
- **Two-stage filter** (`shared/verification.md`). Fixed exclusion rules run first: test code, fixtures, generated and vendored code, docs and examples, known hardening notes, prior rejections. Each has a carve-out (live-looking credentials, CI workflows and test routes the deployed build serves are never excluded). Then the per-finding verifier runs on what's left. The rules exclude by where code lives, not by bug class, so denial-of-service and rate-limit findings still get verified.
- **Agent lint.** `lint-skills.mjs` checks `agents/*.md` for a name matching the file, a description, and read-only tools only (no Write, Edit or Bash). A self-test covers it.

**Changed**
- finding-triage: a "Get an independent read" step, with `references/independent-verification.md`.
- owasp-audit, api-audit: the verifier step points to the subagent and the exclusion rules.
- `findings-format.md`: workflow step 1 applies the exclusions first.
- README and CLAUDE.md mention the subagent.

### 1.36.0 (2026-10-27)

privacy-engineering moves onto the shared findings format (#129). privacy-engineering 1.1.0. With this, all ten skills on #129's list write `findings.json`. Eighteen skills now use the format.

**Changed**
- **Verify, then record.** A new section after Practice 8. A gap against a GDPR or CCPA obligation is a finding, rated by the exposure for the personal data rather than the size of a possible fine. The data subject is the affected principal.
  - **Confirmed:** account deletion that skips the Segment and Algolia deletion calls; Sentry set to send every user's email and IP; analytics loading before the user makes a consent choice.
  - **Needs validation:** whether a DPA is on file; vendor or backup retention settings.
  - **Rejected:** an erase job that reaches every vendor; a Sentry `beforeSend` scrubber; an SDK that's installed but never initialized, pointing at its dependency declaration.
- **Paperwork doesn't reject a flow.** A notice, a DPA or legal sign-off doesn't reject a data flow the code actually performs. Evidence files record field names, never personal data values.
- **Fingerprints:** `privacy-engineering/<class>/<file or resource>/<name>`.
- **`ext` keys:** `obligation` (e.g. `GDPR Art. 17(1)`), `data_class`, `processor`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)" and a "Documentation gaps (not findings)" section, and keeps the data inventory, DSAR, vendor and consent sections.
- The skill now gets copies of the six shared findings files.
- **SkillSpector baseline.** Two new rules for verdict examples that describe what to flag.

### 1.35.0 (2026-10-27)

hipaa-audit moves onto the shared findings format (#129). hipaa-audit 1.1.0.

**Changed**
- **Verify, then record.** A gap against a required Security Rule specification is a finding, rated by ePHI exposure.
  - **Addressable specs:** one with neither the control nor a documented alternative is treated like a required spec. One with a documented equivalent or rationale (§164.306(d)(3)) is `rejected`, pointing at that document.
  - **Breach status:** rejecting an addressable spec doesn't change it. Unencrypted ePHI is still "unsecured", and the report says so under Breach response readiness.
  - **Confirmed:** a shared `phi_admin` database role; Mixpanel receiving PHI with no BAA on record; a full patient record returned to a scheduling view (minimum necessary); a shipped `PHI_AUDIT_LOG=false` default.
  - **Needs validation:** a vendor's BAA status when no register was provided; RDS encryption for a console-created database, with the exact `describe-db-instances` check.
  - **Rejected:** no idle logoff, but the risk analysis documents MDM screen lock as the equivalent; a Sentry `beforeSend` hook that strips request data.
- **Encryption wording.** The "treat as required" wording on encryption is replaced by the implement-or-document rule.
- **Fingerprints:** `hipaa-audit/<class>/<file or resource>/<name>`, with 11 named classes, built from the resource rather than the evidence file.
- **`ext` keys:** `standard` (e.g. `164.312(b)`), `addressable`, `rule` (security, privacy or breach-notification).
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)", a PHI flow map and an addressable-specifications table.
- The skill now gets copies of the six shared findings files.
- **SkillSpector baseline.** One new rule: saving a redacted BAA register entry as evidence was read as session persistence.

### 1.34.0 (2026-10-27)

pci-audit moves onto the shared findings format (#129). pci-audit 1.1.0.

**Changed**
- **Verify, then record.** A gap against a PCI DSS requirement is a finding, since the requirement is the intended control. Severity rates the exposure for cardholder data, not the audit consequence.
  - **Confirmed:** `logger.info(req.body)` logging a posted `cardNumber` (Req 3.5.1); an IdP export allowing password-only sign-in to the CDE admin console (8.4.2); a shipped `LOG_REQUEST_BODIES=true` default.
  - **Needs validation:** Sentry scrubbing set in the dashboard, not the repo; whether the staging seed really runs with `--sanitize`.
  - **Rejected:** a Stripe Elements iframe where the server only reads `paymentMethodId`; a published test PAN in a fixture.
- **Compensating controls.** A compensating control rejects a candidate only when its worksheet exists and there's evidence it works. Without that evidence, it's `needs_validation`.
- **Documentation gaps (not findings).** A new report section for gaps with no exposure to card data: a missing policy, overdue training. They're kept apart from hardening notes.
- **Evidence.** IdP and MFA policies, firewall rules, log retention, AoCs and written policies go in `evidence/`. Never save PAN, CVV, track data, PIN blocks or credentials there.
- **Fingerprints:** `pci-audit/<class>/<file or resource>/<name>`, with 13 named classes. Deployed resources are fingerprinted by the resource, not the evidence file.
- **`ext` keys:** `requirement` (e.g. `8.4.2`), `scope` (cde, connected-to or security-impacting), `data_element`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)". The old audit checklist moved into the report template.
- The skill now gets copies of the six shared findings files.

### 1.33.0 (2026-10-27)

prompt-injection moves onto the shared findings format (#129). prompt-injection 1.2.0.

**Changed**
- **Step 9, "Verify, then record".** A finding is what a steered model can reach, not the fact that it can be steered.
  - **Confirmed:** a viewer-writable comment reaches an admin assistant that holds an ungated `send_email`; LLM output goes into `dangerouslySetInnerHTML`; a shipped MCP tool description carries a hidden instruction.
  - **Needs validation:** a hosted guardrail whose policy isn't in the repo; a production prompt pulled from a registry.
  - **Rejected:** an `authorize(user, tool, args)` check in the tool dispatcher; a pinned sanitizer.
- **What doesn't reject.** System-prompt instructions, delimiters, the provider's safety training and a model-based classifier on its own lower likelihood but never reject a candidate.
- **Hardening notes and the CWE.** A jailbreak that only affects the person typing is a hardening note. A leaked system prompt is a finding only if it holds a secret. Prompt injection uses CWE-1427.
- **Evidence.** Live canary transcripts and remote MCP `tools/list` output go in `evidence/`.
- **Fingerprints:** `prompt-injection/<class>/<file>/<symbol>`, with ten named classes.
- **`ext` keys:** `owasp_llm` (e.g. `LLM01:2025`), `category`, `untrusted_source`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)" and keeps the integration map, defense assessment and remediation sections. The "Potential" and "Possible" labels are gone.
- The skill now gets copies of the five shared findings files it didn't already have.
- **SkillSpector baseline.** One new rule, for the "no confirmation gate" verdict example, which describes what to flag.

### 1.32.0 (2026-10-27)

web-pentest moves onto the shared findings format (#129). web-pentest 1.2.0.

**Changed**
- **Verify, then record.** A new step after the paired-evidence rule:
  - **Confirmed:** paired evidence holds, for example a non-owner and the owner both get 200 on the same order id. A paired capture against an authorized target sets `reproduced: true`, so high confidence is allowed.
  - **Needs validation:** the isolating control wasn't captured, or a WAF, proxy or IdP fact decides it, like a `Host:`-poisoned reset link not yet seen in the mail.
  - **Rejected:** the control held on every path (403 or 404 for a non-owner, `state` validated).
- **Evidence.** Both request/response exchanges are saved, redacted, to `evidence/`, and `location` points there. Combined-mode findings also cite the source handler in `trace[]`.
- **Fingerprints:** `web-pentest/<wstg-or-class>/<endpoint or resource>/<parameter or operation>`, with `host:port` written as `host/port`.
- **`ext` keys:** `wstg`, `endpoint`, `mode` (black-box, grey-box or combined).
- **Output Format** is rendered from `findings.json`. It has a verdict and severity summary, confirmed findings, needs validation, hardening notes, "Rejected (do not re-raise)" and "Out of scope / not tested". The old per-finding `VERDICT` framing is gone.
- The skill now gets copies of the four shared findings files it didn't already have.

### 1.31.0 (2026-10-27)

mobile-audit moves onto the shared findings format (#129). mobile-audit 1.1.0.

**Changed**
- **Verify, then record.** A new section after runtime testing:
  - **Decompiled binaries.** Save redacted `strings`, jadx, apktool, otool, readelf or manifest-dump output, or a proxied request/response, to `evidence/` and point `location` at it. A hard-coded key's evidence is the call site that uses it, never the key.
  - **Confirmed:** an extracted AES key traced to its decrypt call; cleartext login captured through a shipped `NSAllowsArbitraryLoads=true`, an unsafe default.
  - **Needs validation:** an exported activity whose risk depends on backend authorization; a cleartext exception not yet seen in traffic.
  - **Rejected:** a token log behind `BuildConfig.DEBUG` with `debuggable="false"`; a publishable Firebase or Maps key with its restrictions in place.
  - MASVS-RESILIENCE gaps with no traced impact are hardening notes.
- **Fingerprints:** `mobile-audit/<masvs-or-class>/<file or resource>/<symbol>`. Decompiled code uses the class or symbol, not the evidence file name.
- **`ext` keys:** `masvs`, `platform`, `source` (source, decompiled or runtime).
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)", and the MASVS category table becomes a coverage table with verdict counts.
- The skill now gets copies of the six shared findings files.

### 1.30.0 (2026-10-27)

crypto-audit moves onto the shared findings format (#129). crypto-audit 1.1.0.

**Changed**
- **Verify, then record.** A new step after the checklist, with examples for each verdict:
  - **Confirmed:** a fixed GCM IV reused with one key, `Math.random()` session tokens, a `JWT_SECRET || 'dev-secret'` fallback (an unsafe shipped default), unsalted SHA-256 passwords.
  - **Needs validation:** `nginx.conf` allows TLS 1.0, but a CDN may terminate TLS first. The check is a `testssl.sh` run.
  - **Rejected:** `jwt.verify` without `algorithms`, ruled out by the pinned `jsonwebtoken` version (a control inside a dependency); MD5 used only for an ETag, ruled out at its only call site.
- **Hardening notes.** bcrypt cost 10, correct CBC+HMAC, extra TLS 1.2 CBC suites and no KMS rotation are hardening notes. Custom crypto is a finding only when you trace what it fails to protect.
- **Fingerprints:** `crypto-audit/<class>/<file or resource>/<symbol or name>`. A live TLS endpoint is written as `host/<name>/<port>`.
- **`ext` keys:** `primitive`, `library`, `standard`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)" and keeps the TLS posture and key inventory sections. "Verify Fixes at Runtime" is unchanged.
- The skill now gets copies of the six shared findings files.

### 1.29.0 (2026-10-26)

iam-audit moves onto the shared findings format (#129). iam-audit 1.1.0.

**Changed**
- **Verify, then record.** A new step covering Audit mode and the current-state inventory of a migration:
  - Save the redacted IAM and IdP exports to `evidence/` and point `location` at the decisive statement.
  - Run the refutation pass. The strongest controls are SCPs, permissions boundaries, organization conditions like `aws:PrincipalOrgID`, and Conditional Access.
  - Examples for each verdict: a GitHub OIDC role trusting `repo:acme/*` with `iam:PassRole` on an admin role is confirmed. `iam:CreatePolicyVersion` behind SCPs you can't see needs validation. A `Principal: "*"` trust limited by organization ID is rejected.
- **Reproduction.** A provider's read-only policy simulator returning "allowed" counts as `reproduced`: `simulate-principal-policy`, `gcloud policy-troubleshoot iam`, Entra What If. The escalation itself is never exercised.
- **Severity notes.** Escalation paths that start from someone who is already admin aren't findings. Missing MFA is rated by what the affected accounts can reach.
- **Fingerprints:** `iam-audit/<class>/<provider>/<tenant>/<principal or policy>`, or the file and symbol for app authorization and IaC.
- **`ext` keys:** `provider`, `tenant`, `principal`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)" and a privileged access inventory. Design and migration advice goes in its own Recommendations table, not in findings.
- The skill now gets copies of the six shared findings files.

### 1.28.0 (2026-10-26)

container-audit moves onto the shared findings format (#129). container-audit 1.1.0.

**Changed**
- **Verify, then record.** A new step after the checklists:
  - Run the refutation pass. The strongest controls are an admission policy, a namespace Pod Security Standards (PSS) label, a Helm value that overrides the default, or a later build stage that discards the layer.
  - Name the principal, the boundary and the result before calling anything a finding.
  - Examples for each verdict: a committed `kind: Secret` with the live database password, and a `system:authenticated` binding that can read every secret, are confirmed. A namespace label set outside the repo needs validation. A Kyverno `Enforce` policy, or a build-arg used only in the builder stage, gets the candidate rejected.
  - Shipped Helm defaults like `privileged: true` are confirmed, with confidence capped at medium.
- **Hardening notes.** Running as root, a tag instead of a digest, and missing limits are hardening notes on their own. A missing NetworkPolicy is a finding only when you name what it exposes. Image CVEs follow dependency-audit's reachability rule.
- **Cluster evidence.** Live-cluster findings point at saved, redacted output. Strip Secret `.data` before saving.
- **Fingerprints:** `container-audit/<class>/<file or resource>/<name>`. Image references are written without the tag.
- **`ext` keys:** `resource`, `cis`, `pss`.
- **Output Format** is rendered from `findings.json`. It has "Rejected (do not re-raise)", a cluster posture table and a remediation plan. "Verify Fixes at Runtime" is unchanged.
- The skill now gets copies of the six shared findings files.

### 1.27.0 (2026-10-26)

cloud-audit moves onto the shared findings format (#129). cloud-audit 1.2.0.

**Changed**
- **Verify, then record.** A new step after the audit categories:
  - Save the redacted, read-only output behind each finding to `evidence/` and point `location` at the decisive line, since cloud findings are about resources, not source lines.
  - Run the refutation pass. The strongest control is often account-level: Block Public Access, an SCP, a private subnet with no route out, deployment protection.
  - Close each candidate as confirmed, needs validation or rejected. There are cloud examples for each verdict, and unsafe IaC module defaults count as confirmed.
  - Rate severity by what the resource holds, not the benchmark ID.
- **Confidence.** Config read from the API is evidence, not reproduction. Only an authorized, non-destructive request, such as an anonymous `curl -sI` returning 200, sets `reproduced`. IaC-only findings cap at medium.
- **Fingerprints** are built from the resource: `cloud-audit/<class>/<provider>/<account>/<resource>`, or the IaC file and resource address. ARNs are written with slashes.
- **`ext` keys:** `provider`, `account`, `region`, `resource`.
- **Output Format** is rendered from `findings.json`. It has confirmed findings, needs validation, hardening notes, "Rejected (do not re-raise)", a coverage table, a PaaS deployment inventory and the remediation plan.
- **`references/paas.md`** gets the evidence-file rule, and a warning never to save `railway variables` output, which prints values.
- The skill now gets copies of the six shared findings files.

### 1.26.6 (2026-10-26)

owasp-audit fix from the worked-example run (#159). owasp-audit 1.3.2.

**Fixed**
- **A03 without network.** A03 said to run `npm audit`, which queries the registry, so a static no-network run couldn't do the check and had no instructions for that case. It now says:
  - record versions the lockfile shows as vulnerable as `needs_validation`, with "advisory data not checked" as the blocker and the audit command as the plan;
  - mark the A03 advisory unit `deferred`, which makes the run partial;
  - never call A03 clean from the lockfile alone.
- **Report summary.** The unit count line includes `candidate`, matching the v1.26.0 coverage rule.

This is the last of the #159 fixes. The others shipped in v1.26.0 through v1.26.5.

### 1.26.5 (2026-10-26)

api-audit fix from the worked-example run (#159). api-audit 1.1.5.

**Fixed**
- **Classes outside API1–API10.** SQL injection, command injection, path traversal, XSS in an HTML response and crypto misuse have no OWASP API Security Top 10 category, and the skill didn't say what to put in the heading or in `owasp_category`. They now use the matching web Top 10:2025 category, such as `A05:2025` for injection, rather than being stretched into API8 or API10. The worked example already did this for its two SQL injections.
- **"Items checked and found clean".** It now says `covered` and `not_applicable` units, and that a unit with a confirmed or needs_validation finding stays `candidate`. This matches the v1.26.0 coverage rule.

### 1.26.4 (2026-10-26)

finding-triage fixes from the worked-example run (#159). finding-triage 1.1.2.

**Fixed**
- **"Fix now" versus `Fixed`.** The disposition table said a Fix now decision is "recorded as Fixed". But writing `Fixed` before the fix ships is false, and `to-sarif.mjs` drops Fixed records, so the alert would vanish while the bug was still live.
  - A Fix now finding now keeps `disposition` unset until the change has shipped and its verification passed.
  - The writeup records the commit or release.
  - The final checklist asks about any early `Fixed`.
  The worked example already did this by hand.

**Added**
- **"Related candidates (not triaged here)".** A new section in the session output for things noticed while triaging, such as a sibling route or a second call site. Each gets a location, why it's related, and the skill that should review it. None gets a verdict or severity until someone triages it.

### 1.26.3 (2026-10-26)

dependency-audit fixes from the worked-example run (#159). dependency-audit 1.2.3.

**Fixed**
- **Fingerprint form.** The skill wrote `dependency-audit/<ecosystem>/<package>/<advisory>`, while `findings-format.md` and the worked example use `dependency-audit/<advisory>/<lockfile>/<package>`. The skill now uses the shared form.
- **Report template.** It now has the "Rejected (do not re-raise)" table that `findings-format.md` requires. Most advisories in a real audit end up there; the example had 40 never-called ones.
- **The Latest column.** The "Latest" column in the stack inventory couldn't be filled without a permission prompt. `Bash(npm view:*)` and `Bash(npm outdated:*)`, both read-only, are now pre-approved. An offline run writes "not checked" instead of guessing.

**Changed**
- **Rejection rules.** "Never called" and "guard inside the dependency" rejections follow the v1.26.1 table. A never-called advisory points at the package's only call site, or at its manifest line. A library guard rejects only with a checked lockfile pin; otherwise it's `needs_validation`. The skill now gets a copy of `verification.md`.
- **Docs.** The `docs/security-scanning.md` grant table lists the two new rules.

### 1.26.2 (2026-10-26)

secrets-audit fixes from the worked-example run (#159). secrets-audit 1.1.3.

**Fixed**
- **Fingerprint form.** The skill wrote `secrets-audit:<type>:<file>:last4-XXXX` and `findings-format.md` wrote `secrets-audit/<type>/<file>/<VAR>`. The skill now uses the shared slash form, with the variable name as the last part. If the value has no variable name, it uses the enclosing symbol or `last4-XXXX`. The worked example's five fingerprints are renamed to match, and its SARIF is regenerated.
- **Report template.** It now has the "Rejected (do not re-raise)" section that `findings-format.md` requires.
- **Value printing.** The generic 40-character and high-entropy greps printed every match, which the skill tells agents not to do. The provider sweeps now list files (`-l`), the 40-character sweep counts per file, and the env-file sweep masks values to first and last 4.
- **Cross-reference.** "`owasp-audit` A02 (in-source secret patterns)" was ambiguous after the 2025 renumbering. It now reads A04:2025 Cryptographic Failures, where owasp-audit checks hard-coded secrets.

**Changed**
- **Verdicts follow the v1.26.1 rules.** A hard-coded fallback secret is `confirmed`, with confidence capped at medium. A vendor's published example value is `rejected`, pointing at the line that holds it.
- The skill now links `verification.md` for the refutation pass, and gets a copy of it.

### 1.26.1 (2026-10-26)

Closes the verdict and severity gaps that the worked-example runs hit (#159). Where the guides were silent, the runs made different calls on the same facts. Shared guides only; the skills that ship them get the new copies.

**Added**
- **Rejections with no guard to point at** (`verification.md`, `findings-format.md`). There's now a table for each kind, saying what `ruled_out_by.control` states and where `location` points:
  - never reached: point at the only call site, or the manifest line if nothing imports the package;
  - a known-inert value, like AWS's documented example key: point at the line holding the value;
  - a control inside a dependency: point at the lockfile pin.
  A dependency's guard rejects a candidate only when the installed version is pinned and checked. Otherwise the candidate is `needs_validation`.
- **Unsafe shipped defaults** (`verification.md`). A hard-coded fallback secret or a permissive default is `confirmed` in every skill:
  - it gets a `system_configuration` condition;
  - severity is rated as if the default were live;
  - the unseen deployment caps confidence at medium.
  The worked examples split three ways on exactly this. `examples/README.md` now says how a run today would record it.
- **Missing rate limiting** (`severity-calibration.md`). It's a finding when repeated requests do concrete harm: password guessing with no lockout, OTP brute force, paid sends. It's `needs_validation` when an unseen gateway might limit it, and a hardening note elsewhere.
- **Availability anchors** (`severity-calibration.md`). A crash or hang from one unauthenticated request is High. It's Medium when it needs an account, hits only one worker of several, or the platform restarts it quickly. It's Low when only the attacker's own request suffers.
- **Verifier batching for small targets** (`verification.md`). Up to about five candidates that share no code path may go to one verifier. Candidates touching the same handler, and any High or Critical candidate, each still get their own verifier.

### 1.26.0 (2026-10-26)

Fixes the coverage ledger instructions that the worked examples tripped over (#159). Following them as written could list a confirmed vulnerability under "Items checked and found clean", and the owasp-audit example did exactly that for 11 units.

**Fixed**
- `covered` versus `candidate` in `shared/recon-and-coverage.md`. The guide said both "covered means no candidate came out of it" and "once its candidates have verdicts it can move to covered". Now there is one rule:
  - a unit whose candidates were all rejected becomes `covered`, keeping the rejected fingerprints;
  - a unit with any confirmed or needs_validation finding stays `candidate` for good;
  - "Items checked and found clean" is built from `covered` and `not_applicable` units only.
- The unit id example (`src/app/api/invoices/[id]/route.ts#PUT:...`) used `#`, `[` and `]`, which the validator rejects. The new example passes, and the guide says which characters to drop. Its `owasp_category` is now `A01:2025`, as the skills write it.
- Unit ids may now start with `.`, so a dotfile like `.env.example` can be an id prefix.

**Added**
- `validate-coverage.mjs --findings` fails a `covered` unit that lists a confirmed or needs_validation fingerprint. Tests cover the new rule, dotfile ids, and the guide's example.

**Changed**
- `examples/owasp-audit/`: the 11 affected units are now `candidate`, and their rows are gone from the report's clean list (21 covered, 11 candidate).

### 1.25.0 (2026-10-26)

The findings format gets room for skill-specific fields and a rule for findings that aren't in a source file. Both are needed before the remaining audit skills move onto it (#129): a PCI gap needs its requirement number, and a cloud finding is about a bucket, not a line of code.

**Added**
- `ext`, an optional object on any record, for the producing skill's own fields (`requirement`, `account`, `masvs`, ...). Keys are snake_case; values are scalars or arrays of scalars. The validator checks the shape, the schema documents it, and `to-sarif.mjs` copies it to the SARIF result's `properties.ext`. Each skill will list its keys in its own SKILL.md.
- "Findings about deployed resources" in `findings-format.md`: save the redacted read-only output to `<audit dir>/evidence/` and point `location` at it. Fingerprints use the resource id with slashes, since ARNs and `host:port` look like line numbers to the validator.
- Tests for both. The findings-format example test now reads the block under "## Example".

The eight skills that already use the format get the new copies; their content doesn't change.

### 1.24.0 (2026-10-26)

**Changed**
- `templates/skill-template.md` now matches how the skills are written (#128). It adds:
  - a `Cross-references:` line, and `## When to use` with a **Not for:** list of near-misses and their owners (which double as trigger-eval near-misses)
  - a skill-specific `## Authorization` section
  - a "Verify, then record" step for the shared findings format: verdicts, verification, severity calibration, `findings.json`, validation, SARIF, dispositions, and the `shared/manifest.json` entries to add
  - `allowed-tools` guidance in the frontmatter comments
  - the standard section order: `## Output Format`, `## Boundaries`, `## References`
  - a closing checklist for trigger prompts, issue-form dropdowns, README and versions
- Section names are now the same everywhere:
  - `## Report Format` → `## Output Format` in owasp-audit, api-audit and container-audit
  - `## Output format` → `## Output Format` in ai-risk-management and privacy-engineering
  - `## References & Sources` → `## References` in api-audit
  - `## Refusal boundaries` / `## Sources` → `## Boundaries` / `## References` in business-logic-testing
  - cross-references to "owasp-audit's Report Format" updated in cloud-audit, privacy-engineering and vuln-research

**Added**
- Lint errors for a skill without `## Boundaries` or `## References`, and for an output section spelled anything but `## Output Format`. Self-tests cover both. CLAUDE.md and CONTRIBUTING describe the standard sections.

### 1.23.8 (2026-10-26)

**Added**
- Worked examples (#127):
  - `examples/target/` is notes-api, a small deliberately vulnerable Express API with planted bugs and a real vulnerable lockfile.
  - `examples/<skill>/` holds one real run each of owasp-audit, api-audit, dependency-audit, secrets-audit and finding-triage: the rendered report, `findings.json`, SARIF from `to-sarif.mjs`, and the coverage ledger where the skill keeps one. dependency-audit also includes its raw `npm audit --json` output.
  - Each run was a separate agent following the skill as written, static and read-only.
- [examples/README.md](examples/README.md) summarizes the runs and what's worth noticing. For example, the same hard-coded JWT default came out critical in api-audit, high in owasp-audit and needs-validation in secrets-audit.
- The rough edges each run hit are filed as #159.
- `scripts/test/examples.test.mjs` checks every example's `findings.json` and `coverage.json` with the shared validators. It also checks that each cited file and line exists in the target and that the committed SARIF matches a fresh conversion, so the examples double as format regression fixtures.
- The five skills' README rows link to their example run.

### 1.23.7 (2026-10-26)

**Added**
- Issue forms (#126) in `.github/ISSUE_TEMPLATE/`:
  - **Field report:** skill, version, what it ran against, what it missed, false positives, suggested change, agent. Redaction is called out.
  - **Skill request:** problem, overlap with existing skills, example prompts for the trigger eval, outline, and a scope checkbox.
  - **Skill bug**
  - **Trophy case:** a real bug found with these skills, with an optional public link.
  - `config.yml` sends security reports to private vulnerability reporting.
- A new `trophy-case` label.
- PR templates:
  - a default for tooling and docs
  - `new-skill.md` and `skill-update.md`, which turn the CONTRIBUTING checklist into checkboxes: authorization section, scoped grants, findings format and manifest, trigger prompts, README row/map/crossover, back-references, version bumps, adapters, `npm run check`, SkillSpector
- `scripts/test/repo-templates.test.mjs` fails when an issue form's skill dropdown drifts from `skills/`.
- CONTRIBUTING, CLAUDE.md and the README link to the forms and templates.

### 1.23.6 (2026-10-26)

**Added**
- `SECURITY.md` (#125). It explains how to report privately through GitHub private vulnerability reporting, which is now turned on, and sets response targets. It also says what counts as a vulnerability in a skills repo:
  - over-broad `allowed-tools` grants
  - instructions that skip the authorization check or send data out
  - prompt injection or hidden Unicode in skill content
  - the plugin manifests, build and workflows
  - the bundled scripts, when they run on untrusted input
- It also lists what's out of scope, such as upstream tools, stale advice (that's a field report) and marked example snippets.
- `.github/CODEOWNERS` requires maintainer review on every path, with `skills/`, `shared/`, `.github/`, `.claude-plugin/` and `scripts/` listed explicitly.
- The README's security section links to the policy.
- The Dependabot part of #125 already shipped in v1.23.3.

### 1.23.5 (2026-10-26)

**Added**
- `claude plugin eval` routing suite (#124). `evals/cases/` holds 11 cases for the skills most likely to collide:
  - owasp-audit vs api-audit
  - incident-triage vs finding-triage vs breach-patterns
  - recon vs osint-recon
  - secrets-audit vs scanner-pipeline
  - two everyday coding requests where no security skill should load
- Each routing case has a `fires-<skill>` grader. It also has `quiet-<rival>` graders that check the rival skills don't load (`min: 0`, `max: 0`, `arm: both`).
- New **Plugin evals** workflow (`.github/workflows/evals.yml`):
  - runs on demand, and on pushes to `main` that change a skill or a case
  - never runs on PRs
  - pinned model and CLI, 3 runs per case, threshold 0.8, $15 cost ceiling, `--ablation none`, `--no-publish`
  - uploads the results as an artifact
  - skips with a notice until the repo has an `ANTHROPIC_API_KEY` secret
- `.github/scripts/eval-summary.mjs` writes the score table to the run summary. It fails on runs that ended in an API error, because the pinned CLI (before 2.1.299) still grades those.
- `scripts/test/eval-cases.test.mjs` checks the suite's shape on every PR at no cost: graders name real skills, prompt.md keys are valid, and each routing case has a rival.
- `evals/results/` is git-ignored. [evals/README.md](evals/README.md) documents the suite and has a results table to record which wordings fire, with model and CLI version.

### 1.23.4 (2026-10-26)

**Added**
- Offline trigger eval (#123). `evals/triggers/<skill>.json` holds at least 5 prompts that should fire each skill and 5 near-misses, each near-miss naming the skill that should own it instead. Some prompts are casual and some paste code or config. `scripts/eval-triggers.mjs` ranks all 350 prompts against every description with BM25. It needs no dependencies and makes no API calls.
- A new CI job, **Trigger eval (offline)**, fails when:
  - fewer than 85% of should-fire prompts rank their skill first
  - fewer than 90% of near-misses rank their owner above the skill
  - any skill wins fewer than 3 of its own 5
  - two descriptions are more than 0.55 similar (TF-IDF cosine)
  - a skill has no triggers file
- Current scores:
  - should-fire top-1 160/175 (91.4%)
  - near-miss 171/175 (97.7%)
- [evals/README.md](evals/README.md) explains the numbers, what the proxy can't see, and which misses point at descriptions worth sharpening.
- `npm run check` runs the trigger eval. CONTRIBUTING, CLAUDE.md and the README's new-skill steps now include writing trigger prompts.

### 1.23.3 (2026-10-26)

Weekly checks for problems that show up without a PR: broken external links, new SkillSpector rules, and outdated action pins. Repo tooling only; no skill content changes. Closes #122.

**Added**

- `.github/workflows/links.yml`: every Monday, lychee (pinned action and binary) checks every link in the README, `CONTRIBUTING.md`, docs, `shared/` and skills, internal `#anchors` included. 403 and 429 count as OK, since some sites block or rate-limit CI runners. A failing run opens or updates one `broken-links` issue, and the next clean run closes it. It runs on a schedule rather than on PRs because external sites break on their own timeline. It can also be run on demand. A local run against v1.23.2 found 373 links and 0 errors.
- `.github/dependabot.yml`: one grouped PR a week against `development` for the SHA-pinned GitHub Actions. Those PRs skip the version-bump check (#120).

**Changed**

- `ci.yml` also runs every Monday on `main` (the full workflow, including SkillSpector and the code-scanning upload).
- `docs/security-scanning.md` has a new "Scheduled checks" section. It notes that `SKILLSPECTOR_REF` and `CLAUDE_CODE_VERSION` are still bumped by hand. `CLAUDE.md` lists the new files.

### 1.23.2 (2026-10-26)

CI now runs Claude Code's own plugin validator, and the repo's checkers get self-tests, so none of them can quietly stop catching problems. Repo tooling plus one README line; no skill content changes. Closes #121.

**Added**

- **Plugin validate** CI job: installs a pinned Claude Code CLI and runs `claude plugin validate --json .` through `.github/scripts/plugin-validate.mjs`. That is `--strict` with named exceptions. Any error, or any warning not in the script's `ALLOWED` list (each entry has a reason), fails the job. The one accepted warning is the root `CLAUDE.md`, which is contributor guidance and not plugin context.
- `scripts/test/self-test.test.mjs`: 7 tests that feed known-bad fixtures to each checker.
  - The lint: name mismatch, short description, missing Authorization section, WebFetch with unscoped Bash, destructive grant, broken link, unknown cross-reference, 500+ lines, and a shared trigger phrase. A clean fixture must pass.
  - The SkillSpector baseline check: missing reason, unknown skill, wildcard-only message and a bad `*/` target, plus slicing that must not leak another skill's rules.
  - `merge-sarif.mjs`: one run, rewritten paths, de-duplicated rules, remapped indexes and dropped baselined results.
  - The plugin-validate filter.
- `npm run check`: lint, baseline check, version check, adapter drift and tests in one command, mirroring CI except the SkillSpector and plugin-validate jobs, which need extra tools.

**Changed**

- `scripts/lint-skills.mjs` takes `--skills-dir <dir>`, and `.github/scripts/skillspector-baseline.mjs` reads `SKILLSPECTOR_BASELINE`, so the self-tests can point them at fixtures.
- `.claude-plugin/marketplace.json`: dropped `metadata.repository`, which Claude Code doesn't recognize (`plugin.json` already has `repository`).
- README: the plugin install is now one line, `/plugin install cybersecurity-skills --marketplace briiirussell/cybersecurity-skills` (Claude Code 2.1.275+), with the two-step form kept for older versions.
- `docs/security-scanning.md`, `CLAUDE.md` and `CONTRIBUTING.md` document the new checks and `npm run check`.

### 1.23.1 (2026-10-26)

CI now enforces the per-merge versioning rule. Until now it was checked only by hand. Repo tooling only; no skill content changes. Closes #120.

**Added**

- `scripts/check-versions.mjs`, a new **Version check** CI job. On every run it fails when:
  - `plugin.json` and `marketplace.json` versions differ
  - `VERSIONS.md` has no `### X.Y.Z (date)` entry for the current version
  - a skill folder has no `VERSIONS.md` row, or a row has no folder
  - a row isn't x.y.z

  On a PR (`--base origin/<base branch>`) it also fails when the repo version isn't higher than the base branch's, or when a file under `skills/<name>/` changed and that skill's row wasn't bumped. Generated copies of `shared/` files are exempt, since they follow the `shared/` change. Dependabot PRs skip the bump check.
- `scripts/test/check-versions.test.mjs`: 7 tests. I also replayed the check against five past releases (v1.19.5, v1.19.6, v1.19.7, v1.20.0, v1.23.0); all pass.

**Changed**

- `CONTRIBUTING.md` PR checklist gains a version-bump item. `CLAUDE.md` and `docs/security-scanning.md` list the new check.

### 1.23.0 (2026-10-26)

Every skill now has an Authorization section, and the lint fails a skill without one. `CLAUDE.md` always required an authorization check, but only 13 of 35 skills had a heading for it. The others had a line in Boundaries, an inline paragraph, or nothing. Closes #119.

**Changed**

- The lint (`scripts/lint-skills.mjs`) fails when `SKILL.md` has no level-2 heading containing "Authorization". `## Authorization`, `## Authorization Check`, `## Authorization and Mode` and `## Step 0 — Authorization and scope` all pass.
- **New `## Authorization` sections** (PATCH each), written for what each skill actually touches:
  - Audit skills (cloud, container, IAM, crypto, secrets, prompt-injection) say which systems are in scope, that pre-approved commands only read, and which actions (key checks, TLS probes, live injection tests, privilege-escalation paths) need the owner first.
  - Data-handling skills (HIPAA, PCI, privacy) say never to copy real PHI, PAN or personal data into the transcript; record the location instead.
  - Advisory skills (security-comms, csf-mapping, threat-modeling, ai-risk-management, soc-operations) state whose organization they work for and who signs off.
  - Skills: **ai-risk-management** (1.1.1), **breach-patterns** (1.0.4), **cloud-audit** (1.1.2), **container-audit** (1.0.2), **crypto-audit** (1.0.3), **csf-mapping** (1.0.2), **hipaa-audit** (1.0.2), **iam-audit** (1.0.3), **pci-audit** (1.0.3), **privacy-engineering** (1.0.3), **prompt-injection** (1.1.3), **secrets-audit** (1.1.2), **security-comms** (1.0.3), **siem-detection** (1.0.3), **soc-operations** (1.0.4), **threat-hunting** (1.0.4), **threat-modeling** (1.0.4), **vuln-research** (1.0.2).
- **Inline authorization text promoted to a heading** (PATCH each): **api-audit** (1.1.3) and **dependency-audit** (1.2.2). api-audit also says live requests stay non-destructive.
- **Headings renamed** (PATCH each): **osint-recon** (1.0.2) "Ethics Check" → "Authorization and Ethics Check", with written authorization required for organization assessments. **personal-opsec** (1.0.1) "Consent and scope" → "Authorization: consent and scope".
- `CLAUDE.md`, `CONTRIBUTING.md` and `docs/security-scanning.md` describe the rule.

### 1.22.0 (2026-10-26)

incident-triage moves from NIST SP 800-61 Rev. 2 (2012) to **Rev. 3** (April 2025), which `soc-operations` already cited. Rev. 3 drops the four-phase lifecycle and becomes a CSF 2.0 Community Profile, so the methodology changes, not just the citation. Closes #117.

**Changed**

- **incident-triage** (1.1.0):
  - **Structure:** each step names the CSF 2.0 outcomes it produces (DE.AE, RS.MA, RS.MI, RS.AN, RS.CO, RC.RP, ID.IM), so the report maps onto the organization's CSF profile (`csf-mapping`). The intro explains the Rev. 3 model: Govern, Identify and Protect are preparation; Detect, Respond and Recover are response.
  - **New Authorization section.** Only read-only listings are pre-approved. Every containment action needs the incident lead's go-ahead, with its blast radius named. Systems out of scope are reported, never touched.
  - **Step 1 is now "Declare, validate and prioritize".** Confirm against a second source, record the declaration time (clocks often start at discovery), start the IR plan's third parties (including notifying the cyber insurer before outside responders are engaged), and apply escalation criteria.
  - **Containment** covers revoking credentials and tokens, plus coordinated containment so an attacker who is still active doesn't pivot.
  - **Evidence preservation** adds hashing at collection, provenance, an action log, and copying cloud and SaaS logs before retention rotates them.
  - **Analysis** adds a magnitude estimate: known / suspected / ruled out, each with its evidence.
  - **New Step 6, notification clocks:** GDPR 72h, NIS2 24h/72h/1 month, HIPAA 60 days, SEC 8-K Item 1.05 four business days after materiality, PCI, state laws and contracts. Hands off to `security-comms` and the privacy and compliance skills.
  - **New Step 7, handoff:** eradication, recovery criteria and lessons learned.
  - **Report:** scope table, action log with approver, notification-clock table, insurer escalation and a handoff section.
  - **Description:** names Rev. 3. It narrows 'triage' to 'incident triage' and 'breach' to 'we've been breached' (overlaps with `finding-triage` and `breach-patterns`), and adds 'active incident', 'ransomware' and 'contain the incident'.

### 1.21.0 (2026-10-26)

ai-risk-management's regulatory section is brought up to date. It listed Executive Order 14110 as current, but it was rescinded on 20 January 2025. The EU AI Act section stopped at "phasing in through 2026". Closes #116.

**Changed**

- **ai-risk-management** (1.1.0):
  - **EU AI Act:**
    - A date table: prohibitions and AI literacy from 2 Feb 2025, general-purpose AI model obligations from 2 Aug 2025, Article 50 transparency from 2 Aug 2026.
    - High-risk obligations moved by the 2026 Digital Omnibus on AI: Annex III to 2 Dec 2027 and Annex I products to 2 Aug 2028. Both are marked "(verify)" against EUR-Lex.
    - New GPAI obligations tier and Code of Practice. The prohibited list now matches Article 5.
  - **US:**
    - EO 14110 is marked rescinded.
    - Current federal policy: EO 14179, America's AI Action Plan (July 2025), and the 11 December 2025 order directing agencies to challenge state AI laws.
    - A note to cite the AI RMF revision actually used.
    - State laws, each with its status: the Colorado AI Act's 30 June 2026 date is marked "(verify)", plus NYC LL 144, Illinois BIPA, and California AB 2013 and SB 942.
  - The section opens with "Status as of October 2026" and says to re-check items marked (verify). The report's regulatory-mapping table gains "Status as of" and "Applies from" columns. References add the GPAI Code of Practice and the US policy documents.

### 1.20.0 (2026-10-26)

owasp-audit now audits against the **OWASP Top 10:2025** ([owasp.org/Top10/2025](https://owasp.org/Top10/2025/)). The checklist is reordered to the new numbering and gains two categories. Every check from the 2021 version is kept and moved to its 2025 home. Closes #115.

**Heads-up:** category IDs in owasp-audit output change. Findings and coverage units are now tagged `A01:2025` … `A10:2025`. If you compare against a 2021-tagged report, use the mapping at the top of the Audit Checklist:
- SSRF, 2021's A10, is now part of A01.
- Crypto A02 → A04, Injection A03 → A05, Insecure Design A04 → A06, Misconfiguration A05 → A02, Vulnerable Components A06 → A03.
- A07–A09 keep their numbers.

**Changed**

- **owasp-audit** (1.3.0):
  - **A03 Software Supply Chain Failures** replaces Vulnerable Components. It keeps the `npm audit` reachability triage and takes the CI/CD-integrity and lockfile-integrity checks from A08. It adds Subresource Integrity for CDN scripts, install-time code and dependency confusion (handed to `dependency-audit`), and a grep for workflow actions pinned to a branch or tag instead of a SHA.
  - **A10 Mishandling of Exceptional Conditions** is new:
    - fail-open `catch` blocks around authorization and signature checks, and policy or IdP outages that default to allow
    - silent error swallowing and parser errors outside the error boundary (moved from A09)
    - NaN and missing-value comparisons that fail open
    - partial failures that leave inconsistent state
    - one bad request crashing a shared worker
  - **A09** is renamed Security Logging and *Alerting* Failures. It notes that error paths hidden from monitoring are also A10.
  - **SSRF** is now a subsection of A01, with the full allow-list bypass set.
  - The description, intro, report template (`A0X:2025`) and References name the 2025 list.
  - `references/checklist-details.md` and `references/webhooks-and-parsers.md` headings and anchors are renumbered. Every in-skill link was updated and checked.
- Cross-references to owasp-audit category numbers updated (PATCH each): **api-audit** (1.1.2), **breach-patterns** (1.0.3), **crypto-audit** (1.0.2), **business-logic-testing** (1.0.1), **threat-modeling** (1.0.3), **web-pentest** (1.1.3).
- `shared/findings-format.md`, `shared/coverage.schema.json` and `shared/orchestration.md`: examples use `A01:2025` and 2025 numbering. Example text only; no schema rule changed, and 2021-tagged findings still validate.
- README: owasp-audit row says OWASP Top 10:2025.

### 1.19.11 (2026-10-26)

The lint now fails any `allowed-tools` Bash grant that would pre-approve a write. This rule would have caught the heroku grants fixed in 1.19.7. Repo tooling only; no skill content changes. Closes #118.

**Added**

- `scripts/grant-check.mjs`: checks each `Bash(...)` rule. It fails when the rule:
  - is unscoped
  - names a write verb (`delete`, `rollback`, `set`, `push`, `--fix`, ...), matched as whole segments so `get-credential-report`, `--prefix` and `assignment` don't trip it
  - is a wildcard whose prefix also matches a known destructive command (125 entries across heroku, vercel, gh, git, package managers, and cloud and infra CLIs)
  - is a wildcard on a bare multi-command CLI (`git:*`, `vercel:*`, `aws:*`)
  - is a wildcard on a tool that rewrites source files with a flag (`semgrep:*`, `eslint:*`, `terraform fmt:*`)
- `scripts/test/grant-check.test.mjs`: 8 tests. The 1.19.6 heroku grants and the earlier `git branch:*` and `npm audit:*` grants all fail. Their replacements pass. Every shipped skill's grants pass.

**Changed**

- `scripts/lint-skills.mjs` runs the check on every skill.
- `docs/security-scanning.md`, `CONTRIBUTING.md` and `CLAUDE.md` describe the rule. They also say where to add a new CLI's destructive subcommands. Report-file flags (`--output`, `--report-path`) are out of scope on purpose. `bundle audit update` is left out because it only refreshes bundler-audit's own advisory database.

### 1.19.10 (2026-10-26)

Example cleanup. Two skill examples used the maintainer's own name as the person who added a suppression. Both now use a neutral placeholder. Closes #114.

**Fixed**

- **log-watch** (1.0.1): the suppression example's `"added_by": "brianna"` is now `"added_by": "jdoe"`. The OWASP LLM Top 10 reference now names the 2025 list (`LLM01:2025`), matching 1.19.8.
- **scanner-pipeline** (1.0.2): the baseline-entry example's `owner: "@bri"` is now `owner: "@jdoe"`. Found while checking the whole repo for personal names.

The Claude pricing table in log-watch stays as written. It is already dated, framed as assumptions, and says to re-check the pricing page before quoting.

### 1.19.9 (2026-10-26)

pci-audit now targets PCI DSS v4.0.1. The skill said "PCI DSS v4.0 (effective March 2025)", but v4.0 was retired on 31 December 2024; v4.0.1 is the only active version. Closes #113.

**Fixed**

- **pci-audit** (1.0.2):
  - The description, intro, report header and references now name v4.0.1. A version note says that the requirements v4.0 marked "future-dated" became mandatory on 31 March 2025, so assess against all of them.
  - MFA for all access into the CDE now cites Req 8.4.2 and says it is mandatory, not "new".
  - The internal-network encryption line cited Req 4.2.1.1, which is the trusted keys and certificates inventory. It now says Req 4.2.1 mandates strong cryptography only over open, public networks, so encrypting internal links is defense in depth.
- README: pci-audit row says v4.0.1.

### 1.19.8 (2026-10-26)

Citation fix for prompt-injection. Its References cited "LLM08: Excessive Agency", which is the 2023 numbering. In the OWASP Top 10 for LLM Applications 2025, Excessive Agency is **LLM06** and LLM08 is Vector and Embedding Weaknesses. Closes #112.

**Fixed**

- **prompt-injection** (1.1.2): both LLM Top 10 citations now name the 2025 list. References cite LLM01:2025 Prompt Injection, LLM05:2025 Improper Output Handling (Step 4), LLM06:2025 Excessive Agency, and LLM08:2025 Vector and Embedding Weaknesses (the RAG and memory checks). A note covers the 2023 numbering that older reports use, plus a link to the list. `agent-supply-chain-audit` and `personal-opsec` already used 2025 IDs. `log-watch`'s citation, which has no year, is fixed in 1.19.10.

### 1.19.7 (2026-10-26)

Security fix for patch-sweep's `allowed-tools`. Claude Code permission rules match by prefix, so `Bash(heroku apps:*)`, `Bash(heroku releases:*)` and `Bash(heroku stack:*)` also pre-approved `heroku apps:destroy`, `heroku releases:rollback` and `heroku stack:set` with no prompt. The skill never runs any of them; the grants were broader than the inventory commands it documents. Missed in the 1.19.2 tightening. Closes #111.

**Fixed**

- **patch-sweep** (1.0.2): the three heroku wildcards are replaced with rules for exactly the read-only commands the skill uses: `heroku apps --all --json` (exact), `heroku apps:info`, `heroku domains -a`, `heroku releases -a`, `heroku releases:info`, `heroku pipelines:info`. `heroku stack` is dropped; the stack comes from `apps:info`. The Authorization note now explains why `heroku releases -a:*` is used and `heroku releases:*` is not. The vercel, gh and git grants were rechecked; none prefix-matches a write.

If you run patch-sweep, `heroku domains`, `heroku releases` and `heroku stack` without `-a`, and any rollback or destroy, now ask for approval.

### 1.19.6 (2026-10-26)

CI now fails when two skills claim the same trigger phrase. v1.19.5 brought the count to zero; this keeps it there. Repo tooling only; no skill content changes.

**Changed**

- `scripts/lint-skills.mjs`: a single-quoted trigger phrase that appears in two or more skill descriptions is now an **error** (exit 1), not a warning. The same request could activate either skill (SkillSpector rule TR2). The message names both skills and the fix: keep the phrase in the skill that owns the work, and narrow or drop it in the other.
- `docs/security-scanning.md` and `CONTRIBUTING.md`: updated to match. The contributor checklist now asks that no trigger phrase is already claimed by another skill.

### 1.19.5 (2026-10-26)

Trigger-phrase cleanup. Seven phrases appeared in two skills' descriptions, so the same request could activate either one (SkillSpector rule TR2). Each phrase now belongs to the skill that actually does that work. The other skill either drops it, when it already has a more specific trigger, or uses a narrower wording. Description-only changes; no skill bodies changed. `node scripts/lint-skills.mjs` now reports 0 warnings.

**Changed**

- **ai-risk-management** (1.0.3): 'AI red team' → 'AI red-team program' (governance). Hands-on adversarial testing stays with `prompt-injection`.
- **web-pentest** (1.1.2): dropped 'business logic testing'. It belongs to `business-logic-testing`, which Phase 8 already hands off to.
- **security-comms** (1.0.2): dropped 'risk justification', which belongs to `finding-triage`; 'why this matters to the business' stays. 'breach notification' → 'breach notification letter', since engineering the notification pipeline is `privacy-engineering`.
- **privacy-engineering** (1.0.2): dropped 'BAA', which belongs to `hipaa-audit`; 'DPA' and 'data processing agreement' stay.
- **threat-modeling** (1.0.2): dropped 'security review', which belongs to `owasp-audit` for code; 'security architecture review' and 'design review' stay.
- **soc-operations** (1.0.3): dropped 'alert tuning', which belongs to `siem-detection` for rule tuning; 'alert fatigue' stays.

### 1.19.4 (2026-10-26)

CI fix: code scanning raised every baselined SkillSpector match (221 intentional examples) as an open alert. GitHub ignores the `kind: external` suppressions SkillSpector writes for baselined results. Repo tooling only; no skill content changes.

**Fixed**

- `.github/scripts/merge-sarif.mjs` drops results that SkillSpector already suppressed via `.skillspector-baseline.yaml`, and records how many it dropped in the run's properties. Code scanning now shows only real, unbaselined findings, and those still fail the scan job first. Uploading the clean run closes the 221 stale alerts on `development` and the open PRs.

### 1.19.3 (2026-10-26)

CI fix: the SkillSpector scan passed, but uploading its SARIF to GitHub code scanning failed with "more runs than allowed (35 > 20)". Repo tooling only; no skill content changes.

**Fixed**

- `.github/scripts/merge-sarif.mjs` now folds every per-skill scan into one SARIF run. Paths are still rewritten to `skills/<skill>/…`. Rules are de-duplicated by id, and the indexes pointing to rules and files are remapped. The catalog can now grow past 20 skills without breaking the upload.

### 1.19.2 (2026-10-26)

Tightens two pre-approvals that were broader than they looked. Found in the 1.19.1 SkillSpector triage. (#65)

**Fixed**

- **patch-sweep** (1.0.1): removed `Bash(git branch:*)`. The prefix also matched `git branch -D` / `-m`, and the skill never needed it. Branch inspection goes through `git ls-remote` and `git log`, which are still pre-approved.
- **scanner-pipeline** (1.0.1):
  - `osv-scanner:*` is narrowed to `osv-scanner scan:*`, so `osv-scanner fix` (which rewrites lockfiles) now prompts.
  - `trivy:*` is narrowed to `trivy fs` / `image` / `config`.
  - `semgrep` and `pip-audit` are no longer pre-approved. Both have a file-rewriting flag (`--autofix` / `--fix`), and a prefix rule can't exclude a trailing flag, so they now prompt each time.
- `docs/security-scanning.md`: table rows updated to match.

### 1.19.1 (2026-10-26)

Repo trust: CI, lint, and a SkillSpector scan on every PR. Repo tooling only; no skill content changes.

**Added**

- **`.github/workflows/ci.yml`**: runs on PRs and pushes to `development` and `main`. Every action is pinned to a full commit SHA, and permissions are kept to the minimum. (#69)
  - **Skill lint** (`scripts/lint-skills.mjs`, no dependencies). Fails when:
    - `name` doesn't match the folder
    - the description is outside 200–1024 characters
    - `SKILL.md` is 500 lines or more
    - a cross-referenced skill or relative link doesn't resolve
    - `allowed-tools` pairs `WebFetch` with unscoped `Bash`

    It also warns when two skills share a trigger phrase.
  - **Adapter drift:** rebuilds the adapters and shared reference copies, and fails if the committed copies are stale.
  - **Tests:** `npm test` (Node 22).
  - **SkillSpector:** NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector), pinned commit, `--no-llm`, one skill at a time. The tool rejects `--baseline` on recursive scans and reports paths relative to each skill. SARIF is merged and uploaded to code scanning.
- **`.skillspector-baseline.yaml`**: 117 narrow rules, each with a written reason. They cover all 221 current matches, every one of them an intentional example. A security skill has to name `~/.aws/credentials`, show an injection payload, and grep for collector domains. A `*` skill wildcard is only allowed for files copied from `shared/`. `node .github/scripts/skillspector-baseline.mjs --check` validates the file.
- **`docs/security-scanning.md`**: the CI checks, how the baseline works, how to scan this repo yourself before installing, and the full allowed-tools before → after table from 1.19.0 with a reason per skill.
- **README:** CI badge, a "Security scanning" section, build and test commands, and how `shared/` copies work.

**Changed**

- `CLAUDE.md` and `CONTRIBUTING.md`: directory tree and commands now cover `shared/` + `manifest.json` ("edit shared/, never the copies"), `npm test`, the lint, and the baseline check. The contributor checklist points at the CI jobs.

### 1.19.0 (2026-10-26)

**Heads up: this may change how skills feel to use.** `allowed-tools` in a Claude Code skill lists tools that run **without a permission prompt** while the skill is active. It is not an access list or a ceiling. Before this version, 26 of 29 skills pre-approved plain `Bash`, 24 pre-approved `Write`, and 5 paired `Bash` with `WebFetch`. That last combination gives attacker-controlled web content a path to the shell with no prompt in between. Nothing is removed from what a skill *can* do. Commands that used to run silently now ask first, unless they're read-only and listed below. If you relied on the old pre-approvals for unattended runs, add the specific commands to your own permission settings. Credit: NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) rule LP3. (#65)

**Changed**

- **No skill pairs `WebFetch` with unscoped `Bash` anymore.** `recon` and `osint-recon` keep only `whois` / `dig`. `vuln-research` keeps only read-only package queries (`npm ls`, `pip show`, `bundle info`, `go list`). `breach-patterns` and `web-pentest` pre-approve no shell at all; every active test against a target prompts.
- **Bash removed** (the skill runs no commands, or its commands hit a live target and should prompt): ai-risk-management, api-audit, breach-patterns, crypto-audit, csf-mapping, finding-triage, hipaa-audit, mobile-audit, pci-audit, privacy-engineering, prompt-injection, red-team-engagement, siem-detection, threat-hunting, web-pentest.
- **Bash scoped to read-only commands:**
  - cloud-audit and iam-audit: documented `aws` / `gcloud` / `az` read calls
  - container-audit: `trivy image|config`, `kube-bench run`
  - dependency-audit: exact `npm audit` / `pnpm audit --prod` rules so `audit fix` always prompts; plus `npm ls`, `pnpm why`, `yarn why`, `yarn npm audit`, `osv-scanner scan`, `govulncheck`, `bundle audit`, `composer audit`, `dotnet list package`, `trivy fs|image`
  - disk-forensics: `file`, `sha256sum`, `fdisk -l`, `mmls`, `fsstat`, `fls`, `icat`, `strings`
  - incident-triage: `ps`, `netstat`, `lsof`, `who`
  - owasp-audit: exact `npm audit` rules
  - secrets-audit: `trufflehog git`
- **`Write` dropped everywhere** except the skills whose main output is a file: siem-detection (rule files), scanner-pipeline (plan + workflow) and log-watch (plan). Edits still work; they just prompt.
- The new 1.5.0–1.10.0 skills already shipped with scoped grants. agent-supply-chain-audit only pre-approves `skillspector scan --no-llm`, because LLM mode sends file contents to a provider.
- `CLAUDE.md` and `templates/skill-template.md` now describe `allowed-tools` correctly. The template default is `Read, Grep, Glob`.
- Note: the Cursor and Codex adapters carry no tool restrictions at all. Those agents use their own permission settings.

All 29 pre-existing skills get a patch bump. The full before → after table with a reason per skill ships in `docs/security-scanning.md` in 1.19.1.

### 1.18.0 (2026-10-26)

cloud-audit adds a PaaS section. Many small teams have no AWS account at all: production is a Vercel team, a few Heroku apps and a Render service. Every check here comes from a real October 2026 fleet sweep.

**Changed**

- **cloud-audit** (1.1.0). New section **"PaaS (Vercel / Netlify / Heroku / Render / Railway / Fly)"**, with read-only CLI/API commands for each check (#83):
  1. **Stale manual production deploys.** One client site was serving a 96-day-old `vercel deploy --prod` from a laptop while `main` held only a README. Compare the deploy's source, age and commit against the head of the production branch.
  2. **Silently broken git deploys.** For example, an Ignored Build Step running `git diff` while `.vercelignore` excluded `.git`, or a second project still linked to an old org.
  3. **Legacy projects still serving old code** on `*.vercel.app` after their domains moved.
  4. **Duplicate projects per repo**, each carrying its own copy of env vars and secrets.
  5. **Preview and production exposure.** Is deployment protection on? Can `*.vercel.app` addresses bypass the WAF in front of the custom domain? Do preview env vars point at production databases?
  6. **The build queue as an availability risk** during an emergency patch.
  7. **Heroku specifics:** stack and libvips version, runtime pin vs what's actually running, `pg:backups` schedule and restore test, live keys in review-app config vars.
  8. **Repo security defaults:** Dependabot alerts, secret scanning, push protection, branch protection. They were off on 142 repos in one account.
  - New finding type: **"Production not reproducible from source (manual deploy / branch mismatch)"**.
  - Netlify, Render, Railway and Fly versions of the checks live in `references/paas.md`. Supabase RLS advisors are covered too.
  - Cross-references to `patch-sweep` and `scanner-pipeline`. The disposition list now matches the shared set.
- README: cloud-audit row updated.

### 1.17.0 (2026-10-26)

web-pentest gets a combined white-box + black-box mode and a paired-evidence rule for every PoC.

**Changed**

- **web-pentest** (1.1.0)
  - **New section: "Combined white-box + black-box mode".** When you have both the source and a running instance, build a Target Map linking code handlers to live endpoints, along with their shared auth and config. Prioritization runs both ways: code findings guide live testing, and anomalies seen live decide which code gets read first. The authorization check still applies to the live target. owasp-audit points here. (#76)
  - **Paired evidence.** A validated finding shows the attack request next to its baseline or control: unauthenticated vs authenticated, benign vs payload, owner vs non-owner. IDOR / BOLA findings must show owner and non-owner requests that are identical except for the token. Single-request PoCs no longer count as validated. (#76)
  - **Phase 8 (business logic)** is kept and now hands off to `business-logic-testing` for invariants, state-machine abuse and dynamic race proofs. (#74)
  - The report uses the shared verdicts (`confirmed` / `needs_validation` / `rejected`) and severity calibration. Ideas paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0); its never-refuse posture is not adopted.
- README: web-pentest row updated.

### 1.16.0 (2026-10-26)

prompt-injection now catches instructions a human reviewer can't see but the model reads, and MCP tool poisoning.

**Changed**

- **prompt-injection** (1.1.0)
  - **New Step 3: inspect instruction-bearing content for concealment.** Applies to system prompts, RAG corpora, tool and MCP manifests, and agent instruction files. Copy-paste patterns in both `rg` and portable `grep` for:
    - invisible characters (zero-width, bidi overrides, word joiners, BOM, soft hyphen, and the Unicode tag block)
    - directive keywords hidden in HTML or `[//]: #` comments
    - long whitespace runs that push text out of view
    - `data:text/...;base64,` payloads

    The old Steps 3–7 are now 4–8. (#70)
  - **MCP tool poisoning:** injection inside parameter descriptions, a tool's description not matching its behaviour, pinning and diffing tool definitions after approval (rug pulls), and Unicode deception in tool names. (#70)
  - Anti-refusal phrasing added to the indirect-injection patterns. New output category: **Hidden Instruction / Tool Poisoning**. NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) (Apache-2.0) added to References. (#70)
  - **Hardening notes are no longer findings.** "Low — defense-in-depth improvements" moves out of the findings list into a "Hardening notes (not findings)" section, with severity per `references/severity-calibration.md`. (#63)
  - Cross-references to `agent-supply-chain-audit`, `log-watch` and `personal-opsec`.
- README: prompt-injection row updated.

### 1.15.0 (2026-10-26)

secrets-audit now covers AI agent configs and transcripts, which have become one of the most common places secrets leak. It also checks key type before rating a find.

**Changed**

- **secrets-audit** (1.1.0)
  - **AI agent locations** (#73):
    - `env` blocks in `.mcp.json`, `.cursor/mcp.json` and `claude_desktop_config.json`
    - `.claude/settings.local.json`, including `apiKeyHelper`, which runs a shell command
    - agent session transcripts such as `~/.claude/projects/**/*.jsonl`, where secrets get pasted
    - the Cursor, Codex and Gemini equivalents

    The transcript greps only list files, count matches or mask values, so running them from an agent doesn't copy secrets into a fresh transcript. New checklist item: agent configs are gitignored or contain only `${ENV}` references.
  - **Exfiltration collectors as egress indicators:** Discord, Telegram and Slack webhooks, webhook.site, requestbin / pipedream, ngrok, interactsh and similar. Cross-referenced from incident-triage and threat-hunting. (#73)
  - **Key-type check before rating.** Publishable, restricted and secret keys are different findings (Google `AIza…` browser keys, Stripe `pk_` / `rk_` / `sk_`, Supabase anon vs service_role, Firebase config). A public identifier called a key is not a secret. (#63)
  - **findings.json** is written and validated, with secret values redacted to prefix + last 4. (#64)
  - Cross-references to `agent-supply-chain-audit`, `scanner-pipeline` and `personal-opsec`.
- `incident-triage` (1.0.3), `threat-hunting` (1.0.2): cross-references to secrets-audit's collector-domain list for egress checks.
- README: secrets-audit row updated.

### 1.14.0 (2026-10-26)

dependency-audit gets field feedback from a 45-app CVE sweep (October 2026), CI/release trust handoffs, and package-source redirection checks.

**Changed**

- **dependency-audit** (1.2.0)
  - **Step 0: audit the branch that's actually deployed.** Confirm the production branch, plus the deployed package in a monorepo, and the package manager before running anything. In one real repo, `main` held only a README. (#81)
  - **Fixing safely**, from the sweep, in `references/fixing-safely.md` (#81):
    - `pnpm audit --fix` writes open-ended `>=` overrides that force major jumps. Rewrite them to same-major ranges.
    - In-range re-resolves can create duplicate singleton packages. A real case: two copies of `prosemirror-model` broke a live editor while install, lint and build all passed.
    - When a fix is blocked, name the intermediate package that pins the vulnerable version rather than reporting "no fix available".
    - Fixes can raise the Node `engines` floor.
    - pnpm and yarn need their own audit commands. `npm audit` in a pnpm repo fails silently.
    - New "Verify after fixing" checklist: singleton dupes, engines floor, clean `--frozen-lockfile` / `npm ci`, and a preview smoke test of the features those packages power.
  - **Runtimes** (#81):
    - Every pin has to move together (`.ruby-version`, Gemfile `ruby`, lockfile, Dockerfile `ARG`, CI image, buildpack; `.nvmrc`, `.node-version`, `engines`, platform setting).
    - Ruby gotchas: `--conservative` still jumping shared deps, the tighten-resolve-restore pin trick, Brakeman being latest-only, patch-level Rails breaking specs.
    - "No in-place fix exists" is separated from in-range fixes.
    - Platform mitigations count as compensating controls.
  - **New dispositions:** `Mitigated (platform/config)` and `Requires major migration (est. effort)`. (#81)
  - **CI and release trust handoffs** in `references/ci-release.md`, plus a Step 5b summary (#71):
    - Ten patterns, each with a grep: `workflow_run` / `pull_request_target` restoring artifacts or caches into privileged jobs, cache keys that PRs can write, missing or `write-all` `permissions:` combined with a reachable privileged step, OIDC `id-token: write` and the cloud trust-policy subject, release jobs promoting by tag instead of digest, a checksum fetched from the same origin as the artifact, and more.
    - New rule next to the CVE table: a mutable or known-vulnerable dependency is not a finding by itself. Show who can influence resolution and what boundary follows.
    - Facts that only exist on the hosting platform go to `needs_validation`.
    - Paraphrased from Cloudflare's [SUPPLY-CHAIN-AND-RELEASE.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md) (MIT).
  - **Agent extensions and source redirection** (#72):
    - The inventory now includes `.mcp.json` / `.cursor/mcp.json` server commands, installed skills and plugin marketplaces.
    - A per-ecosystem table of package-source redirection (npm, Yarn, pip/uv, Poetry, Maven/Gradle, Cargo, including env-var and CLI forms) in `references/source-redirection.md`.
    - Greps for unpinned `npx -y` / `uvx` / `docker run`, and a check for `.pyc` files with no matching source.
    - New risk row: "Agent extension (unpinned / unreviewed)".
  - **findings.json** is written and validated before the prose (#64). Diff / lockfile-scoped review mode (#67).
  - Cross-references to `patch-sweep`, `scanner-pipeline`, `agent-supply-chain-audit` and cloud-audit "PaaS".
- README: dependency-audit row updated.

### 1.13.0 (2026-10-26)

api-audit gets a much deeper GraphQL playbook, a paired-evidence rule, and the same verify-then-report workflow owasp-audit adopted in 1.12.0.

**Changed**

- **api-audit** (1.1.0)
  - **GraphQL playbook** in `references/graphql.md`, paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0) (#75):
    - schema inference when introspection is off (field suggestions, "Expected one of" enum leaks, existence oracles)
    - an aliased owned-vs-foreign IDOR comparison in a single request
    - child resolvers that assume the parent checked auth
    - Relay `node(id:)` global-ID swaps
    - federation `_entities` / `_service{sdl}`
    - `@defer` / `@stream` leaks
    - subscriptions authorized only at the handshake
    - persisted-query replay
    - `@oneOf` coercion
    - cursor tampering
    - alias/batch rate-limit bypass
    - fragment-split WAF evasion
  - **Paired evidence.** A validated finding shows the attack request next to its baseline. BOLA / BOPLA / BFLA must show owner vs non-owner requests that are byte-identical except for the token. (#76)
  - **Recon first + coverage ledger.** An API entry surface is a REST route, GraphQL operation or resolver, gRPC method, webhook or websocket channel. There's a coverage critic before the report, and partial reports say so. (#68)
  - **Verify every finding** using the three verdicts. "Potential" is retired for `needs_validation` with blockers and a plan, and there's a "Rejected (do not re-raise)" section. (#62)
  - **Severity calibration and hardening notes.** CORS and header issues are findings only with a traced impact. (#63)
  - **findings.json** is written and validated before the prose. (#64)
  - **Diff / PR-scoped mode** for API changes. (#67)
  - Cross-reference to `business-logic-testing` for invariant and race testing of API flows. Existing API1–API10 checklist kept as is.
- README: api-audit row updated.

### 1.12.0 (2026-10-26)

owasp-audit adopts the full audit workflow: recon first, per-finding verification, coverage tracking, machine-readable findings, run profiles and diff mode. Most of these ideas come from a deep dive into [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT) and [Strix](https://github.com/usestrix/strix) (Apache-2.0). Everything is paraphrased and cited.

**Changed**

- **owasp-audit** (1.2.0). New workflow: Scope → Recon → run profile / mode → category checklist → Verify every finding → coverage critic → `findings.json` → report.
  - **Recon first.** Write a short `architecture.md` covering principals, entry surfaces, trust boundaries with the `file:line` of each control, and sinks. Then build a `coverage.json` ledger per surface × boundary × attack class. "Clean" now requires reviewed paths and a check that was actually run, so "A01 clean" can no longer hide routes nobody read. (#68)
  - **Verify every finding.** A separate refutation pass re-reads each cited `file:line`, names the strongest control on the path, and returns one verdict:
    - `confirmed`: carries severity.
    - `needs_validation`: lists blockers plus a check the owner can run. Replaces the old "Potential" label.
    - `rejected`: names the control and its location. These are kept so re-runs don't raise them again.

    A "does NOT rule out" list blocks lazy rejections, and moving a verdict up needs a fresh verifier. (#62)
  - **Severity calibration.** Headers, CORS and cookie flags count as findings only when there's a traced impact. A new "Hardening notes (not findings)" section, and an anti-patterns list (checklist deviations presented as vulns; self-impact presented as crossing a boundary). The A05 `curl -I` checks become needs-validation items. (#63)
  - **findings.json first.** Write and validate `findings.json` (plus `coverage.json`), then render the markdown from it. Prose never changes a verdict or severity. SARIF export for code scanning. (#64)
  - **Run profiles and orchestration.** Quick / standard / deep profiles change breadth, never the evidence bar, and the report header names the profile. For large codebases, a coordinator splits the work across subagent hunters (including a Wildcard and an "Obvious things" hunter), with a sequential fallback for agents that can't run subagents. Re-runs carry findings forward by fingerprint and never re-raise a rejected claim. (#77)
  - **Diff / PR-scoped mode.** In scope: what the change introduces, old weaknesses it newly reaches, helpers it weakens (checked across sibling call sites), controls it removes, and assumptions it breaks. Unrelated old bugs are noted, not filed. The PR description is treated as untrusted. Reports are labeled "diff-scoped (partial)", and there's an optional CI recipe. (#67)
  - **Inbound webhook patterns**, from a real Codex second-model review (`references/webhooks-and-parsers.md`) (#82):
    - Multipart field-index amplification: a 78-byte request expanded to about 5 MB of JSON. Comes with a parser-limits table per framework.
    - Unauthenticated inbound webhooks that trigger paid work. Comes with a provider signature table and the raw-body requirement.
    - Parser errors thrown outside the error boundary, hiding attack traffic from monitoring.
  - When both the source and a running instance are available, the skill points to web-pentest's "Combined white-box + black-box mode". A04 race patterns cross-reference `business-logic-testing` for proving them live. (#76, #74)
  - All existing checklist content is kept. The long tables and payload sets moved to `references/checklist-details.md`. The Second-Opinion Pass is kept as the post-fix review.
- README: owasp-audit row updated.

### 1.11.0 (2026-10-26)

finding-triage gets severity calibration and structured input. This is the first skill to adopt the shared findings foundation from 1.4.0.

**Changed**

- **finding-triage** (1.1.0)
  - **Step 2: the boundary + result gate.** A finding must name six things: the lower-trust principal, the input it controls, the intended control, the boundary crossed, the affected principal or resource, and a concrete observed result. Missing any one makes it a hardening note or a needs-validation item. (#63)
  - **Step 3: severity calibration.**
    - Severity anchors: high fully defeats an explicit control with real consequences; medium only weakens one.
    - `overall ≤ demonstrated impact`.
    - An over-rating list: self-XSS, missing headers, a lone open redirect, "could matter if chained", anything that already needs admin.
    - A High/Critical acceptance checklist.
    - The SLA column is kept separate from severity.
    - Full detail in `references/severity-calibration.md`. (#63)
  - **Defense-in-depth is no longer Low.** A gap where another layer already stops the attack is now a **Hardening note**, outside the findings list. (#63)
  - **Verdict vocabulary:** accepts `confirmed` / `needs_validation` / `rejected` from any audit skill. Severity applies only to `confirmed`. (#62)
  - **Structured input:** accepts a `findings.json` record by fingerprint, using the shared schema and validator now shipped in `references/`. (#64)
  - **New dispositions:** `Mitigated (platform/config)` and `Requires major migration`, alongside Fixed / Deferred / Accepted Risk / False Positive. These came from the October 2026 field sweep (#81).
- README: finding-triage row updated.

### 1.10.0 (2026-10-26)

New skill: **personal-opsec**. Every other skill in the catalog is aimed at an org or a codebase. This one covers the individual: the founder or operator who holds the keys, and who is usually the easiest way in.

**Added**

- **personal-opsec** (1.0.0). An agent-run audit of one person's setup, not a static checklist.
  - **Karpathy's 15 controls** (via Andrej Karpathy's digital security checklist). The agent checks current state on the local machine where it can, using read-only commands: disk encryption, firewall, DNS resolver, password manager CLI, registrar lock via `whois`. It asks the user about the rest.
  - **Operator-critical additions:** account recovery paths, SIM-swap protection and carrier port-out PIN, recovery codes stored offline, registrar and DNS account lock, hardware-key MFA on GitHub and cloud consoles.
  - **The AI-agent-era layer:**
    - tokens and API keys your coding agents can read (→ `secrets-audit`)
    - MCP server trust and what a connected agent could exfiltrate (→ `agent-supply-chain-audit`)
    - prompt injection of personal and inbox assistants (→ `prompt-injection`)
    - clipboard exposure
    - scoped, short-lived tokens over long-lived ones
  - **Output:** a prioritized gap report in the catalog's finding vocabulary, handed to `finding-triage`. Privacy-preference items that don't lead to account takeover are reported as hardening notes, not findings.
  - This is explicitly not security-awareness or phishing training. It refuses to audit someone else's personal security without their consent. (#61)

**Changed**

- `iam-audit` (1.0.1), `breach-patterns` (1.0.1), `agent-supply-chain-audit` (1.0.1): cross-references to personal-opsec.
- README: added to Design & Governance, the skill table, crossovers, and Where to start.

### 1.9.0 (2026-10-26)

New skill: **log-watch**. It sets up scheduled, agent-driven log review and paging for small teams that have no SIEM and no security staff, but do have logs.

**Added**

- **log-watch** (1.0.0).
  - **Inventory the logs you already have** and map each source to the detections it can support: Vercel, Heroku, Render, Sentry, Supabase / Neon / Postgres auth tables, Stripe, Cloudflare, CloudTrail, the GitHub audit log.
  - **Ten starter detections**, each with a signal, threshold and severity, plus example queries: credential stuffing, new admin/owner grants, API key creation, 401/403/404 spikes on admin/`.env`/`.git` paths, bad webhook signatures, unusual export volume, impossible travel, Stripe refund/dispute spikes, CloudTrail root logins and IAM changes, and egress to collector domains.
  - **Two-stage pipeline.** A deterministic filter or cheap classifier first, then a strong model reviews only flagged events alongside the previous run's state. A cost table converts events/min → tokens/day → $/month.
  - **Schedule and state:** cron agent, GitHub Actions schedule or Vercel cron. A checkpoint, a dedupe key per alert, and a suppression list with expiry, so the same issue doesn't page every 5 minutes.
  - **Paging** to Slack, Pushover, PagerDuty or email, with a "why this fired" summary and raw event links.
  - **Logs are untrusted input.** User agents, paths, emails and error text are attacker-controlled, so the reviewing agent gets read-only credentials, log content is fenced as data, and log text never picks an action. Rule-based hits always page; the model can raise their severity but never silence them.
  - **Detection only:** no auto-blocking. Hands off to `incident-triage`, and to `siem-detection` / `soc-operations` when the team outgrows it.
  - Optional scaffold: a GitHub Actions workflow plus a runner in `references/scaffold.md`. (#79)

**Changed**

- `siem-detection` (1.0.1), `soc-operations` (1.0.1), `incident-triage` (1.0.2): cross-references to log-watch.
- README: added to Detect & Respond, the skill table, crossovers, and Where to start.

### 1.8.0 (2026-10-26)

New skill: **scanner-pipeline**. The idea: stop asking an agent to hack your own app. Have it set up real scanners for each layer, then pass their findings to agents to fix.

**Added**

- **scanner-pipeline** (1.0.0).
  - **Pick tools by stack and layer:**
    - secrets: gitleaks, trufflehog
    - code: semgrep, codeql
    - dependencies: osv-scanner (one multi-ecosystem pass is preferred over per-package-manager audits), pip-audit, bundle-audit, govulncheck
    - infrastructure: trivy, checkov
    - Supabase advisors for apps backed by Supabase
    - live app: ZAP baseline, then nuclei, and only on domains the user owns and names
  - **Secrets in full git history.** A verified live secret is P0: rotate it before cleaning history, and never print the value.
  - **Normalize findings** to SARIF or the shared `findings.json`, dedupe across tools, and keep a suppression file where every entry needs a reason and an expiry.
  - **Fleet mode** across `gh repo list`, skipping forks and archived repos, with a roll-up board.
  - **CI template** in `references/security-scan.yml`, with actions pinned to commit SHAs and images pinned to digests: gitleaks, osv-scanner and semgrep on PRs, a weekly full scan, and SARIF upload.
  - **A semgrep rule** in `references/semgrep/supabase-rls.yml` for always-true RLS policies (`x = x`, `using (true)`). It's based on a real bug that exposed 472k email bodies.
  - **Hand-off:** findings go to `finding-triage`, each fix agent gets one finding, the same tool is re-run to confirm the fix, and the agent never edits scanner config to make a finding disappear.
  - Live scanners (nuclei, ZAP) are deliberately not pre-approved and always prompt. (#84)

**Fixed**

- `build-adapters.mjs`: files in nested `references/` folders are now listed in the Cursor/Codex adapters. The appended section is renamed "Reference files" so it no longer clashes with a skill's own "References" heading.

**Changed**

- README: added to AppSec & Supply Chain, the skill table, crossovers, and Where to start.

### 1.7.0 (2026-10-26)

New skill: **patch-sweep**. It came out of a real October 2026 sweep: about 45 apps (Heroku Rails, Render, and around 39 Vercel Next.js projects) responding to a wave of Ruby, Node, PHP, Rails/libvips and Next.js advisories. Most of the real work happened outside any single `npm audit`.

**Added**

- **patch-sweep** (1.0.0). Fleet-wide CVE response.
  - **Inventory:** map each repo to its platform project and the domains it actually serves. Flag legacy projects still serving `*.vercel.app`, projects with no custom domain, and duplicate projects built from the same repo.
  - **Production branch:** find the branch each project really deploys from. Don't assume it's the default.
  - **Stale deploys:** detect stale manual deploys and broken git deploys, which need an owner decision rather than a merge.
  - **Affectedness:** check the runtime, the dependency, and whether the vulnerable code path is used. Read every pin file, call out EOL lines that won't get a fix, and note managed runtimes that patch themselves.
  - **Mitigate before patching**, e.g. `VIPS_BLOCK_UNTRUSTED`.
  - **Patch procedure per app:** hotfix branch from production, in-range fixes only, lint/typecheck/build, preview check, merge, confirm production returns 200, sync back.
  - **Delegation:** about 6 repos per agent, watch for build queues, and repos owned by clients or other maintainers get PRs, never merges.
  - **Prevention:** turn on Dependabot alerts across the fleet.
  - **Output:** a status board with one row per app, plus "not shipped, and why" and "needs a major-version upgrade". Pre-approved commands are read-only inventory only. (#80)

**Changed**

- README: added to AppSec & Supply Chain, the skill table, crossovers, and Where to start.

### 1.6.0 (2026-10-26)

New skill: **business-logic-testing**. Business logic and race conditions are the bugs scanners can't find, and until now the catalog covered them only thinly (web-pentest Phase 8 was eight one-line bullets).

**Added**

- **business-logic-testing** (1.0.0).
  - **Invariants first:** conservation of value, uniqueness, monotonicity, exclusivity. Then an Actor × Action × Resource matrix.
  - **State-machine abuse:** skip, reorder or replay steps, and limit-slicing.
  - **Numeric issues:** float vs decimal, rounding, cross-currency refund arbitrage, negative amounts. Also stale feature gates and roles, and gaps in event-driven sagas.
  - **Concurrency methodology** in `references/concurrency.md`: HTTP/2 single-packet and last-byte sync, connection warming, idempotency keys scoped to a path instead of a principal, cache-before-commit, lost updates, Redis locks without NX/EX or fencing tokens, READ COMMITTED anomalies, upsert races.
  - **Validation and false positives per class.** Example of a validated race: one request is denied, N concurrent ones succeed, and durable state proves it. Truly idempotent operations and visual-only glitches don't count.
  - **Authorization:** concurrency testing against production money flows needs explicit written scope. Staging or test mode is preferred, request counts are capped, and third parties are never targeted. Pre-approved tools are read-only, so live requests always prompt.
  - Uses the shared verdicts and `findings.json`. Methodology paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0). Strix's never-refuse posture is explicitly not adopted. (#74)

**Changed**

- README: added to Offensive & Recon, the skill table and crossovers. The links from owasp-audit, api-audit and web-pentest come with those skills' own versions.

### 1.5.0 (2026-10-26)

New skill: **agent-supply-chain-audit**. Coding-agent extensions are now a supply-chain surface that runs with your privileges and almost no review. NVIDIA's SkillSpector cites research finding vulnerabilities in about a quarter of 31k published skills, with about 5% likely malicious.

**Added**

- **agent-supply-chain-audit** (1.0.0). Audits the skills, plugins, marketplaces, hooks, settings, MCP servers, and instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `copilot-instructions.md`) that Claude Code, Cursor, Codex, Gemini CLI and Copilot load, at both project and user level.
  - Inventory with source and pin for every extension.
  - Content checks, each with a grep and the matching SkillSpector rule ID: hidden instructions, invisible Unicode, agent snooping, exfiltration wording, anti-refusal language, `curl | bash`, shipped `.pyc` files, persistence writes.
  - Hooks and settings review: `defaultMode`, `permissions.allow`, `apiKeyHelper`, hooks that call out to the network.
  - MCP pinning and tool-definition diffing to catch rug pulls.
  - Optional SkillSpector pass. Only `--no-llm` is pre-approved, because LLM mode sends file contents to a provider.
  - Read-only. Output is an inventory table plus findings in the shared `findings.json` format, with a SAFE / CAUTION / DO NOT INSTALL verdict per item. (#66)

**Changed**

- `ai-risk-management` (1.0.1): new "AI coding agents and extensions" row in the AI inventory, pointing to agent-supply-chain-audit.
- `incident-triage` (1.0.1), `threat-hunting` (1.0.1): cross-references to agent-supply-chain-audit.
- README: added to the AI Security family, the skill table, crossovers, and Where to start.

### 1.4.0 (2026-10-26)

Findings foundation. No skill content changes in this version. It adds the shared machinery that the audit skills adopt one at a time in the versions that follow.

**Added**

- `shared/findings.schema.json` + `shared/validate-findings.mjs`: a machine-readable `findings.json` with stable root-cause `fingerprint`s and three verdicts (`confirmed` / `needs_validation` / `rejected`). The validator has no dependencies and exits non-zero on bad input. It enforces sort order, no duplicates, safe repo-relative paths, a trace that runs entrypoint → sink, `overall ≤ impact`, severity only on `confirmed`, blockers + plan on `needs_validation`, a named control on `rejected`, and `high` confidence only when reproduced. Schema structure adapted from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). (#64)
- `shared/to-sarif.mjs`: findings.json → SARIF 2.1.0 for GitHub code scanning. Fingerprint → `partialFingerprints`, trace → `codeFlows`, severity → `security-severity`. (#64)
- `shared/coverage.schema.json` + `shared/validate-coverage.mjs`: a coverage ledger per surface × trust boundary × attack class. `covered` requires reviewed paths and a check. (#68)
- `shared/severity-calibration.md`: the boundary + result gate, severity anchors, the `overall ≤ demonstrated impact` rule, the over-rating list, the High/Critical checklist, and hardening notes ≠ findings. (#63)
- `shared/verification.md`, `recon-and-coverage.md`, `orchestration.md`, `diff-review.md`: the per-finding refutation pass, recon-first + coverage critic, coordinator/hunter orchestration with quick / standard / deep run profiles and re-run carry-forward, and diff / PR-scoped review. (#62, #67, #68, #77)
- `shared/manifest.json`: declares which skills receive a copy of each shared file. `scripts/build-adapters.mjs` now copies shared files into `skills/<skill>/references/`, because `npx skills` installs one folder at a time. Cursor/Codex adapters gain a References section linking those files. It's empty in this version; each skill adds itself when it starts using a file.
- `npm test`: a zero-dependency `node:test` suite (53 tests) for the validators, SARIF export and the build. Needs Node ≥ 21.

**Decided (#78):** live probing stays allowed when it's authorized and non-destructive, e.g. checking whether a leaked key is live or running `curl -I` against your own origin. A check that wasn't actually run is recorded as `needs_validation`, never as confirmed or clean.

### 1.3.0 (2026-05-26)

Compliance and governance release. **Six new skills**, taking the catalog from 23 → 29 skills across seven families (added: Compliance & Privacy). Catalog audited end to end before tag: all 29 skills pass mechanical checks; content audit found no fatigue, no pattern reuse, all cross-references resolve.

**New skills:**

- **security-comms** — Translate security work for non-security audiences. Seven audience archetypes (board / executive / engineering leadership / individual engineers / customer success / customers / procurement-legal-compliance), two-mode workflow (draft from technical input / review a draft), six templates (board update, executive memo, customer disclosure draft, post-mortem narrative, audit-findings-for-engineering, sales-engineering FAQ). Closes the gap every other skill produces — namely, the technical output that has to land with a non-security audience.
- **privacy-engineering** — GDPR / CCPA / CPRA / LGPD / PIPEDA technical implementation. Eight engineering practices (data classification, minimization, lawful basis, consent management, DSAR pipeline with full deletion fan-out across DBs / caches / search / analytics / vendors, vendor / sub-processor management, breach-notification engineering hooks, DPIA inputs). Concrete grep patterns for PII leakage in code and analytics SDK initializations.
- **ai-risk-management** — NIST AI Risk Management Framework (RMF) 1.0 + EU AI Act. Broader than prompt-injection (which is the security slice). Four-function workflow (Govern / Map / Measure / Manage with inventory as prereq), evaluation categories with concrete tooling per category (Fairlearn, AIF360, What-If Tool, Aequitas, SHAP, LIME, HELM, MMLU), regulatory layer covering EU AI Act risk tiers, US federal patchwork, state laws.
- **red-team-engagement** — Authorized adversary emulation methodology. Distinct from web-pentest (technique-focused). Multi-week, objective-based, often assumed-breach. Carries the heaviest authorization gating in the catalog: seven required checks before any planning, explicit refusal language, RoE document with twelve specific sections, and a Boundaries section with eight separate refusal categories.
- **pci-audit** — PCI DSS v4.0 audit. Leads with scope determination (the single most-leveraged variable). Engineering-relevant requirements (Req 3 storage of CHD with PAN regex patterns by brand; Req 4 transmission; Req 6 cross-ref to owasp-audit / api-audit / vuln-research / dependency-audit; Req 7-8 cross-ref iam-audit; Req 10 cross-ref siem-detection; Req 11 cross-ref dependency-audit / web-pentest / red-team-engagement; Req 12 cross-ref incident-triage).
- **hipaa-audit** — HIPAA Security / Privacy / Breach Notification / HITECH. Three safeguard categories (Administrative / Physical / Technical) with §164.308 / §164.310 / §164.312 citations. 18 identifiers, BA chain-of-liability, minimum-necessary at the query / API level, 60-day breach notification timing by recipient, encryption-as-safe-harbor framing.

**Existing skills updated (back-references added):**

- `incident-triage` — added cross-refs to security-comms (stakeholder / customer notifications), privacy-engineering / hipaa-audit / pci-audit (regulatory clock determination), ai-risk-management (AI-specific incident classes)
- `finding-triage` — added cross-ref to security-comms (translating dispositions for non-security audiences)
- `breach-patterns` — added cross-refs to hipaa-audit / pci-audit / privacy-engineering for regulatory implications
- `prompt-injection` — added cross-ref to ai-risk-management for the broader governance frame

**README:**

- Skill-map diagram expanded from six → seven families with the new Compliance & Privacy family
- Skills table includes all 29 entries
- "Where to start" section expanded with new contexts: working under a specific regulation, translating security work upward / outward

**Repo state:**

- 50+ PRs since v1.0.0; 7 PRs in this release cycle (#54–#60)
- main + development synced
- Plugin metadata (`marketplace.json`, `plugin.json`) at 1.3.0
- npx skills and Claude plugin marketplace install paths verified

**Audit pre-release confirmation:**

A comprehensive content + mechanical audit ran before the v1.3.0 tag. Mechanical checks (build, naming, JSON validity, npx enumeration, adapter sync, description length, line count) all clean. Content audit specifically checked for fatigue / pattern-reuse risk after six skills in one stretch — none found. pci-audit and hipaa-audit are demonstrably distinct skills, not the same template with different acronyms. security-comms is the strongest new addition. red-team-engagement carries the heaviest and most appropriate authorization framing in the entire catalog.

### 1.2.2 (2026-05-26)

Audit-driven polish patch. Full mechanical + content audit of all 23 skills landed with one substantive fix and six minor cross-reference / description improvements.

**Mechanical audit results (all clean):**
- Build script succeeds for all 23 skills
- Every skill's `name` field matches its directory name
- Every description in the 200-1024 character target range
- Every adapter file (Cursor `.mdc`, Codex `.md`) generated and in sync
- `.claude-plugin/{marketplace,plugin}.json` JSON valid
- `npx skills add briiirussell/cybersecurity-skills --list` enumerates all 23
- All skills under 500 lines (largest: `owasp-audit` at 365)

**Content fixes:**

- **`siem-detection`** — stripped four stale "future" / "coming in this release" qualifiers that referenced `soc-operations`, `threat-hunting`, and `breach-patterns` as forthcoming. All three skills now exist (since v1.2.0), so the cross-references are now correct and live.
- **`incident-triage`** — added an explicit cross-references block. The skill predates the detect/respond family; every adjacent skill referenced back into it, but it referenced none of them. Now points at `siem-detection` (the rule that fired), `disk-forensics` (deeper analysis), `breach-patterns` (post-incident pattern extraction), `soc-operations` (the ops layer above).
- **`prompt-injection`** — added cross-references to `threat-modeling` (design-time AI risk), `owasp-audit` (output-rendering XSS overlap), and `api-audit` (LLM tool / MCP server API surface). The skill was an island; it now sits in the family.
- **`cloud-audit`** — added explicit cross-references pointing IAM deep-dive at `iam-audit`, K8s posture at `container-audit`, secrets hygiene at `secrets-audit`. Also added a disposition-rule pointer to `owasp-audit`'s three-disposition Report Format.
- **`recon`** and **`osint-recon`** — added bidirectional cross-references. recon now references osint-recon and web-pentest; osint-recon now references recon, breach-patterns, and incident-triage. The passive→active and OSINT→active pairings are now explicit.
- **`disk-forensics`** — added an explicit `## Authorization Check` section (previously folded into Boundaries only) covering lawful basis, chain of custody, and privacy scope. Expanded description with more trigger phrases ("timeline analysis," "memory forensics," "volatility," "plaso," "log2timeline," "artifact analysis," "chain of custody").
- **`owasp-audit`** — broadened description from 311 to 757 characters with the full OWASP Top 10 category list and additional trigger phrases ("appsec review," "secure code review," "IDOR," "SQL injection," "XSS," "SSRF," etc.). The anchor skill of the catalog deserves the pushy invocation.

**No skill content was added or removed.** All changes are descriptive / cross-reference improvements that make the catalog feel like one connected family instead of 23 independent files.

Plugin metadata (`marketplace.json`, `plugin.json`) bumped to 1.2.2.

### 1.2.1 (2026-05-26)

Documentation patch — no skill content changes.

- README opening rewritten to make audience inclusive. Previous framing positioned the skills as "for security engineers and red/blue teamers"; v1.2.1 explicitly welcomes developers shipping safer code without a dedicated security team, and founders / ops folks / small-team operators securing stacks they can't afford a CISO for.
- New **Where to start** section maps user context to recommended starting skills — reviewing your own code, securing cloud infrastructure, responding to incidents, building a security program from scratch, closing the loop on a single finding.
- Honest note about offensive skills (`recon`, `osint-recon`, `web-pentest`) requiring more security context and explicit authorization — these stay opt-in for users with the right footing.
- Contributing language broadened — field feedback is welcome from every level of expertise, not just practitioners.

This patch reflects the project's actual reach: while security professionals are still the majority of users, the skills are designed to be usable end-to-end by anyone whose AI agent needs to do security work. The technical depth is in the skills; the explanations are in the agent's output.

Plugin metadata (`marketplace.json`, `plugin.json`) bumped to 1.2.1 to keep release and bundle aligned.

### 1.2.0 (2026-05-26)

Major expansion. **Fifteen new skills** added, growing the repo from 8 → 23 skills across six families. Repo is now installable via `npx skills` and the Claude Code plugin marketplace.

**New skills:**

- **api-audit** — OWASP API Security Top 10 (2023). BOLA, mass assignment, BFLA, sister-route gaps, GraphQL introspection, webhook signature verification.
- **breach-patterns** — Preemptive hardening from public breach disclosures. Ten patterns catalogued (Capital One, SolarWinds, LastPass, Okta Lapsus$, Snowflake, MOVEit, Codecov, Twitter insider, Equifax, Uber).
- **container-audit** — Docker + Kubernetes security. Dockerfile, pod security, RBAC, NetworkPolicy, secrets, image policy, runtime detection.
- **crypto-audit** — Cryptography implementation review. Deeper than owasp-audit A02 — algorithm/mode choice, KDF parameters, IV/nonce handling, signature verification ordering, randomness, TLS posture, key lifecycle.
- **csf-mapping** — NIST CSF 2.0 governance frame. Subcategory mapping, current/target tiers, prioritized roadmap. Translates technical findings into board language.
- **finding-triage** — Single-finding disposition workflow. Closes the loop on every audit skill. Four templates (Fix / Defer / Accept Risk / False Positive) with required-field enforcement.
- **iam-audit** — Consultant-style IAM. Three modes (audit / design / migrate) covering cloud IAM (AWS/GCP/Azure), identity providers (Okta/Entra/Auth0/Workspace), and application authorization (RBAC/ABAC/ReBAC).
- **mobile-audit** — iOS + Android against OWASP MASVS / MASTG. Storage, crypto, network (cert pinning), auth (biometrics, OAuth), platform (deeplinks, IPC), code, resilience.
- **secrets-audit** — Find leaked secrets (code, Git history, build artifacts, CI, frontend bundles) + audit secrets-management posture (rotation, scope, workload identity federation).
- **siem-detection** — Detection engineering. Log source → ATT&CK coverage mapping, Sigma rule authoring, FP tuning lifecycle, detection-as-code Git+CI workflow.
- **soc-operations** — Build / run / improve a SOC. Staffing math, runbook structure, escalation criteria, KPIs (MTTD / MTTR / FP rate), alert-fatigue tuning loop.
- **threat-hunting** — Proactive, hypothesis-driven hunts. PEAK framework, ATT&CK-driven hunt catalog, every hunt produces a rule / dead-end doc / coverage gap.
- **threat-modeling** — Pre-implementation security design. STRIDE-per-element + abuse cases, Shostack four-question frame, data flow diagrams with trust boundaries.
- **vuln-research** — CVE deep-dive. Pull canonical sources (NVD / vendor / GHSA / CISA KEV / EPSS), reachability analysis, exploitation availability check, patch / mitigate / accept-risk decision.
- **web-pentest** — Live web application testing. OWASP WSTG-structured, nine phases from config through business logic. Heavy authorization-check + boundaries because most dual-use skill in the family.

**Distribution:**

- `npx skills add briiirussell/cybersecurity-skills` — works out of the box (vercel-labs/skills)
- `/plugin marketplace add briiirussell/cybersecurity-skills` — Claude Code plugin marketplace via new `.claude-plugin/` scaffold (marketplace.json + plugin.json)

**README and docs:**

- Updated skill-map diagram showing the six families and cross-references
- Six install methods documented in priority order (npx, plugin marketplace, manual, Cursor, Codex, submodule)

**Repo health:** main + development synced, all 50 PRs in this release cycle merged, no open issues or PRs.

### 1.1.0 (2026-05-26)

Field-feedback release. Thirteen PRs (#21–#33) closing every open issue from real-world audits — owasp-audit grew from 163 → 365 lines, dependency-audit from 235 → 281 lines, both still well under the 500-line guideline.

**owasp-audit additions:**

- **A01:** auth-check ordering (404/400/401 ordering as state-enumeration leak), IDOR via foreign keys in mutation payloads, framework RPC surface enumeration (server actions, tRPC, GraphQL, Remix), open-redirect control-byte rejection (extends PR #20)
- **A02:** full provider key prefix list (Stripe, GitHub, AWS, GCP, Slack, OpenAI/Anthropic, Vercel), bcrypt cost ≥ 12, VERIFY_PEER managed-service caveat with three-option remediation ladder, config-file extensions (.yml / .yaml / .toml / .json) in grep sweep, type coercion in cryptographic-verification paths (parseInt → NaN defeating freshness checks)
- **A03:** full JSON-LD JSON.stringify breakout pattern (replaces "typically safe" parenthetical), Rails ERB sinks + Rails JSON-LD idiom, SVG upload as stored XSS, regex-sanitizer anti-pattern with [/\s] / cross-namespace / CSP-backstop requirements, sanitize on write AND on render with backfill migration
- **A04:** configured-but-not-loaded check, multi-tenant webhook signature N-way matching DoS, rate-limit key fallback as lockout vector, fire-and-forget background jobs lose request-scoped auth, sister-route audit, external-resource-create TOCTOU with billing implications, worker-queue atomic claim
- **A05:** Rails admin-engine mounts gated on Rails.env.production? (PgHero / Sidekiq::Web / Flipper / Mission Control leak in staging), source-tree hygiene (macOS sync-conflict duplicates), Next.js next.config.ts headers() rule merging, auth middleware that doesn't exempt bearer/HMAC routes, bearer-token compare with unset env interpolation, API routes returning HTML 302 instead of JSON 401, framework header locations, baseline header values table, concurrent-execution races on paid endpoints
- **A06:** cross-reference to dependency-audit, npm prod/dev triage
- **A07:** Devise :validatable enforcement, NextAuth v5 / Auth.js footguns (AUTH_SECRET fallthrough, credentials rate-limit, account enumeration, JWT-strategy adapter no-op)
- **A08:** external-resource overwrite without state check, external side-effects before durable DB state (reserve-then-act)
- **A09:** silent-catch anti-pattern, unauthenticated email to user-supplied address (phishing vector against sender reputation)
- **A10:** image-optimizer-as-proxy (next/image, Nuxt, SvelteKit), expanded SSRF bypass matrix (decimal/hex/octal IPv4, IPv4-mapped IPv6, trailing-dot, cloud metadata, CGNAT, link-local IPv6)
- **New section:** Second-Opinion Pass — adversarial second-pass review of the report and the fix branch, plus verify-against-library-internals rule
- **Verify Fixes:** canonical XSS payload bank for sanitizer-config verification
- **Report Format:** three-disposition rule (Fixed / Deferred / Accepted Risk) with required fields, per-category Clean / N/A states, enriched Verification field requiring concrete adversarial input

**dependency-audit additions:**

- **Step 1:** package manifest edge cases (optionalDependencies, overrides used to silence, monorepos, engines)
- **Step 2:** `npm audit --omit=dev` for prod-vs-dev triage, `--force` downgrade footgun warning, "when audit fix cannot resolve" subsection
- **Step 3:** advisory-freshness methodology (cross-ref GitHub Advisories before consulting hardcoded patterns)
- **Next.js:** server-only import detection
- **Express / Node:** new Serverless / edge runtime subsection (in-memory Map rate-limit is per-instance, x-forwarded-for trust, unbounded collections)
- **Step 4 lockfile/CI:** concrete grep commands replacing prose checklist
- **Output:** "Where reachable" column added to the CVE table (runtime / build-only / dev-only)

All thirteen field-feedback issues from @coreyhaines31 closed in this release. Acknowledgements in the GitHub Release.

### 1.0.0 (2026-05-26)

First tagged release. Eight skills covering AppSec, offensive recon, detect-and-respond, cloud, and AI security:

- **owasp-audit** — Source-code audit against OWASP Top 10 (2021). Category-by-category checklist, grep patterns, remediation guidance, report template.
- **dependency-audit** — Dependency, framework, runtime, and toolchain audit. CVE lookups, supply chain risk, security anti-patterns.
- **prompt-injection** — Audit AI features / LLM integrations / agents for prompt injection, privilege escalation, and authorization bypass.
- **recon** — Structured attack surface enumeration for authorized pentests, bug bounty, and CTF.
- **osint-recon** — Open source intelligence gathering and correlation for authorized investigations.
- **incident-triage** — NIST SP 800-61 incident response triage.
- **disk-forensics** — Disk image analysis, evidence recovery, timeline reconstruction.
- **cloud-audit** — AWS / GCP / Azure misconfiguration and IAM audit.

Also includes:

- Build script (`scripts/build-adapters.mjs`) for Cursor `.mdc` and Codex `.md` outputs
- Skill template (`templates/skill-template.md`)
- `CLAUDE.md` with skill format spec and writing guidance
- `CONTRIBUTING.md` with full workflow
- README modeled on the AI-skills ecosystem standard

Repo workflow established:

- `main` — stable, tagged releases
- `development` — integration branch
- `feature/<name>` — per-change branches, merged into `development`, then `development` → `main` at release cut
