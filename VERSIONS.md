# Cybersecurity Skills Versions

Current versions of all skills. Agents can compare against local versions to check for updates.

| Skill | Version | Last Updated |
|-------|---------|--------------|
| agent-supply-chain-audit | 1.0.2 | 2026-10-27 |
| ai-risk-management | 1.1.2 | 2026-10-26 |
| api-audit | 1.1.7 | 2026-10-27 |
| breach-patterns | 1.0.4 | 2026-10-26 |
| business-logic-testing | 1.0.2 | 2026-10-26 |
| cicd-security | 1.0.0 | 2026-10-27 |
| cloud-audit | 1.2.0 | 2026-10-26 |
| container-audit | 1.1.0 | 2026-10-26 |
| control-audit | 1.2.0 | 2026-10-27 |
| crypto-audit | 1.1.2 | 2026-10-27 |
| csf-mapping | 1.0.3 | 2026-10-27 |
| dependency-audit | 1.3.0 | 2026-10-29 |
| disk-forensics | 1.0.2 | 2026-10-27 |
| finding-triage | 1.3.1 | 2026-10-27 |
| fuzzing-harness | 1.0.1 | 2026-10-27 |
| hipaa-audit | 1.1.1 | 2026-10-27 |
| iam-audit | 1.2.0 | 2026-10-27 |
| incident-triage | 1.1.2 | 2026-10-27 |
| log-watch | 1.0.1 | 2026-10-26 |
| malware-triage | 1.0.0 | 2026-10-27 |
| mobile-audit | 1.1.1 | 2026-10-27 |
| native-code-review | 1.0.1 | 2026-10-27 |
| osint-recon | 1.0.2 | 2026-10-26 |
| owasp-audit | 1.6.0 | 2026-10-27 |
| patch-sweep | 1.1.0 | 2026-10-29 |
| pci-audit | 1.1.1 | 2026-10-27 |
| personal-opsec | 1.0.1 | 2026-10-26 |
| privacy-engineering | 1.1.0 | 2026-10-27 |
| prompt-injection | 1.2.1 | 2026-10-27 |
| recon | 1.0.1 | 2026-10-26 |
| red-team-engagement | 1.0.1 | 2026-10-26 |
| scanner-pipeline | 1.0.4 | 2026-10-27 |
| secrets-audit | 1.1.4 | 2026-10-27 |
| security-comms | 1.0.3 | 2026-10-26 |
| security-start | 1.0.0 | 2026-10-27 |
| siem-detection | 1.0.5 | 2026-10-27 |
| soc-operations | 1.0.4 | 2026-10-26 |
| threat-hunting | 1.0.5 | 2026-10-27 |
| threat-modeling | 1.0.4 | 2026-10-26 |
| variant-analysis | 1.0.0 | 2026-10-27 |
| vuln-research | 1.0.4 | 2026-10-27 |
| web-pentest | 1.2.1 | 2026-10-27 |

## Recent Changes

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
