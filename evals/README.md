# Evals

Forty-two skills means a lot of overlap. `incident-triage`, `finding-triage` and `breach-patterns` all sound like "triage" to someone in a hurry, and `recon` and `osint-recon` share half a vocabulary. These evals check that a prompt lands on the skill that should handle it.

## Offline trigger eval (every PR)

`evals/triggers/<skill>.json` holds, for every skill:

- **`should_fire`**: at least 5 prompts that should load the skill. Some are casual ("ransomware just hit our file server"), and at least one pastes code or config, because real requests often do.
- **`near_miss`**: at least 5 prompts that sound close but belong to another skill, each with the `owner` that should take it.

```bash
node scripts/eval-triggers.mjs --verbose
```

The script ranks every prompt against every skill's description with BM25, a plain term-matching score, and prints each prompt that ranked wrong. No model, no API key, no cost. CI fails when:

| Check | Floor |
|---|---|
| Should-fire prompts that rank their own skill first | 85% overall |
| Near-misses that rank their owner above the skill they were written for | 90% overall |
| Any single skill's own prompts won | at least 3 of 5 (60%) |
| TF-IDF similarity between any two descriptions | at most 0.55 |
| Prompts per skill | at least 5 of each kind |

The floors sit a little under what the current descriptions score. They're there to catch a description edit that quietly steals another skill's prompts, or loses its own. When descriptions improve, raise the floors. Don't lower them to get a PR through.

### What it is and isn't

It's a proxy. Claude reads descriptions and understands them; BM25 counts shared words. So a miss here is a hint, not a verdict. "How do we detect jailbroken devices?" belongs to `mobile-audit` and any model gets that, but BM25 ranks it 21st because the description says "jailbreak detection" and the stemmer connects neither "jailbroken" to "jailbreak" nor "detect" to "detection". Real routing needs the model itself, which is what the [plugin evals](#plugin-evals-on-demand) are for.

What the proxy is good at: it's free, it runs on every PR, and it notices when two descriptions start sounding alike.

### Results

At v1.50.1 (42 skills): should-fire top-1 **213/228 (93.4%)**, top-3 223/228 (97.8%); near-miss **217/221 (98.2%)**. The most similar pair is `ai-risk-management` / `prompt-injection` at 0.45. (At v1.23.4, with 35 skills, it was 91.4% and 97.7%.)

The misses worth knowing about, since they point at descriptions that could be sharper:

- `incident-triage` wins only 3 of 5. "Ransomware just hit our file server" and "someone created a new admin user at 3am" go elsewhere, and two near-misses ("we've just been breached…", "we were compromised through that CVE…") go to `breach-patterns` and `patch-sweep`. The description leans on 'incident' and 'breach' words that other skills also use.
- `prompt-injection` wins 3 of 5. Prompts about agents being hijacked by a web page or an email don't share words with "prompt injection".
- `mobile-audit` loses the jailbreak prompt (see above).
- `fuzzing-harness` loses "write a fuzzer for our packet parser? it's C" to `native-code-review`, and `security-start` doesn't take any other skill's prompts.
- Pasted-code prompts are the weakest group: the Dockerfile goes to `secrets-audit` (it contains `AWS_SECRET_ACCESS_KEY`), and a balance-check race goes to `pci-audit` (it says `charge_card`).

## Plugin evals (on demand)

`evals/cases/<case>/` is a [`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals.md) suite. Each case is a real prompt sent to a real model with this plugin installed. Its graders check which skills actually loaded:

- `graders/fires-<skill>.md` passes when that skill loads (`tool_used`, `tool: Skill`).
- `graders/quiet-<skill>.md` passes when the rival doesn't load (`min: 0`, `max: 0`, `arm: both`).
- The two `quiet-*` cases are everyday coding requests where no security skill should load at all.

| Group | Cases |
|---|---|
| `owasp-vs-api` | `owasp-audit-code-review`, `api-audit-bola` |
| `triage` | `incident-triage-live`, `finding-triage-scanner`, `breach-patterns-lessons` |
| `recon` | `recon-bug-bounty`, `osint-recon-phishing-domain` |
| `secrets-vs-scanners` | `secrets-audit-git-history`, `scanner-pipeline-ci` |
| `quiet` | `quiet-commit-message`, `quiet-async-question` |

These cost API money, so they never run on PRs. The [Plugin evals workflow](../.github/workflows/evals.yml) runs them:

- on demand (Actions → Plugin evals → Run workflow, with an optional case glob and run count)
- on pushes to `main` that change a `SKILL.md` or a case

It pins the model (`claude-sonnet-5-5`) and the Claude Code CLI (2.1.296), runs each case 3 times, and fails a case that scores under 0.8. It stops at $15 of estimated spend and uploads `aggregate-result.json` and `report.html` as an artifact. `.github/scripts/eval-summary.mjs` writes the score table to the run summary. It also fails on any run that ended in an API error, because CLI versions before 2.1.299 still grade those runs. The workflow skips with a notice until the repo has an `ANTHROPIC_API_KEY` secret. Forks never get it.

Locally, with Claude Code 2.1.269 or later:

```bash
claude plugin eval . --eval-dir evals/cases --ablation none --runs 1                    # everything, one run each
claude plugin eval . --eval-dir evals/cases --ablation none --runs 3 --case 'recon-*'   # one group
```

`--ablation none` skips the without-plugin baseline arm. A baseline is pointless for "did the skill load", and it doubles the cost. Results go to `evals/results/`, which git ignores. `scripts/test/eval-cases.test.mjs` checks the suite's shape on every PR for free: it catches a grader naming a skill that doesn't exist, an unknown frontmatter key, or a routing case with no rival.

### Which wordings fire

Record each run here with its model and CLI version, so a description change can be judged against the last good run.

| Date | Model | Claude Code | Passed | Notes |
|---|---|---|---|---|
| – | – | – | – | Not run yet: needs the `ANTHROPIC_API_KEY` secret |

## Writing prompts

- Write the way people ask, not the way the description reads. Copying trigger phrases into prompts makes the eval pass without proving anything.
- Near-misses should be genuinely close: the request you'd expect to wrongly pull in this skill.
- If a new prompt misses, look at the description first. If the description is right and the proxy is just being literal, keep the prompt. An honest miss is better than a prompt bent to fit.
