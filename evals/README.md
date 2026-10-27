# Evals

Thirty-five skills means a lot of overlap. `incident-triage`, `finding-triage` and `breach-patterns` all sound like "triage" to someone in a hurry, and `recon` and `osint-recon` share half a vocabulary. These evals check that a prompt lands on the skill that should handle it.

## Offline trigger eval (every PR)

`evals/triggers/<skill>.json` holds, for every skill:

- **`should_fire`**: at least 5 prompts that should load the skill. Some are casual ("ransomware just hit our file server"), and at least one pastes code or config, because real requests often do.
- **`near_miss`**: at least 5 prompts that sound close but belong to another skill, each with the `owner` that should take it.

```bash
node scripts/eval-triggers.mjs --verbose
```

The script ranks every prompt against all 35 descriptions with BM25, a plain term-matching score, and prints each prompt that ranked wrong. No model, no API key, no cost. CI fails when:

| Check | Floor |
|---|---|
| Should-fire prompts that rank their own skill first | 85% overall |
| Near-misses that rank their owner above the skill they were written for | 90% overall |
| Any single skill's own prompts won | at least 3 of 5 (60%) |
| TF-IDF similarity between any two descriptions | at most 0.55 |
| Prompts per skill | at least 5 of each kind |

The floors sit a little under what the current descriptions score. They're there to catch a description edit that quietly steals another skill's prompts, or loses its own. When descriptions improve, raise the floors. Don't lower them to get a PR through.

### What it is and isn't

It's a proxy. Claude reads descriptions and understands them; BM25 counts shared words. So a miss here is a hint, not a verdict. "How do we detect jailbroken devices?" belongs to `mobile-audit` and any model gets that, but BM25 ranks it 17th because the description says "jailbreak detection" and the stemmer connects neither "jailbroken" to "jailbreak" nor "detect" to "detection". Real routing needs the model itself; that is what the `claude plugin eval` cases ([#124](https://github.com/briiirussell/cybersecurity-skills/issues/124)) are for.

What the proxy is good at: it's free, it runs on every PR, and it notices when two descriptions start sounding alike.

### Results

At v1.23.4: should-fire top-1 **160/175 (91.4%)**, top-3 170/175 (97.1%); near-miss **171/175 (97.7%)**. The most similar pair is `ai-risk-management` / `prompt-injection` at 0.48.

The misses worth knowing about, since they point at descriptions that could be sharper:

- `incident-triage` wins only 3 of 5. "Ransomware just hit our file server" and "someone created a new admin user at 3am" go elsewhere, and two near-misses ("we've just been breached…", "we were compromised through that CVE…") go to `breach-patterns` and `patch-sweep`. The description leans on 'incident' and 'breach' words that other skills also use.
- `prompt-injection` wins 3 of 5. Prompts about agents being hijacked by a web page or an email don't share words with "prompt injection".
- `mobile-audit` loses the jailbreak prompt (see above).
- Pasted-code prompts are the weakest group: the Dockerfile goes to `secrets-audit` (it contains `AWS_SECRET_ACCESS_KEY`), and a balance-check race goes to `pci-audit` (it says `charge_card`).

## Writing prompts

- Write the way people ask, not the way the description reads. Copying trigger phrases into prompts makes the eval pass without proving anything.
- Near-misses should be genuinely close: the request you'd expect to wrongly pull in this skill.
- If a new prompt misses, look at the description first. If the description is right and the proxy is just being literal, keep the prompt. An honest miss is better than a prompt bent to fit.
