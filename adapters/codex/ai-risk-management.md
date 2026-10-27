# ai-risk-management

> Apply the NIST AI Risk Management Framework (AI RMF 1.0) and adjacent guidance to AI / ML systems — model lifecycle governance, fairness and bias evaluation, robustness, transparency, accountability, third-party model risk, monitoring for drift, and AI incident response. Broader than prompt-injection (which is the security slice). Use when the user mentions 'AI risk,' 'AI governance,' 'NIST AI RMF,' 'AI compliance,' 'ML governance,' 'model risk management,' 'AI fairness,' 'AI bias,' 'algorithmic accountability,' 'AI Bill of Rights,' 'EU AI Act,' 'AI transparency,' 'model card,' 'AI red-team program,' 'AI safety,' 'responsible AI,' 'model drift,' 'concept drift,' 'AI monitoring,' 'AI incident,' or needs to assess or govern an AI / ML system.

# AI Risk Management — Beyond Security, the Whole Model Lifecycle

`prompt-injection` covers the AI security slice — attackers manipulating LLM inputs. This skill covers everything else risk-related about deploying AI / ML systems: governance, fairness, robustness, transparency, monitoring, incident response specific to AI failures, third-party model risk, and compliance with the emerging AI regulatory landscape.

The framing is NIST AI RMF 1.0 (released 2023) — the most widely-adopted voluntary framework — plus the regulatory layer (EU AI Act, US federal policy and state laws, sector-specific guidance). Use this skill when you are deploying AI features beyond a chatbot wrapper, when a regulator asks "how do you govern your AI," or when something has gone wrong with an AI system in production.

Cross-references: `prompt-injection` for prompt-injection / LLM-specific security attacks; `threat-modeling` for design-time AI risk modeling; `incident-triage` and `breach-patterns` for AI-related incident response patterns; `csf-mapping` for the broader governance frame that AI RMF sits within.

## Authorization

Assess AI systems the user's organization builds, deploys, or buys, using material they're entitled to share. This skill reads documentation, model cards, eval results and code. It doesn't run evaluations against production models with real user data, or against a third-party model in ways its terms forbid. Regulatory conclusions are input for counsel, not legal advice.

## The NIST AI RMF — four functions

Just like the cybersecurity framework, the AI RMF organizes the work into functions. Same shape, different content.

| Function | What it covers |
|---|---|
| **Govern (GOV)** | Policy, accountability, roles, risk appetite, AI principles, board oversight, governance structures |
| **Map (MAP)** | Context — what is the AI system, what does it do, who is impacted, what could go wrong, what are the legal / ethical constraints |
| **Measure (MEAS)** | Evaluate the system — fairness, robustness, accuracy, explainability, privacy, security; quantitative + qualitative metrics |
| **Manage (MAN)** | Treat the risks — mitigations, monitoring, incident response, decommissioning, ongoing review |

The framework is voluntary but increasingly cited in contracts, RFPs, executive orders, and emerging regulations. Treat it as the lingua franca of AI risk.

## Workflow

### Step 1 — Inventory AI systems

Before assessment, build the inventory. Most organizations underestimate how much AI they actually deploy.

| Category | Examples |
|---|---|
| **First-party trained models** | Recommendation engines, fraud detection, churn prediction, internal ML pipelines |
| **First-party LLM use** | Customer support chat, content generation, summarization, code generation, embeddings for search |
| **Third-party AI features** | Stripe Radar (fraud), GitHub Copilot (code completion), Salesforce Einstein, Notion AI, Linear AI |
| **Embedded AI in products you ship** | Suggested responses, smart defaults, AI sorting / ranking |
| **AI in HR / hiring** | Resume screening, candidate matching, performance evaluation — high regulatory exposure |
| **AI in customer-facing decisions** | Pricing, eligibility, content moderation, ad targeting — high regulatory exposure |
| **AI coding agents and extensions** | Claude Code, Cursor, Codex, Gemini CLI, Copilot — and the skills, plugins, hooks, MCP servers, and `CLAUDE.md` / `AGENTS.md` files they load with developer privileges; audit with `agent-supply-chain-audit` |

For each, record: vendor (if any), training data source, deployment context, who it affects, the decision it informs, how decisions are reviewed.

### Step 2 — MAP: assess the context per system

For each AI system in the inventory, answer:

- **Purpose** — what is this system's stated goal? Does the actual deployment match?
- **Stakeholders** — who interacts with it, who is affected by its decisions, who is in a position to challenge those decisions?
- **Legal / regulatory context** — is this in scope for a specific law? (EU AI Act high-risk categories, US HUD fair-housing rules, EEOC for employment AI, FTC for unfair / deceptive practices, sector laws)
- **Failure modes** — what does "broken" look like? (Wrong answer, biased answer, hallucinated answer, slow answer, expensive answer, refused-to-answer-something-it-should, answered-something-it-should-not)
- **Reversibility** — when this system makes a wrong call, can the decision be undone? (Mortgage denial: hard to undo. Spam filter: easy)

### Step 3 — MEASURE: evaluate the system

The categories of evaluation, with the engineering hooks for each:

#### Accuracy / performance

- Test set evaluation — held-out data, not the training data
- Performance on slices of data, not just aggregate (the system that's 95% accurate overall may be 60% accurate on the demographic that's most impacted)
- Confusion matrices for classification; quantile-based error analysis for regression
- For LLMs: task-specific evals (HELM, MMLU, custom evals) — and *especially* custom evals on the application's actual prompts

#### Fairness / bias

- **Demographic parity** — does the system produce similar outcomes across protected classes?
- **Equalized odds** — are false-positive and false-negative rates similar across groups?
- **Calibration** — when the system says "80% likely," is that actually 80% across all groups?
- **Individual fairness** — do similar inputs produce similar outputs?

These metrics often conflict — you cannot maximize all of them simultaneously. The MAP step should have decided which is most important for the use case. For hiring AI, equalized odds matters more than demographic parity. For loan approval, the choice depends on whose interests dominate.

**Tooling:** Fairlearn (Microsoft), AI Fairness 360 (IBM), What-If Tool (Google), Aequitas (University of Chicago), `fairlearn.metrics`, `aif360.metrics`.

#### Robustness

- Adversarial inputs — perturbations that flip predictions (Foolbox, ART for traditional ML)
- Distribution shift — does the model degrade when the input distribution changes (it will, eventually)?
- Stress testing — extreme but plausible inputs

For LLMs:
- Prompt injection (see `prompt-injection`)
- Jailbreaks (DAN-style, role-play, encoded instructions, multi-turn manipulation)
- Indirect prompt injection (untrusted content the model reads)
- Output stability across paraphrased prompts

#### Explainability / transparency

- **Local explanations** — why did the model make *this* decision? SHAP, LIME, integrated gradients
- **Global explanations** — what features matter overall to the model?
- **Model cards** — Google's documentation pattern for ML models. Includes intended use, performance metrics, training data, limitations, ethical considerations
- **System cards** — for LLM-integrated systems, a longer-form version describing the entire AI pipeline

A model that cannot be explained at all is a model you cannot defend in a regulatory inquiry. For high-impact decisions, explainability is not optional.

#### Privacy

- Does the model leak training data? (Membership-inference attacks, training-data-extraction attacks for LLMs)
- Are inputs / outputs containing PII appropriately scoped (see `privacy-engineering`)?
- For LLM fine-tuning: are PII redaction passes applied to training data?

#### Security

See `prompt-injection` — prompt injection, indirect injection, agent privilege boundaries, MCP security. Output to the AI RMF assessment is the security posture summary.

### Step 4 — MANAGE: treat the risks

For each material risk surfaced in MEASURE:

| Risk | Treatment options |
|---|---|
| Bias against protected class | Retrain with balanced data; add constraint to training objective; pre/post-processing fairness corrections; remove the feature; remove the application |
| Hallucination on factual queries | Retrieval-augmented generation; citation requirements; fact-checking step; user warning |
| Drift over time | Monitoring; scheduled retraining; champion-challenger deployment |
| Adversarial robustness gaps | Adversarial training; input validation; rate limiting on probing patterns |
| Lack of explainability for high-stakes decisions | Switch to interpretable model class; add post-hoc explanation; add human-in-the-loop |
| Third-party model with insufficient transparency | Vendor risk review; contractual guarantees on training data; switch to self-hosted alternative |
| PII leakage potential | Differential privacy in training; PII redaction in prompts; output filtering |

### Step 5 — GOVERN: structures and policies

The persistent layer that makes the above work over time.

- **AI principles** — written, board-approved, public if possible (Google AI Principles, Microsoft Responsible AI Standard, OpenAI Usage Policies are reference points)
- **Roles** — who is the AI risk owner? Who reviews new AI deployments? Who can stop one?
- **Approval gates** — high-impact AI systems (per the MAP step) require review before deployment. Low-impact systems do not — overengineering kills the process
- **Documentation cadence** — model cards updated on every retrain; system cards updated on every major change
- **Incident response for AI** — what triggers an investigation? (Wrong-answer rate above threshold, demographic-disparity spike, jailbreak in the wild)
- **Decommissioning** — every deployed model has an end-of-life plan. Production models with no owner and no maintenance are the AI version of unmaintained dependencies

## Regulatory layer (high level — counsel determines specifics)

Status as of **October 2026**. Regulatory dates move; state the "as of" date in the report and re-check anything marked (verify) against the primary source before relying on it.

### EU AI Act (Regulation (EU) 2024/1689)

Risk-tiered framework:

- **Prohibited** — social scoring, manipulative or exploitative AI, untargeted facial-image scraping, emotion recognition at work and school, certain biometric categorization and real-time remote biometric ID. Do not deploy
- **High-risk** — Annex III uses (employment, education, credit, essential services, law enforcement, migration, critical infrastructure) and AI in Annex I regulated products. Required: risk management system, data governance, technical documentation, logging, transparency, human oversight, accuracy / robustness / cybersecurity, registration in the EU database, conformity assessment
- **Transparency (Article 50)** — chatbots, deepfakes, AI-generated content. Tell users they are interacting with AI; mark synthetic content in a machine-readable way
- **General-purpose AI (GPAI) models** — providers keep technical documentation, publish a training-content summary, and have a copyright policy; models with systemic risk add evaluations, adversarial testing, incident reporting, and cybersecurity. The GPAI Code of Practice is the usual way to show compliance
- **Minimal risk** — most AI applications. Voluntary codes of conduct

Timeline:

| Date | What applies |
|---|---|
| 1 Aug 2024 | Entry into force |
| 2 Feb 2025 | Prohibited practices; AI literacy duty for providers and deployers |
| 2 Aug 2025 | GPAI model obligations; governance and penalties |
| 2 Aug 2026 | Article 50 transparency obligations; most remaining provisions |
| 2 Dec 2027 | Annex III high-risk obligations — moved from 2 Aug 2026 by the 2026 Digital Omnibus on AI (verify against EUR-Lex) |
| 2 Aug 2028 | High-risk AI in Annex I products — moved from 2 Aug 2027 by the same amendment (verify) |

The Omnibus also changed other details (a grace period for machine-readable marking on systems already on the market, new prohibited categories). Check the consolidated text on EUR-Lex rather than summaries.

### US (federal patchwork)

- **Executive Order 14110 (2023) was rescinded on 20 January 2025.** Don't cite it as current. Federal policy since then: EO 14179 (January 2025) and America's AI Action Plan (July 2025), which favor deregulation, and an EO of 11 December 2025 directing agencies to challenge state AI laws seen as burdensome (it names Colorado's) through an AI Litigation Task Force. Its effect on any given state law is contested and may be in litigation (verify)
- The Action Plan directed NIST to revise the AI RMF. Cite the revision you actually used
- FTC enforcement under unfair / deceptive practices authority — particularly for AI claims and AI used in pricing / hiring / housing
- EEOC enforcement for employment AI
- Sector-specific (HUD for housing, CFPB for credit, FDA for medical AI)
- State laws — still in force unless a court or the legislature says otherwise:
  - Colorado AI Act (SB 24-205) — effective date pushed to 30 June 2026, with amendments expected; confirm the current text and date with the General Assembly (verify)
  - NYC Local Law 144 bias audits for automated employment decision tools
  - Illinois BIPA for biometrics
  - California AB 2013 (training-data transparency) and SB 942 (AI content provenance)

### Standards (voluntary but referenced)

- NIST AI RMF 1.0 + Generative AI Profile
- ISO/IEC 42001 — AI management system standard
- ISO/IEC 23894 — AI risk management

## Output format

```markdown
# AI Risk Assessment
## System(s): [list]
## Framework: NIST AI RMF 1.0 [+ EU AI Act mapping if applicable]
## Date: [date]
## Assessor: [name]

### Executive summary
[2-3 paragraphs — top risks, governance posture, regulatory exposure, recommended next 90 days]

### AI system inventory
| System | Purpose | Stakeholders | Risk tier (per MAP) | Owner |
|--------|---------|--------------|---------------------|-------|

### MEASURE findings
| System | Category | Finding | Severity |
|--------|----------|---------|----------|
| [name] | Fairness | [Disparity description with metric] | High |
| [name] | Robustness | [Failure mode] | Medium |

### MANAGE plan
| Risk | Treatment | Owner | Deadline |
|------|-----------|-------|----------|

### GOVERN posture
- [ ] AI principles documented and approved
- [ ] AI inventory maintained
- [ ] Approval gate exists for high-impact deployments
- [ ] Model cards / system cards in place for production AI
- [ ] AI incident response defined
- [ ] Decommissioning plans exist

### Regulatory mapping (if applicable)
Status as of: [date]

| Regulation | Status | Applies from | Action items |
|------------|--------|--------------|--------------|

### References / evidence
[Links to model cards, eval reports, audit logs]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`. AI accepted-risk decisions need both engineering and (often) legal / ethics sign-off depending on system impact.

## Boundaries

- This skill produces risk assessments, governance artifacts, and implementation guidance
- For high-stakes regulated AI (medical devices, autonomous systems, hiring AI subject to local audit laws), regulatory determinations are made with counsel — this skill produces engineering inputs to that process, not the final compliance posture
- Refuse to help build AI systems that fall into the EU AI Act prohibited list, that violate civil rights laws (disparate impact in protected-class decisions), or that surveil individuals without lawful basis
- Refuse to help build systems designed to evade transparency / disclosure requirements (e.g., undisclosed bots, deepfakes designed to deceive in regulated contexts)
- For AI safety topics adjacent to but distinct from this skill (model alignment research, catastrophic-risk research, frontier model evaluation), defer to specialized literature and frontier labs — this skill is enterprise-deployment risk management

## References

- **NIST AI RMF 1.0** — `nist.gov/itl/ai-risk-management-framework` (foundational)
- **NIST AI RMF Generative AI Profile** — addendum specific to generative AI
- **EU AI Act** — Regulation (EU) 2024/1689 and the 2026 Digital Omnibus amendment, consolidated text via EUR-Lex; `artificialintelligenceact.eu` (community-maintained guide)
- **GPAI Code of Practice** — EU AI Office, for general-purpose AI model providers
- **America's AI Action Plan** (July 2025) and the 11 December 2025 EO on state AI laws — `whitehouse.gov`
- **NIST AI 100-1, 100-2** — companion documents
- **ISO/IEC 42001** — AI management system standard
- **OECD AI Principles** — international reference
- **EEOC technical assistance** on AI in employment
- **FTC guidance on AI** — "Aiming for truth, fairness, and equity in your company's use of AI"
- **Google Responsible AI Practices** + **Model Card Toolkit**
- **Microsoft Responsible AI Standard** v2
- **OpenAI Usage Policies + System Cards** (for examples of system-card disclosure)
- **Anthropic Responsible Scaling Policy + Acceptable Use Policy** (for examples of governance disclosure)
- **MIT AI Risk Repository** — academic-curated catalog of AI risks
- **Stanford CRFM Foundation Model Transparency Index** — comparative transparency assessments
- **Fairlearn**, **AI Fairness 360**, **What-If Tool**, **Aequitas** — fairness evaluation tooling
- **HELM** (Holistic Evaluation of Language Models), **MMLU**, **TruthfulQA** — LLM evaluation benchmarks