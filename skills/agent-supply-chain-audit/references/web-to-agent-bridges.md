# Web-to-agent bridges (WB1–WB4)

Loaded from `agent-supply-chain-audit` Step 4. Read-only.

Ask first. Nothing here starts the agent. This is an exposure to inventory and reduce, not a version to patch. Do not
call the product vulnerable, and do not call the chain exploited. Say "exposure: a hijacked extension could drive the
agent."

Report, checked 2026-11-05. [Forever Security](https://forever.security/blog/thisbash-claude-dispatch-browser-extension-rce)
(2026-11-04, researcher Gal Weizman, named ThisBash) and [The Register](https://www.theregister.com/research/2026/11/05/anthropic-wont-fix-a-claude-dispatch-flaw-that-could-let-attackers-execute-remote-commands-across-corporate-boundaries/5307684)
(2026-11-05). A browser extension that can run on `claude.ai` could drive Claude Desktop's Dispatch feature: send
prompts as if the user typed them, and operate an approval rendered on that same page. On one machine that is a
browser-to-OS path. Across two machines on one account it is cross-machine. No CVE, no vendor advisory, no reported
exploitation. The phone-to-desktop path is described as peer-to-peer, and the researcher found no flaw there. The
claim that Claude Code Remote Control and Claude Cowork web sessions share the design is vendor-unconfirmed: Forever
Security said a follow-up would cover it, and The Register does not show a proof of concept for those features.
Dispatch retirement was announced for the end of October 2026. The Register says the support page still listed it on
2026-10-30. Whether it is still offered after that date is unverified. Re-check when the follow-up is published.

| ID | Check | Finding |
|---|---|---|
| **WB1** | A remote-control or web-session feature is on. Ask which of these they use: Claude Dispatch, Claude Code Remote Control, Claude Cowork sessions on the web, or any "send a task from my phone or browser to my desktop agent" feature. Read the app's settings for it. Names vary by version, so do not assume a toggle. | needs_validation, medium. High when the machine holds production or deploy credentials and WB2 also hits |
| **WB2** | A browser extension that can run on the agent's web origin. List extensions in each browser profile signed in to `claude.ai`, `chatgpt.com`, `gemini.google.com`, or the equivalent. Flag `<all_urls>`, `*://*/*`, or an explicit match for that origin, together with `scripting`, `tabs`, or `webRequest`. Record id, publisher, last update, and install count. Paths are in [references/locations.md](locations.md). | medium. High with WB1. An unknown publisher, a recent ownership change, or an unexpected permission increase goes to `incident-triage` |
| **WB3** | One agent account across personal and work machines. Ask whether the same account is signed in on a work or client laptop and on a personal browser. | medium. Recommend separate accounts, or turning WB1 off on the managed machine |
| **WB4** | Approval that lives in a page. Note whether the prompt for running a command is rendered in a web page or app view that a script on that page could operate. | Hardening note. Consent shown inside an attacker-reachable surface does not prove the user agreed. Prefer an approval the requesting page cannot operate (the terminal, or an OS prompt) where the agent offers it |

Chromium manifests on macOS (read-only, names that start with `__MSG_` need the locale file):

```bash
jq -r '[.name, (.permissions // [] | join(",")), (.host_permissions // [] | join(","))] | @tsv' \
  "$HOME/Library/Application Support/Google/Chrome"/*/Extensions/*/*/manifest.json 2>/dev/null
```

Hardening, no product required: turn off remote-control features that are unused. Keep the browser profile signed in
to the agent site free of "read all sites" extensions. Do not sign a personal agent account in on a managed laptop.
