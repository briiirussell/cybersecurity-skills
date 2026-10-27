---
description: "Loads scanner-pipeline, not secrets-audit."
tags: [routing, secrets-vs-scanners]
allowed_tools: [Read, Glob, Grep, Skill]
---

Set up gitleaks, semgrep and osv-scanner in GitHub Actions so they run weekly across all our repos and upload SARIF to code scanning.
