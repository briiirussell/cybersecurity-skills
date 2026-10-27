---
description: "Loads finding-triage, not incident-triage."
tags: [routing, triage]
allowed_tools: [Read, Glob, Grep, Skill]
---

Semgrep flagged this line as a high severity SQL injection:

```js
const q = `SELECT * FROM orders WHERE id = ${Number(req.query.id)}`;
```

Is it a real vulnerability or a false positive, and what severity should it actually get?
