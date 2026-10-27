---
description: "Loads api-audit, not owasp-audit."
tags: [routing, owasp-vs-api]
allowed_tools: [Read, Glob, Grep, Skill]
---

Our REST API serves GET /api/orders/:id and PATCH /api/users/:id. Can user A read user B's orders by changing the id, or set fields they shouldn't through the PATCH body? Check the endpoints against the OWASP API Security Top 10.
