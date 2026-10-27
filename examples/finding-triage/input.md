# Input: two scanner alerts on `examples/target`

These are the alerts handed to `finding-triage`, one at a time, as they'd arrive from CI. They were written for this example in the format each tool prints. They aren't captured output.

## Alert 1: semgrep

```
src/routes/notes.js
  javascript.express.security.injection.tainted-sql-string
     Detected user input used to manually construct a SQL string. This is usually bad practice
     because manual construction could accidentally result in a SQL injection. An attacker could
     use a SQL injection to steal or modify contents of the database. Instead, use a
     parameterized query.
     Severity: ERROR   Confidence: MEDIUM   CWE-89

      15┆ const notes = db.prepare(`SELECT * FROM notes WHERE owner_id = ? ORDER BY ${order}`).all(req.user.id);
```

## Alert 2: OWASP ZAP baseline (staging)

```
WARN-NEW: Application Error Disclosure [90022] x 1
	https://staging.notes-api.example/api/preview (500 Internal Server Error)
	Evidence: "stack":"Error: getaddrinfo ENOTFOUND nope.invalid\n    at GetAddrInfoReqWrap.onlookup [as oncomplete] (node:dns:107:26)"
	Risk: Medium
```
