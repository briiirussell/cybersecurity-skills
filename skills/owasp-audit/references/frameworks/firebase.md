# Firebase playbook

Load this during an `owasp-audit` run when recon detects Firebase ([detection signals](README.md)). Firebase clients
talk to Firestore, Realtime Database, and Cloud Storage directly, using a project config (including a web `apiKey`)
that ships in every app. So the security rules files are the access control, and Cloud Functions using the Admin SDK
skip those rules entirely and need their own checks.

Findings use the normal OWASP Top 10:2025 categories, verdicts, and `findings.json` format. Fingerprints name the
rules file and match path, or the function: `owasp-audit/CWE-862/firestore.rules/users-uid`.

## Add these surfaces to the ledger

| Surface | Where it lives | Principals to test against |
|---|---|---|
| Each Firestore `match` block | `firestore.rules` (path set in `firebase.json` → `firestore.rules`) | unauthenticated, anonymous auth (if enabled), signed-in user B |
| Each Realtime Database path with `.read` / `.write` | `database.rules.json` (`firebase.json` → `database.rules`) | same |
| Each Storage `match` block | `storage.rules` (`firebase.json` → `storage.rules`) | same |
| Each Cloud Function | `functions/src/**`: `onRequest`, `onCall`, and triggers (`onDocumentCreated`, `onCreate`, ...) | anonymous caller, other user, a user who can write the triggering document |
| Auth providers and sign-up | Console / Identity Platform settings (not in the repo) | anyone holding the web config |

If `firebase.json` has no `firestore`, `database`, or `storage` block, or names a rules file that isn't in the tree,
the deployed rules aren't managed in the repo. Add a `blocked` unit for each and record the console or Rules API
as the place to read them; don't conclude "nothing to review".

```bash
rg -n '"rules"' firebase.json; ls firestore.rules storage.rules database.rules.json 2>/dev/null
rg -n "onRequest\(|onCall\(|on(Document|Value)?(Created|Updated|Deleted|Written|Create|Update|Delete|Write)\(" functions/ -g '!node_modules'
```

## Checks

### 1. Rules that allow everything (A01)

**Look for:**
- `allow read, write: if true;` (or any `allow` ending `if true`) in Firestore or Storage rules
- `".read": true` / `".write": true` near the root of `database.rules.json`
- The console's test-mode gate, `allow read, write: if request.time < timestamp.date(...)`. Until that date the data is
  open, and teams often extend it rather than write real rules
- A recursive wildcard (`match /{document=**}` or `{allPaths=**}`) with a loose `allow`. Rules combine with OR across
  every matching block, so one permissive catch-all reopens paths that a more specific block restricts

**Find candidates:**

```bash
rg -n "allow [a-z, ]+:\s*if\s+true\b|request\.time\s*<\s*timestamp\.date|\{[a-zA-Z]+=\*\*\}" -g '*.rules'
rg -n '"\.(read|write)"\s*:\s*(true|"true")' -g '*.json' -g '!node_modules'
# portable
grep -rnE "if +true *;|request\.time *< *timestamp\.date|=\*\*\}" --include='*.rules' .
grep -rnE '"\.(read|write)" *: *(true|"true")' --include='*.json' . | grep -v node_modules
```

**Verify:** confirmed when the open path holds data that isn't meant to be public, or allows writes, and the rules
file is what's deployed (it's referenced by `firebase.json` and deployed by CI or the documented process). If you
can't tell whether this file is what's live, it's `needs_validation`: the owner compares the Rules tab in the console
(or the Firebase Rules API's current release) with the file. Rejected for a path that's public on purpose (published
content) where the open `allow` is `read` only and scoped to that path.

### 2. `request.auth != null` as the only check (A01)

**Look for:** `allow read, write: if request.auth != null;` (Realtime Database: `"auth != null"`) on data that belongs
to individual users or tenants. Any signed-in account passes. With email/password or anonymous sign-in enabled,
anyone can get an account through the Auth REST API using the public config, even if the app's UI has no sign-up
screen. Also flag custom-claim presence checks (`request.auth.token.role != null`) that don't check the value.

**Find candidates:**

```bash
rg -n "request\.auth\s*!=\s*null\s*(;|\)|$)" -g '*.rules'
rg -n '"auth\s*!=\s*null"' -g '*.json' -g '!node_modules'
```

**Verify:** confirmed when another user's documents become readable or writable and sign-up is open (anonymous or
email/password enabled; the repo often shows it in client code calling `signInAnonymously` or
`createUserWithEmailAndPassword`). When sign-up state is only in the console, it's `needs_validation` with that
setting as the blocker. Rejected when the rule also pins ownership, e.g. `request.auth.uid == uid` on
`/users/{uid}`, or checks membership with `exists(...)`/`get(...)` on a members document.

### 3. Ownership and field-level gaps (A01)

**Look for:**
- Ownership taken from the incoming document (`request.resource.data.ownerId != null`) instead of compared with
  `request.auth.uid`, and on update, not compared with the existing `resource.data.ownerId`
- `create` / `update` with no field allowlist, so a user can add `role: 'admin'`, `plan`, `credits`, or `orgId`.
  Look for `request.resource.data.keys().hasOnly([...])` on create and
  `request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])` on update
- `list` allowed more broadly than `get`, or a collection-group rule (`match /{path=**}/comments/{id}`) that's looser
  than the per-collection rule
- Rules that trust a document the user can write (`get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role`
  when the same user can update their own `users` doc, including `role`)

**Find candidates:** list every write rule, then read each block and note which fields it constrains.

```bash
rg -n "allow [a-z, ]*(create|update|write)" -g '*.rules'
rg --files-without-match "hasOnly|affectedKeys" -g '*.rules'   # a rules file with writes but no field allowlist is a strong lead
```

**Verify:** confirmed when a user can write a field or document that changes their own privileges or another user's
data. The Firestore emulator with `@firebase/rules-unit-testing` (`assertSucceeds` / `assertFails`) proves it locally
without touching the real project. Rejected when an allowlist or ownership comparison covers the field on every
write path, named by line.

### 4. Cloud Storage rules and bucket access (A01)

**Look for:** the same patterns in `storage.rules` (`if true`, `request.auth != null` alone, `{allPaths=**}`), uploads
with no `request.resource.size` or `contentType` limits, and per-user paths not pinned with
`request.auth.uid == userId`. Storage has a second way in: the bucket's Google Cloud IAM and object ACLs
(`allUsers`, `allAuthenticatedUsers`, or objects published with the Admin SDK's `makePublic()`), which the rules file
doesn't govern.

**Find candidates:**

```bash
rg -n "match /|allow " storage.rules
rg -n "makePublic\(|public:\s*true|predefinedAcl" functions/ -g '!node_modules'
```

**Verify:** rules gaps verify like checks 1 to 3. Bucket IAM and ACLs live outside the repo: `needs_validation`, with
the owner running `gcloud storage buckets get-iam-policy gs://<bucket>` and checking for `allUsers` /
`allAuthenticatedUsers`.

### 5. Cloud Functions trusting the caller (A01, A07)

**Look for:**
- `onRequest` handlers that act on user data without verifying an ID token
  (`admin.auth().verifyIdToken(...)` on the `Authorization: Bearer` header). `onRequest` gets no auth for free
- `onCall` handlers that read the user id from `request.data` / `data.uid` instead of `request.auth.uid`
  (v2) or `context.auth.uid` (v1), or that don't reject when `auth` is missing
- Admin SDK reads and writes using an id from the request without an ownership check. The Admin SDK bypasses every
  rules file, so the function is the only control
- Triggers that grant roles or credits based on a document the client wrote (`onDocumentCreated('invites/{id}')`
  adding the creator to an org, with no check on who created the invite)
- v2 functions deployed with `invoker: 'public'` that are meant to be internal

**Find candidates:**

```bash
rg --files-without-match "verifyIdToken|verifySessionCookie" $(rg -l "onRequest\(" functions/ -g '!node_modules')
rg -n "onCall\(" -A10 functions/ -g '!node_modules' | rg "data\.(uid|userId)|request\.data\.(uid|userId)"
rg -n "invoker:\s*['\"]public['\"]" functions/ -g '!node_modules'
```

**Verify:** the standard A01 trace from the function's entry to the Admin SDK write. Rejected when the handler derives
identity from a verified token and checks ownership before the first read or write, named by line.

### 6. API key scope and App Check (A02, usually hardening)

**Look for:** the right thing, not the wrong one. The Firebase web `apiKey` (`AIza...`) identifies the project and is
meant to ship. Finding it in the client is **not** a finding (see the anti-patterns in SKILL.md). What does matter:
- The same key has no API restrictions in Google Cloud and is also used for paid APIs (Maps, Gemini / Generative
  Language), so anyone can spend against the project's quota. Firebase-created keys are restricted to Firebase APIs by
  default, so this usually means someone edited the key or reused it
- Server-side credentials in the client: a service-account JSON (`"type": "service_account"`), a database secret, or
  an Admin SDK init in client code. These are real secrets (A04); hand rotation to `secrets-audit`
- App Check treated as authorization. App Check makes it harder to call the backend from outside the real app; it
  doesn't decide who may read what. Rules and function checks still have to hold without it

**Find candidates:**

```bash
rg -n "AIza[0-9A-Za-z_-]{35}" -g '!node_modules'                  # expected; check what else the key is used for
rg -n '"type":\s*"service_account"|firebase-admin|initializeApp\(\s*\{\s*credential' -g '!node_modules' -g '!functions/**'
rg -n "initializeAppCheck|enforceAppCheck|consumeAppCheckToken" -g '!node_modules'
```

**Verify:** key restrictions are visible only in Google Cloud (`gcloud services api-keys describe <key-id>`), so a
broad-scope concern is `needs_validation` or a hardening note. A service-account key in client code is confirmed
A04.

## Worked examples

**Confirmed (A01).** `firestore.rules` line 8: `match /users/{uid} { allow read, write: if request.auth != null; }`.
The app calls `signInAnonymously` on first launch (`src/auth.ts:12`), so anyone gets a token. `users/{uid}` holds
email, phone, and a `role` field that the rules for `/admin/**` trust. Any visitor can read every user's profile and
set their own `role` to `admin`.

```json
{
  "fingerprint": "owasp-audit/CWE-862/firestore.rules/users-uid",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-862", "confidence": "medium",
  "counterevidence": "no other match block covers /users; no hasOnly on writes; anonymous sign-in is called by the client, so a token is free",
  "severity": { "likelihood": { "score": "high", "reason": "anonymous token from the public config" },
                "impact": { "score": "critical", "reason": "read all profiles; self-promote to admin" }, "overall": "critical" }
}
```

**Rejected (A04).** The secrets sweep flagged `AIza...` in `src/firebase.ts`. It's the Firebase web `apiKey` in the
project config object, which identifies the project and is meant to be public. Access is enforced by
`firestore.rules`, where every user-data path pins `request.auth.uid`.

```json
{
  "fingerprint": "owasp-audit/CWE-798/src/firebase.ts/firebase-web-api-key",
  "verdict": "rejected", "owasp_category": "A04:2025", "confidence": "high",
  "counterevidence": "value is the apiKey field of the client Firebase config; no service-account or Admin SDK credential in client code",
  "ruled_out_by": { "control": "known-inert value: Firebase web API key is a public project identifier; authorization is in security rules",
                    "location": { "file": "src/firebase.ts", "line": 4 } }
}
```

Both are abridged; see [findings-format.md](../findings-format.md) for the full record shape.

## Sources

Paraphrased, not copied:

- Strix (Apache-2.0): [technologies/firebase.md](https://github.com/usestrix/strix/blob/main/strix/skills/technologies/firebase.md)
  (rules gaps, the two Storage access paths, Functions identity, App Check limits, unmanaged rules)
- Trail of Bits skills (CC-BY-SA-4.0): [firebase-apk-scanner](https://github.com/trailofbits/skills/tree/main/plugins/firebase-apk-scanner)
  (what a Firebase config in a shipped client exposes; rationalizations such as "the API key is public anyway" that
  shouldn't excuse open rules). Ideas only; no text reused
- Firebase docs: [Security checklist](https://firebase.google.com/support/guides/security-checklist),
  [API keys](https://firebase.google.com/docs/projects/api-keys),
  [Security Rules](https://firebase.google.com/docs/rules), [App Check](https://firebase.google.com/docs/app-check)
