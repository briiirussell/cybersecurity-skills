# Inbound Webhooks and Request Parsers

Detail for three `owasp-audit` checklist items (A06, A01/A07, A10). They came from a second-model review of a real
Next.js pages-router app's email-ingest endpoint (SendGrid Inbound Parse, parsed with multer). The multi-tenant HMAC
fan-out pattern in A06 is a different class. These three cover multipart parsing and webhooks that trigger paid work
without authenticating the caller.

Find candidate endpoints first:

```bash
rg -n -i "inbound|webhook|sendgrid|mailgun|postmark|resend|twilio|multer\(|busboy|formidable|multiparty|bodyParser:\s*false" \
  -g '!node_modules' -g '!*.lock'
rg -n "/api/.*(email|inbound|parse|hook)" -g '!node_modules'
# portable
grep -rnEi "inbound|webhook|multer\(|busboy|formidable|bodyParser: *false" --include='*.ts' --include='*.js' --include='*.rb' --include='*.py' . | grep -v node_modules
```

## 1. Request parsers without explicit limits (A06 / A02)

**Pattern.** A parser runs with library defaults (or no limits at all), and the parsed body is logged or stored before
it's validated.

**Field-index amplification.** Bracket-notation field names are expanded into arrays by many parsers. In the observed
case, a **78-byte** multipart request with the field `x[1000000]=1` was parsed into an array of 1,000,001 elements,
about **5 MB** once serialized to JSON, and the handler wrote that JSON to a `webhook_request` table before checking
anything. It reproduced on multer 1.x and 2.x. Attachments were also buffered in memory although the handler never
read them. Result: cheap requests cost memory, CPU, and database storage at a large multiple of their size.

**Check:**
- Every multipart, urlencoded, and JSON parser on an unauthenticated or webhook route has explicit size, count, and
  depth limits.
- Unused file parts are rejected, not buffered.
- The handler validates a small **allowlisted** payload (the fields it actually uses) before it logs, stores, or
  forwards anything.

**Fix shape (multer):**

```js
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fields: 50, fieldSize: 64 * 1024, fieldNameSize: 100, files: 0, parts: 60 },
  // multer 2.x: also cap bracket expansion, e.g. fieldNestingDepth: 0 (check the option name at your pinned version)
});
app.post("/api/inbound", upload.none(), handler); // .none() rejects any file part
```

Then pick only the fields you use (`const { from, to, subject, text } = req.body`), validate them with a schema, and
store that object, not `req.body`.

| Parser / framework | Limits to set |
|---|---|
| multer / busboy (Node) | `limits: { fields, fieldSize, fieldNameSize, files, fileSize, parts, headerPairs }`; `.none()` or `files: 0` when no files are expected |
| formidable | `maxFields`, `maxFieldsSize`, `maxFiles`, `maxFileSize`, `maxTotalFileSize` |
| multiparty | `maxFields`, `maxFieldsSize`, `maxFilesSize` |
| body-parser / `express.urlencoded` | `limit`, `parameterLimit`, `depth` (where supported by your version); prefer `extended: false` unless you need nesting |
| `qs` (direct use) | `arrayLimit`, `depth`, `parameterLimit`; consider `allowSparse: false`, `parseArrays: false` for webhooks |
| `express.json` / `body-parser.json` | `limit`; reject unexpected `Content-Type` with `type` |
| Next.js pages router API | `export const config = { api: { bodyParser: { sizeLimit: "1mb" } } }`; with `bodyParser: false`, you own the limits |
| Next.js app router route handler | `req.formData()` / `req.json()` have no per-field limits. Check `content-length`, then parse a bounded stream or a capped `arrayBuffer()` |
| Rails / Rack | Rack query-parser limits (`params_limit`, `bytesize_limit`, param depth) and multipart part limits (`RACK_MULTIPART_PART_LIMIT`, `RACK_MULTIPART_TOTAL_PART_LIMIT`); names vary by Rack version, so check yours |
| Django | `DATA_UPLOAD_MAX_NUMBER_FIELDS`, `DATA_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_NUMBER_FILES`, `FILE_UPLOAD_MAX_MEMORY_SIZE` |
| Starlette / FastAPI | `await request.form(max_files=..., max_fields=...)` (recent Starlette versions; check yours) plus a body-size limit at the proxy |
| Go `net/http` | `http.MaxBytesReader` before `ParseMultipartForm(maxMemory)` |

Proxy or platform body caps (Vercel, nginx `client_max_body_size`) bound total size but **not** amplification: a
78-byte request passes any size cap. If the only limit you can find is at the proxy, that's a `needs_validation` item
for the size dimension and still a finding for the field-index dimension.

**Verification.** Send the small amplification request against a local instance and measure the parsed size, or
the stored row size:

```bash
curl -s -X POST http://localhost:3000/api/inbound -F 'x[1000000]=1' -o /dev/null -w '%{http_code}\n'
# Expected after fix: 400/413, and no row written
```

## 2. Inbound webhook triggers paid work without authenticating the caller (A01 / A07)

**Pattern.** The handler identifies the account from something in the payload (the `to` address, a slug, a phone
number), checks that the account exists and its user is active, and proceeds. It never checks **who sent the
request**. Anyone who knows or guesses an inbound address can POST to the endpoint, trigger paid work (in the observed
case, screenshot rendering billed per call), and create records inside that account.

Knowing the account identifier is not authentication. Inbound email addresses, phone numbers, and slugs leak through
email headers, forwarding, and support tickets.

**Check:**
- Every inbound webhook (email, SMS, voice, payments, git, CI, chat) verifies the provider's signature or credential
  **before** any database write, external call, or paid work.
- Verification runs over the **raw** request bytes. For multipart and urlencoded providers, that means capturing the
  raw body before the parser runs. In Next.js pages router that's `export const config = { api: { bodyParser: false } }`
  plus reading the raw buffer, then parsing from the buffer. Once a parser has re-serialized the body, the signature
  can't be checked.
- Timestamps are checked for freshness (replay), with `Number.isFinite` before any comparison (see A04 type coercion).
- Comparison is constant-time.
- A missing signing secret fails closed at startup, not open at request time.

| Provider | Mechanism (check current provider docs for exact header names) |
|---|---|
| Stripe | `Stripe-Signature` header, HMAC-SHA256 over timestamp + raw body; `stripe.webhooks.constructEvent(rawBody, sig, secret)` |
| GitHub | `X-Hub-Signature-256`, HMAC-SHA256 of raw body |
| Slack | `X-Slack-Signature` + `X-Slack-Request-Timestamp`, HMAC-SHA256 over a versioned base string |
| Twilio (SMS/voice) | `X-Twilio-Signature`, HMAC over the full URL + sorted POST params; `twilio.validateRequest(...)` |
| SendGrid Inbound Parse | Supports signed webhooks and OAuth for Inbound Parse (newer feature); enable one. Without it, treat the endpoint as unauthenticated |
| Mailgun | `timestamp`, `token`, `signature` fields; HMAC-SHA256 of timestamp + token with the webhook signing key. Also cache tokens to block replay |
| Postmark inbound | No payload signature; use HTTP basic auth credentials embedded in the webhook URL, checked server-side, plus their published IP ranges as a secondary control |
| Resend | Svix-style headers (`svix-id`, `svix-timestamp`, `svix-signature`); verify with the Svix library over the raw body |
| Shopify | `X-Shopify-Hmac-Sha256`, base64 HMAC-SHA256 of raw body |

If the provider has no signing scheme, put a long random secret in the webhook URL path, compare it in constant time,
rotate it, and treat the endpoint as low-trust anyway: still cap and rate-limit the paid work it can trigger.

**Severity.** Calibrate by the paid work and the records an outsider can create ([severity-calibration.md](severity-calibration.md)). Cost
amplification against a metered provider and record injection into another account cross a real boundary. "The
endpoint has no signature but only writes a log line" is usually a hardening note.

## 3. Parser errors thrown outside the error boundary (A10 / A09)

**Pattern.** Body parsing or middleware runs **above** the handler's `try`:

```js
export default async function handler(req, res) {
  await runMiddleware(req, res, upload.any()); // throws on missing boundary / oversized field
  try {
    // ... Sentry.captureException + failure logging live here
  } catch (err) { /* never sees parser errors */ }
}
```

A request with a missing multipart boundary or an oversized field rejects in `runMiddleware`, the framework returns a
generic 500, and the handler's monitoring never runs. Malformed traffic and attack attempts are invisible, and the
500 rate looks like an outage instead of abuse.

**Check:**
- Method check first (reject non-POST with 405 before parsing).
- Parsing and middleware run **inside** the error boundary that reports to monitoring.
- Parser errors map to **400** (malformed) or **413** (too large) with a structured log line (error class, limit hit,
  route, no body contents). Keep 5xx for real processing failures, so alerts mean something.
- Framework-level error handlers (Express error middleware, Next.js `onRequestError` / instrumentation, Rails
  `rescue_from`) cover the parser's error classes (`MulterError`, `PayloadTooLargeError`, `ActionDispatch::Http::Parameters::ParseError`).

**Verification.** Send a multipart request with no boundary and an oversized field to a local instance. Confirm the
response is 400/413 and that the monitoring sink (or a local logger stub) recorded one structured event for each.

## Cross-references

- `owasp-audit` A06 multi-tenant webhook signature matching (O(N) secret fan-out)
- `owasp-audit` A02 auth middleware that doesn't exempt bearer/HMAC routes
- `api-audit` API4 (unrestricted resource consumption) for rate and cost limits
- `business-logic-testing` for proving cost-amplification and race effects against a running instance
