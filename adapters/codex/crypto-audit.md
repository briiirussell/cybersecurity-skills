# crypto-audit

> Audit cryptography implementation — algorithm choice, key sizes, KDF parameters, IV/nonce handling, signature verification, randomness, TLS configuration, and key rotation. Deeper than owasp-audit A04. Use when the user mentions 'crypto review,' 'cryptography audit,' 'encryption review,' 'KDF,' 'PBKDF2,' 'Argon2,' 'bcrypt cost,' 'IV reuse,' 'nonce reuse,' 'AES mode,' 'AES-GCM,' 'AES-ECB,' 'signature verification,' 'TLS configuration,' 'cipher suites,' 'key rotation,' 'libsodium,' 'BoringSSL,' or 'is this crypto right.'

# Crypto Audit — Cryptography Implementation Review

Audit how cryptography is implemented in an application — algorithm choices, parameters, modes, and the implementation patterns that turn good primitives into broken systems. Deeper than `owasp-audit` A04 Cryptographic Failures (which catches the obvious "MD5 password" and "VERIFY_NONE" cases). This skill is for the subtler implementation review.

Most crypto failures are not "they used MD5." Most failures are: right primitive, wrong mode (ECB instead of GCM), right algorithm, wrong parameter (PBKDF2 with 1,000 iterations in 2026), right library, wrong call order (init the cipher after the data was loaded).

Cross-references: `owasp-audit` A04 (baseline) + A07 (timing-safe comparison), `secrets-audit` (key storage), `iam-audit` (KMS / HSM patterns), `native-code-review` (memory safety in C, C++ and Rust crypto code, and wiping secrets from memory), `fuzzing-harness` (round-trip and tamper-rejection property tests for encode/decode and sign/verify).

## Authorization

Review code, configuration and key-management setup the user owns or is authorized to audit. TLS probing (`testssl.sh`, `openssl s_client`) is a live check: run it only against endpoints the user is authorized to test; it isn't pre-approved, so it prompts every time. Never try to recover keys, crack hashes or decrypt data you weren't given access to.

## Don't roll your own

The default audit verdict for any custom encryption scheme is "use libsodium / Tink / WebCrypto instead." There are < 50 people on Earth who can design new crypto safely, and they don't work at your company. Unless an explicit threat model says otherwise, custom crypto is a finding.

## Audit Checklist

### Algorithm and mode

- **Symmetric:** AES-256-GCM or ChaCha20-Poly1305 (authenticated encryption — confidentiality + integrity in one primitive)
- **Reject:** AES-ECB (block-pattern leak — identical plaintext → identical ciphertext), AES-CBC without HMAC (unauthenticated; padding oracle attacks), AES-CTR without HMAC (malleable; bit-flip = plaintext-flip), DES / 3DES, RC4, Blowfish (use Twofish or skip altogether)
- **Asymmetric:** Ed25519 / X25519 for signatures and key exchange; RSA-OAEP / RSA-PSS at 3072+ bits if compatibility forces RSA; never RSA with PKCS#1 v1.5 padding for encryption (Bleichenbacher); never raw RSA
- **Hashing (general purpose):** SHA-256, SHA-3, BLAKE2 / BLAKE3
- **Hashing (passwords) — categorically different problem:** Argon2id, scrypt, bcrypt (with cost ≥ 12 for bcrypt; OWASP 2024 floor)
- **MAC:** HMAC-SHA256 minimum; never CBC-MAC; never homemade `hash(key + message)`
- Grep for: `MD5`, `SHA1` (outside of HMAC-SHA1 in legacy compat), `DES`, `RC4`, `Blowfish`, `AES.*ECB`, `pkcs1_v1_5` (Python), `RSA.encrypt` without OAEP

### Key derivation

- **From a password:** Argon2id (memory-hard) or PBKDF2-HMAC-SHA256 with ≥ 600,000 iterations (OWASP 2024) or scrypt with N=2^17, r=8, p=1
- **From a high-entropy secret:** HKDF-SHA256 — the right primitive when you have key material and need to derive sub-keys
- **From a low-entropy secret to encryption key:** PBKDF2 / Argon2 (treat it as a password)
- Grep for: `PBKDF2` (check iteration count), `HKDF`, `Argon2`, `scrypt`, `pbkdf2_hmac` (Python; check `iterations` arg)

### IV / nonce handling

Wrong IV / nonce handling is one of the top three sources of "the crypto looks right but actually leaks plaintext."

- **AES-GCM:** unique nonce per encryption under the same key. **NEVER reuse.** If you reuse a GCM nonce with the same key, you give the attacker the XOR of two plaintexts and the ability to forge messages. Use 96-bit random nonces (RFC 5116). For high-volume systems, switch to AES-GCM-SIV (nonce-misuse-resistant)
- **AES-CBC:** IV must be unpredictable AND unique. Random 16-byte IV per encryption
- **AES-CTR:** counter must never repeat for a (key, counter) pair within the lifetime of the key
- **ChaCha20-Poly1305:** unique nonce per message; XChaCha20-Poly1305 has 192-bit nonce so random nonces are safe at scale
- Grep for: hardcoded IVs (`iv = "0000000000000000"`, `iv = bytes(16)`), zero-IV constructors, counter resets
- Specifically grep for: `Cipher.getInstance("AES")` (Java default is ECB), `AES.new(key)` (PyCryptodome default is ECB), `crypto.createCipher` (Node, deprecated, derives IV from key — DON'T)

### Authenticated encryption

- Always use authenticated modes — AES-GCM, ChaCha20-Poly1305, or Encrypt-then-MAC (HMAC-SHA256 over ciphertext)
- Never decrypt → check MAC; always check MAC → then decrypt (otherwise: padding oracle)
- If using Encrypt-then-MAC, use **separate keys** for encryption and authentication (or HKDF-derive both from one master key)
- Verify the MAC with a constant-time compare (`crypto.timingSafeEqual` in Node, `hmac.compare_digest` in Python, `subtle.ConstantTimeCompare` in Go) — see `owasp-audit` A07

### Signature verification

- The most common signature-verification bug isn't a broken algorithm — it's not checking the signature at all, or checking the algorithm from the message itself
- **JWT:** verify `alg` is exactly what your code expects. Never call `jwt.decode` and use the claims without `jwt.verify`. Many libraries accept `alg: none` (un-signed) by default — verify the library version doesn't have this
- **Webhook signatures:** verify the signature BEFORE doing anything else with the body. Many implementations parse-then-verify, leaving a JSON-parsing attack surface
- Constant-time comparison for the signature byte string
- Timestamp tolerance window — accept signatures from within ± 5 minutes (Stripe, GitHub, Slack all do this), not "forever" (replay attack)
- See `owasp-audit` A04 type-coercion in signature paths (`parseInt → NaN`)
- Grep for: `jwt.decode` (without subsequent `verify`), `alg: 'none'`, `verify.*sig` without `timingSafeEqual` nearby

### Randomness

- **Use:** `crypto.randomBytes` (Node), `secrets.token_bytes` (Python ≥ 3.6), `crypto/rand` (Go), `SecRandomCopyBytes` (iOS), `SecureRandom` (Java)
- **Never use:** `Math.random()` (Node — Mersenne Twister, predictable), `random.random()` (Python — same), `rand()` (C — terrible), `arc4random_uniform` for crypto (BSD — historical name only, but verify the runtime)
- For UUIDs, prefer UUID v4 from a CSPRNG (most language stdlibs do this correctly; verify by reading the implementation if it matters)
- Token / session ID minimum entropy — 128 bits (16 random bytes, base64 → 22 chars) is the floor; 256 bits is the sane default
- Grep for: `Math.random`, `random.random`, `rand(`, `mt_rand` (PHP), `Random.new` (Ruby)

### TLS configuration

- **Versions:** TLS 1.3 preferred, TLS 1.2 minimum, refuse TLS 1.0 / 1.1 / SSLv3 / SSLv2
- **Cipher suites (TLS 1.2):** ECDHE only, AEAD ciphers only (AES-GCM, ChaCha20-Poly1305). Reject CBC, RC4, NULL, EXPORT, anonymous
- **Certificate validation:** `VERIFY_PEER`, full chain, hostname check enabled (see `owasp-audit` A04 for managed-service caveat)
- **Certificate pinning:** for high-trust connections (mobile apps to your backend, sensitive internal services); pair with backup pin (rotation)
- **HSTS preload:** verified every subdomain serves HTTPS first; preload submission is sticky (months to remove)
- **OCSP stapling** for performance and privacy
- Test with: `testssl.sh https://target` or `sslyze --regular target`

### Key lifecycle

- **Where keys live:** HSM / cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit) — applications request encrypt / decrypt without ever seeing the key material
- **Envelope encryption:** per-record data key wrapped by a customer master key — limits blast radius if any single data key is exposed
- **Rotation:** master keys annually (or per provider default); data keys per record (no rotation needed — re-encrypt only if compromise suspected). KMS providers handle this if configured
- **Key versioning:** every ciphertext records the key ID that encrypted it, so decryption can find the right key after rotation
- **Revocation:** how do you stop a compromised key from being used to decrypt? Plan exists, documented, tested

### Specific framework patterns

- **Rails:** `MessageVerifier` / `MessageEncryptor` use modern primitives by default; verify they're configured with a strong key (32 bytes / 256 bits)
- **Django:** `cryptography.fernet` is AES-128-CBC + HMAC-SHA256 (acceptable but not GCM); `django.core.signing` for short signed values
- **Node/Express:** prefer `iron-session` / `cookie-signature` over rolling your own
- **iOS:** CryptoKit for modern Swift code; `CommonCrypto` works but has more footguns
- **Android:** Tink (Google) is the recommended high-level library; raw JCA has historical AES-ECB defaults

## Verify, then record

Close every candidate from the checklist with one verdict, using the shared format in [references/findings-format.md](references/findings-format.md). Before anything is `confirmed`, run the refutation pass in [references/verification.md](references/verification.md): open the call site, find where the key, IV, salt and parameters actually come from, and check whether the library version in use already applies a safe default.

A weak primitive is a finding when you can name who gains what: the lower-trust principal (anyone who sees ciphertext, a holder of a leaked hash table, a client that sends a token, a network attacker on the path), the control it defeats (confidentiality, integrity, authentication, password secrecy) and the result. Rate severity with [references/severity-calibration.md](references/severity-calibration.md) by the data the broken control protects. Conditions such as "attacker already holds a copy of the users table" go in `conditions[]` (`data_state`); they lower likelihood, not impact.

**`confirmed`** — the code shows the broken use and the result follows. Examples:
- `createCipheriv('aes-256-gcm', key, FIXED_IV)` in `src/lib/vault.ts` with one key for every record: anyone who reads the encrypted column gets the XOR of plaintexts and can forge ciphertexts. A unit test that encrypts two values and shows the repeated keystream sets `reproduced: true`.
- Session tokens from `Math.random()` in `src/lib/session.ts`: predictable tokens for any user's session.
- `jwt.sign(..., process.env.JWT_SECRET || 'dev-secret')`: confirmed with a `system_configuration` condition ("deployments that don't set `JWT_SECRET`") and confidence `medium`. Anyone who reads the repo can mint tokens for those deployments.
- Unsalted SHA-256 or PBKDF2 at 1,000 iterations for passwords, with a `data_state` condition for the hash-table leak.

**`needs_validation`** — the code supports it, but one fact lives outside it. Examples:
- `nginx.conf` allows `TLSv1 TLSv1.1`, but a CDN or load balancer may terminate TLS first. Blocker: which config serves `api.example.com`. Plan: `testssl.sh --protocols https://api.example.com` (live check, needs authorization). A TLS check described but not run stays here.
- A KMS-wrapped data key whose key policy lives in another repo. Blocker: which principals hold `kms:Decrypt`. Plan: `aws kms get-key-policy --key-id <id> --policy-name default`.

**`rejected`** — a named control at a named location rules it out. Examples:
- `jwt.verify(token, key)` with no `algorithms` option, ruled out by the library: `control` is "jsonwebtoken 9.0.2 `verify()` rejects `alg: none` and HS/RS confusion for asymmetric keys", `ruled_out_by.location` is the `package-lock.json` line that pins 9.0.2.
- `createHash('md5')` in `src/lib/etag.ts`, used only as a cache ETag. `ruled_out_by.location` is the only call site, which sets a response header and makes no trust decision.

**Hardening notes, not records:** a weaker-than-recommended choice with no traced exposure. Examples: bcrypt cost 10 instead of 12, Encrypt-then-MAC with AES-CBC done correctly (prefer GCM), TLS 1.2 CBC suites offered next to AEAD suites, no OCSP stapling, no rotation schedule on a KMS key, missing HSTS preload. Custom crypto is a finding when you trace what it fails to protect; otherwise it's a "replace, don't patch" hardening note.

**Live and cloud evidence.** TLS scans and KMS or HSM settings describe deployed resources, not files. Save the read-only output, redacted, to `<audit dir>/evidence/<name>.json` or `.txt` (`testssl.sh --jsonfile`, `sslyze --json_out`, `aws kms describe-key`) and point `location` and `evidence[]` at that file and line. Never save key material, private keys, plaintext you decrypted or a secret value.

**Fingerprint:** `crypto-audit/<class>/<file or resource>/<symbol or name>`, no line numbers:
- `crypto-audit/gcm-nonce-reuse/src/lib/vault.ts/encryptField`
- `crypto-audit/CWE-338/src/lib/session.ts/newSessionId`
- `crypto-audit/tls-legacy-protocol/host/api.example.com/443`
- `crypto-audit/kms-key-policy/aws/123456789012/us-east-1/alias/app-data`

Write `host:port` as `host/<host>/<port>` and ARNs with slashes: the validator rejects `:<digits>` segments.

**`ext` keys** (optional, on any record):

| Key | Value | Example |
|---|---|---|
| `primitive` | Algorithm, mode and parameters as used | `"AES-256-GCM, static 96-bit IV"`, `"PBKDF2-HMAC-SHA256, 1000 iterations"` |
| `library` | Library and version that performs the operation | `"node:crypto (Node 20)"`, `"pycryptodome 3.20.0"` |
| `standard` | The guidance the use departs from | `"NIST SP 800-38D 8.2"`, `"RFC 8996"`, `"OWASP Password Storage"` |

Then write `findings.json` sorted by fingerprint, validate it, and optionally export SARIF:

```bash
node references/validate-findings.mjs findings.json
node references/to-sarif.mjs findings.json -o findings.sarif
```

## Verify Fixes at Runtime

- Test encryption / decryption round-trip after every change — silent data corruption is the failure mode of crypto changes
- For algorithm changes (e.g., bcrypt → Argon2id): plan migration on next user login (rehash from plaintext during auth flow); old hashes need to remain readable until migrated
- For TLS changes: verify with `testssl.sh` and `curl --tlsv1.3 --tls-max 1.3 https://target` (lower-bound TLS version enforcement)
- For KMS changes: verify the IAM permissions cover both encrypt AND decrypt (common rollout bug: encrypted data, can't decrypt it back)

## Output Format

Write `findings.json` first and validate it. Render the report from it, plus your hardening-notes list. The prose never changes a verdict, severity or blocker the JSON doesn't already say.

```markdown
# Cryptography Implementation Audit
## Project: [name]   ## Date: [date]
## Scope: [components covered; full | partial — what was left out, e.g. "no TLS scan run"]
## findings.json: [path] — validated: [yes]

### Summary
- Confirmed: [N] (Critical [n] | High [n] | Medium [n] | Low [n])   Needs validation: [N]   Rejected: [N]   Hardening notes: [N]

### Confirmed findings
#### [SEVERITY] [Title]  `fingerprint`
**Location:** `path:line`   **CWE:** [CWE-n]   **Confidence:** [medium | high (reproduced)]   **Primitive:** [ext.primitive]
**What and why it matters:** [principal, control defeated, result]
**Conditions:** [e.g. data_state: attacker holds the users table]
**Vulnerable code:** [snippet]
**Fix:** [concrete change, including migration of existing ciphertext or hashes]
**Verify the fix:** [round-trip test, rehash on login, testssl output; see Verify Fixes at Runtime]

### Needs validation
| Finding | Blockers | Check for the owner to run |
|---|---|---|

### Hardening notes (not findings)
- [location] — [gap] — [why it isn't a finding] — [effort]

### Rejected (do not re-raise)
| Fingerprint | Claim | Ruled out by | Location |
|---|---|---|---|

### TLS posture (if applicable)
[Summary of saved testssl.sh / sslyze output, with the evidence file path, or "not run"]

### Key inventory
| Key | Purpose | Location | Algorithm | Rotation |
|-----|---------|----------|-----------|----------|

### Prioritized remediation plan
1. [Critical / High confirmed findings]
2. [Medium / Low confirmed findings]
3. [Owner-run checks for needs-validation items]
4. [Hardening notes worth the effort]
```

Dispositions for confirmed findings (set later, usually by `finding-triage`): Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration. A false positive is a `rejected` record, not a disposition.

## Boundaries

- Audit code and configurations the user provides
- Refuse to help break, weaken, or build backdoors into cryptography
- For TLS testing — only test endpoints the user has authorization for
- If the audit surfaces a fundamentally broken design (custom crypto, ROT13-as-protection), the recommendation is "replace, don't patch" — don't try to incrementally improve broken designs
- Quantum-resistant migration: track NIST PQC standardization but don't recommend specific PQC primitives until they're standardized and library-supported; the field is changing

## References

- NIST SP 800-57 (Key Management)
- NIST SP 800-131A (Algorithm Transitions)
- NIST SP 800-175B (Cryptographic Standards Guidelines)
- NIST FIPS 140-3 (Cryptographic Module Standards)
- IETF RFC 7525 (TLS Recommendations)
- OWASP Cryptographic Storage Cheat Sheet
- OWASP Transport Layer Protection Cheat Sheet
- "Cryptography Engineering" — Ferguson, Schneier, Kohno (the book to read)
- "Real-World Cryptography" — David Wong
- libsodium / Tink / BoringSSL documentation
- Shared references (copied into `references/` at build time): [findings-format.md](references/findings-format.md), [severity-calibration.md](references/severity-calibration.md), [verification.md](references/verification.md), [validate-findings.mjs](references/validate-findings.mjs), [to-sarif.mjs](references/to-sarif.mjs), [findings.schema.json](references/findings.schema.json)

## Reference files

This skill links to supporting files under `references/`. They are not inlined in this adapter; open them on GitHub (or in `skills/crypto-audit/references/` if you have the repo checked out):

- [references/findings-format.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/findings-format.md)
- [references/findings.schema.json](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/findings.schema.json)
- [references/severity-calibration.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/severity-calibration.md)
- [references/to-sarif.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/to-sarif.mjs)
- [references/validate-findings.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/validate-findings.mjs)
- [references/verification.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/crypto-audit/references/verification.md)
