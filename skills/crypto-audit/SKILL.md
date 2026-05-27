---
name: crypto-audit
description: "Audit cryptography implementation — algorithm choice, key sizes, KDF parameters, IV/nonce handling, signature verification, randomness, TLS configuration, and key rotation. Deeper than owasp-audit A02. Use when the user mentions 'crypto review,' 'cryptography audit,' 'encryption review,' 'KDF,' 'PBKDF2,' 'Argon2,' 'bcrypt cost,' 'IV reuse,' 'nonce reuse,' 'AES mode,' 'AES-GCM,' 'AES-ECB,' 'signature verification,' 'TLS configuration,' 'cipher suites,' 'key rotation,' 'libsodium,' 'BoringSSL,' or 'is this crypto right.'"
allowed-tools: Read, Grep, Glob, Bash, WebSearch
---

# Crypto Audit — Cryptography Implementation Review

Audit how cryptography is implemented in an application — algorithm choices, parameters, modes, and the implementation patterns that turn good primitives into broken systems. Deeper than `owasp-audit` A02 (which catches the obvious "MD5 password" and "VERIFY_NONE" cases). This skill is for the subtler implementation review.

Most crypto failures are not "they used MD5." Most failures are: right primitive, wrong mode (ECB instead of GCM), right algorithm, wrong parameter (PBKDF2 with 1,000 iterations in 2026), right library, wrong call order (init the cipher after the data was loaded).

Cross-references: `owasp-audit` A02 (baseline) + A07 (timing-safe comparison), `secrets-audit` (key storage), `iam-audit` (KMS / HSM patterns).

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
- See `owasp-audit` A02 type-coercion in signature paths (`parseInt → NaN`)
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
- **Certificate validation:** `VERIFY_PEER`, full chain, hostname check enabled (see `owasp-audit` A02 for managed-service caveat)
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

## Verify Fixes at Runtime

- Test encryption / decryption round-trip after every change — silent data corruption is the failure mode of crypto changes
- For algorithm changes (e.g., bcrypt → Argon2id): plan migration on next user login (rehash from plaintext during auth flow); old hashes need to remain readable until migrated
- For TLS changes: verify with `testssl.sh` and `curl --tlsv1.3 --tls-max 1.3 https://target` (lower-bound TLS version enforcement)
- For KMS changes: verify the IAM permissions cover both encrypt AND decrypt (common rollout bug: encrypted data, can't decrypt it back)

## Output Format

```markdown
# Cryptography Implementation Audit
## Project: [name]
## Scope: [components covered]
## Date: [date]

### Summary
[2-3 paragraphs]

### Findings
| ID | Severity | Component | Issue | CWE |
|----|----------|-----------|-------|-----|

### Per-finding detail
[Title, severity, file:line, description, vulnerable snippet, remediation, verification]

### TLS posture (if applicable)
[Output of testssl.sh / sslyze]

### Key inventory
| Key | Purpose | Location | Algorithm | Rotation |
|-----|---------|----------|-----------|----------|

### Recommendations
[Prioritized]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`.

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
