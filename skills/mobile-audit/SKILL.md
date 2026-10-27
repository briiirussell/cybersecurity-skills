---
name: mobile-audit
description: "Audit iOS and Android mobile applications against OWASP MASVS / MASTG — insecure storage, weak crypto, certificate pinning, deeplinks, IPC, jailbreak/root detection, reverse-engineering resistance. Use when the user mentions 'mobile security,' 'iOS security,' 'Android security,' 'mobile audit,' 'mobile pentest,' 'MASVS,' 'MASTG,' 'certificate pinning,' 'jailbreak detection,' 'root detection,' 'deeplink,' 'URL scheme,' 'app transport security,' 'keychain,' 'keystore,' 'mobile reverse engineering,' or has a mobile app to review."
allowed-tools: Read, Grep, Glob, WebSearch
---

# Mobile Audit — iOS & Android Application Security Review

Audit mobile apps against the OWASP Mobile Application Security Verification Standard (MASVS) and Mobile Application Security Testing Guide (MASTG). Covers source code review, static analysis of compiled binaries, and runtime testing.

Scope: this skill covers the *app* and its interaction with the device, the backend, and other apps. For backend API security, pair with `api-audit`. For dependency CVEs (CocoaPods, SPM, Gradle), pair with `dependency-audit`.

## Authorization Check

Before reverse-engineering or runtime-testing a binary, confirm:
1. The app is yours, or you have written authorization from the publisher
2. You're operating in an environment you control (test device, emulator, dedicated sandbox)
3. App store ToS — Apple and Google generally allow security research on apps you own; testing competitor apps without authorization is a fast path to legal exposure

If unclear, ask before proceeding.

## Audit Checklist — MASVS-STORAGE (Sensitive Data Storage)

- **iOS:** keychain items use the strongest available `kSecAttrAccessible` class — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Avoid `Always` and `ThisDeviceOnly`-less variants
- **iOS:** no secrets in `NSUserDefaults`, plist, or app bundle — `strings <app>.ipa` should not reveal API keys or secrets
- **Android:** secrets in EncryptedSharedPreferences / Keystore-backed encrypted storage, not raw SharedPreferences
- **Android:** `android:allowBackup="false"` in the manifest (or backup rules carefully scoped) — otherwise `adb backup` extracts everything
- **Both:** no PII / tokens written to logs that survive a crash (NSLog, Log.d, third-party crash reporters)
- **Both:** Pasteboard / Clipboard access — sensitive fields don't auto-share to system clipboard (iOS `pasteboard.expirationDate`, Android `ClipDescription.EXTRA_IS_SENSITIVE`)
- **Both:** the OS app-switcher screenshot doesn't capture sensitive screens — iOS `applicationDidEnterBackground` blur, Android `FLAG_SECURE` on the activity

## Audit Checklist — MASVS-CRYPTO (Cryptography)

- No hardcoded keys in the app bundle — `strings`, `class-dump`, `apktool` reveal embedded constants
- Modern algorithms only — AES-GCM, ChaCha20-Poly1305; reject AES-ECB, DES, RC4, MD5, SHA-1
- Random number generation uses `SecRandomCopyBytes` (iOS) / `SecureRandom` (Android) — not `arc4random()` for crypto, never `Math.random()`
- Key derivation from passwords uses PBKDF2 with ≥ 600,000 iterations (OWASP 2024) or Argon2id
- IVs / nonces are not reused — if you see `iv = "0000000000000000"`, that's worse than no encryption (reveals plaintext patterns)
- Don't roll your own crypto — flag any custom encryption scheme; bias toward libsodium / Tink

## Audit Checklist — MASVS-NETWORK (Network Communication)

- **iOS:** App Transport Security enabled — no global `NSAllowsArbitraryLoads = true`. If exceptions exist, they're specific domains, justified, and documented
- **Android:** `network_security_config.xml` exists and enforces cleartext-traffic refusal — `<base-config cleartextTrafficPermitted="false">`
- **Both:** Certificate pinning for high-trust backends — public-key pinning preferred over certificate pinning (survives cert rotation). For iOS: `URLSessionDelegate` + `URLAuthenticationChallenge`; Android: `NetworkSecurityConfig` `<pin-set>` or OkHttp `CertificatePinner`
- **Both:** Pinning has a backup pin — pinning to a single cert means the next rotation breaks the app for all users
- WebView usage — `WKWebView` only (iOS, not `UIWebView`); JavaScript bridge audited; `setJavaScriptEnabled(false)` if the WebView doesn't need JS
- WebView `loadUrl` with user-controlled URL — open redirect, intent-spoofing, phishing surface

## Audit Checklist — MASVS-AUTH (Authentication & Session)

- Biometric prompts use `LAContext.evaluatePolicy` (iOS) / `BiometricPrompt` (Android) — not the deprecated `FingerprintManager`
- Biometric auth is bound to keychain/keystore access, not just a UI check (`SecAccessControl.biometryAny`, Android `KeyGenParameterSpec.setUserAuthenticationRequired(true)`)
- Session tokens stored in keychain/keystore (not SharedPreferences/NSUserDefaults)
- Refresh-token flow — short-lived access token, refresh token revocable server-side
- OAuth flows use the platform browser (ASWebAuthenticationSession on iOS, Custom Tabs on Android) — never a WebView (steals credentials trivially)
- App-level passcode independent of device unlock if the app holds sensitive data

## Audit Checklist — MASVS-PLATFORM (Platform Interaction)

### Deeplinks / URL schemes (iOS) and Intent filters (Android)

- Every exported activity (`android:exported="true"`) reviewed for parameter handling
- Universal Links (iOS) and App Links (Android) use HTTPS + verified domain — not custom schemes (`myapp://`) which any app can register
- Deeplinks that trigger sensitive actions (purchase, share, change account) require user confirmation in-app
- WebView-loaded URLs filtered — opening `myapp://` from a WebView to trigger an in-app action without user consent is an XSS-to-action chain

### Inter-process communication (Android)

- Content providers — `android:exported="false"` unless explicitly intended for cross-app access; if exported, every URI path validated
- Services — exported services have permission strings; exposed without `android:permission` is callable by any app
- Broadcast receivers — `LocalBroadcastManager` for in-app broadcasts; system broadcasts validated

### Inter-process communication (iOS)

- App groups configured only when sharing is genuinely required
- Keychain access groups limited to your own apps (no shared keychain group with unrelated bundles)
- URL scheme handlers validate the source app (`UIApplication.openURL` options include `UIApplicationOpenURLOptionsSourceApplicationKey`)

## Audit Checklist — MASVS-CODE (Code Quality)

- Native libraries — modern compilers, no stack canaries disabled, PIE enabled (`otool -hv` on iOS, `readelf -h` on Android `.so`). For memory-safety review of the native and JNI source itself → `native-code-review`
- Symbols stripped from release builds (`strip`, ProGuard/R8)
- No debug builds in production (`DEBUG` flag, `isDebuggable` in manifest)
- No reflection-based hidden APIs (Android non-SDK interfaces) — break on OS upgrades
- Updates: in-app update prompt that forces upgrade past known-vulnerable versions

## Audit Checklist — MASVS-RESILIENCE (Anti-Reverse-Engineering)

This category is rated optional in MASVS — only required for high-risk apps (banking, DRM, government). For most apps, **don't waste effort here**; ship secure crypto and a proper backend.

If required:
- Jailbreak / root detection — not bulletproof (every detection technique has a public bypass) but raises the cost
- Code obfuscation — DexGuard / Arxan for high-value apps; standard ProGuard / R8 minimally for everyone
- Anti-debugging — `ptrace` self-attach (iOS / Linux), `Debug.isDebuggerConnected` (Android)
- SSL pinning resistant to Frida-style bypass — pin in native code, not Swift / Kotlin

Note: every resilience control will be bypassed by a determined attacker with physical device access. They buy time, they don't prevent.

## Static analysis tools

| Tool | Platform | Use |
|---|---|---|
| MobSF | iOS + Android | Automated static + dynamic scanner; first-pass triage |
| nuclei + mobile templates | Both | Pattern-based scanner |
| semgrep + mobile rules | Both | AST-based rules |
| jadx | Android | Decompile APK to Java |
| apktool | Android | Disassemble APK |
| Hopper / Ghidra / IDA | iOS | Disassemble Mach-O |
| class-dump / nm / otool | iOS | Symbol and structure inspection |
| `strings` | Both | First check — secrets, URLs, debug strings |
| Frida + objection | Both | Runtime instrumentation, SSL-pinning bypass, method tracing |

## Runtime testing

For grey/black-box assessment, use a non-personal device:

- Burp Suite / mitmproxy as system proxy on the test device — observe API traffic
- Bypass SSL pinning with Frida + `objection` if you need to see encrypted traffic during testing
- Modify requests, replay them, look for IDOR / BFLA (see `api-audit`)
- Force background → resume to test session handling and screenshot blur
- Force-quit → relaunch to test session persistence and auto-login
- Install a malicious sibling app and test IPC paths (Android Intent fuzzing)

## Verify, then record

Every candidate goes through the refutation pass in [references/verification.md](references/verification.md) before it reaches `findings.json`: a separate read that starts from the cited evidence and tries to disprove the claim. Close each candidate with exactly one verdict, per [references/findings-format.md](references/findings-format.md). Gaps with no traced impact are hardening notes, not records.

**Citing a decompiled binary.** Mobile findings usually come from a compiled app, not source you can point a repo line at. Save the read-only tool output — `strings`, a `jadx` / `apktool` decompilation, `class-dump`, `otool -hv`, `readelf -h`, a manifest or plist dump, a proxied request/response — redacted, to `<audit dir>/evidence/<name>.txt` (or `.json`), and point `location` and each `evidence[]` entry at that file and the line within it. **Never write a secret value to an evidence file:** a hardcoded key's evidence is the decompiled call site that uses it, redacted to type + last 4 — not the key.

- `confirmed` — a complete trace from attacker-reachable input (or an extracted artifact) to impact, or a runtime proof. Examples: an AES key read out of the decompiled APK with `strings`, traced to the decrypt call that uses it (evidence file saved; static-only, so `confidence: medium`); cleartext login captured over the test proxy because `NSAllowsArbitraryLoads=true` ships in `Info.plist` — a permissive shipped default, so `confirmed` at `confidence: medium` with a `system_configuration` condition for builds that don't override it, and `reproduced: true` once the request is captured.
- `needs_validation` — the binary supports the claim but one decisive fact lives off-device. Examples: an `android:exported="true"` activity whose real risk depends on backend authorization you can't see; a `network_security_config` cleartext exception whose domain you have not yet confirmed the running app contacts. A live check you describe but don't run (a proxy capture, a Frida hook) is `needs_validation` with that capture as the plan — not `confirmed`.
- `rejected` — a named control at a named location rules it out. Examples: a `Log.d` of a token gated behind `if (BuildConfig.DEBUG)` with `android:debuggable="false"` in the release manifest (`ruled_out_by` points at the manifest line in the evidence dump); a candidate "hardcoded key" that is a publishable Firebase/Maps identifier with its restrictions in place (see [references/severity-calibration.md](references/severity-calibration.md) §6).

Severity goes on `confirmed` records only, calibrated with [references/severity-calibration.md](references/severity-calibration.md): `overall ≤ demonstrated impact`; a static-only extraction caps confidence at `medium`. MASVS-RESILIENCE gaps (root/jailbreak detection, obfuscation, anti-debugging) with no traced impact are **hardening notes, not findings** — they raise an attacker's cost, they don't cross a boundary.

Record domain fields under `ext` (optional object on any record):

| `ext` key | Meaning | Example |
|---|---|---|
| `masvs` | MASVS control id | `MASVS-STORAGE-1` |
| `platform` | platform the finding is on | `ios` \| `android` \| `both` |
| `source` | where the evidence came from | `source` \| `decompiled` \| `runtime` |

Fingerprint: `mobile-audit/<masvs-or-class>/<file or resource>/<symbol or name>`, slash-separated, no line numbers (the validator rejects `:<digits>` segments). Examples: `mobile-audit/MASVS-NETWORK-1/Info.plist/NSAllowsArbitraryLoads`, `mobile-audit/MASVS-STORAGE-1/AndroidManifest.xml/allowBackup`, `mobile-audit/MASVS-CRYPTO-2/com/acme/app/crypto/Vault/decrypt`. For a decompiled app, use the class or symbol the code lives in, not the evidence file name, so the fingerprint stays the same when the evidence is re-captured.

Write `findings.json` sorted by fingerprint, then validate and fix until it passes:

```bash
node references/validate-findings.mjs findings.json
```

Optionally export SARIF: `node references/to-sarif.mjs findings.json -o findings.sarif`. Dispositions (Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration) are set later, usually by `finding-triage`; a false positive is a `rejected` record, not a disposition.

## Output Format

Write `findings.json` first and validate it; the markdown report is rendered from the JSON and never changes a verdict or severity the JSON doesn't already say.

```markdown
# Mobile Application Security Audit
## App: [name + version]   ## Platform: iOS / Android / both   ## MASVS profile: L1 / L2 / R
## findings.json: [path] — validated: [yes]   ## Date: [date]

### Summary
- Confirmed: [N] (Critical [n] | High [n] | Medium [n] | Low [n])   Needs validation: [N]   Rejected: [N]

### Confirmed findings
#### [SEVERITY] [Title]  `fingerprint`
**Location:** `evidence/<file>:line` (or repo `path:line`)   **MASVS:** [MASVS-X-n]   **CWE:** [CWE-n]   **Platform:** [ios | android | both]   **Confidence:** [medium | high (reproduced)]
**What and why it matters:** [the trace, in a few lines]
**Fix:** [concrete change]   **Verify the fix:** [the check that proves it]

### Needs validation
| Finding | Blockers | Check for the owner to run |
|---|---|---|

### Hardening notes (not findings)
- [gap] — [why it isn't a finding] — [effort]   (RESILIENCE controls usually land here)

### Rejected (do not re-raise)
| Fingerprint | Ruled out by | Location |
|---|---|---|

### MASVS category coverage
| Category | Confirmed | Needs validation | Severity high-water mark |
|---|---|---|---|
| STORAGE / CRYPTO / NETWORK / AUTH / PLATFORM / CODE / RESILIENCE | | | |

### Backend API findings
[Cross-link to api-audit / owasp-audit output]

### Prioritized remediation plan
1. [highest first — 30 / 60 / 90 day fixes]
```

## Boundaries

- Audit only apps you own or have written authorization to test
- Reverse-engineering a competitor's app is a legal risk — refuse unless the user can show authorization
- Frida / Objection / SSL-pinning bypass are for your own apps in test environments — they are not "test in production" tools
- Refuse to help build malware, surveillance apps, or stalkerware
- If the audit surfaces evidence of an active backdoor in someone else's code, escalate; don't quietly fix and forget

## References

- OWASP MASVS (Mobile Application Security Verification Standard)
- OWASP MASTG (Mobile Application Security Testing Guide)
- Shared references (copied into `references/` at build time): findings-format.md, severity-calibration.md, verification.md
- OWASP Mobile Top 10
- Apple Security: Apple Platform Security Guide
- Android Security: Android Security Best Practices
- iOS App Programming Guide — Security
- "iOS Application Security" — David Thiel
- "Android Hacker's Handbook"
