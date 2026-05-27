---
name: mobile-audit
description: "Audit iOS and Android mobile applications against OWASP MASVS / MASTG — insecure storage, weak crypto, certificate pinning, deeplinks, IPC, jailbreak/root detection, reverse-engineering resistance. Use when the user mentions 'mobile security,' 'iOS security,' 'Android security,' 'mobile audit,' 'mobile pentest,' 'MASVS,' 'MASTG,' 'certificate pinning,' 'jailbreak detection,' 'root detection,' 'deeplink,' 'URL scheme,' 'app transport security,' 'keychain,' 'keystore,' 'mobile reverse engineering,' or has a mobile app to review."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
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

- Native libraries — modern compilers, no stack canaries disabled, PIE enabled (`otool -hv` on iOS, `readelf -h` on Android `.so`)
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

## Output Format

```markdown
# Mobile Application Security Audit
## App: [name + version]
## Platform: iOS / Android / both
## MASVS profile: L1 / L2 / R (resilience required)
## Date: [date]

### Executive summary
[2-3 paragraphs]

### MASVS category findings
| Category | Findings | Severity high-water mark |
|---|---|---|
| STORAGE | N | |
| CRYPTO | N | |
| NETWORK | N | |
| AUTH | N | |
| PLATFORM | N | |
| CODE | N | |
| RESILIENCE | N | (only if R-profile) |

### Per-finding detail
[Title, MASVS-ID, severity, description, location, evidence, remediation, verification]

### Backend API findings
[Cross-link to api-audit / owasp-audit output]

### Recommendations
[Prioritized 30/60/90 day fixes]
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
- OWASP Mobile Top 10
- Apple Security: Apple Platform Security Guide
- Android Security: Android Security Best Practices
- iOS App Programming Guide — Security
- "iOS Application Security" — David Thiel
- "Android Hacker's Handbook"
