# Electron playbook

Load this during an `owasp-audit` run when recon detects Electron ([detection signals](README.md)). The trust
boundary in an Electron app runs between web content in a renderer and the main process, which has full OS access.
The question for every check is the same: which document or frame can reach which native capability, and what stops
it?

Findings use the normal OWASP Top 10:2025 categories, verdicts, and `findings.json` format. Fingerprints name the
window, the preload export, or the IPC channel: `owasp-audit/CWE-749/src/preload.ts/invoke`.

A web-preference flag on its own is a **hardening note**. It becomes a finding when you can trace untrusted content
(a remote page, a rendered message, a deep link) into the renderer and through the weakened boundary to a native
action.

## Add these surfaces to the ledger

| Surface | How to enumerate | Principal |
|---|---|---|
| Each `BrowserWindow` / `WebContentsView` / `<webview>` | `new BrowserWindow(`, `new WebContentsView(`, `webviewTag` | whatever content it can load: local files only, a remote origin, user-generated HTML |
| Each preload export | `contextBridge.exposeInMainWorld(` | every document that can load in a window with that preload |
| Each IPC handler | `ipcMain.handle(`, `ipcMain.on(`, `webContents.ipc.handle(` | renderers that can reach the preload bridge |
| Navigation and popups | `will-navigate`, `will-frame-navigate`, `will-redirect`, `setWindowOpenHandler`, `loadURL(` | links and redirects in rendered content |
| Deep links and second instance | `setAsDefaultProtocolClient`, `open-url`, `second-instance`, `process.argv` | any web page or local app that can open a URL |
| Auto-update | `autoUpdater`, `electron-updater`, `publish` / `build` config | network path to the update feed |
| Packaging and fuses | `@electron/fuses`, `flipFuses`, `electronFuses` in builder config | local users and processes on the same machine |

```bash
rg -n '"electron":' package.json; rg -n '"main":' package.json
rg -n "new (BrowserWindow|WebContentsView|BrowserView)\(|webviewTag|exposeInMainWorld|ipcMain\.(handle|on|once)\(|webContents\.ipc\." -g '!node_modules' -g '!dist' -g '!out'
```

Record the installed Electron major. Defaults changed over time: `nodeIntegration` is off by default since 5,
`contextIsolation` on since 12, and the renderer sandbox on since 20. A window that doesn't set them inherits the
defaults of the installed version.

## Checks

### 1. Web preferences that remove the boundary (A02, escalating to A05 / A01)

**Look for:**
- `nodeIntegration: true` (or `nodeIntegrationInWorker` / `nodeIntegrationInSubFrames`) in a window that can run any
  untrusted script. Any XSS there becomes code execution on the user's machine
- `contextIsolation: false`: page scripts share a world with the preload and can tamper with what it exposes
- `sandbox: false`: the renderer runs without Chromium's process sandbox, and the preload gets full Node
- `webSecurity: false`, `allowRunningInsecureContent: true`, `experimentalFeatures: true`, `webviewTag: true` with
  loose `<webview>` attributes
- Remote content (`loadURL('https://...')`) in a window that also has a privileged preload

**Find candidates:**

```bash
rg -n "nodeIntegration(InWorker|InSubFrames)?\s*:\s*true|contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|experimentalFeatures\s*:\s*true|webviewTag\s*:\s*true" -g '!node_modules' -g '!dist'
rg -n "loadURL\(" -g '!node_modules' -g '!dist'
# portable
grep -rnE "nodeIntegration *: *true|contextIsolation *: *false|sandbox *: *false|webSecurity *: *false" --include='*.js' --include='*.ts' . | grep -v node_modules
```

**Verify:** confirmed when you can name the untrusted content source, show it reaches that window (a remote URL, a
navigation the app doesn't block, user HTML rendered without sanitizing), and show what the flag lets it do. Category:
A05 when the path is injection into a renderer with Node access; A01 when it's a privileged bridge reachable by
the wrong origin; A02 for the flag itself as a hardening note. Rejected when the window loads only packaged files and
navigation is locked down (check 4).

### 2. Preload bridges that expose too much (A01)

**Look for:** anything in `exposeInMainWorld` beyond narrow, fixed operations:
- `ipcRenderer` itself, or a generic `send(channel, ...)` / `invoke(channel, ...)` that lets the page pick the channel
- Node modules or objects (`fs`, `child_process`, `shell`, `require`)
- Callback registration that hands the raw `IpcRendererEvent` (it carries `sender`) back to the page
- Secrets or tokens returned to the page so it can call an API

**Find candidates:**

```bash
rg -n "exposeInMainWorld" -A20 -g '!node_modules' | rg -n "ipcRenderer\b|invoke\(\s*\w+\s*,|send\(\s*\w+\s*,|require\(|child_process|shell\.|fs\."
```

**Verify:** confirmed when a document that shouldn't have the capability can reach the export and drive it to a native
action. A generic `invoke(channel)` is a strong lead, but the handlers decide what's reachable (check 3). Rejected
when the exports are fixed functions with validated arguments and every handler they reach checks its sender.

### 3. IPC handlers without sender or argument validation (A01, A05)

**Look for:** for each `ipcMain.handle` / `ipcMain.on`:
- No check of `event.senderFrame` (its URL or origin) against the app's own origin. Any frame that reaches the bridge,
  including an iframe or a page navigated to by a link, can call the handler
- Arguments used as file paths (`fs.readFile(arg)`, `fs.writeFile(arg, ...)`) without resolving and confining them to
  an allowed directory
- Arguments passed to `child_process`, `shell.openPath`, or a shell command
- Handlers that perform account or admin actions with an id from the renderer and no check of the current session

**Find candidates:**

```bash
rg -n "ipcMain\.(handle|on|once)\(['\"]([^'\"]+)" -o -r '$2' -g '!node_modules' | sort | uniq
rg -n "senderFrame|event\.sender(Frame)?\.url|validateSender" -g '!node_modules'
rg -n "ipcMain\.(handle|on)\(" -A12 -g '!node_modules' | rg -n "readFile|writeFile|rm\(|unlink|spawn|exec\(|execFile|openPath"
```

**Verify:** confirmed with a trace from a reachable renderer input through the handler to the file, process, or
account action. Rejected when the handler checks the sender's origin and validates the argument (for paths: resolve,
then confirm it's inside the allowed root) before the sink.

### 4. Navigation, popups, and `shell.openExternal` (A01, A05)

**Look for:**
- No `will-navigate` handler (and no `will-frame-navigate` / `will-redirect` where frames or redirects matter) on
  windows with a privileged preload. A link in rendered content then loads a remote page that inherits the bridge
- `setWindowOpenHandler` missing or returning `{ action: 'allow' }` for arbitrary URLs
- Allowlists using `startsWith('https://app.example.com')`, which `https://app.example.com.evil.test` passes. Parse
  with `new URL()` and compare `protocol` and `host` exactly
- `shell.openExternal(url)` with a URL from content or IPC. The OS hands it to whatever handler owns the scheme, so
  `file:`, `smb:`, and app-specific schemes can open local executables or other apps. Allow only `https:` (and
  `mailto:` if needed) after parsing

**Find candidates:**

```bash
rg -n "will-navigate|will-frame-navigate|will-redirect|setWindowOpenHandler|new-window" -g '!node_modules'
rg -n "openExternal\(" -B3 -g '!node_modules'
rg -n "startsWith\(['\"]https?://" -g '!node_modules'
```

**Verify:** confirmed when content the app renders can produce the navigation or URL and nothing on that path restricts
it. Rejected when every window denies navigation away from the packaged origin and `openExternal` is reached only
after a scheme and host allowlist.

### 5. Deep links and second-instance arguments (A01, A05)

**Look for:** URLs from `open-url` (macOS), `second-instance` argv (Windows/Linux), or the initial `process.argv`
routed into navigation, file operations, or account actions (completing a login, accepting an invite, importing a
file) without validation or user confirmation. Any web page can trigger a registered scheme.

```bash
rg -n "setAsDefaultProtocolClient|open-url|second-instance|process\.argv" -g '!node_modules'
```

**Verify:** confirmed when an externally supplied URL reaches a state change or sink without validation. Rejected when
the router parses the URL, allows a fixed set of actions, and asks the user before anything that changes state.

### 6. Fuses, ASAR integrity, and updates (A08, A03)

**Look for:**
- Fuses left at defaults in a packaged app. `RunAsNode`, `EnableNodeOptionsEnvironmentVariable`, and
  `EnableNodeCliInspectArguments` are on by default, which lets a local process run code under the app's identity
  (and the OS permissions and code-signing trust it was granted). `EnableEmbeddedAsarIntegrityValidation` and
  `OnlyLoadAppFromAsar` are off by default
- Electron versions affected by CVE-2025-55305: the ASAR integrity fuses didn't cover V8 heap snapshot files, so code
  could be planted in an app that had them enabled. Fixed in 35.7.5, 36.8.1, 37.3.1, and 38.0.0-beta.6. Hand version
  triage to `dependency-audit`
- Auto-update over plain HTTP, a feed URL the user or a config file controls, or signature checks turned off
  (`verifyUpdateCodeSignature: false` in electron-builder, or no code signing on the published artifacts)

```bash
rg -n "FuseV1Options|flipFuses|electronFuses|@electron/fuses" -g '!node_modules'
rg -n "autoUpdater|electron-updater|setFeedURL|verifyUpdateCodeSignature|publisherName|\"publish\"" -g '!node_modules'
```

**Verify:** fuse settings are usually hardening notes: the attacker already runs code as the same user, so a finding
needs a concrete gain (the app holds entitlements or permissions the attacker's process doesn't). The owner can read
the shipped state with `npx @electron/fuses@2.1.3 read --app <path to packaged app>`. An update path without signature
verification is confirmed A08 when the feed or transport can be influenced by a network attacker.

## Worked examples

**Confirmed (A01).** `src/preload.ts` exposes `invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args)`.
`src/main/ipc.ts` registers `ipcMain.handle('file:save', (_e, path, data) => fs.promises.writeFile(path, data))` with
no sender check. The chat window renders message links and has no `will-navigate` handler, so clicking a link in a
message from another user loads that page in the window with the preload attached. The page can call
`invoke('file:save', ...)` and write any file the user can write.

```json
{
  "fingerprint": "owasp-audit/CWE-749/src/main/ipc.ts/file-save",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-749", "confidence": "medium",
  "counterevidence": "no senderFrame check in any handler; no will-navigate or setWindowOpenHandler in src/main; path not confined",
  "conditions": [ { "kind": "user_interaction", "description": "victim clicks a link in a chat message" } ],
  "severity": { "likelihood": { "score": "medium", "reason": "needs one click on a message link" },
                "impact": { "score": "critical", "reason": "arbitrary file write as the user, leading to code execution" }, "overall": "high" }
}
```

**Rejected (A02 → A05 candidate).** `src/main/window.ts` sets `sandbox: false` for the settings window, flagged as
renderer code execution. The window loads only `loadFile('dist/settings.html')`, the CSP in that file is
`default-src 'self'`, it renders no remote or user-supplied HTML, and `will-navigate` calls `preventDefault()` for
every URL outside the app at line 31. No untrusted script reaches the renderer. The flag stays as a hardening note.

```json
{
  "fingerprint": "owasp-audit/CWE-693/src/main/window.ts/settings-window-sandbox",
  "verdict": "rejected", "owasp_category": "A05:2025", "confidence": "medium",
  "counterevidence": "searched for loadURL, innerHTML, and remote fetches in the settings renderer; none. Navigation handler blocks external URLs",
  "ruled_out_by": { "control": "window loads only packaged files and will-navigate blocks all external navigation",
                    "location": { "file": "src/main/window.ts", "line": 31 } }
}
```

Both are abridged; see [findings-format.md](../findings-format.md) for the full record shape.

## Sources

Paraphrased, not copied:

- Strix (Apache-2.0): [technologies/electron_desktop_apps.md](https://github.com/usestrix/strix/blob/main/strix/skills/technologies/electron_desktop_apps.md)
  (authority map from frame to native action, preload export classes, navigation paths, flags as leads rather than proof)
- Cloudflare security-audit-skill (MIT): [DESKTOP-MOBILE-AND-LOCAL-IPC.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md)
  (bridge reachable from the wrong origin, deep-link handling, confirmed vs needs_validation for packaging facts)
- Electron docs: [Security checklist](https://www.electronjs.org/docs/latest/tutorial/security),
  [Process sandboxing](https://www.electronjs.org/docs/latest/tutorial/sandbox),
  [Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- CVE-2025-55305: [Trail of Bits write-up](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/),
  [GitHub advisory](https://github.com/electron/electron/security/advisories/GHSA-vmqv-hx8q-j7mg)
