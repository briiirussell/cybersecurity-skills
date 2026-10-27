# Framework and BaaS playbooks

Framework-specific checks for `owasp-audit`. Generic checklists miss these because the dangerous surface is a
framework convention (a server action, an RLS policy, a security rules file, an IPC handler) rather than a route.

**Load only the playbooks whose signals recon finds.** Most repos match one or two. A monorepo can match several:
load each one for the packages it applies to, and note in `architecture.md` which playbooks you loaded and why.

| Playbook | Load when recon finds any of |
|---|---|
| [Next.js](nextjs.md) | `next` in `package.json` dependencies; `next.config.{js,mjs,ts}`; an `app/` or `pages/` tree next to them; `middleware.{ts,js}` or `proxy.{ts,js}` at the root or in `src/` |
| [Supabase](supabase.md) | `@supabase/supabase-js`, `@supabase/ssr`, or `@supabase/auth-helpers-*` in `package.json`; `supabase` in `requirements.txt` / `pyproject.toml`; `supabase_flutter` in `pubspec.yaml`; a `supabase/` directory with `config.toml`, `migrations/`, or `functions/`; `SUPABASE_URL` in `.env.example` |
| [Firebase](firebase.md) | `firebase`, `firebase-admin`, `firebase-functions`, or `@react-native-firebase/*` in `package.json`; `firebase.json` or `.firebaserc`; `firestore.rules`, `storage.rules`, or `database.rules.json`; `google-services.json` (Android) or the `GoogleService-Info` config file (iOS); `firebase_core` in `pubspec.yaml` |
| [Electron](electron.md) | `electron` in `package.json` (usually `devDependencies`); `electron-builder`, `@electron-forge/*`, or `electron-vite`; `forge.config.*` or `electron-builder.{yml,json}`; `BrowserWindow` in the file named by `package.json` `"main"` |

```bash
# Quick detection pass (run at the repo root; checks nested package.json files too)
rg -l --glob '**/package.json' --glob '!**/node_modules/**' '"(next|@supabase/[a-z-]+|firebase(-admin|-functions)?|@react-native-firebase/[a-z-]+|electron)"\s*:' .
ls next.config.* middleware.* proxy.* src/middleware.* src/proxy.* supabase/config.toml firebase.json *.rules \
   forge.config.* electron-builder.* 2>/dev/null
# portable
find . -name package.json -not -path '*/node_modules/*' -exec grep -lE '"(next|@supabase/[a-z-]+|firebase(-admin|-functions)?|@react-native-firebase/[a-z-]+|electron)"[[:space:]]*:' {} +
```

## How playbook checks fit the audit

- **Recon:** each playbook's "Add these surfaces to the ledger" table adds units to `coverage.json`, same id format as
  any other unit (`<file>:<export or resource>:<boundary>:<category>`).
- **Hunt:** work the playbook checks alongside the main checklist for those units.
- **Verify and record:** every candidate goes through the normal per-finding verification. Findings use the
  OWASP Top 10:2025 category the playbook gives, the usual verdicts and severity rules, and fingerprints like
  `owasp-audit/<class>/<file or resource>/<name>`. Nothing about the findings format changes.
- **Report:** in the header's Stack line, list the playbooks loaded.

Each playbook has the same parts: surfaces to add, checks (what to look for, `rg` and portable `grep` commands, what
makes a candidate confirmed or rejected, and the category), one confirmed and one rejected worked example, and its
sources with licenses.
