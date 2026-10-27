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
| [Django](django.md) | `manage.py`; `django` or `djangorestframework` in `requirements*.txt`, `pyproject.toml`, `Pipfile`, or `poetry.lock`; a `settings.py` (or `settings/`) with `INSTALLED_APPS`; `urls.py` files |
| [Rails](rails.md) | `gem "rails"` in `Gemfile` or `rails (` in `Gemfile.lock`; `config/application.rb`, `config/routes.rb`, `bin/rails` |

```bash
# Quick detection pass (run at the repo root; checks nested package.json files too)
rg -l --glob '**/package.json' --glob '!**/node_modules/**' '"(next|@supabase/[a-z-]+|firebase(-admin|-functions)?|@react-native-firebase/[a-z-]+|electron)"\s*:' .
find . -maxdepth 2 -not -path '*/node_modules/*' \( -name 'next.config.*' -o -name 'middleware.[jt]s' -o -name 'proxy.[jt]s' \
  -o -name firebase.json -o -name '*.rules' -o -name 'forge.config.*' -o -name 'electron-builder.*' -o -name manage.py \
  -o -path ./supabase/config.toml -o -path ./config/routes.rb \)
rg -il "^\s*[\"']?(django|djangorestframework)\b" -g 'requirements*.txt' -g 'pyproject.toml' -g 'Pipfile' . ; rg -l "^\s*gem ['\"]rails['\"]" -g Gemfile .
# portable
find . -name package.json -not -path '*/node_modules/*' -exec grep -lE '"(next|@supabase/[a-z-]+|firebase(-admin|-functions)?|@react-native-firebase/[a-z-]+|electron)"[[:space:]]*:' {} +
find . -maxdepth 3 -not -path '*/node_modules/*' \( -name 'requirements*.txt' -o -name pyproject.toml -o -name Pipfile \) \
  -exec grep -ilE "^[[:space:]]*[\"']?(django|djangorestframework)" {} +
grep -lE "^[[:space:]]*gem ['\"]rails['\"]" Gemfile 2>/dev/null
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
