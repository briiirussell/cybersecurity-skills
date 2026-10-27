# Architecture — notes-api (examples/target)

Recon for the owasp-audit run of 2026-10-26. Paths are relative to `examples/target/`, treated as the repo root.
No git history is available for this directory, so no audit commit is recorded.

## Product & stack

A small JSON notes API. Users sign up, log in, get a JWT, and create, list, search, read, edit and delete notes.
`POST /api/preview` fetches a URL and returns its `<title>`. `/api/admin/*` lists and deletes users.

- Node.js, CommonJS, Express 4.17.1 (`package.json:13`)
- SQLite via better-sqlite3 9.4.3, file path from `DATABASE_PATH` (`src/db.js:4`)
- jsonwebtoken 8.5.1 (HS256 by default), axios 0.21.0, lodash 4.17.15
- No frontend in the repo. Responses are JSON only (`res.json`), except `/healthz` (`res.send("ok")`).

## Build/run

`npm start` → `node src/app.js` (`package.json:8`). No tests, no CI config, no Dockerfile. **Nothing was run**: this is
a static, read-only review. `npm audit` was not run because it needs network access, which was out of scope.

## Principals & controls

| Principal | Can reach | Control | Location |
|---|---|---|---|
| Anonymous internet client | `/api/users/signup`, `/api/users/login`, `/healthz`, the JSON parser and query parser on every route | none (by design) | `src/app.js:5-12` |
| Signed-in user (open signup) | `/api/notes/*`, `/api/preview` | `requireAuth`: Bearer JWT, `jwt.verify` with `config.jwtSecret` | `src/auth.js:22-33`; mounted `src/routes/notes.js:7`, `src/routes/preview.js:8` |
| Another user's data (the boundary) | — | per-query `owner_id = req.user.id` predicates | `src/routes/notes.js:15,22,41,50` |
| Admin | `/api/admin/*` | `requireAuth` then `requireAdmin` (role read from the DB, not the token) | `src/auth.js:35-39`; mounted `src/routes/admin.js:6` |

There is no route that grants the admin role; it is set out of band in the database.

## Entry surfaces

- Anonymous: `POST /api/users/signup` (`src/routes/users.js:7`), `POST /api/users/login` (`src/routes/users.js:15`),
  `GET /healthz` (`src/app.js:12`), global middleware (`express.json`, Express query parser), global error handler (`src/app.js:15`)
- User: `GET /api/notes` (`notes.js:12`), `GET /api/notes/search` (`notes.js:20`), `GET /api/notes/:id` (`notes.js:27`),
  `POST /api/notes` (`notes.js:33`), `PATCH /api/notes/:id` (`notes.js:40`), `DELETE /api/notes/:id` (`notes.js:49`),
  `POST /api/preview` (`preview.js:8`)
- Admin: `GET /api/admin/users` (`admin.js:8`), `DELETE /api/admin/users/:id` (`admin.js:12`)
- No webhooks, jobs, cron, uploads, WebSockets or CLI entrypoints.

## Trust boundaries

1. Internet → app (anonymous): signup, login, parsers, error handler
2. User A → user B's notes (ownership)
3. User → admin (role)
4. App → network the server can reach (outbound HTTP from `/api/preview`)
5. Deploy environment → app (`JWT_SECRET` and other env read in `src/config.js`)

## Sinks

- SQL: `db.prepare(...)` in every route; two are template-literal built (`notes.js:15` ORDER BY, `notes.js:22` search)
- Object merge of request body into a DB row: `_.merge(note, req.body)` (`notes.js:43`)
- Outbound HTTP: `axios.get(url)` (`preview.js:12`)
- Token minting / verification: `jwt.sign` (`auth.js:18`), `jwt.verify` (`auth.js:27`)
- Error output to clients: `res.status(500).json({ error, stack })` (`app.js:17`); logs: `console.error(err)` (`app.js:16`)
- No HTML rendering, shell, filesystem writes (other than the SQLite file), email or paid third-party calls.

## Deployed vs local

Nothing about the deployment is in the repo: no proxy, CDN, WAF, platform config or egress policy. `.env.example`
mentions S3 backups, which suggests AWS, but no backup code exists. Facts that live outside the code and become
`needs_validation` blockers: whether `JWT_SECRET` is set in production (the code falls back to `"changeme"`), whether
an edge rate limit exists on login, whether TLS terminates in front of the plain-HTTP `app.listen` (`src/app.js:20`), whether an egress proxy exists, what the server can reach on its network, and the advisory status of the pinned
dependency versions (needs `npm audit`, which needs network).

## Out of scope

- Any frontend that renders note titles/bodies or preview titles: not in the repo.
- Running the app, dynamic testing, `npm install` / `npm audit`: excluded by the engagement (static, no network).
- Dependency source code (`node_modules` is not vendored): not readable in this run; library-behaviour claims are
  `needs_validation`, not rejected.
- Full secrets sweep and full dependency CVE triage: handed to `secrets-audit` and `dependency-audit`.
