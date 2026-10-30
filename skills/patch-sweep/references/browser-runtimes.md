# Browser Runtimes in a Sweep

Companion to `patch-sweep`, for an advisory set that includes a Chrome or Chromium CVE. The usual sweep maps repos to
deployed apps. A Chromium advisory also hits browsers that agents and test suites download, which the usual map never
lists:

1. **Developer and operator machines.** Playwright, Puppeteer and agent-browser caches, which never update on their own.
2. **Repos whose lockfile pins `playwright`, `@playwright/test` or `puppeteer`.** Every `npm ci` plus browser install
   downloads the *pinned* Chromium again, on laptops and in CI.
3. **CI runners and images:** `mcr.microsoft.com/playwright:v1.x-…`, `ghcr.io/puppeteer/puppeteer`,
   `browserless/chrome`, and steps like `npx playwright install --with-deps`.
4. **Deployed services that run a headless browser in production:** PDF and OG-image generation, scrapers, screenshot
   services (`@sparticuz/chromium` on Lambda or Vercel, Puppeteer in a Docker service). These load
   attacker-influenced HTML **on the server**, so a renderer RCE becomes a server RCE.

## Step 1 — Inventory browser runtimes

**Repos that pin a browser** (the production branch's lockfile, as in Step 4):

```bash
rg -n --glob '**/{package-lock.json,pnpm-lock.yaml,yarn.lock}' \
  -e '"node_modules/(playwright|playwright-core|@playwright/test|puppeteer|puppeteer-core|@sparticuz/chromium|chrome-aws-lambda)"' \
  -e '^\s*/?(playwright|playwright-core|@playwright/test|puppeteer|puppeteer-core|@sparticuz/chromium)@' .
```

Map each package version to its Chromium:

- **Playwright:** each release's notes list its browser versions. `npx playwright@<version> install --dry-run chromium`
  prints the revision and download location without installing (it downloads that Playwright version to run it, so it
  prompts).
- **Puppeteer:** pins one Chrome per release, in `packages/puppeteer-core/src/revisions.ts` (`PUPPETEER_REVISIONS.chrome`)
  at that release's tag.
- **`@sparticuz/chromium`:** majors track Chromium majors.

**CI:**

```bash
rg -n -e 'mcr\.microsoft\.com/playwright' -e 'ghcr\.io/puppeteer' -e 'browserless/chrom' \
      -e 'playwright install' -e 'puppeteer browsers install' -e 'setup-chrome' \
      .github/workflows Dockerfile* docker-compose*.yml .gitlab-ci.yml 2>/dev/null
```

An image tag like `mcr.microsoft.com/playwright:v1.49.0-noble` fixes the Chromium major. Treat it like a runtime pin.

**Deployed headless browsers.** Check the **production** dependency tree, not dev:

```bash
npm ls --omit=dev puppeteer puppeteer-core playwright playwright-core @sparticuz/chromium 2>/dev/null
```

A hit means the app renders HTML in Chromium on the server. Those rows go first.

**Operator machines.** For each person in scope who runs agents, use `personal-opsec` C7's inventory (cached builds and
versions), or ask them to run it and report back. These rows are owner actions: the sweep can't touch other people's
laptops.

## Step 4 — Is each runtime affected?

The usual three-part test, mapped:

| Part | For a browser runtime |
|---|---|
| Vulnerable version | Chromium major and build below the advisory's fixed version |
| Component present | The binary is on disk, in the image, or in the deployed bundle |
| Code path used | **Platform** (a macOS-only bug doesn't affect Linux CI or Lambda), **what it loads** (untrusted URLs or HTML, or only its own previews), and **launch context** (an app holding Accessibility, for permission-inheritance bugs) |

Special cases:

- **Platform-specific CVEs.** A macOS GPU or WindowServer bug is `not affected (platform)` on Linux CI and serverless.
  **The same Chrome release fixes other bugs too,** usually renderer ones that do affect Linux. Read the full release
  notes for the fixed version, not just the headline CVE.
- **Server-side renderers load untrusted content** whenever any user input reaches the HTML: invoice templates, OG
  images with user titles, "screenshot this URL". Severity follows the server's blast radius.
- **`--no-sandbox` / `--disable-gpu-sandbox`** in launch arguments (common in Docker and Lambda configs) remove the
  sandbox, so any renderer bug becomes a full compromise of that process's user. Grep for them and flag them whatever
  the version:
  ```bash
  rg -n -e '--no-sandbox' -e '--disable-gpu-sandbox' -e '--disable-setuid-sandbox' --glob '!**/node_modules/**' .
  ```

## Step 6 — Patch each runtime

| Asset | Patch |
|---|---|
| Repo pins `playwright` / `@playwright/test` | Bump to a release that bundles the fixed Chromium, `npx playwright install chromium`, run the e2e suite (selectors and screenshots can shift between majors) |
| Repo pins `puppeteer` | Bump, then `npx puppeteer browsers install chrome` |
| `@sparticuz/chromium` | Bump to the major that matches the fixed Chromium; check the Lambda layer or function size limit |
| CI image | Bump the tag **and pin it by digest** (`scanner-pipeline`'s image policy) |
| Operator machine | The tool's updater (`personal-opsec` local checks), delete old builds, **restart running sessions**, since the old binary stays in memory |

## Board

```markdown
## Browser runtimes

| asset | kind | platform | chromium old→new | loads untrusted? | launched w/ Accessibility? | status | owner action |
|---|---|---|---|---|---|---|---|
| acme/pdf-service | puppeteer 22 (prod) | linux/docker | 124→156 | **yes (user HTML)** | n/a | PR #12 | uses --no-sandbox: remove |
| operator-laptop | agent-browser | macOS | 149→156 | yes (research) | yes (Terminal) | owner action | update + restart sessions |
| acme/site | @playwright/test 1.49 (dev, e2e) | linux CI | 131→156 | no (own previews) | n/a | PR #88 | — |
```

Sort: production server-side renderers that load user input, then operator machines with Accessibility and untrusted
browsing, then CI, then dev-only e2e.

## Prevention

- Dependabot or Renovate groups for `playwright`, `puppeteer` and `@sparticuz/chromium`, so a browser bump isn't held
  back by unrelated e2e churn.
- A weekly check in `scanner-pipeline`'s schedule that the bundled Chromium major in CI images is at least stable − 1.
- For operators: a monthly reminder to run the browser tool's updater.

## Sources

- Playwright CLI (`install --dry-run`, `uninstall --all`), checked in `packages/playwright-core/src/cli/program.ts` on
  2026-10-30; Puppeteer `revisions.ts` (`PUPPETEER_REVISIONS`)
- Chrome for Testing availability JSON; Chrome Releases blog for each release's full CVE list
- Proposed by @coreyhaines31 in issue #219, prompted by CVE-2026-106378
