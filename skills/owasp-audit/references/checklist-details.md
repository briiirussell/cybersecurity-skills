# OWASP Audit — Checklist Details

Long tables, payload sets, and code idioms moved out of `owasp-audit` SKILL.md to keep it under the line cap. Each
section is linked from the checklist item it supports.

## A05: Rails JSON-LD idiom

Inside `<script type="application/ld+json">`, do NOT use `j` / `escape_javascript` for field values. `j` emits `\'`
and `\$`, which are valid JS but invalid JSON, so `JSON.parse` fails on any field containing an apostrophe or `$`. Use
this instead:

```erb
<% schema = { "@context" => "https://schema.org",
              "@type" => "Article",
              "headline" => @post.title } %>
<script type="application/ld+json">
<%= json_escape(schema.to_json).html_safe %>
</script>
```

`to_json` handles JSON escaping; `json_escape` covers `<>&  ` against `</script>` breakout. Verify with a
round-trip: `JSON.parse(json_escape(article.to_json))` equals the source hash.

## A06: Configured-but-not-loaded check

Before declaring a security middleware (rate-limit, auth, CSRF, throttle) "already configured," verify the package is
actually installed, not just that the initializer exists. Initializers wrapped in `if defined? Foo` /
`if PACKAGE in sys.modules` silently no-op when the package isn't bundled.

| Stack | Check |
|---|---|
| Ruby/Rails | `grep -E "^    GEM_NAME " Gemfile.lock` (4-space indent = top-level gems) |
| Node | `grep "\"PACKAGE_NAME\":" package-lock.json` or `node -e "require('PACKAGE_NAME')"` |
| Python | `pip show PACKAGE_NAME` |
| Go | `grep PACKAGE_PATH go.sum` |

For Rails, also verify the middleware is in the runtime stack: `bundle exec rails middleware | grep -i FOO`.

## A02: Security header baseline (for fixes and hardening notes)

Missing headers are **hardening notes** unless you trace an impact (see SKILL.md A02). When recommending values,
start here and tune:

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload`. Preload requires verifying every `*.example.com` serves HTTPS first |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` (defence-in-depth alongside CSP `frame-ancestors`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), browsing-topics=()`. `interest-cohort` is the legacy FLoC name (Chrome ≤ 100); current Chrome uses `browsing-topics` |
| `Content-Security-Policy` | Start with `frame-ancestors 'self'`. A full CSP needs a per-site script audit (inline `<style>`, JSON-LD, analytics) |

HSTS preload submission is sticky; removal takes months. Verify before submitting.

Where security headers live, by framework:
- Next.js: `next.config.{js,ts}` `headers()` block; `vercel.json` `headers`
- Rails: `config/initializers/secure_headers.rb`, `config/application.rb`
- Express: `app.use(helmet())`
- Django: `SECURE_*` settings in `settings.py`

Config only tells you what the app intends to send. Proxies, CDNs, and platform defaults add, strip, and merge
headers. The deployed header set is a `needs_validation` item with an owner-run `curl -sI https://<origin>/<path>`
check unless you actually ran it against an origin you're authorized to probe.

## A02: Rails admin-engine mounts

```bash
grep -E "mount .+::(Engine|Web|UI)|mount .+::App" config/routes.rb
grep -rn "Rails.env.production?" config/initializers/ | \
  grep -B1 -A5 "Auth::Basic\|authenticate\|secure_compare"
```

The README examples for PgHero, Sidekiq::Web, Flipper, and Mission Control all wrap auth in `if Rails.env.production?`,
which leaves staging, review apps, and preview deploys serving the admin UI anonymously. Fix: switch the guard to
`unless Rails.env.local?` (Rails 7.1+ helper for `development || test`), and add a fail-closed check that refuses
access when the auth env vars are unset.

## A01: SSRF allow-list bypass set

A real allow-list must reject **all** of these:

- Wrong scheme: `http://allowed.com/` (when only `https:` is expected)
- Embedded credentials: `https://user:pass@allowed.com/`
- `@`-host trick: `https://allowed.com@evil.com/` (hostname resolves to `evil.com`)
- Non-default ports: `https://allowed.com:8443/`
- Punycode/IDN spoof: `https://аllowed.com/` (Cyrillic а) or `xn--llowed-pdc.com`
- Trailing dot: `https://allowed.com./` (DNS-equivalent, often missed by string compare)
- Subdomain confusion: `https://allowed.com.evil.com/`
- Bracketed IPv6 literal: `https://[::1]/`
- Bare IPv4: `https://127.0.0.1/`
- Decimal-integer IPv4: `http://2130706433/` → 127.0.0.1
- Hex IPv4: `http://0x7f000001/`
- Octal IPv4: `http://0177.0.0.1/`; zero-padded `0010.0.0.1/` → 8.0.0.1 (octal!)
- IPv4-mapped IPv6: `http://[::ffff:127.0.0.1]/`. Block the whole `::ffff:*` range
- Trailing-dot hostname: `http://localhost./`, `http://metadata.google.internal./`
- Cloud metadata endpoints: AWS `169.254.169.254`, GCP `metadata.google.internal`, ECS `169.254.170.2`
- CGNAT range: `100.64.0.0` – `100.127.255.255`
- Link-local IPv6: `fe80::/10`; unique-local IPv6: `fc00::/7`

## Fix verification: XSS / sanitizer payload set

Run each through the configured sanitizer policy and confirm it's neutralized:

```
<img src=x onerror=alert(1)>
<a href="javascript:alert(1)">x</a>
<a href="data:text/html,<svg onload=alert(1)>">x</a>
<img srcset="javascript:alert(1) 1x,https://ok.com/a.png 2x">
<svg><script>alert(1)</script></svg>
<math><mtext></style><img src=x onerror=alert(1)></math>
<a href="//evil.com">protocol-relative</a>
<svg></svg><img/onerror=alert(1) src=x>
```
