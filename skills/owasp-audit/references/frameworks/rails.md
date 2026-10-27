# Rails playbook

Load this during an `owasp-audit` run when recon detects Rails ([detection signals](README.md)). Rails gives you
strong parameters, CSRF protection, escaped ERB, and parameterized Active Record queries by default. Findings come
from the places code opts out: `permit!`, `Model.find(params[:id])` without a scope, interpolated SQL strings,
`html_safe`, and controllers that skip the authorization callback.

The main checklist already covers Rails admin-engine mounts (A02), ERB sinks and JSON-LD (A05), and Devise
`:validatable` (A07). This playbook adds the controller and model checks.

Findings use the normal OWASP Top 10:2025 categories, verdicts, and `findings.json` format. Fingerprints name the
controller action or model: `owasp-audit/CWE-639/app/controllers/invoices_controller.rb/show`.

## Add these surfaces to the ledger

| Surface | How to enumerate |
|---|---|
| Each route → controller action, including non-resource routes and `member` / `collection` actions | `bin/rails routes` (if it runs) or `config/routes.rb` |
| Each `*_params` method and every other use of `params` in a write | `app/controllers/**` |
| Authorization layer: Pundit, CanCanCan, Action Policy, or hand-rolled `before_action` | `app/policies/**`, `app/models/ability.rb`, `ApplicationController` |
| API-only controllers (`ActionController::API`), GraphQL mutations, Action Cable channels, jobs that take ids | `app/controllers/api/**`, `app/graphql/**`, `app/channels/**`, `app/jobs/**` |

```bash
rg -n "^\s*(get|post|put|patch|delete|resources?|member|collection|mount|namespace)\b" config/routes.rb
rg -n "before_action|skip_before_action|after_action :verify_(authorized|policy_scoped)|load_and_authorize_resource|authorize\b|policy_scope" app/controllers
rg -n "def \w+_params" -A4 app/controllers
```

## Checks

### 1. Unscoped finds: IDOR (A01)

**Look for:** a record loaded by a user-supplied id without going through the current user's or tenant's scope:
- `Model.find(params[:id])`, `Model.find_by(id: params[:id])`, `Model.where(id: params[:...])` in a controller whose
  resource belongs to a user or account. The scoped form is `current_user.invoices.find(params[:id])` or
  `Current.account.invoices.find(...)`, or a policy scope
- Pundit apps where an action never calls `authorize` and `ApplicationController` has no
  `after_action :verify_authorized` (or skips it with `skip_after_action`) for that controller
- CanCanCan `load_and_authorize_resource` with `only:` / `except:` that leaves out a custom action
- A `set_<resource>` `before_action` that scopes correctly, plus a custom action that does its own unscoped `find`
- Foreign keys from params (`project_id`, `account_id`) stored on a record with no check that the caller owns the
  referenced record
- Jobs (`perform_later(id)`) and Action Cable channels (`stream_from "room_#{params[:room]}"`) that accept an id and
  never check it

**Find candidates:**

```bash
rg -n "\b[A-Z]\w+\.(find|find_by|find_by!|where)\(\s*(id:\s*)?params\[" app/controllers app/graphql app/channels
rg -n "stream_from .*params|stream_for .*params" app/channels
# portable
grep -rnE "[A-Z][A-Za-z]+\.(find|find_by|where)\( *(id: *)?params\[" app/controllers
```

**Verify:** confirmed when a user from another account can reach the action and the record isn't scoped or authorized
before it's read or changed. Default scopes and `acts_as_tenant`-style gems are real controls only if they're active
on that model in that request (check that the tenant is set before the action runs). Rejected when the find goes
through an association of the current user/account, or `authorize @record` runs on every path before use; name the
line.

### 2. Strong parameters opted out or too broad (A08, A01)

**Look for:**
- `params.permit!`, `params.require(:x).permit!`, `params.to_unsafe_h`, `to_unsafe_hash`. These mark everything as
  permitted, so any column (`role`, `admin`, `account_id`, `confirmed_at`) is writable
- `permit` lists that include privilege or ownership attributes: `:role`, `:admin`, `:account_id`, `:user_id`,
  `:verified`, `:plan`, `:credits`, or nested `*_attributes` for associations the user shouldn't edit
- A permit list shared between a user-facing and an admin controller
- `update(params[:user])` style calls that would raise `ForbiddenAttributesError` and were "fixed" with `permit!`
- Rails 8's `params.expect(user: [...])` is the same allowlist in a stricter wrapper; review its list the same way

**Find candidates:**

```bash
rg -n "permit!|to_unsafe_h|to_unsafe_hash" app/
rg -n "\.permit\(|params\.expect\(" -A3 app/controllers | rg -n ":(role|admin|is_admin|account_id|user_id|owner_id|organization_id|verified|confirmed_at|plan|credits|balance)\b"
```

**Verify:** confirmed when a lower-trust user can submit the attribute and it reaches `create` / `update` on a model where
it changes privileges, ownership, or another tenant's data. Category A08 (CWE-915), or A01 when the attribute is an
ownership or tenant key. Rejected when the attribute is dropped by the permit list, overwritten from `current_user`
before save, or protected by a model-level guard that runs on every save; name the line.

### 3. Raw SQL and interpolated queries (A05)

**Look for:** string interpolation or concatenation into SQL:
- `where("email = '#{params[:email]}'")`, `where("name LIKE '%#{q}%'")`, `having(...)`, `joins("... #{x}")`,
  `group(...)` with a string built from input
- `order(params[:sort])` / `reorder(...)` with a raw param. Recent Rails rejects many non-attribute strings unless
  wrapped in `Arel.sql`, so look for `Arel.sql(params[...])` too. Map sort keys through an allowlist
- `find_by_sql`, `select_all`, `connection.execute`, `exec_query` with interpolated strings
- `sanitize_sql_like` missing on `LIKE` input (wildcard injection, usually low impact)

The safe forms are hash conditions (`where(email: params[:email])`) and placeholders (`where("email = ?", value)`).

```bash
rg -n "(where|having|joins|group|order|reorder|pluck|select|from|find_by_sql|execute|exec_query|select_all)\(\s*\"[^\"]*#\{" app/ lib/
rg -n "Arel\.sql\(.*params|order\(\s*params|reorder\(\s*params" app/ lib/
# portable
grep -rnE "(where|order|find_by_sql|execute)\( *\"[^\"]*#\{" app lib
```

**Verify:** confirmed with a trace from `params` to the interpolated fragment. Rejected when the interpolated value is a
constant, an integer cast (`Integer(params[:id])`), or comes from a fixed allowlist hash; name the line. Brakeman flags
most of these and is a good second source.

### 4. Output escaping and other dangerous sinks (A05, A01, A08)

**Look for:**
- `html_safe`, `raw(...)`, `<%==`, `render html: ... .html_safe`, and permissive `sanitize(..., tags:, attributes:)`
  on user content. Details and the JSON-LD idiom are in the main checklist (A05)
- `render inline:` or `ERB.new(...)` with user-controlled template text (template injection, A05)
- `link_to` / `href` with a user-supplied URL: Rails escapes the attribute but not the scheme, so `javascript:` URLs
  survive. Allow only `http(s):`
- `redirect_to params[:return_to]` (open redirect, A01). Rails 7.0+ raises on off-host redirects when
  `raise_on_open_redirects` is on (the default for apps that load 7.0 defaults); check that it's on and not bypassed
  with `allow_other_host: true`
- `send_file` / `send_data` with a path built from params (path traversal, A01)
- `constantize`, `safe_constantize`, `public_send(params[...])`, `send(params[...])` (A05)
- `YAML.load` (instead of `YAML.safe_load`), `Marshal.load`, or `Oj.load` on request data or cookies (A08)
- `skip_forgery_protection`, `protect_from_forgery with: :null_session`, or `skip_before_action :verify_authenticity_token`
  on controllers that authenticate by cookie (A01)

```bash
rg -n "html_safe|raw\(|<%==|render (inline|html):|ERB\.new" app/
rg -n "redirect_to\s+params|allow_other_host:\s*true|raise_on_open_redirects|send_file\s*\(?\s*params" app/ config/
rg -n "constantize|public_send\(params|\.send\(params|YAML\.load\(|Marshal\.load|Oj\.load" app/ lib/
rg -n "skip_forgery_protection|null_session|skip_before_action :verify_authenticity_token" app/controllers
```

**Verify:** each sink needs the usual trace from a lower-trust principal's input. A CSRF skip is confirmed only on a
state-changing action that authenticates with a session cookie.

### 5. Secrets and environment config (A04, A02)

**Look for:** the Rails master key or a per-environment credentials key tracked in the repo (the `.key` files under
`config/`), `secret_key_base` hard-coded in a YAML file or an initializer, and production config with
`config.consider_all_requests_local = true` or `config.force_ssl` off. Once `secret_key_base` is exposed, signed and
encrypted cookies can't be trusted; hand rotation to `secrets-audit`.

```bash
git ls-files config | rg "master\.key|credentials/.*\.key$"
rg -n "secret_key_base\s*[:=]\s*['\"]" config/
rg -n "consider_all_requests_local\s*=\s*true|force_ssl\s*=\s*false" config/environments/production.rb
```

## Worked examples

**Confirmed (A01).** `app/controllers/invoices_controller.rb`: `before_action :set_invoice` with
`@invoice = Invoice.find(params[:id])` at line 41. `ApplicationController` authenticates with Devise but the app has
no Pundit or CanCanCan, and `show`, `update`, and `destroy` use `@invoice` directly. Any signed-in user of any account
can view, edit, or delete any invoice by id.

```json
{
  "fingerprint": "owasp-audit/CWE-639/app/controllers/invoices_controller.rb/set_invoice",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-639", "confidence": "medium",
  "counterevidence": "no default_scope on Invoice, no acts_as_tenant, no authorize calls anywhere in the controller; authenticate_user! only checks sign-in",
  "severity": { "likelihood": { "score": "high", "reason": "integer ids; any account holder" },
                "impact": { "score": "high", "reason": "read and modify other accounts' invoices" }, "overall": "high" }
}
```

**Rejected (A08).** `permit!` in `app/controllers/admin/settings_controller.rb` was flagged as mass assignment. The
controller inherits from `Admin::BaseController`, whose `before_action :require_super_admin` at line 5 halts every
request from non-super-admins, and the permitted hash writes only to the `SiteSetting` key-value table, which super
admins can already change in full.

```json
{
  "fingerprint": "owasp-audit/CWE-915/app/controllers/admin/settings_controller.rb/update",
  "verdict": "rejected", "owasp_category": "A08:2025", "confidence": "high",
  "counterevidence": "permit! does allow any key, but only super admins reach the action and they already hold full write access to SiteSetting",
  "ruled_out_by": { "control": "require_super_admin before_action halts every request from lower roles",
                    "location": { "file": "app/controllers/admin/base_controller.rb", "line": 5 } }
}
```

Both are abridged; see [findings-format.md](../findings-format.md) for the full record shape. The `permit!` can still
be a hardening note.

## Sources

Paraphrased, not copied:

- Rails Guides: [Securing Rails Applications](https://guides.rubyonrails.org/security.html) (CC BY-SA 4.0),
  [Action Controller Overview: strong parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- OWASP Cheat Sheet Series (CC BY-SA 4.0): [Ruby on Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html),
  [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- Sentry skills (Apache-2.0): [django-access-review](https://github.com/getsentry/skills/tree/main/skills/django-access-review)
  (the "can user A reach user B's record" trace, applied here to Active Record)
- [Brakeman warning types](https://brakemanscanner.org/docs/warning_types/) (which sinks a Rails static scanner treats as
  candidates)
