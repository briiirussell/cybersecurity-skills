# Django playbook

Load this during an `owasp-audit` run when recon detects Django ([detection signals](README.md)). Django's defaults
are good (auto-escaping templates, CSRF middleware, a parameterized ORM). The bugs live where code steps around them:
querysets that aren't scoped to the user, serializers and forms that accept every field, raw SQL, `mark_safe`, and
settings that differ between dev and production.

Start the way Sentry's access review does: before looking for bugs, find out how this codebase does authorization
(base views, mixins, DRF permission classes, custom managers, tenant middleware). Then trace each endpoint against
that model. A pattern match isn't a finding until you've followed it to the query.

Findings use the normal OWASP Top 10:2025 categories, verdicts, and `findings.json` format. Fingerprints name the
view, serializer, or setting: `owasp-audit/CWE-639/api/views.py/DocumentViewSet`.

## Add these surfaces to the ledger

| Surface | How to enumerate |
|---|---|
| Each URL pattern → view (function view, class-based view, DRF ViewSet and each `@action`) | `urls.py` files, `router.register(` |
| Each serializer and `ModelForm` that writes | `serializers.py`, `forms.py` |
| Admin (`ModelAdmin` classes, custom admin views and actions) | `admin.py` |
| Channels consumers, Celery tasks that take ids | `consumers.py`, `tasks.py` |
| Settings per environment | `settings.py`, `settings/*.py`, `.env.example` |

```bash
rg -n "path\(|re_path\(|router\.register\(" -g 'urls.py'
rg -n "class \w+\((.*ViewSet|.*APIView|.*View|.*Mixin)" -g '*.py'
rg -n "permission_classes|DEFAULT_PERMISSION_CLASSES|@login_required|@permission_required|LoginRequiredMixin" -g '*.py'
rg -n "def get_queryset|def get_object|def has_object_permission|class \w+Manager" -g '*.py'
```

## Checks

### 1. Object-level access and unscoped querysets (A01)

**Look for:**
- A view or ViewSet whose `get_queryset()` returns `Model.objects.all()` (or a `queryset = Model.objects.all()`
  attribute) while the permission class only checks login. Any signed-in user can read, change, or delete any row by id
- `Model.objects.get(pk=pk)` / `get_object_or_404(Model, pk=pk)` in a function view with no owner or tenant filter
- DRF's `has_object_permission` relied on where it never runs: it's called by `get_object()`, not on `list`, and not
  in custom code that queries directly
- `DEFAULT_PERMISSION_CLASSES` unset (DRF's default is `AllowAny`) and views that don't set `permission_classes`
- A ViewSet that protects the standard actions but has an `@action(detail=True)` with its own query, or overrides
  `permission_classes` with something weaker
- Create paths where the owner or org comes from the request (`serializer.save(**request.data)`) instead of
  `serializer.save(owner=request.user)` in `perform_create`
- Celery tasks and Channels consumers that receive an id and load it without re-checking who asked

**Find candidates:**

```bash
rg -n "objects\.all\(\)|objects\.get\(pk=|get_object_or_404\(\w+,\s*(pk|id)=" -g '*.py' -g '!*/migrations/*' -g '!tests/*'
rg -n "@action\(" -A8 -g '*.py'
rg -n "DEFAULT_PERMISSION_CLASSES" -A3 -g '*.py'
# portable
grep -rnE "objects\.all\(\)|objects\.get\(pk=|get_object_or_404" --include='*.py' . | grep -v /migrations/
```

**Verify:** for each candidate answer "if I'm user A and know the id of user B's object, can I reach it?" Trace the id
from the URL or body to the query. Confirmed when no filter on `request.user` / the user's org sits between them and
no permission class or mixin checks the object. Before rejecting, check parent classes, managers, middleware, and
URL-level decorators, and name the one that holds.

### 2. Mass assignment through serializers and forms (A08, A01)

**Look for:**
- `ModelSerializer` or `ModelForm` with `fields = '__all__'` or an `exclude` list, on a model with `is_staff`,
  `is_superuser`, `role`, `plan`, `balance`, `owner`, or `organization`. New model fields become writable silently
- Sensitive fields missing from `read_only_fields`, or a nested writable serializer that lets the client point a foreign
  key at another tenant's object
- `Model.objects.create(**request.data)`, `.update(**request.POST.dict())`, `setattr` loops over request keys
- `Model.objects.filter(**request.GET.dict())`: the caller picks the lookups, including ones across relations
  (`owner__email__startswith=`), which turns a search box into a data oracle. Django releases before 5.2.8, 5.1.14,
  and 4.2.26 also allowed SQL injection through a crafted `_connector` key in such expansions (CVE-2025-64459)

**Find candidates:**

```bash
rg -n "fields\s*=\s*['\"]__all__['\"]|^\s*exclude\s*=" -g '*.py'
rg -n "\*\*request\.(data|POST|GET|query_params)|\*\*\w+\.(data|validated_data)\b" -g '*.py'
rg -n "read_only_fields" -g '*.py'
```

**Verify:** confirmed when a lower-trust user can set a field that changes their privileges, ownership, or another
tenant's data, traced through the view to `save()`. Category A08 (CWE-915), or A01 when the field is an ownership or
tenant key. Rejected when the field is in `read_only_fields`, not in an explicit `fields` list, or overwritten
server-side in `perform_create` / `perform_update` before save.

### 3. Raw SQL (A05)

**Look for:** user input formatted into SQL with f-strings, `%`, `.format()`, or `+` in `raw()`, `extra()`,
`RawSQL()`, `cursor.execute()`, and `connection.cursor()`. Parameters passed as the second argument
(`cursor.execute(sql, [value])`, `raw(sql, [value])`) are safe; identifiers (column, table, `ORDER BY` field) can't be
parameterized and need an allowlist.

```bash
rg -n "\.raw\(|\.extra\(|RawSQL\(|cursor\(\)|\.execute\(" -g '*.py' -g '!*/migrations/*'
rg -n "(raw|extra|RawSQL|execute)\(\s*f['\"]|(raw|execute)\(.*%\s*\(|(raw|execute)\(.*\.format\(" -g '*.py'
```

**Verify:** confirmed with a trace from request input to the interpolated string. Rejected when the interpolated value
is a constant or comes from a fixed allowlist, named by line.

### 4. Template and HTML output (A05)

**Look for:** `mark_safe(...)` and `|safe` on anything that contains user data, `{% autoescape off %}`,
`format_html()` called with an already-formatted string (which defeats its escaping), `Template(user_string)` (template
injection), and the Jinja2 backend configured without `autoescape`.

```bash
rg -n "mark_safe\(|SafeString\(|\|\s*safe\b|autoescape off|format_html\(\s*f['\"]|Template\(" -g '*.py' -g '*.html'
```

**Verify:** confirmed when user-controlled content reaches the unescaped output in a page another user views.
Rejected when the marked-safe value is built only from constants or already-escaped parts.

### 5. Settings: DEBUG, SECRET_KEY, hosts, cookies, CSRF (A02, A04)

**Look for:**
- `DEBUG = True`, or `DEBUG = os.environ.get('DEBUG', True)` style defaults that turn on when the variable is unset.
  The debug page shows settings, local variables, and SQL
- `SECRET_KEY` committed in the repo, or loaded with a hard-coded fallback (`os.environ.get('SECRET_KEY',
  'django-insecure-...')`). With the key, an attacker can forge signed cookies and values signed with
  `django.core.signing`. Treat a committed key as compromised and hand rotation to `secrets-audit`
- `ALLOWED_HOSTS = ['*']`: password-reset and other absolute links built from the `Host` header can point at an
  attacker's domain
- `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` off in production settings, `CSRF_TRUSTED_ORIGINS` with broad
  wildcards, `@csrf_exempt` on views that use session auth
- `SESSION_SERIALIZER` set to the pickle serializer on old Django versions (removed in 5.0): with a leaked key, that's
  code execution, not just session forgery

```bash
rg -n "^\s*DEBUG\s*=|SECRET_KEY\s*=|ALLOWED_HOSTS\s*=|_COOKIE_SECURE|CSRF_TRUSTED_ORIGINS|SESSION_SERIALIZER" -g '*.py'
rg -n "@csrf_exempt|csrf_exempt\(" -g '*.py'
```

**Verify:** a hard-coded fallback key or debug default is an unsafe shipped default: confirmed, with confidence capped
by whether production sets the variable (see `verification.md`). Which settings module production loads
(`DJANGO_SETTINGS_MODULE`) is often outside the repo; record it as a condition. `@csrf_exempt` is confirmed only on a
cookie-authenticated, state-changing view.

### 6. Version advisories (A03, hand off)

Check the installed Django and DRF against current advisories (`pip-audit`, via `dependency-audit`). Example:
CVE-2025-64459 (SQL injection through `_connector` in `filter()`, `exclude()`, `get()`, and `Q()` with dictionary
expansion), fixed in 5.2.8, 5.1.14, and 4.2.26.

## Worked examples

**Confirmed (A01).** `api/views.py`: `class DocumentViewSet(viewsets.ModelViewSet)` with
`permission_classes = [IsAuthenticated]` and `def get_queryset(self): return Document.objects.all()` at line 22. No
`has_object_permission`, no scoped manager, no tenant middleware. Any signed-in user can `GET`, `PATCH`, or `DELETE`
`/api/documents/<id>/` for any document.

```json
{
  "fingerprint": "owasp-audit/CWE-639/api/views.py/DocumentViewSet",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-639", "confidence": "medium",
  "counterevidence": "checked base classes (ModelViewSet only), DEFAULT_PERMISSION_CLASSES (IsAuthenticated), Document.objects (default manager), middleware (none tenant-related)",
  "severity": { "likelihood": { "score": "high", "reason": "sequential integer ids; open sign-up" },
                "impact": { "score": "high", "reason": "read and modify every user's documents" }, "overall": "high" }
}
```

**Rejected (A08).** `billing/serializers.py` `AccountSerializer` uses `fields = '__all__'` on a model with `plan` and
`credit_balance`. Both are listed in `read_only_fields` at line 14, and the only view that writes through it,
`AccountViewSet.perform_update`, saves with `serializer.save()` and no extra kwargs from the request.

```json
{
  "fingerprint": "owasp-audit/CWE-915/billing/serializers.py/AccountSerializer",
  "verdict": "rejected", "owasp_category": "A08:2025", "confidence": "high",
  "counterevidence": "fields='__all__' would expose plan and credit_balance, but both are read-only; no other serializer writes Account",
  "ruled_out_by": { "control": "read_only_fields excludes plan and credit_balance from writes",
                    "location": { "file": "billing/serializers.py", "line": 14 } }
}
```

Both are abridged; see [findings-format.md](../findings-format.md) for the full record shape. The `fields = '__all__'`
pattern itself can still go in hardening notes: a field added later won't be read-only by default.

## Sources

Paraphrased, not copied:

- Sentry skills (Apache-2.0): [django-access-review](https://github.com/getsentry/skills/tree/main/skills/django-access-review)
  (understand the authorization model first, then trace "can user A reach user B's object" per endpoint; fixes must
  enforce, not document)
- Strix (Apache-2.0): [frameworks/django.md](https://github.com/usestrix/strix/blob/main/strix/skills/frameworks/django.md)
  (DRF permission gaps, serializer mass assignment, raw SQL and template sinks, settings review)
- Django: [Security in Django](https://docs.djangoproject.com/en/stable/topics/security/),
  [Deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/),
  [CVE-2025-64459 release notes](https://www.djangoproject.com/weblog/2025/nov/05/security-releases/)
- Django REST framework: [Permissions](https://www.django-rest-framework.org/api-guide/permissions/)
