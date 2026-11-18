# Python Startup Hooks and Release-Shape Anomalies

Companion to `dependency-audit` Step 4. Covers three checks a lockfile-and-CVE audit misses for Python:

1. **startup hooks**: `.pth` import lines, `sitecustomize.py`, `usercustomize.py`
2. **release shape** of a version bump: what the new release ships compared with the ones before it
3. the **exposure window** of a floor-only range, and what to do when a known-bad version was installed

## Worked example: `agent-framework` 1.26.1 and 1.26.2 (2026-11-17)

Checked 2026-11-18 against Wiz, Socket and Aikido (links below) and the PyPI JSON API. Vendor research, reported, not re-verified. No CVE.

- Two malicious releases of Microsoft's `agent-framework` meta-package went to PyPI on 2026-11-17: 1.26.1 at 20:35 UTC and 1.26.2 at 21:08 UTC, 33 minutes apart. Aikido says both were gone by 21:20 UTC. Wiz says both were unavailable by 21:30 UTC.
- The last safe version is 1.26.0. On PyPI it has a wheel and an sdist, uploaded 2026-11-12. Wiz's timeline says it was published alongside `agent-framework-core` 1.26.0. The affected-files table in Wiz's post lists only a wheel for each bad version. PyPI now returns 404 for 1.26.1.
- Each bad version drops a `.pth` file in the root of `site-packages`: `agent_framework_meta.pth` (1.26.1) and `af_runtime_diag.pth` (1.26.2). In 1.26.2 that file imports a new top-level module, `af_runtime_diag.py`. Python runs a `.pth` import line on every interpreter start, so the payload runs whenever Python starts in that environment, even if nothing imports `agent-framework`.
- What it collects, as reported: env vars with credential-like names, other processes' environments from `/proc/<pid>/environ`, credential files (Azure CLI, npm, pip, netrc, git, Docker, Hugging Face, Azure DevOps agent), `.env` files, Azure DevOps OIDC tokens, Azure managed-identity tokens and instance metadata. 1.26.2 also requests GitHub Actions OIDC tokens in workflows with `id-token: write`. All of it is POSTed to a `webhook[.]site` URL.
- Aikido notes that a loose requirement such as `agent-framework>=1.26` picks up a bad release on the next install.
- Root cause is not confirmed. Wiz says the attacker "appears to have compromised" a client certificate and key for Microsoft's ESRP publishing service, and that how the credentials were obtained "is not yet known".

Hashes and the full webhook URL are in the Wiz and Socket posts. Don't copy them into findings unless you're matching them.

## 1. Startup hooks

`site` runs a `.pth` line that starts with `import ` or `import<TAB>` (no leading whitespace) at every interpreter start. Other lines are path entries. `sitecustomize` and `usercustomize` are imported at start if they're on `sys.path`. Check the project venv, CI images and the runner's Python without starting that interpreter, since starting it runs the hooks:

```bash
# Uses find, not python: starting the interpreter would run the hooks you are looking for.
for root in .venv venv "$VIRTUAL_ENV" /opt /usr/lib /usr/local/lib "$HOME/.local/lib"; do
  [ -n "$root" ] && [ -d "$root" ] || continue
  find "$root" -maxdepth 6 -name '*.pth' -path '*-packages/*' -exec grep -lE '^import[[:blank:]]' {} + 2>/dev/null
  find "$root" -maxdepth 6 \( -name sitecustomize.py -o -name usercustomize.py \) 2>/dev/null
done
```

Add other roots as needed (a macOS framework Python is under `/Library/Frameworks/Python.framework/Versions/`). For a container image, run it against the image's exported filesystem, not inside a running container. Note that `python -S -c 'import site; print(site.getsitepackages())'` does not run hooks, but inside a venv it prints the base interpreter's paths, not the venv's.

**How to read hits:**
- Some importers are normal: editable-install finders (`__editable__.*.pth`, `_<name>_editable.pth`), `distutils-precedence.pth` from setuptools, coverage's startup hook, and a distro `sitecustomize.py` (Debian and Ubuntu ship one).
- A candidate finding is a `.pth` that imports a module named after a package you didn't expect, or one that a package added in its latest version. Open the imported module and look for network calls, env reads, `/proc` reads, `exec` or `base64`.
- For a lockfile diff, list the new wheel's top-level entries and compare with the previous version: `unzip -Z1 pkg-X.Y.Z-*.whl | grep -v /`. A new top-level `.pth` or `.py` is a candidate finding. A single-module package such as `six.py` is normal when the prior release had it too.

## 2. Release shape on a version bump

When a Python dependency bump lands, mark it `needs_validation` when the new version:
- is wheel-only, while prior releases shipped a wheel and an sdist. Check `https://pypi.org/pypi/<pkg>/<version>/json` and compare `urls[].packagetype` with the previous version;
- has no matching git tag or GitHub release in the upstream repo the project page links;
- adds top-level files outside the package directory (`*.pth`, a new top-level `.py`);
- is out of step with its sibling packages, when they normally release together (a meta-package and its `-core` at the same version).

None of these proves compromise. Each is a reason to hold the bump and read the diff before it ships. A version yanked or removed from PyPI soon after release is a stronger signal: check whether any lockfile, cache or image resolved it.

## 3. Exposure window and remediation

- Note in the report every Python requirement that is a floor-only range (`>=`, no upper bound and no lockfile) for a package that runs code at install or start. Such a range installs whatever is newest, including a bad release live for an hour. The fix is a hash-pinned lockfile (`uv lock`, `pip-compile --generate-hashes`, `poetry lock`) installed with hash checking, plus a cooldown before taking new releases where the tool supports it.
- If a known-bad version was installed: uninstall it, delete the dropped `.pth` and module from `site-packages`, rebuild the venv or image, and pin the last safe version. Then **rotate every credential that user, runner or container could read** (env vars, credential files, `.env`, cloud and OIDC-federated access, registry and git tokens), not only the ones the project uses. Upgrading or uninstalling stops the next run. It does not undo data already sent.
- Search CI logs, caches, built images and proxy or DNS logs for the bad version and the reported exfil host. Review cloud sign-in logs for the identities those hosts could reach. Incident handling beyond that goes to `incident-triage`, and the secrets inventory to `secrets-audit`.

## Sources

- Wiz, "Malicious version of Microsoft's agent-framework published to PyPI": https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
- Socket, "agent-framework PyPI package compromised with credential stealer": https://socket.dev/blog/agent-framework-pypi-package-compromised-with-credential-stealer
- Aikido, "Two malicious agent-framework releases hit PyPI in 33 minutes": https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes
- Python docs, `site` module (`.pth` handling, `sitecustomize`, `usercustomize`): https://docs.python.org/3/library/site.html
