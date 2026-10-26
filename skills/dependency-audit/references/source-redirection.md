# Package-Source Redirection, Agent Extensions, and Shipped Bytecode

Companion to `dependency-audit` Steps 1 and 4. Covers three supply-chain surfaces that manifest-and-lockfile audits miss:

1. config that **adds or replaces where packages come from** (registry, index, mirror)
2. **agent extensions** (MCP servers, skills, plugins) that run code fetched at launch, often unpinned
3. **compiled Python bytecode** shipped without matching source

Detection ideas adapted (paraphrased) from NVIDIA SkillSpector's dependency-source-redirection, MCP rug-pull, and supply-chain patterns (Apache-2.0). The greps here are written for this repo.

## 1. Package-source redirection

A changed source means every package name now resolves somewhere else. That's how dependency confusion and registry hijacks work, and a one-line `.npmrc` change in a PR is easy to miss. Check committed config files, CI env, Dockerfiles, and install scripts, since redirection often lives in `ENV` lines or `run:` steps rather than in the config file.

| Ecosystem | Config file / setting | CLI form | Env-var form |
|---|---|---|---|
| npm | `.npmrc`: `registry=`, scoped `@scope:registry=`, `//host/:_authToken` | `npm config set registry ...`, `npm install --registry ...` | `NPM_CONFIG_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_@SCOPE:REGISTRY` |
| pnpm | `.npmrc` (same keys), `pnpm-workspace.yaml` | `pnpm config set registry ...` | same `npm_config_*` vars |
| Yarn v1 | `.yarnrc`: `registry "..."` | `yarn config set registry ...` | `YARN_REGISTRY`, `npm_config_registry` |
| Yarn Berry | `.yarnrc.yml`: `npmRegistryServer`, `npmScopes.<scope>.npmRegistryServer`, `unsafeHttpWhitelist` | `yarn config set npmRegistryServer ...` | `YARN_NPM_REGISTRY_SERVER` |
| pip | `pip.conf` / `pip.ini` / `requirements*.txt`: `index-url`, `extra-index-url`, `--index-url`, `--extra-index-url`, `--trusted-host`, `--find-links` | `pip config set global.index-url ...` | `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`, `PIP_FIND_LINKS` |
| uv | `pyproject.toml` `[[tool.uv.index]]`, `uv.toml` | `uv pip install --index-url / --extra-index-url` | `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL`, `UV_INDEX`, `UV_DEFAULT_INDEX` |
| Poetry | `pyproject.toml` `[[tool.poetry.source]]` (`priority = primary / supplemental / explicit`) | `poetry source add ...` | `POETRY_REPOSITORIES_<NAME>_URL` |
| Maven | `settings.xml` `<mirrors>` / `<mirrorOf>`, `pom.xml` `<repositories>` / `<pluginRepositories>` | `mvn -s custom-settings.xml` | `MAVEN_OPTS`, `MAVEN_ARGS` pointing at a different settings file |
| Gradle | `repositories { maven { url ... } }`, `settings.gradle` `dependencyResolutionManagement`, `init.gradle` | `--init-script` | `GRADLE_USER_HOME` (relocates `init.d` scripts) |
| Cargo | `.cargo/config.toml`: `[source.crates-io] replace-with = ...`, `[source.<name>]`, `[registries.<name>]` | `cargo install --registry / --index` | `CARGO_REGISTRIES_<NAME>_INDEX`, `CARGO_REGISTRY_DEFAULT`, `CARGO_SOURCE_*` |
| Go | `go.env`, `go.mod` `replace` | `go env -w GOPROXY=...` | `GOPROXY`, `GONOSUMDB`, `GOPRIVATE`, `GOINSECURE`, `GOSUMDB=off` |
| RubyGems / Bundler | `Gemfile` `source`, `.gemrc` `:sources:`, `.bundle/config` `BUNDLE_MIRROR__*` | `bundle config set mirror.https://rubygems.org ...` | `BUNDLE_MIRROR__RUBYGEMS__ORG` |
| Composer | `composer.json` `repositories` | `composer config repositories.<name> ...` | `COMPOSER_MIRROR_PATH_REPOS` |
| NuGet | `nuget.config` `<packageSources>` (and missing `<clear/>`) | `dotnet nuget add source ...` | |

```bash
# Config files that set or replace a source
grep -rnE "^\s*(@[^:]+:)?registry\s*=|npmRegistryServer|unsafeHttpWhitelist|^\s*registry\s+\"" \
  --include=".npmrc" --include=".yarnrc" --include=".yarnrc.yml" . 2>/dev/null | grep -v node_modules
grep -rnE "(extra-)?index-url|trusted-host|find-links|\[\[tool\.(poetry\.source|uv\.index)\]\]" \
  --include="pip.conf" --include="pip.ini" --include="requirements*.txt" --include="pyproject.toml" --include="uv.toml" . 2>/dev/null
grep -rnE "<mirror>|<mirrorOf>|<repository>|<pluginRepository>" --include="settings.xml" --include="pom.xml" . 2>/dev/null
grep -rnE "replace-with|^\[source\.|^\[registries\." .cargo/ 2>/dev/null
grep -rnE "<packageSources>|<add key=" --include="nuget.config" --include="NuGet.Config" . 2>/dev/null

# CLI and env-var forms in CI, Dockerfiles, scripts
grep -rnE "(npm|pnpm|yarn|pip|uv|poetry|bundle|composer|dotnet nuget|go env) (config set|source add|config repositories|add source|-w GOPROXY)|--(extra-)?index-url|--registry[ =]|NPM_CONFIG_REGISTRY|npm_config_registry|YARN_(NPM_)?REGISTRY|PIP_(EXTRA_)?INDEX_URL|PIP_TRUSTED_HOST|UV_(EXTRA_)?INDEX|POETRY_REPOSITORIES_|CARGO_REGISTR(Y|IES)_|GOPROXY|GONOSUMDB|GOINSECURE|GOSUMDB=off|BUNDLE_MIRROR" \
  .github/ .gitlab-ci.yml .circleci/ Dockerfile* docker-compose*.y*ml Makefile scripts/ *.sh 2>/dev/null
```

**How to judge a hit:**
- An org's private registry for its own scope (`@acme:registry=https://npm.acme.internal`) is normal. Record it in the inventory, then check the scope is reserved on the public registry too.
- **`extra-index-url` is the dependency-confusion pattern.** pip consults every index and takes the highest version it finds, so a public package with the same name as a private one and a higher version wins. Prefer one `index-url` pointing at a proxy that serves both, or uv's per-index pinning / Poetry `priority = "explicit"` sources bound to specific packages.
- A **default-registry replacement** (`registry=`, `replace-with`, `GOPROXY`, Maven `mirrorOf *`) pointing at a host the org doesn't control, or over plain `http://`, or added in the PR under review, is a candidate finding. Show who controls the host and which builds use the config.
- `--trusted-host`, `unsafeHttpWhitelist`, `GOSUMDB=off`, `GONOSUMDB`, and `GOINSECURE` turn off transport or checksum verification. Record which packages they cover.
- Tokens in `.npmrc` (`_authToken=`) committed to the repo are a `secrets-audit` finding.

## 2. Agent extensions inventory

Coding agents load code at launch from MCP configs, installed skills, and plugin marketplaces. That code runs with the developer's (or CI's) filesystem and credentials, so it belongs in the dependency inventory.

**Where to look:**

```bash
# MCP server configs (project and user scope)
ls -la .mcp.json .cursor/mcp.json .vscode/mcp.json .gemini/settings.json .codex/config.toml \
  ~/.claude.json ~/.cursor/mcp.json "$HOME/Library/Application Support/Claude/claude_desktop_config.json" 2>/dev/null
# Installed skills, rules, and plugins
find . ~/.claude -maxdepth 4 \( -name SKILL.md -o -path "*/.claude/agents/*" -o -path "*/.claude/commands/*" \
  -o -name "*.mdc" -o -name "AGENTS.md" -o -name "plugin.json" -o -name "marketplace.json" \) 2>/dev/null | grep -v node_modules
# Plugin marketplaces and auto-enabled plugins in settings
grep -nE "extraKnownMarketplaces|enabledPlugins|enableAllProjectMcpServers|enabledMcpjsonServers" \
  .claude/settings*.json ~/.claude/settings*.json 2>/dev/null
```

Record each one in the Stack Inventory: name, source (marketplace / repo / registry), version or commit, and the command it launches.

**Unpinned launch commands.** An MCP server launched as `npx -y some-mcp-server` runs whatever version is newest on every start. If the package is compromised or changes hands, the next launch runs the new code with no review step (the "rug pull" pattern).

```bash
# npx / bunx / pnpm dlx without @version (also catches @latest)
rg -n '"(npx|bunx)"|"pnpm",\s*"dlx"|npx\s+-y' .mcp.json .cursor/mcp.json .vscode/mcp.json 2>/dev/null
grep -nE '"(-y|--yes)",\s*"(@[a-z0-9._-]+/)?[a-z0-9._-]+(@latest)?"' .mcp.json .cursor/mcp.json .vscode/mcp.json 2>/dev/null
# uvx / pipx run without ==version
grep -nE '"(uvx|pipx)"' -A3 .mcp.json .cursor/mcp.json 2>/dev/null | grep -vE '==[0-9]'
# docker run without a tag or digest (or with :latest)
grep -nE '"docker"' -A8 .mcp.json .cursor/mcp.json 2>/dev/null | grep -E '"[a-z0-9./-]+(:latest)?"\s*[,\]]' | grep -v '@sha256:'
# Remote MCP servers (code you can't pin at all; review the host and auth instead)
grep -nE '"(url|serverUrl)"\s*:' .mcp.json .cursor/mcp.json 2>/dev/null
```

Pinned looks like `npx -y some-mcp-server@1.4.2`, `uvx some-tool==0.9.1`, `docker run ...image@sha256:<digest>`. Skills and plugins installed from a marketplace should be pinned to a commit or release where the tool allows it.

**Scope boundary:** this skill inventories extensions and checks pinning and provenance. Reviewing what an extension's instructions or tool descriptions tell the agent to do (hidden instructions, overbroad permissions, exfiltration) is `agent-supply-chain-audit`. Hand off each extension that is unpinned or from an unreviewed source.

## 3. Shipped `.pyc` without matching source

Compiled `.pyc` files in a repo or package can carry code that doesn't match any `.py` next to them, and reviewers rarely open them. A `.pyc` with no source, or whose source has changed since compile, is worth a look.

```bash
# Bytecode tracked in git (should almost never be)
git ls-files | grep -E '\.py[co]$|__pycache__/'
# .pyc with no matching .py (handles both __pycache__/name.cpython-3XX.pyc and legacy name.pyc)
find . -name "*.pyc" -not -path "*/.venv/*" -not -path "*/node_modules/*" | while read -r f; do
  base=$(basename "$f" | sed -E 's/\.cpython-[0-9]+(\.opt-[0-9])?\.pyc$|\.pyc$//')
  dir=$(dirname "$f"); [ "$(basename "$dir")" = "__pycache__" ] && dir=$(dirname "$dir")
  [ -f "$dir/$base.py" ] || echo "no source: $f"
done
# Inside a wheel or sdist before publishing / after downloading
unzip -l dist/*.whl 2>/dev/null | grep -E '\.pyc$'
```

Finding when a `.pyc` with no source is imported at runtime (a sibling module imports its name, or it sits on `sys.path` ahead of the source). Otherwise it's a hardening note: remove it and add `__pycache__/` and `*.pyc` to `.gitignore` and the package's exclude list. Other concealed executables (prebuilt `.so` / `.node` / `.exe` / `.jar` files in a source package) deserve the same check: is there a build recipe that produces them from source in this repo?

## Sources

- NVIDIA SkillSpector (Apache-2.0): [`docs/DEPENDENCY_SOURCE_REDIRECTION.md`](https://github.com/NVIDIA/SkillSpector/blob/main/docs/DEPENDENCY_SOURCE_REDIRECTION.md), [`mcp_rug_pull.py`](https://github.com/NVIDIA/SkillSpector/blob/main/src/skillspector/nodes/analyzers/mcp_rug_pull.py), [README supply-chain patterns](https://github.com/NVIDIA/SkillSpector/blob/main/README.md#supply-chain-10-patterns). Patterns paraphrased; greps written for this repo.
- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021)
- pip documentation, "Secure installs" and `--extra-index-url` notes; Cargo book, "Source replacement"; Maven "Using Mirrors for Repositories"
