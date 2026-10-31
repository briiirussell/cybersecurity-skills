/**
 * Check one `allowed-tools` Bash rule for grants that would pre-approve a write.
 * Zero dependencies. Used by scripts/lint-skills.mjs; tested in scripts/test/grant-check.test.mjs.
 *
 * Claude Code matches `Bash(<prefix>:*)` (and `Bash(<prefix> *)`) by prefix, so a grant
 * covers every command that starts with its prefix, including subcommands and any trailing
 * flags. A rule is flagged when:
 *
 *   1. it is unscoped (`Bash`, `Bash(*)`, `Bash(:*)`);
 *   2. its own text names a write verb (`delete`, `rollback`, `--fix`, ...);
 *   3. it is a wildcard whose prefix also matches a known destructive command
 *      (`heroku releases:*` matches `heroku releases:rollback`);
 *   4. it is a wildcard on a bare multi-command CLI (`git:*`, `vercel:*`, `aws:*`);
 *   5. it is a wildcard on a tool that rewrites source files when given a flag
 *      (`semgrep:*` allows `semgrep --autofix`), since a prefix rule can't exclude
 *      trailing flags;
 *   6. it is a wildcard on a command where a trailing flag turns a read into a write
 *      (`gh api repos/:*` allows `gh api repos/x -X DELETE`, `exiftool:*` allows `-TAG=`);
 *   7. it lets a secret scanner send the secrets it finds to their providers to check them
 *      (`trufflehog git:*` verifies by default; `betterleaks git:*` allows `-v`). Checking a
 *      key uses it, so it must prompt.
 *
 * Not covered on purpose: report-file flags (`--output`, `--report-path`, `git log --output`).
 * Almost every scanner has one, and they write a new report rather than change the project.
 */

/** Words that mean the command changes state. Matched as whole segments split on space, colon, `-`, `=`. */
export const WRITE_VERBS = new Set([
  "delete", "destroy", "remove", "rm", "drop", "purge", "wipe", "reset", "rollback", "revert",
  "set", "unset", "put", "create", "update", "upgrade", "apply", "patch", "terminate", "kill",
  "revoke", "attach", "detach", "push", "publish", "unpublish", "install", "uninstall", "deploy",
  "promote", "merge", "prune", "scale", "rename", "transfer", "archive", "edit",
  "fix", "autofix", "autocorrect", "write",
]);

/**
 * Known destructive commands a broader prefix could match. A grant is flagged when one of
 * these starts with its prefix. Add entries when a skill starts using a new CLI.
 */
export const DESTRUCTIVE_COMMANDS = [
  // heroku
  "heroku apps:destroy", "heroku apps:rename", "heroku apps:transfer", "heroku releases:rollback",
  "heroku stack:set", "heroku config:set", "heroku config:unset", "heroku pg:reset",
  "heroku domains:add", "heroku domains:remove", "heroku domains:clear", "heroku ps:scale",
  "heroku maintenance:on", "heroku access:remove", "heroku run",
  // vercel (a bare `vercel` deploys)
  "vercel --prod", "vercel deploy", "vercel remove", "vercel rm", "vercel promote", "vercel rollback",
  "vercel alias", "vercel env add", "vercel env rm", "vercel domains add", "vercel domains rm",
  "vercel domains remove", "vercel project add", "vercel project rm", "vercel project remove",
  "vercel dns add", "vercel dns rm", "vercel api",
  // gh
  "gh repo delete", "gh repo edit", "gh repo archive", "gh repo rename", "gh repo create",
  "gh api -X", "gh api --method", "gh api -f", "gh api -F", "gh release create", "gh release delete",
  "gh secret set", "gh secret delete", "gh variable set", "gh pr merge", "gh workflow run",
  "gh auth logout", "gh auth token",
  // git
  "git push", "git reset", "git clean", "git checkout", "git switch", "git restore", "git rebase",
  "git commit", "git merge", "git branch -d", "git branch -D", "git branch -m", "git branch -M",
  "git tag -d", "git remote add", "git remote remove", "git stash drop", "git filter-branch",
  "git filter-repo", "git gc", "git config",
  // package managers
  "npm audit fix", "npm install", "npm i ", "npm ci", "npm uninstall", "npm update", "npm publish",
  "npm unpublish", "npm exec", "npm run",
  "pnpm audit --fix", "pnpm install", "pnpm add", "pnpm update", "pnpm remove", "pnpm publish", "pnpm exec",
  "yarn install", "yarn add", "yarn up", "yarn remove", "yarn npm publish", "yarn run",
  // `bundle audit update` is left out: it refreshes bundler-audit's own advisory database only.
  "bundle install", "bundle update", "bundle exec",
  "composer install", "composer update", "composer require", "composer remove",
  "pip install", "pip uninstall", "dotnet add", "dotnet remove", "go get", "go install", "go mod tidy",
  "osv-scanner fix",
  // cloud and infra
  "aws s3 rm", "aws s3 cp", "aws s3 mv", "aws s3 sync", "kubectl delete", "kubectl apply",
  "kubectl edit", "kubectl exec", "docker rm", "docker run", "docker exec", "terraform apply",
  "terraform destroy", "terraform import", "terraform state",
];

/** CLIs with many subcommands; a wildcard on the bare tool grants all of them. */
export const MULTI_COMMAND_CLIS = new Set([
  "git", "gh", "npm", "npx", "pnpm", "yarn", "bundle", "composer", "pip", "pip3", "dotnet", "go",
  "cargo", "heroku", "vercel", "netlify", "aws", "az", "gcloud", "kubectl", "helm", "docker",
  "podman", "terraform", "tofu", "pulumi", "brew", "apt", "systemctl", "launchctl", "osv-scanner",
]);

/** Tools that rewrite source files when given a flag (or by default). */
export const SOURCE_REWRITERS = new Set([
  "semgrep", "eslint", "prettier", "ruff", "black", "isort", "gofmt", "goimports", "golangci-lint",
  "rubocop", "standardrb", "rustfmt", "clippy-driver", "biome", "stylelint", "terraform fmt",
]);

/**
 * Commands where a trailing flag turns a read into a write. Any wildcard starting with one of
 * these is flagged, however specific the rest of the prefix is; use an exact rule or none.
 */
export const TRAILING_FLAG_WRITERS = [
  "gh api",   // -X / --method / -f / -F send a write request
  "exiftool", // -TAG=value rewrites metadata in place
  "floss",    // --install-right-click-menu changes the Windows registry
];

/**
 * Secret scanners that can send found credentials to the provider to check them: trufflehog by
 * default (unless `--no-verification`), betterleaks with `-v` / `-a` or `validate` / `analyze`.
 * Any wildcard on these is flagged, and so is an exact rule that verifies.
 */
export const CREDENTIAL_CHECKERS = ["trufflehog", "betterleaks"];

/** True when an exact rule for a CREDENTIAL_CHECKERS tool would check found keys against the provider. */
function exactRuleChecksKeys(tool, pattern) {
  const words = pattern.split(/\s+/);
  if (tool === "trufflehog") return words.length > 1 && !/^(--help|-h|--version)$/.test(words[1]) && !words.includes("--no-verification");
  return words.some((w) => /^(validate|analyze|-v|-a|--validate|--analyze|--validate=true|--analyze=true)$/.test(w));
}

/** Parse `Bash(...)`. Returns { pattern, prefix, wildcard } or null for non-Bash tools. */
export function parseBashRule(tool) {
  if (tool === "Bash") return { pattern: "", prefix: "", wildcard: true };
  const m = /^Bash\((.*)\)$/s.exec(tool.trim());
  if (!m) return null;
  const pattern = m[1].trim();
  let prefix = pattern;
  let wildcard = false;
  if (pattern.endsWith(":*")) { prefix = pattern.slice(0, -2); wildcard = true; }
  else if (pattern.includes("*")) { prefix = pattern.slice(0, pattern.indexOf("*")); wildcard = true; }
  return { pattern, prefix: prefix.trim(), wildcard };
}

const segments = (s) => s.toLowerCase().split(/[\s:=\-/]+/).filter(Boolean);

/** Return a list of reasons this rule pre-approves a write. Empty means OK. */
export function checkGrant(tool) {
  const rule = parseBashRule(tool);
  if (!rule) return [];
  const { prefix, wildcard } = rule;
  if (!prefix) return ["unscoped Bash pre-approves every command; scope it to a read-only prefix"];

  const reasons = [];
  const verb = segments(prefix).find((s) => WRITE_VERBS.has(s));
  if (verb) reasons.push(`names the write verb '${verb}'`);

  if (wildcard) {
    const hits = DESTRUCTIVE_COMMANDS.filter((d) => d.startsWith(prefix) && d !== prefix);
    const exactHit = DESTRUCTIVE_COMMANDS.includes(prefix);
    if (exactHit) reasons.push(`prefix is the destructive command '${prefix}'`);
    if (hits.length) reasons.push(`prefix also matches ${hits.slice(0, 3).map((h) => `'${h.trim()}'`).join(", ")}${hits.length > 3 ? ` (+${hits.length - 3} more)` : ""}`);

    const words = prefix.split(/\s+/);
    if (words.length === 1 && MULTI_COMMAND_CLIS.has(words[0]))
      reasons.push(`wildcard on the bare '${words[0]}' CLI grants every subcommand`);

    const tool2 = words.slice(0, 2).join(" ");
    if (SOURCE_REWRITERS.has(words[0]) || SOURCE_REWRITERS.has(tool2))
      reasons.push(`'${SOURCE_REWRITERS.has(tool2) ? tool2 : words[0]}' rewrites files with a flag, which a prefix rule can't exclude; use an exact rule`);

    const flagWriter = TRAILING_FLAG_WRITERS.find((t) => prefix === t || prefix.startsWith(t + " "));
    if (flagWriter) reasons.push(`a trailing flag turns '${flagWriter}' into a write, which a prefix rule can't exclude; use an exact rule`);

    if (CREDENTIAL_CHECKERS.includes(words[0]))
      reasons.push(`a trailing flag makes '${words[0]}' send found secrets to their providers, which uses them; use an exact rule that doesn't verify`);
  } else if (CREDENTIAL_CHECKERS.includes(rule.pattern.split(/\s+/)[0]) && exactRuleChecksKeys(rule.pattern.split(/\s+/)[0], rule.pattern)) {
    reasons.push("exact rule checks found secrets against their providers, which uses them; it must prompt");
  } else if (DESTRUCTIVE_COMMANDS.some((d) => rule.pattern === d.trim() || rule.pattern.startsWith(d))) {
    reasons.push("exact rule is a destructive command");
  }
  return reasons;
}
