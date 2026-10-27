import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { checkGrant, parseBashRule } from "../grant-check.mjs";
import { parseFrontmatter } from "../build-adapters.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const flagged = (t) => checkGrant(t).length > 0;

test("parseBashRule: legacy :*, space-star, exact, non-Bash", () => {
  assert.deepEqual(parseBashRule("Bash(git log:*)"), { pattern: "git log:*", prefix: "git log", wildcard: true });
  assert.deepEqual(parseBashRule("Bash(git log *)"), { pattern: "git log *", prefix: "git log", wildcard: true });
  assert.deepEqual(parseBashRule("Bash(npm audit --json)"), { pattern: "npm audit --json", prefix: "npm audit --json", wildcard: false });
  assert.equal(parseBashRule("Read"), null);
});

test("v1.19.6 heroku grants that slipped through are flagged", () => {
  assert.match(checkGrant("Bash(heroku apps:*)").join(), /apps:destroy/);
  assert.match(checkGrant("Bash(heroku releases:*)").join(), /releases:rollback/);
  assert.match(checkGrant("Bash(heroku stack:*)").join(), /stack:set/);
});

test("their replacements are clean", () => {
  for (const t of ["Bash(heroku apps --all --json)", "Bash(heroku apps:info:*)", "Bash(heroku domains -a:*)",
    "Bash(heroku releases -a:*)", "Bash(heroku releases:info:*)", "Bash(heroku pipelines:info:*)"])
    assert.deepEqual(checkGrant(t), [], t);
});

test("earlier fixes stay fixed: git branch, npm audit wildcard", () => {
  assert.ok(flagged("Bash(git branch:*)"));
  assert.ok(flagged("Bash(npm audit:*)"));
  assert.ok(!flagged("Bash(npm audit --json)"));
});

test("unscoped, bare multi-command CLIs and write verbs are flagged", () => {
  for (const t of ["Bash", "Bash(*)", "Bash(:*)", "Bash(git:*)", "Bash(vercel:*)", "Bash(aws:*)",
    "Bash(aws iam delete-user:*)", "Bash(gcloud projects set-iam-policy:*)", "Bash(kubectl delete:*)",
    "Bash(npm audit fix)", "Bash(pnpm audit --fix)", "Bash(gh api:*)", "Bash(vercel env:*)"])
    assert.ok(flagged(t), t);
});

test("source rewriters need exact rules", () => {
  assert.match(checkGrant("Bash(semgrep:*)").join(), /semgrep/);
  assert.match(checkGrant("Bash(eslint:*)").join(), /eslint/);
  assert.match(checkGrant("Bash(terraform fmt:*)").join(), /terraform fmt/);
  assert.deepEqual(checkGrant("Bash(semgrep scan --config p/default --json)"), []);
});

test("verbs match whole segments only", () => {
  // 'get-credential-report' contains no write verb; '--prefix' is not '--fix'; 'assignment' is not 'set'
  for (const t of ["Bash(aws iam get-credential-report:*)", "Bash(npm ls --prefix:*)", "Bash(az role assignment list:*)"])
    assert.deepEqual(checkGrant(t), [], t);
});

test("every shipped skill's grants pass", () => {
  for (const name of readdirSync(join(ROOT, "skills"))) {
    const { meta } = parseFrontmatter(readFileSync(join(ROOT, "skills", name, "SKILL.md"), "utf8"));
    for (const t of (meta["allowed-tools"] ?? "").match(/Bash(\([^)]*\))?/g) ?? [])
      assert.deepEqual(checkGrant(t), [], `${name}: ${t}`);
  }
});

test("v1.50.1 trailing-flag writers are flagged even with a specific prefix", () => {
  for (const g of ["Bash(gh api repos/:*)", "Bash(gh api graphql:*)", "Bash(exiftool:*)", "Bash(exiftool -json:*)", "Bash(floss:*)"]) {
    assert.ok(checkGrant(g).some((r) => /trailing flag/.test(r)), g);
  }
  for (const g of ["Bash(exiftool -json sample.bin)", "Bash(gh workflow list:*)", "Bash(floss --help)"]) {
    assert.deepEqual(checkGrant(g), [], g);
  }
});
