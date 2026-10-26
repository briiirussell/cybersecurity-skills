import { test } from "node:test";
import assert from "node:assert/strict";
import { check, cmpSemver, parseVersions } from "../check-versions.mjs";

const versions = (repo, rows) =>
  `# Versions\n\n| Skill | Version | Last Updated |\n|-------|---------|--------------|\n` +
  Object.entries(rows).map(([k, v]) => `| ${k} | ${v} | 2026-10-26 |`).join("\n") +
  `\n\n## Recent Changes\n\n### ${repo} (2026-10-26)\n\nNotes.\n`;
const state = (repo, rows, market = repo) => ({
  plugin: JSON.stringify({ version: repo }),
  marketplace: JSON.stringify({ metadata: { version: market } }),
  versionsText: versions(repo, rows),
});

test("cmpSemver orders numerically, not lexically", () => {
  assert.ok(cmpSemver("1.19.10", "1.19.9") > 0);
  assert.ok(cmpSemver("1.20.0", "1.19.11") > 0);
  assert.equal(cmpSemver("1.2.3", "1.2.3"), 0);
});

test("parseVersions reads rows and entries", () => {
  const { rows, entries } = parseVersions(versions("1.2.0", { a: "1.0.0", b: "2.1.0" }));
  assert.deepEqual([...rows], [["a", "1.0.0"], ["b", "2.1.0"]]);
  assert.ok(entries.has("1.2.0"));
});

test("in sync: no errors", () => {
  assert.deepEqual(check({ head: state("1.2.0", { a: "1.0.0" }), skillDirs: ["a"] }), []);
});

test("plugin/marketplace mismatch, missing entry, missing row, orphan row", () => {
  const head = state("1.2.0", { a: "1.0.0", gone: "1.0.0" }, "1.1.0");
  head.versionsText = head.versionsText.replace("### 1.2.0", "### 1.1.9");
  const errs = check({ head, skillDirs: ["a", "b"] }).join("\n");
  assert.match(errs, /marketplace.json metadata.version \(1.1.0\) differ/);
  assert.match(errs, /no "### 1.2.0/);
  assert.match(errs, /no row for skills\/b\//);
  assert.match(errs, /row "gone" has no skills\/gone\/ folder/);
});

test("with base: repo version must go up", () => {
  const errs = check({ head: state("1.2.0", { a: "1.0.0" }), base: state("1.2.0", { a: "1.0.0" }), skillDirs: ["a"], changed: ["README.md"] });
  assert.match(errs.join(), /not higher than the base's 1.2.0/);
});

test("with base: a changed skill needs a row bump; generated copies and new skills don't", () => {
  const base = state("1.2.0", { a: "1.0.0", b: "1.0.0" });
  const head = state("1.3.0", { a: "1.0.0", b: "1.0.0", c: "1.0.0" });
  const generated = new Set(["skills/b/references/findings.schema.json"]);
  const errs = check({ head, base, skillDirs: ["a", "b", "c"], generated,
    changed: ["skills/a/SKILL.md", "skills/b/references/findings.schema.json", "skills/c/SKILL.md"] });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /skills\/a\/ changed but its VERSIONS.md row is still 1.0.0/);
});

test("with base: bumped skill passes; no changes skips the bump check", () => {
  const base = state("1.2.0", { a: "1.0.0" });
  assert.deepEqual(check({ head: state("1.2.1", { a: "1.0.1" }), base, skillDirs: ["a"], changed: ["skills/a/SKILL.md"] }), []);
  assert.deepEqual(check({ head: state("1.2.0", { a: "1.0.0" }), base, skillDirs: ["a"], changed: [] }), []);
});
