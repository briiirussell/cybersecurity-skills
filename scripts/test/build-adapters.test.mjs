import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { parseFrontmatter, buildReferencesSection } from "../build-adapters.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("frontmatter: quoted description with colons, quotes and commas", () => {
  const { meta, body } = parseFrontmatter(
    '---\nname: x\ndescription: "Use when: \'triage this,\' or say \\"hi\\"."\nallowed-tools: Read, Grep\n---\n\n# Body\n'
  );
  assert.equal(meta.name, "x");
  assert.equal(meta.description, "Use when: 'triage this,' or say \"hi\".");
  assert.equal(meta["allowed-tools"], "Read, Grep");
  assert.equal(body, "# Body");
});

test("frontmatter: allowed-tools with parentheses and colons", () => {
  const { meta } = parseFrontmatter("---\nname: y\nallowed-tools: Read, Grep, Bash(git log:*), Bash(gitleaks:*)\n---\nbody");
  assert.equal(meta["allowed-tools"], "Read, Grep, Bash(git log:*), Bash(gitleaks:*)");
});

test("frontmatter: list form, single quotes, block scalars, CRLF", () => {
  const src = "---\r\nname: 'z'\r\nallowed-tools:\r\n  - Read\r\n  - Bash(git diff:*)\r\ndescription: >-\r\n  folded line one\r\n  line two\r\n---\r\nbody\r\n";
  const { meta, body } = parseFrontmatter(src);
  assert.equal(meta.name, "z");
  assert.equal(meta["allowed-tools"], "Read, Bash(git diff:*)");
  assert.equal(meta.description, "folded line one line two");
  assert.equal(body, "body");
});

test("frontmatter: no frontmatter returns body", () => {
  assert.deepEqual(parseFrontmatter("# just body\n"), { meta: {}, body: "# just body" });
});

test("every existing SKILL.md parses with name = folder and a description", () => {
  const dir = join(ROOT, "skills");
  for (const s of readdirSync(dir)) {
    const f = join(dir, s, "SKILL.md");
    if (!existsSync(f)) continue;
    const { meta } = parseFrontmatter(readFileSync(f, "utf8"));
    assert.equal(meta.name, s);
    assert.ok(meta.description && meta.description.length >= 200, `${s} description`);
    assert.ok(!meta.description.startsWith('"'), `${s} description still quoted`);
  }
});

test("references section links each file on GitHub", () => {
  assert.equal(buildReferencesSection("a", []), "");
  const s = buildReferencesSection("finding-triage", ["findings-format.md", "severity-calibration.md"]);
  assert.match(s, /## Reference files/);
  assert.match(s, /\(https:\/\/github\.com\/briiirussell\/cybersecurity-skills\/blob\/main\/skills\/finding-triage\/references\/severity-calibration\.md\)/);
});

test("manifest maps only files that are expected in shared/", () => {
  const m = JSON.parse(readFileSync(join(ROOT, "shared", "manifest.json"), "utf8"));
  for (const [file, skills] of Object.entries(m.files)) {
    assert.ok(Array.isArray(skills), file);
    for (const s of skills) assert.match(s, /^[a-z0-9]+(-[a-z0-9]+)*$/, `${file}: ${s}`);
  }
});
