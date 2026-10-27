// The issue forms list every skill in a dropdown; keep them in sync with skills/.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FORMS = join(ROOT, ".github", "ISSUE_TEMPLATE");
const SKILLS = readdirSync(join(ROOT, "skills")).filter((d) => existsSync(join(ROOT, "skills", d, "SKILL.md"))).sort();

/** Options of the `id: skill` dropdown in an issue form (plain-YAML read, no dependency). */
function skillOptions(yml) {
  const block = yml.split(/\n  - type: /).find((b) => /\n    id: skill\n/.test(b));
  if (!block) return null;
  return [...block.split("options:\n")[1].matchAll(/^        - (.+)$/gm)].map((m) => m[1].trim());
}

for (const form of ["field-report.yml", "bug.yml", "trophy-case.yml"]) {
  test(`${form}: the skill dropdown lists exactly the skills in skills/`, () => {
    const opts = skillOptions(readFileSync(join(FORMS, form), "utf8"));
    assert.ok(opts, "no `id: skill` dropdown");
    const skills = opts.filter((o) => /^[a-z0-9-]+$/.test(o));
    assert.deepEqual(skills, SKILLS, "add or remove the skill in this form's dropdown (sorted)");
    assert.equal(new Set(opts).size, opts.length, "duplicate option");
  });
}

test("issue forms: every form has a name, a description and a body", () => {
  for (const f of readdirSync(FORMS).filter((f) => f.endsWith(".yml") && f !== "config.yml")) {
    const yml = readFileSync(join(FORMS, f), "utf8");
    assert.match(yml, /^name: .+/m, f);
    assert.match(yml, /^description: .+/m, f);
    assert.match(yml, /^body:\n/m, f);
  }
});
