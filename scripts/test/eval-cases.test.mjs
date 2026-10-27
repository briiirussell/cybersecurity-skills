// Offline shape check for evals/cases/ (the `claude plugin eval` suite), so a typo in a grader
// is caught on the PR instead of in a paid run on main.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFrontmatter } from "../build-adapters.mjs";
import { summarize } from "../../.github/scripts/eval-summary.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CASES = join(ROOT, "evals", "cases");
const SKILLS = new Set(readdirSync(join(ROOT, "skills")).filter((d) => existsSync(join(ROOT, "skills", d, "SKILL.md"))));
const CASE_KEYS = new Set(["schema_version", "name", "description", "tags", "plugins", "runs", "expected_outcome", "model",
  "max_turns", "timeout_seconds", "allowed_tools", "append_system_prompt", "env"]);
const caseDirs = readdirSync(CASES).filter((d) => existsSync(join(CASES, d, "prompt.md")));

/** Skill names a tool_used grader's input_match targets: `...)?name"` or `...)?(?:a|b|c)"`. */
const targets = (re) => {
  const m = /\?\(?(?:\?:)?([a-z0-9|-]+)\)?"$/.exec(re);
  return m ? m[1].split("|") : [];
};

test("evals/cases: every case has a prompt, known frontmatter keys and at least one grader", () => {
  assert.ok(caseDirs.length >= 10, `only ${caseDirs.length} cases`);
  for (const c of caseDirs) {
    const { meta, body } = parseFrontmatter(readFileSync(join(CASES, c, "prompt.md"), "utf8"));
    for (const k of Object.keys(meta)) assert.ok(CASE_KEYS.has(k), `${c}: unknown prompt.md key "${k}"`);
    assert.ok(body.length > 20, `${c}: empty prompt`);
    const graders = existsSync(join(CASES, c, "graders")) ? readdirSync(join(CASES, c, "graders")).filter((f) => f.endsWith(".md")) : [];
    assert.ok(graders.length, `${c}: no graders`);
  }
});

test("evals/cases: Skill graders name real skills, and each routing case fires one skill and quiets a rival", () => {
  for (const c of caseDirs) {
    const dir = join(CASES, c, "graders");
    let fires = 0, quiet = 0;
    for (const f of readdirSync(dir)) {
      const { meta } = parseFrontmatter(readFileSync(join(dir, f), "utf8"));
      assert.equal(meta.type, "tool_used", `${c}/${f}: type`);
      assert.equal(meta.tool, "Skill", `${c}/${f}: tool`);
      const names = targets(meta.input_match ?? "");
      assert.ok(names.length, `${c}/${f}: can't read a skill name from input_match ${meta.input_match}`);
      for (const n of names) assert.ok(SKILLS.has(n), `${c}/${f}: input_match names unknown skill "${n}"`);
      new RegExp(meta.input_match); // compiles as a JavaScript regex
      if (meta.max === "0") { quiet++; assert.equal(meta.min, "0", `${c}/${f}: a quiet grader needs min: 0 and max: 0`); }
      else { fires++; assert.equal(f, `fires-${names[0]}.md`, `${c}/${f}: name a firing grader fires-<skill>.md`); }
    }
    if (c.startsWith("quiet-")) assert.equal(fires, 0, `${c}: a quiet case must not require a skill`);
    else assert.ok(fires === 1 && quiet >= 1, `${c}: expected one fires- grader and at least one quiet- grader`);
  }
});

test("evals/cases: the input_match pattern matches the plain and namespaced Skill input, not a longer name", () => {
  const re = new RegExp(String.raw`"skill"\s*:\s*"(?:[\w-]+:)?recon"`);
  assert.ok(re.test(JSON.stringify({ skill: "recon" })));
  assert.ok(re.test(JSON.stringify({ skill: "cybersecurity-skills:recon" })));
  assert.ok(!re.test(JSON.stringify({ skill: "osint-recon" })));
  assert.ok(!re.test(JSON.stringify({ skill: "cybersecurity-skills:osint-recon" })));
});

test("eval-summary: errored runs and partial reports fail; a clean report passes", () => {
  const clean = { aggregates: { casesPassed: 1, casesTotal: 1, overallScore: 1 }, claudeVersion: "2.1.296", costUsd: 0.4,
    cases: [{ name: "a", aggregates: { score: 1 }, arms: { with: [{}, {}, {}] } }] };
  const ok = summarize(clean);
  assert.deepEqual(ok.problems, []);
  assert.match(ok.markdown, /\| a \| 1\.00 \| 3 \| 0 \|/);
  const bad = summarize({ ...clean, partial: true, partialReason: "cost_ceiling",
    cases: [{ name: "a", aggregates: { score: 0.67 }, arms: { with: [{}, { error: "overloaded" }, { aborted: true }] } }] });
  assert.equal(bad.problems.length, 2);
  assert.match(bad.problems.join(), /2\/3 run\(s\) ended in an error/);
  assert.match(bad.problems.join(), /partial run \(cost_ceiling\)/);
  assert.match(summarize({ cases: [] }).problems.join(), /no cases/);
});
