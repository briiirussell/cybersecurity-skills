// Self-tests for the repo's own checkers: each one must still catch what it exists to catch.
// A checker that silently stopped matching would otherwise report a clean repo forever.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { evaluate } from "../../.github/scripts/plugin-validate.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const node = (args, env = {}) => spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8", env: { ...process.env, ...env } });
const tmp = () => mkdtempSync(join(tmpdir(), "cs-selftest-"));

// ---------------------------------------------------------------------------
// lint-skills.mjs
// ---------------------------------------------------------------------------

const DESC = (extra = "") =>
  `Self-test skill used only by scripts/test/self-test.test.mjs to prove that the lint still rejects what it should. ` +
  `It is long enough to pass the description length rule on its own. ${extra}Use when the user mentions 'self test fixture'.`;

const STANDARD = "\n## Boundaries\n\nRead-only.\n\n## References\n\n- None.\n";
const skill = ({ name, desc = DESC(), tools = "Read, Grep, Glob", body = "## Authorization\n\nOwn systems only.\n", standard = STANDARD }) =>
  `---\nname: ${name}\ndescription: "${desc}"\nallowed-tools: ${tools}\n---\n\n# ${name}\n\n${body}${standard}`;

function lintTree(skills) {
  const dir = tmp();
  for (const [folder, content] of Object.entries(skills)) {
    mkdirSync(join(dir, folder), { recursive: true });
    writeFileSync(join(dir, folder, "SKILL.md"), content);
  }
  const r = node(["scripts/lint-skills.mjs", "--quiet", "--skills-dir", dir]);
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("lint: a clean fixture passes", () => {
  const r = lintTree({ "good-skill": skill({ name: "good-skill" }) });
  assert.equal(r.status, 0, r.stderr);
});

test("lint: every rule still fires", () => {
  const r = lintTree({
    "good-skill": skill({ name: "good-skill" }),
    "name-mismatch": skill({ name: "other-name" }),
    "short-desc": skill({ name: "short-desc", desc: "Too short." }),
    "no-auth": skill({ name: "no-auth", body: "## Workflow\n\nDo things.\n" }),
    "webfetch-bash": skill({ name: "webfetch-bash", tools: "Read, WebFetch, Bash" }),
    "bad-grant": skill({ name: "bad-grant", tools: "Read, Bash(heroku releases:*)" }),
    "broken-link": skill({ name: "broken-link", body: "## Authorization\n\nOwn.\n\nSee [x](references/missing.md).\n" }),
    "bad-xref": skill({ name: "bad-xref", body: "## Authorization\n\nOwn.\n\nCross-references: `no-such-skill` for more.\n" }),
    "too-long": skill({ name: "too-long", body: "## Authorization\n\nOwn.\n" + "line\n".repeat(500) }),
    "no-sections": skill({ name: "no-sections", standard: "" }),
    "report-format": skill({ name: "report-format", body: "## Authorization\n\nOwn.\n\n## Report Format\n\nA table.\n" }),
    "dup-phrase-a": skill({ name: "dup-phrase-a", desc: DESC("Also 'shared trigger phrase'. ") }),
    "dup-phrase-b": skill({ name: "dup-phrase-b", desc: DESC("Also 'shared trigger phrase'. ") }),
  });
  assert.equal(r.status, 1);
  const expect = {
    "name-mismatch": /does not match folder/,
    "short-desc": /description is \d+ chars/,
    "no-auth": /no `## Authorization` section/,
    "webfetch-bash": /WebFetch together with unscoped Bash/,
    "bad-grant": /heroku releases:\*.*releases:rollback/,
    "broken-link": /relative link "references\/missing.md" does not resolve/,
    "bad-xref": /`no-such-skill` has no skills\/no-such-skill\/ folder/,
    "too-long": /lines \(must be under 500\)/,
    "no-sections": /no `## Boundaries` section/,
    "report-format": /"## Report Format" should be "## Output Format"/,
  };
  for (const [folder, re] of Object.entries(expect)) {
    const lines = r.stderr.split("\n").filter((l) => l.includes(`/${folder}/SKILL.md`));
    assert.ok(lines.some((l) => re.test(l)), `${folder}: expected ${re}, got:\n${lines.join("\n")}`);
  }
  assert.match(r.stderr, /trigger phrase 'shared trigger phrase' appears in dup-phrase-a, dup-phrase-b/);
  assert.ok(!r.stderr.includes("/good-skill/"), "clean fixture must not be flagged");
});

const agent = ({ name, desc = "Read-only verifier used by the self-test.", tools = "Read, Grep, Glob" }) =>
  `---\nname: ${name}\n${desc === null ? "" : `description: "${desc}"\n`}${tools === null ? "" : `tools: ${tools}\n`}---\n\n# ${name}\n`;

test("lint: agent rules fire, and a read-only agent passes", () => {
  const skills = tmp();
  mkdirSync(join(skills, "good-skill"));
  writeFileSync(join(skills, "good-skill", "SKILL.md"), skill({ name: "good-skill" }));
  const agents = tmp();
  const files = {
    "good-agent": agent({ name: "good-agent" }),
    "name-mismatch": agent({ name: "other-agent" }),
    "no-desc": agent({ name: "no-desc", desc: null }),
    "no-tools": agent({ name: "no-tools", tools: null }),
    "writer": agent({ name: "writer", tools: "Read, Write" }),
    "runner": agent({ name: "runner", tools: "Read, Bash(git log:*)" }),
  };
  for (const [stem, content] of Object.entries(files)) writeFileSync(join(agents, `${stem}.md`), content);
  const r = node(["scripts/lint-skills.mjs", "--quiet", "--skills-dir", skills, "--agents-dir", agents]);
  rmSync(skills, { recursive: true, force: true });
  rmSync(agents, { recursive: true, force: true });
  assert.equal(r.status, 1);
  const expect = {
    "name-mismatch": /does not match file name "name-mismatch"/,
    "no-desc": /`description` missing/,
    "no-tools": /`tools` missing/,
    "writer": /tools grants Write; agents here are read-only/,
    "runner": /tools grants Bash\(git log:\*\); agents here are read-only/,
  };
  for (const [stem, re] of Object.entries(expect)) {
    const lines = r.stderr.split("\n").filter((l) => l.includes(`/${stem}.md`));
    assert.ok(lines.some((l) => re.test(l)), `${stem}: expected ${re}, got:\n${lines.join("\n")}`);
  }
  assert.ok(!r.stderr.includes("/good-agent.md"), "read-only agent must not be flagged");
});

// ---------------------------------------------------------------------------
// skillspector-baseline.mjs
// ---------------------------------------------------------------------------

function baseline(yaml, arg = "--check") {
  const dir = tmp();
  const file = join(dir, "baseline.yaml");
  writeFileSync(file, yaml);
  const r = node([".github/scripts/skillspector-baseline.mjs", arg], { SKILLSPECTOR_BASELINE: file });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

test("baseline: the repo baseline passes", () => {
  const r = node([".github/scripts/skillspector-baseline.mjs", "--check"]);
  assert.equal(r.status, 0, r.stderr);
});

test("baseline: missing reason, unknown skill, wildcard-only message and bad */ targets fail", () => {
  const r = baseline(
    'version: 2\nrules:\n' +
    '  - id: "P1"\n    path: "recon/SKILL.md"\n    message: "something specific"\n' +
    '  - id: "P1"\n    path: "no-such-skill/SKILL.md"\n    message: "something specific"\n    reason: "r"\n' +
    '  - id: "P1"\n    path: "recon/SKILL.md"\n    message: "***"\n    reason: "r"\n' +
    '  - id: "P1"\n    path: "*/references/not-shared.md"\n    message: "something specific"\n    reason: "r"\n'
  );
  assert.equal(r.status, 1);
  assert.match(r.stderr, /rule 1 .*missing reason/);
  assert.match(r.stderr, /rule 2 .*skill "no-such-skill" does not exist/);
  assert.match(r.stderr, /rule 3 .*wildcard-only id\/message/);
  assert.match(r.stderr, /rule 4 .*may only target/);
});

test("baseline: a skill slice keeps only that skill's rules and strips the prefix", () => {
  const r = baseline(
    'version: 2\nrules:\n' +
    '  - id: "P1"\n    path: "recon/SKILL.md"\n    message: "recon example"\n    reason: "r"\n' +
    '  - id: "P2"\n    path: "web-pentest/SKILL.md"\n    message: "pentest example"\n    reason: "r"\n',
    "recon"
  );
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.stringify(JSON.parse(r.stdout));
  assert.match(out, /recon example/);
  assert.ok(!out.includes("pentest example"), "another skill's rule leaked into the slice");
  assert.ok(!out.includes("recon/SKILL.md"), "skill prefix not stripped");
});

// ---------------------------------------------------------------------------
// merge-sarif.mjs
// ---------------------------------------------------------------------------

test("merge-sarif: one run, rewritten paths, de-duplicated rules, baselined results dropped", () => {
  const dir = tmp();
  const result = (ruleId, uri, suppressed = false) => ({
    ruleId, ruleIndex: 0, message: { text: "m" },
    locations: [{ physicalLocation: { artifactLocation: { uri, index: 0 } } }],
    ...(suppressed ? { suppressions: [{ kind: "external", justification: "baseline" }] } : {}),
  });
  const sarif = (rules, results) => ({ version: "2.1.0", runs: [{
    tool: { driver: { name: "skillspector", version: "2.13.1", rules: rules.map((id) => ({ id })) } },
    artifacts: [{ location: { uri: "SKILL.md" } }], results,
  }] });
  writeFileSync(join(dir, "recon.sarif"), JSON.stringify(sarif(["P1"], [result("P1", "SKILL.md"), result("P1", "SKILL.md", true)])));
  writeFileSync(join(dir, "web-pentest.sarif"), JSON.stringify(sarif(["P1", "P2"], [result("P2", "SKILL.md")])));
  const out = join(dir, "merged.sarif");
  const r = node([".github/scripts/merge-sarif.mjs", dir, out]);
  assert.equal(r.status, 0, r.stderr);
  const merged = JSON.parse(readFileSync(out, "utf8"));
  rmSync(dir, { recursive: true, force: true });
  assert.equal(merged.runs.length, 1);
  const run = merged.runs[0];
  assert.deepEqual(run.tool.driver.rules.map((x) => x.id), ["P1", "P2"]);
  assert.equal(run.results.length, 2);
  assert.equal(run.properties.baselineSuppressed, 1);
  const uris = run.results.map((x) => x.locations[0].physicalLocation.artifactLocation.uri).sort();
  assert.deepEqual(uris, ["skills/recon/SKILL.md", "skills/web-pentest/SKILL.md"]);
  const p2 = run.results.find((x) => x.ruleId === "P2");
  assert.equal(run.tool.driver.rules[p2.ruleIndex].id, "P2", "ruleIndex not remapped");
  assert.equal(p2.locations[0].physicalLocation.artifactLocation.index, 1, "artifact index not offset");
});

// ---------------------------------------------------------------------------
// plugin-validate.mjs
// ---------------------------------------------------------------------------

test("plugin-validate: accepts only the named CLAUDE.md warning", () => {
  const claudeMd = { path: "root", message: "CLAUDE.md at the plugin root is not loaded as project context. To ship…" };
  const ok = evaluate({ success: true, manifest: { file: "m", errors: [], warnings: [] }, contents: [{ file: "c", errors: [], warnings: [claudeMd] }] });
  assert.deepEqual(ok.problems, []);
  assert.equal(ok.accepted.length, 1);
  const bad = evaluate({ success: true, manifest: { file: "m", errors: [{ path: "name", message: "bad" }], warnings: [{ path: "metadata.repository", message: "Unknown field" }] }, contents: [] });
  assert.equal(bad.problems.length, 2);
});
