// The worked examples in examples/<skill>/ double as regression fixtures for the shared formats:
// every findings.json and coverage.json must validate, every location must point at a real line in
// examples/target/, and the committed SARIF must match what to-sarif.mjs produces today.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validateFindings } from "../../shared/validate-findings.mjs";
import { validateCoverage } from "../../shared/validate-coverage.mjs";
import { toSarif } from "../../shared/to-sarif.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const EXAMPLES = join(ROOT, "examples");
const TARGET = join(EXAMPLES, "target");
const json = (p) => JSON.parse(readFileSync(p, "utf8"));
const examples = readdirSync(EXAMPLES).filter((d) => existsSync(join(EXAMPLES, d, "findings.json")));
const lineCount = new Map();
const lines = (file) => {
  if (!lineCount.has(file)) lineCount.set(file, readFileSync(join(TARGET, file), "utf8").split("\n").length);
  return lineCount.get(file);
};

test("examples: at least the five audit skills have a worked run, each with a report", () => {
  for (const s of ["owasp-audit", "api-audit", "dependency-audit", "secrets-audit", "finding-triage"])
    assert.ok(examples.includes(s), `examples/${s}/findings.json missing`);
  for (const s of examples) {
    assert.ok(existsSync(join(ROOT, "skills", s, "SKILL.md")), `examples/${s}/ has no matching skill`);
    assert.ok(existsSync(join(EXAMPLES, s, "report.md")), `examples/${s}/report.md missing`);
  }
});

for (const s of examples) {
  const findings = json(join(EXAMPLES, s, "findings.json"));

  test(`examples/${s}: findings.json validates and every record names the skill`, () => {
    assert.deepEqual(validateFindings(findings), []);
    for (const r of findings) assert.equal(r.skill, s, r.fingerprint);
  });

  test(`examples/${s}: every location, trace step and evidence item points at a real line in examples/target/`, () => {
    for (const r of findings) {
      const spots = [r.location, ...(r.trace ?? []), ...(r.evidence ?? []), ...(r.ruled_out_by ? [r.ruled_out_by.location] : [])];
      for (const { file, line } of spots) {
        assert.ok(existsSync(join(TARGET, file)), `${r.fingerprint}: ${file} is not in examples/target/`);
        assert.ok(line <= lines(file), `${r.fingerprint}: ${file}:${line} is past the end of the file`);
      }
    }
  });

  if (existsSync(join(EXAMPLES, s, "coverage.json")))
    test(`examples/${s}: coverage.json validates against its findings`, () => {
      assert.deepEqual(validateCoverage(json(join(EXAMPLES, s, "coverage.json")), findings), []);
    });

  test(`examples/${s}: findings.sarif is what to-sarif.mjs --include-needs-validation produces`, () => {
    const committed = readFileSync(join(EXAMPLES, s, "findings.sarif"), "utf8");
    const fresh = JSON.stringify(toSarif(findings, { includeNeedsValidation: true }), null, 2) + "\n";
    assert.equal(committed, fresh, `regenerate: node shared/to-sarif.mjs examples/${s}/findings.json --include-needs-validation -o examples/${s}/findings.sarif`);
  });
}
