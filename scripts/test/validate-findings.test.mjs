import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { validateFindings, unsafePathReason } from "../../shared/validate-findings.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures");
const CLI = join(HERE, "..", "..", "shared", "validate-findings.mjs");
const load = (name) => JSON.parse(readFileSync(join(FIX, name), "utf8"));
const clone = (v) => structuredClone(v);
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });

const valid = load("findings.valid.json");
const confirmed = () => clone(valid.find((r) => r.verdict === "confirmed"));
const needsValidation = () => clone(valid.find((r) => r.verdict === "needs_validation"));
const rejected = () => clone(valid.find((r) => r.verdict === "rejected"));

/** Assert that validating [rec] yields at least one error matching `re`. */
function expectError(rec, re) {
  const errors = validateFindings([rec]);
  assert.ok(errors.some((e) => re.test(e)), `expected an error matching ${re}, got:\n${errors.join("\n") || "(none)"}`);
}

test("valid fixture passes", () => {
  assert.deepEqual(validateFindings(valid), []);
});

test("empty array is valid", () => {
  assert.deepEqual(validateFindings([]), []);
});

test("top level must be an array", () => {
  assert.match(validateFindings({ findings: [] })[0], /must be a JSON array/);
});

test("unknown verdict is rejected", () => {
  const r = confirmed();
  r.verdict = "potential";
  expectError(r, /verdict: must be one of/);
});

test("additionalProperties: unexpected field is rejected", () => {
  const r = confirmed();
  r.notes = "x";
  expectError(r, /unexpected field "notes"/);
});

test("records must be sorted by fingerprint", () => {
  const errors = validateFindings([...valid].reverse());
  assert.ok(errors.some((e) => /sorted by fingerprint/.test(e)));
});

test("duplicate fingerprints are rejected", () => {
  const errors = validateFindings([confirmed(), confirmed()]);
  assert.ok(errors.some((e) => /duplicate fingerprint/.test(e)));
});

test("fingerprint that embeds a line number is rejected", () => {
  const r = confirmed();
  r.fingerprint = "api-audit/CWE-639/src/routes/orders.ts:88";
  expectError(r, /line number/);
});

test("unsafe paths are rejected", () => {
  for (const bad of ["/etc/passwd", "../x.js", "src/../../x.js", "C:/x.js", "src\\x.js", "~/x.js", "file:///x.js", ""]) {
    assert.ok(unsafePathReason(bad), `expected ${JSON.stringify(bad)} to be unsafe`);
  }
  for (const ok of ["src/x.js", "a/b..c/d.ts", ".github/workflows/ci.yml", "package-lock.json"]) {
    assert.equal(unsafePathReason(ok), null, `expected ${ok} to be safe`);
  }
  const r = confirmed();
  r.trace[1].file = "../outside.ts";
  expectError(r, /trace\[1\]\.file: path .* '\.\.' segment/);
  const r2 = rejected();
  r2.ruled_out_by.location.file = "/abs/x.ts";
  expectError(r2, /ruled_out_by\.location\.file: .* absolute/);
});

test("line must be an integer >= 1", () => {
  const r = confirmed();
  r.location.line = 0;
  expectError(r, /location\.line: must be an integer >= 1/);
  const r2 = confirmed();
  r2.evidence[0].line = 1.5;
  expectError(r2, /evidence\[0\]\.line/);
});

test("trace must start at an entrypoint and end at a sink", () => {
  const r = confirmed();
  r.trace[0].kind = "propagation";
  expectError(r, /must start with an "entrypoint"/);
  const r2 = confirmed();
  r2.trace[r2.trace.length - 1].kind = "propagation";
  expectError(r2, /must end with a "sink"/);
  const r3 = confirmed();
  r3.trace[1].kind = "sink";
  expectError(r3, /may only appear at the end/);
});

test("confirmed needs a trace of at least two steps and evidence", () => {
  const r = confirmed();
  r.trace = [];
  expectError(r, /at least 2 steps/);
  const r2 = confirmed();
  r2.evidence = [];
  expectError(r2, /at least one evidence/);
});

test("overall severity may not exceed impact", () => {
  const r = confirmed();
  r.severity.impact.score = "medium";
  r.severity.overall = "high";
  expectError(r, /exceeds impact/);
});

test("severity is only allowed on confirmed", () => {
  const nv = needsValidation();
  nv.severity = confirmed().severity;
  expectError(nv, /severity is only allowed on confirmed/);
  const rj = rejected();
  rj.severity = confirmed().severity;
  expectError(rj, /severity is only allowed on confirmed/);
});

test("confirmed requires severity and conditions", () => {
  const r = confirmed();
  delete r.severity;
  delete r.conditions;
  expectError(r, /missing required field "severity"/);
  expectError(r, /missing required field "conditions"/);
});

test("condition kind must come from the fixed list", () => {
  const r = confirmed();
  r.conditions[0].kind = "attacker_is_nice";
  expectError(r, /conditions\[0\]\.kind: must be one of/);
});

test("confidence high requires reproduced: true", () => {
  const r = confirmed();
  delete r.reproduced;
  expectError(r, /static-only trace caps confidence at medium/);
});

test("disposition must be from the shared vocabulary and only on confirmed", () => {
  const r = confirmed();
  r.disposition = "False Positive";
  expectError(r, /disposition: must be one of/);
  for (const d of ["Fixed", "Deferred", "Accepted Risk", "Mitigated (platform/config)", "Requires major migration"]) {
    const ok = confirmed();
    ok.disposition = d;
    assert.deepEqual(validateFindings([ok]), [], d);
  }
  const nv = needsValidation();
  nv.disposition = "Fixed";
  expectError(nv, /disposition is only allowed on confirmed/);
});

test("needs_validation requires non-empty blockers and a validation_plan", () => {
  const r = needsValidation();
  r.blockers = [];
  expectError(r, /non-empty array of blockers/);
  const r2 = needsValidation();
  r2.validation_plan = "   ";
  expectError(r2, /validation_plan: must be a non-empty string/);
  const r3 = needsValidation();
  delete r3.validation_plan;
  expectError(r3, /missing required field "validation_plan"/);
});

test("rejected requires ruled_out_by {control, location}", () => {
  const r = rejected();
  delete r.ruled_out_by;
  expectError(r, /missing required field "ruled_out_by"/);
  const r2 = rejected();
  delete r2.ruled_out_by.control;
  expectError(r2, /ruled_out_by: missing required field "control"/);
});

test("invalid fixture fails with several distinct problems", () => {
  const errors = validateFindings(load("findings.invalid.json"));
  assert.ok(errors.length >= 8, errors.join("\n"));
});

test("CLI: exit 0 on valid input", () => {
  const res = run(join(FIX, "findings.valid.json"));
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /OK \(3 records/);
});

test("CLI: exit 1 with messages on invalid input", () => {
  const res = run(join(FIX, "findings.invalid.json"));
  assert.equal(res.status, 1);
  assert.match(res.stderr, /INVALID/);
  assert.match(res.stderr, /absolute/);
});

test("CLI: exit 2 on malformed JSON, missing file, or bad usage", () => {
  assert.equal(run(join(FIX, "findings.malformed.json")).status, 2);
  assert.equal(run(join(FIX, "does-not-exist.json")).status, 2);
  assert.equal(run().status, 2);
});

test("CLI: reads stdin with -", () => {
  const res = spawnSync(process.execPath, [CLI, "-"], { input: "[]", encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
});

test("the example in shared/findings-format.md validates", () => {
  const md = readFileSync(join(HERE, "..", "..", "shared", "findings-format.md"), "utf8");
  const m = md.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(m, "findings-format.md has a ```json example");
  assert.deepEqual(validateFindings(JSON.parse(m[1])), []);
});
