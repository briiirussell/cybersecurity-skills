import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { toSarif } from "../../shared/to-sarif.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures");
const CLI = join(HERE, "..", "..", "shared", "to-sarif.mjs");
const findings = JSON.parse(readFileSync(join(FIX, "findings.valid.json"), "utf8"));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
const confirmed = () => structuredClone(findings.find((r) => r.verdict === "confirmed"));

test("SARIF 2.1.0 envelope", () => {
  const s = toSarif(findings);
  assert.equal(s.version, "2.1.0");
  assert.match(s.$schema, /sarif-2\.1\.0/);
  assert.equal(s.runs.length, 1);
  assert.equal(s.runs[0].tool.driver.name, "cybersecurity-skills");
});

test("only confirmed findings become results by default", () => {
  const { results, tool } = toSarif(findings).runs[0];
  assert.equal(results.length, 1);
  assert.equal(results[0].properties.verdict, "confirmed");
  assert.equal(tool.driver.rules.length, 1);
});

test("fingerprint, severity, level, codeFlows and relatedLocations are mapped", () => {
  const rec = confirmed();
  const run0 = toSarif([rec]).runs[0];
  const r = run0.results[0];
  assert.deepEqual(r.partialFingerprints, { "cybersecuritySkills/v1": rec.fingerprint });
  assert.equal(r.ruleId, rec.fingerprint);
  assert.equal(r.level, "error");
  assert.equal(r.properties["security-severity"], "8.0");
  assert.equal(run0.tool.driver.rules[0].properties["security-severity"], "8.0");
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, rec.location.file);
  assert.equal(r.locations[0].physicalLocation.region.startLine, rec.location.line);
  const flow = r.codeFlows[0].threadFlows[0].locations;
  assert.equal(flow.length, rec.trace.length);
  assert.deepEqual(flow[0].kinds, ["entrypoint"]);
  assert.deepEqual(flow.at(-1).kinds, ["sink"]);
  assert.equal(r.relatedLocations.length, rec.evidence.length);
});

test("severity -> security-severity and level table", () => {
  const expected = { critical: ["9.5", "error"], high: ["8.0", "error"], medium: ["5.5", "warning"], low: ["3.0", "note"] };
  for (const [sev, [score, level]] of Object.entries(expected)) {
    const rec = confirmed();
    rec.severity.impact.score = "critical";
    rec.severity.overall = sev;
    const r = toSarif([rec]).runs[0].results[0];
    assert.equal(r.properties["security-severity"], score, sev);
    assert.equal(r.level, level, sev);
  }
});

test("--include-needs-validation exports needs_validation as note with no security-severity", () => {
  const { results, tool } = toSarif(findings, { includeNeedsValidation: true }).runs[0];
  assert.equal(results.length, 2);
  const nv = results.find((r) => r.properties.verdict === "needs_validation");
  assert.equal(nv.level, "note");
  assert.equal(nv.properties["security-severity"], undefined);
  assert.match(nv.message.text, /^Needs validation:/);
  const rule = tool.driver.rules.find((x) => x.id === nv.ruleId);
  assert.equal(rule.properties["security-severity"], undefined);
});

test("rejected records are never exported", () => {
  const { results } = toSarif(findings, { includeNeedsValidation: true }).runs[0];
  assert.ok(results.every((r) => r.properties.verdict !== "rejected"));
});

test("dispositions: Fixed skipped, Accepted Risk / Mitigated suppressed, Deferred plain", () => {
  const rec = confirmed();
  rec.disposition = "Fixed";
  assert.equal(toSarif([rec]).runs[0].results.length, 0);
  for (const d of ["Accepted Risk", "Mitigated (platform/config)"]) {
    rec.disposition = d;
    const r = toSarif([rec]).runs[0].results[0];
    assert.equal(r.suppressions[0].status, "accepted", d);
  }
  rec.disposition = "Deferred";
  assert.equal(toSarif([rec]).runs[0].results[0].suppressions, undefined);
});

test("CLI writes SARIF to stdout and to -o", () => {
  const res = run(join(FIX, "findings.valid.json"));
  assert.equal(res.status, 0, res.stderr);
  assert.equal(JSON.parse(res.stdout).version, "2.1.0");
  const dir = mkdtempSync(join(tmpdir(), "sarif-"));
  try {
    const out = join(dir, "out.sarif");
    const res2 = run(join(FIX, "findings.valid.json"), "--include-needs-validation", "-o", out);
    assert.equal(res2.status, 0, res2.stderr);
    assert.equal(JSON.parse(readFileSync(out, "utf8")).runs[0].results.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI refuses invalid findings (exit 1, nothing on stdout)", () => {
  const res = run(join(FIX, "findings.invalid.json"));
  assert.equal(res.status, 1);
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /no SARIF written/);
  assert.equal(run(join(FIX, "findings.malformed.json")).status, 2);
});
