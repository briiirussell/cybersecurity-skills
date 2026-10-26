import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { validateCoverage } from "../../shared/validate-coverage.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures");
const CLI = join(HERE, "..", "..", "shared", "validate-coverage.mjs");
const load = (name) => JSON.parse(readFileSync(join(FIX, name), "utf8"));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });

const valid = load("coverage.valid.json");
const findings = load("findings.valid.json");
const unit = (status) => structuredClone(valid.find((u) => u.status === status));

function expectError(units, re, f = null) {
  const errors = validateCoverage(units, f);
  assert.ok(errors.some((e) => re.test(e)), `expected an error matching ${re}, got:\n${errors.join("\n") || "(none)"}`);
}

test("valid fixture passes, with and without the findings cross-check", () => {
  assert.deepEqual(validateCoverage(valid), []);
  assert.deepEqual(validateCoverage(valid, findings), []);
});

test("top level must be an array", () => {
  assert.match(validateCoverage({})[0], /must be a JSON array/);
});

test("covered requires reviewed_paths and at least one check", () => {
  const u = unit("covered");
  u.reviewed_paths = [];
  expectError([u], /"covered" requires at least one reviewed_paths/);
  const u2 = unit("covered");
  u2.checks = [];
  expectError([u2], /"covered" requires at least one check/);
});

test("candidate requires a finding fingerprint; blocked requires an unresolved item", () => {
  const c = unit("candidate");
  c.finding_fingerprints = [];
  expectError([c], /"candidate" requires/);
  const b = unit("blocked");
  b.unresolved = [];
  expectError([b], /"blocked" requires/);
});

test("status must be in the enum", () => {
  const u = unit("covered");
  u.status = "done";
  expectError([u], /status: must be one of/);
});

test("all fields required, no extras", () => {
  const u = unit("covered");
  delete u.boundary;
  u.extra = 1;
  expectError([u], /missing required field "boundary"/);
  expectError([u], /unexpected field "extra"/);
});

test("checks need invariant, method and result", () => {
  const u = unit("covered");
  u.checks = [{ invariant: "x", method: "y" }];
  expectError([u], /missing required field "result"/);
});

test("reviewed_paths must be safe and repo-relative", () => {
  const u = unit("covered");
  u.reviewed_paths = ["/abs/path.ts"];
  expectError([u], /absolute/);
});

test("duplicate ids are rejected", () => {
  expectError([unit("covered"), unit("covered")], /duplicate id/);
});

test("fingerprint cross-check against findings.json", () => {
  const u = unit("candidate");
  u.finding_fingerprints = ["nope/not/here"];
  expectError([u], /not in findings\.json/, findings);
  assert.deepEqual(validateCoverage([u]), [], "no cross-check without findings");
});

test("CLI: exit codes", () => {
  const ok = run(join(FIX, "coverage.valid.json"), "--findings", join(FIX, "findings.valid.json"));
  assert.equal(ok.status, 0, ok.stderr);
  const bad = run(join(FIX, "coverage.invalid.json"), "--findings", join(FIX, "findings.valid.json"));
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /duplicate id/);
  assert.match(bad.stderr, /not in findings\.json/);
  assert.equal(run(join(FIX, "findings.malformed.json")).status, 2);
  assert.equal(run().status, 2);
  assert.equal(run(join(FIX, "coverage.valid.json"), "--findings").status, 2);
});
