import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { parseReport, toFindings } from "../../skills/scanner-pipeline/references/betterleaks-to-findings.mjs";
import { validateFindings } from "../../shared/validate-findings.mjs";
import { toSarif } from "../../shared/to-sarif.mjs";

// Fixtures are real Betterleaks 2.0.0-rc.6 output (--redact) over a throwaway repo holding fake keys: the same
// GitHub PAT in src/a.js and src/b.js, and a Stripe key in .env.production.
const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures", "betterleaks");
const CLI = join(HERE, "..", "..", "skills", "scanner-pipeline", "references", "betterleaks-to-findings.mjs");
const load = (name) => toFindings(parseReport(readFileSync(join(FIX, name), "utf8")));

test("the same key in two files dedupes to one valid record", () => {
  const recs = load("git-redacted.json");
  assert.deepEqual(validateFindings(recs), []);
  assert.equal(recs.length, 2);
  const pat = recs.find((r) => r.ext.detector === "github-pat");
  assert.equal(pat.fingerprint, "secret:github-pat:620e24b63197");
  assert.deepEqual(pat.evidence.map((e) => e.file).sort(), ["src/a.js", "src/b.js"]);
  assert.equal(pat.verdict, "needs_validation");
  assert.equal(pat.ext.scanner, "betterleaks@2.0.0-rc.6");
  assert.match(pat.evidence[0].description, /commit [0-9a-f]{12}/);
});

test("JSON Lines and JSON give the same fingerprints; ./ paths become repo-relative", () => {
  const a = load("git-redacted.json").map((r) => r.fingerprint);
  const b = load("fs-redacted.jsonl");
  assert.deepEqual(b.map((r) => r.fingerprint), a);
  assert.ok(b.every((r) => !r.location.file.startsWith("./")));
  assert.deepEqual(validateFindings(b), []);
});

test("HMAC fingerprints drop their prefix in the dedupe key and keep it in ext", () => {
  const recs = load("fs-hmac.json");
  assert.deepEqual(validateFindings(recs), []);
  assert.ok(recs.every((r) => /^secret:[a-z-]+:[0-9a-f]{12}$/.test(r.fingerprint)));
  assert.ok(recs.every((r) => r.ext.value_fingerprint.startsWith("hmac-sha256:")));
  assert.equal(recs.length, 2);
});

test("an unredacted report is refused, and so is an absolute path", () => {
  const base = { rule_id: "github-pat", rule_hash: "x", match: { value: "REDACTED", fingerprint: "a".repeat(64) }, location: { path: "src/a.js", start_line: 1 } };
  assert.throws(() => toFindings({ findings: [{ ...base, match: { ...base.match, value: "ghp_live" } }], scan: null }), /--redact/);
  assert.throws(() => toFindings({ findings: [{ ...base, location: { path: "/Users/x/a.js" } }], scan: null }), /repo-relative/);
});

test("an all-digit 12-character prefix is extended so it isn't read as a line number", () => {
  const f = { rule_id: "generic-api-key", rule_hash: "x", match: { value: "REDACTED", fingerprint: "1234567890123a" + "b".repeat(50) }, location: { path: "a.env", start_line: 2 } };
  const [rec] = toFindings({ findings: [f], scan: null });
  assert.equal(rec.fingerprint, "secret:generic-api-key:1234567890123a");
  assert.deepEqual(validateFindings([rec]), []);
});

test("CLI writes findings that export to SARIF", () => {
  const r = spawnSync(process.execPath, [CLI, join(FIX, "git-redacted.json")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const sarif = toSarif(JSON.parse(r.stdout), { includeNeedsValidation: true });
  assert.equal(sarif.runs[0].results.length, 2);
});
