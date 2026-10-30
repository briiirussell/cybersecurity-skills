import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { enrich, advisoryIds, KEV_URL, EPSS_URL, OSV_URL } from "../../shared/enrich-advisories.mjs";
import { validateFindings } from "../../shared/validate-findings.mjs";
import { toSarif } from "../../shared/to-sarif.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "..", "shared", "enrich-advisories.mjs");
const EXAMPLE = join(HERE, "..", "..", "examples", "dependency-audit", "findings.json");
const example = JSON.parse(readFileSync(EXAMPLE, "utf8"));
const byFp = (list, part) => list.find((r) => r.fingerprint.includes(part));

// Canned responses: no network in tests.
const KEV = { catalogVersion: "test", vulnerabilities: [
  { cveID: "CVE-2020-28500", dateAdded: "2025-12-05", dueDate: "2025-12-12", knownRansomwareCampaignUse: "Known" },
] };
function fakeFetch({ failEpss = false, failOsv = false } = {}) {
  const calls = [];
  const fn = async (url) => {
    calls.push(url);
    const ok = (body) => ({ ok: true, status: 200, json: async () => body });
    if (url === KEV_URL) return ok(KEV);
    if (url.startsWith(OSV_URL)) {
      if (failOsv) return { ok: false, status: 503, json: async () => ({}) };
      const id = decodeURIComponent(url.slice(OSV_URL.length));
      return ok({ id, aliases: id === "GHSA-29mw-wpgm-hmr9" ? ["CVE-2020-28500"] : [`CVE-2099-${id.slice(5, 9)}`] });
    }
    if (url.startsWith(EPSS_URL)) {
      if (failEpss) throw new Error("network down");
      const cves = new URL(url).searchParams.get("cve").split(",");
      return ok({ data: cves.map((c) => ({ cve: c, epss: c === "CVE-2020-28500" ? "0.912000000" : "0.003000000", percentile: "0.5", date: "2026-10-29" })) });
    }
    throw new Error(`unexpected ${url}`);
  };
  fn.calls = calls;
  return fn;
}

test("advisoryIds reads the fingerprint segment and ext.advisory_ids", () => {
  assert.deepEqual(advisoryIds({ fingerprint: "dependency-audit/GHSA-29mw-wpgm-hmr9/package-lock.json/lodash" }), ["GHSA-29mw-wpgm-hmr9"]);
  assert.deepEqual(advisoryIds({ fingerprint: "dependency-audit/CWE-915/src/routes/notes.js/patchNote" }), []);
  assert.deepEqual(advisoryIds({ fingerprint: "x/y/z", ext: { advisory_ids: ["CVE-2021-44228"] } }), ["CVE-2021-44228"]);
});

test("enrich adds KEV and EPSS ext keys, and the output still validates", async () => {
  const f = fakeFetch();
  const { findings, unchecked } = await enrich(example, { fetch: f });
  assert.equal(unchecked, 0);
  assert.deepEqual(validateFindings(findings), []);
  const lodash = byFp(findings, "GHSA-29mw-wpgm-hmr9");
  assert.equal(lodash.ext.in_kev, true);
  assert.equal(lodash.ext.kev_date_added, "2025-12-05");
  assert.equal(lodash.ext.kev_ransomware_use, "Known");
  assert.equal(lodash.ext.epss, 0.912);
  assert.deepEqual(lodash.ext.advisory_ids, ["GHSA-29mw-wpgm-hmr9", "CVE-2020-28500"]);
  const other = byFp(findings, "GHSA-27r3-jxmh-p828");
  assert.equal(other.ext.in_kev, false);
  assert.equal(other.ext.kev_date_added, undefined);
  // Non-advisory records are untouched; verdicts and severities never change.
  assert.equal(byFp(findings, "CWE-915").ext, undefined);
  findings.forEach((r, i) => {
    assert.equal(r.verdict, example[i].verdict);
    assert.deepEqual(r.severity, example[i].severity);
  });
  // KEV downloaded once; EPSS batched (26 CVEs -> one call).
  assert.equal(f.calls.filter((u) => u === KEV_URL).length, 1);
  assert.equal(f.calls.filter((u) => u.startsWith(EPSS_URL)).length, 1);
});

test("failed lookups are recorded as not checked, never guessed", async () => {
  const { findings, unchecked } = await enrich(example, { fetch: fakeFetch({ failEpss: true }) });
  assert.ok(unchecked > 0);
  const r = byFp(findings, "GHSA-29mw-wpgm-hmr9");
  assert.equal(r.ext.in_kev, true);
  assert.equal(r.ext.epss, "not checked");
  const off = await enrich(example, { offline: true, fetch: () => { throw new Error("no network"); } });
  assert.equal(byFp(off.findings, "GHSA-29mw-wpgm-hmr9").ext.in_kev, "not checked");
  assert.deepEqual(validateFindings(off.findings), []);
  const osvDown = await enrich(example, { fetch: fakeFetch({ failOsv: true }) });
  assert.equal(byFp(osvDown.findings, "GHSA-29mw-wpgm-hmr9").ext.in_kev, "not checked");
});

test("to-sarif tags KEV-listed results and carries EPSS", async () => {
  const { findings } = await enrich(example, { fetch: fakeFetch() });
  const rec = byFp(findings, "GHSA-27r3-jxmh-p828");
  rec.ext.in_kev = true;
  const run = toSarif(findings).runs[0];
  const i = run.results.findIndex((r) => r.ruleId === rec.fingerprint);
  assert.ok(run.tool.driver.rules[i].properties.tags.includes("kev"));
  assert.deepEqual(run.results[i].properties.tags, ["kev"]);
  assert.equal(run.results[i].properties.epss, 0.003);
});

test("CLI: usage errors exit 2; --offline exits 1 with valid output", () => {
  assert.equal(spawnSync(process.execPath, [CLI], { encoding: "utf8" }).status, 2);
  const r = spawnSync(process.execPath, [CLI, EXAMPLE, "--offline"], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.deepEqual(validateFindings(JSON.parse(r.stdout)), []);
  assert.match(r.stderr, /not checked/);
});
