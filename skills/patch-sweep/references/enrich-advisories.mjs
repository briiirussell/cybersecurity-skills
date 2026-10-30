#!/usr/bin/env node
// enrich-advisories.mjs: add exploitation signals (CISA KEV, EPSS) to advisory-based findings. Zero dependencies.
//
// Usage:  node enrich-advisories.mjs findings.json [-o out.json] [--kev kev.json] [--offline]
//         ("-" reads stdin; output goes to stdout unless -o is given)
// Exit:   0 written, every advisory checked; 1 written, but some signals are "not checked" (network failed, or
//         --offline), or the input failed validation (nothing written); 2 usage / read / parse error.
//
// What it does, for each record whose advisory ids it can find (ext.advisory_ids, or a GHSA-/CVE-/PYSEC-/RUSTSEC-/
// GO- id as the fingerprint's second segment, e.g. dependency-audit/GHSA-29mw-wpgm-hmr9/package-lock.json/lodash):
//   1. CVE ids: a CVE id is used as is; any other id is resolved through OSV's `aliases`
//      (GET https://api.osv.dev/v1/vulns/<id>). No CVE: the record is left alone (KEV and EPSS need one).
//   2. KEV: the CISA catalog is downloaded once (or read from --kev) and matched on cveID.
//   3. EPSS: GET https://api.first.org/data/v1/epss, 100 CVEs per call.
//   4. Writes ext keys: advisory_ids, in_kev, kev_date_added, kev_due_date, kev_ransomware_use, epss,
//      epss_percentile, epss_date. A lookup that fails sets in_kev / epss to "not checked"; it never guesses.
// It never changes a verdict, severity or disposition. Signals change likelihood and the order of work only
// (severity-calibration.md, "Exploitation signals").
//
// Network: GET requests to api.osv.dev, www.cisa.gov and api.first.org. It sends advisory and CVE ids only,
// never package names or code.

import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { validateFindings, readJson } from "./validate-findings.mjs";

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_URL = "https://api.first.org/data/v1/epss";
export const OSV_URL = "https://api.osv.dev/v1/vulns/";
const ID_RE = /^(CVE|GHSA|PYSEC|RUSTSEC|GO|OSV)-[A-Za-z0-9-]+$/;
const NOT_CHECKED = "not checked";

/** Advisory ids for a record: ext.advisory_ids, else the fingerprint's second segment when it looks like one. */
export function advisoryIds(rec) {
  const ids = Array.isArray(rec.ext?.advisory_ids) ? [...rec.ext.advisory_ids] : [];
  const seg = rec.fingerprint.split("/")[1];
  if (seg && ID_RE.test(seg) && !ids.includes(seg)) ids.unshift(seg);
  return ids.filter((id) => ID_RE.test(id));
}

async function getJson(fetchFn, url) {
  const res = await fetchFn(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

/**
 * Enrich a valid findings array. Returns { findings, unchecked } where unchecked counts records with a
 * "not checked" signal.
 * @param {object[]} findings
 * @param {{fetch?: Function, kev?: object, offline?: boolean}} [opts]  kev: a parsed KEV catalog to use instead of downloading
 */
export async function enrich(findings, opts = {}) {
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const offline = Boolean(opts.offline);
  const out = structuredClone(findings);
  const targets = out.map((rec) => ({ rec, ids: advisoryIds(rec) })).filter((t) => t.ids.length);

  // 1. CVE ids, resolving non-CVE ids through OSV aliases (one call per unique id).
  const aliasCache = new Map();
  async function cvesFor(ids) {
    const cves = new Set(ids.filter((id) => id.startsWith("CVE-")));
    let failed = false;
    for (const id of ids.filter((x) => !x.startsWith("CVE-"))) {
      if (!aliasCache.has(id)) {
        if (offline) aliasCache.set(id, null);
        else {
          try {
            const v = await getJson(fetchFn, OSV_URL + encodeURIComponent(id));
            aliasCache.set(id, (v.aliases ?? []).filter((a) => a.startsWith("CVE-")));
          } catch {
            aliasCache.set(id, null);
          }
        }
      }
      const a = aliasCache.get(id);
      if (a === null) failed = true;
      else a.forEach((c) => cves.add(c));
    }
    return { cves: [...cves], failed };
  }
  for (const t of targets) Object.assign(t, await cvesFor(t.ids));

  // 2. KEV catalog, once.
  let kev = opts.kev ?? null;
  if (!kev && !offline && targets.some((t) => t.cves.length)) {
    try {
      kev = await getJson(fetchFn, KEV_URL);
    } catch {
      kev = null;
    }
  }
  const kevById = new Map((kev?.vulnerabilities ?? []).map((v) => [v.cveID, v]));

  // 3. EPSS, 100 CVEs per call.
  const allCves = [...new Set(targets.flatMap((t) => t.cves))];
  const epss = new Map();
  let epssOk = !offline;
  for (let i = 0; epssOk && i < allCves.length; i += 100) {
    try {
      const page = await getJson(fetchFn, `${EPSS_URL}?cve=${allCves.slice(i, i + 100).join(",")}`);
      for (const d of page.data ?? []) epss.set(d.cve, d);
    } catch {
      epssOk = false;
    }
  }

  // 4. Write ext keys.
  let unchecked = 0;
  for (const { rec, ids, cves, failed } of targets) {
    const ext = { ...(rec.ext ?? {}) };
    ext.advisory_ids = [...new Set([...ids, ...cves])];
    if (cves.length === 0) {
      if (failed) {
        ext.in_kev = NOT_CHECKED;
        ext.epss = NOT_CHECKED;
        unchecked++;
      }
      rec.ext = ext;
      continue;
    }
    if (kev) {
      const hits = cves.map((c) => kevById.get(c)).filter(Boolean);
      ext.in_kev = hits.length > 0;
      for (const k of ["kev_date_added", "kev_due_date", "kev_ransomware_use"]) delete ext[k];
      if (hits.length) {
        const first = hits.sort((a, b) => a.dateAdded.localeCompare(b.dateAdded))[0];
        ext.kev_date_added = first.dateAdded;
        ext.kev_due_date = first.dueDate;
        ext.kev_ransomware_use = hits.some((h) => h.knownRansomwareCampaignUse === "Known") ? "Known" : "Unknown";
      }
    } else ext.in_kev = NOT_CHECKED;
    const scores = cves.map((c) => epss.get(c)).filter(Boolean);
    for (const k of ["epss", "epss_percentile", "epss_date"]) delete ext[k];
    if (scores.length) {
      const top = scores.reduce((a, b) => (Number(b.epss) > Number(a.epss) ? b : a));
      ext.epss = Number(top.epss);
      ext.epss_percentile = Number(top.percentile);
      ext.epss_date = top.date;
    } else if (!epssOk) ext.epss = NOT_CHECKED;
    if (ext.in_kev === NOT_CHECKED || ext.epss === NOT_CHECKED || failed) unchecked++;
    rec.ext = ext;
  }
  return { findings: out, unchecked };
}

async function main(argv) {
  const args = argv.slice(2);
  let out = null;
  let kevFile = null;
  let offline = false;
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-o" || args[i] === "--output") out = args[++i] ?? "";
    else if (args[i] === "--kev") kevFile = args[++i] ?? "";
    else if (args[i] === "--offline") offline = true;
    else pos.push(args[i]);
  }
  if (pos.length !== 1 || pos[0] === "-h" || pos[0] === "--help" || out === "" || kevFile === "") {
    console.error("usage: node enrich-advisories.mjs <findings.json | -> [-o out.json] [--kev kev.json] [--offline]");
    return 2;
  }
  let data, kev;
  try {
    data = readJson(pos[0]);
    if (kevFile) kev = readJson(kevFile);
  } catch (err) {
    console.error(`error: cannot read input: ${err.message}`);
    return 2;
  }
  const errors = validateFindings(data);
  if (errors.length) {
    for (const e of errors) console.error(e);
    console.error(`\n${pos[0]}: INVALID, nothing written. Fix it first (node validate-findings.mjs ${pos[0]}).`);
    return 1;
  }
  const { findings, unchecked } = await enrich(data, { kev, offline });
  const after = validateFindings(findings);
  if (after.length) {
    for (const e of after) console.error(e);
    console.error("error: enrichment produced invalid records; nothing written");
    return 1;
  }
  const text = JSON.stringify(findings, null, 2) + "\n";
  if (out) writeFileSync(out, text);
  else process.stdout.write(text);
  if (unchecked) {
    console.error(`${unchecked} record(s) have a "not checked" signal (offline or a lookup failed). Report them under "Signals not checked".`);
    return 1;
  }
  return 0;
}

const invokedDirectly = (() => {
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();
if (invokedDirectly) process.exitCode = await main(process.argv);
