#!/usr/bin/env node
// validate-coverage.mjs: zero-dependency validator for coverage.json.
//
// Usage:  node validate-coverage.mjs coverage.json [--findings findings.json]
//         ("-" reads coverage from stdin)
// Exit:   0 valid, 1 invalid (one message per problem on stderr), 2 usage / read / JSON parse error.
//
// Mirrors coverage.schema.json and adds the cross-field rules:
//   - unique unit ids, safe repo-relative reviewed_paths
//   - covered    => >= 1 reviewed path and >= 1 check
//   - candidate  => >= 1 finding fingerprint
//   - blocked    => >= 1 unresolved item
//   - with --findings: every finding_fingerprints entry must exist in findings.json, and a covered unit may list
//     only rejected records (a confirmed or needs_validation finding keeps its unit at candidate)
//
// The coverage-ledger idea is adapted from cloudflare/security-audit-skill (MIT, Copyright (c) Cloudflare, Inc.).
// The code is this repo's own.

import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const STATUSES = ["planned", "in_progress", "blocked", "covered", "candidate", "deferred", "out_of_scope", "not_applicable"];
const FIELDS = ["id", "surface", "boundary", "owasp_category", "status", "reviewed_paths", "checks", "finding_fingerprints", "unresolved"];
const ID_RE = /^[A-Za-z0-9.][A-Za-z0-9._:/@+-]{0,199}$/;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isText = (v) => typeof v === "string" && /\S/.test(v);

function unsafePathReason(p) {
  if (typeof p !== "string" || p.length === 0) return "must be a non-empty string";
  if (p.includes("\0")) return "contains a NUL byte";
  if (p.includes("\\")) return "uses a backslash (use forward slashes)";
  if (p.startsWith("/")) return "is absolute (must be repo-relative)";
  if (p.startsWith("~")) return "starts with ~ (must be repo-relative)";
  if (/^[A-Za-z]:/.test(p)) return "has a drive letter (must be repo-relative)";
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(p)) return "is a URL (must be a repo-relative path)";
  if (p.split("/").some((seg) => seg === "..")) return "contains a '..' segment";
  return null;
}

function textArray(v, where, errors) {
  if (!Array.isArray(v)) return errors.push(`${where}: must be an array`);
  v.forEach((s, i) => {
    if (!isText(s)) errors.push(`${where}[${i}]: must be a non-empty string`);
  });
}

/** Validate one coverage unit. Returns an array of error strings. */
export function validateUnit(u, where = "unit") {
  const errors = [];
  if (!isObj(u)) return [`${where}: must be an object`];
  for (const k of FIELDS) if (!(k in u)) errors.push(`${where}: missing required field "${k}"`);
  for (const k of Object.keys(u)) if (!FIELDS.includes(k)) errors.push(`${where}: unexpected field "${k}"`);

  if ("id" in u && (typeof u.id !== "string" || !ID_RE.test(u.id)))
    errors.push(`${where}.id: must be 1-200 chars of [A-Za-z0-9._:/@+-], starting alphanumeric`);
  for (const k of ["surface", "boundary"]) if (k in u && !isText(u[k])) errors.push(`${where}.${k}: must be a non-empty string`);
  if ("owasp_category" in u && u.owasp_category !== null && !isText(u.owasp_category))
    errors.push(`${where}.owasp_category: must be a non-empty string or null`);
  if ("status" in u && !STATUSES.includes(u.status))
    errors.push(`${where}.status: must be one of ${STATUSES.join(" | ")} (got ${JSON.stringify(u.status)})`);

  if ("reviewed_paths" in u) {
    if (!Array.isArray(u.reviewed_paths)) errors.push(`${where}.reviewed_paths: must be an array`);
    else
      u.reviewed_paths.forEach((p, i) => {
        const r = unsafePathReason(p);
        if (r) errors.push(`${where}.reviewed_paths[${i}]: path ${JSON.stringify(p)} ${r}`);
      });
  }
  if ("checks" in u) {
    if (!Array.isArray(u.checks)) errors.push(`${where}.checks: must be an array`);
    else
      u.checks.forEach((c, i) => {
        const w = `${where}.checks[${i}]`;
        if (!isObj(c)) return errors.push(`${w}: must be an object {invariant, method, result}`);
        for (const k of ["invariant", "method", "result"]) {
          if (!(k in c)) errors.push(`${w}: missing required field "${k}"`);
          else if (!isText(c[k])) errors.push(`${w}.${k}: must be a non-empty string`);
        }
        for (const k of Object.keys(c)) if (!["invariant", "method", "result"].includes(k)) errors.push(`${w}: unexpected field "${k}"`);
      });
  }
  if ("finding_fingerprints" in u) textArray(u.finding_fingerprints, `${where}.finding_fingerprints`, errors);
  if ("unresolved" in u) textArray(u.unresolved, `${where}.unresolved`, errors);

  const len = (k) => (Array.isArray(u[k]) ? u[k].length : 0);
  if (u.status === "covered") {
    if (len("reviewed_paths") === 0) errors.push(`${where}: status "covered" requires at least one reviewed_paths entry`);
    if (len("checks") === 0) errors.push(`${where}: status "covered" requires at least one check`);
  }
  if (u.status === "candidate" && len("finding_fingerprints") === 0)
    errors.push(`${where}: status "candidate" requires at least one finding_fingerprints entry`);
  if (u.status === "blocked" && len("unresolved") === 0)
    errors.push(`${where}: status "blocked" requires at least one unresolved entry saying what blocks it`);
  return errors;
}

/**
 * Validate a parsed coverage.json document. If `findings` (a parsed findings.json array) is given,
 * every referenced fingerprint must exist in it. Returns an array of error strings (empty = valid).
 */
export function validateCoverage(data, findings = null) {
  if (!Array.isArray(data)) return ["top level: coverage.json must be a JSON array of units"];
  const errors = [];
  const seen = new Map();
  const verdictOf = Array.isArray(findings)
    ? new Map(findings.filter((f) => typeof f?.fingerprint === "string").map((f) => [f.fingerprint, f.verdict]))
    : null;
  data.forEach((u, i) => {
    const id = isObj(u) && typeof u.id === "string" ? u.id : null;
    const where = id ? `[${i}] (${id})` : `[${i}]`;
    errors.push(...validateUnit(u, where));
    if (id) {
      if (seen.has(id)) errors.push(`${where}: duplicate id (also at index ${seen.get(id)})`);
      else seen.set(id, i);
    }
    if (verdictOf && isObj(u) && Array.isArray(u.finding_fingerprints))
      u.finding_fingerprints.forEach((fp, j) => {
        if (typeof fp !== "string") return;
        if (!verdictOf.has(fp)) errors.push(`${where}.finding_fingerprints[${j}]: "${fp}" is not in findings.json`);
        // "Items checked and found clean" is built from covered units, so a covered unit can only hold rejected records.
        else if (u.status === "covered" && verdictOf.get(fp) !== "rejected")
          errors.push(`${where}: status "covered" but "${fp}" is ${verdictOf.get(fp)}; a unit with a confirmed or needs_validation finding stays "candidate"`);
      });
  });
  return errors;
}

function readJson(file) {
  return JSON.parse(readFileSync(file === "-" ? 0 : file, "utf8"));
}

function main(argv) {
  const args = argv.slice(2);
  let findingsPath = null;
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--findings") findingsPath = args[++i];
    else pos.push(args[i]);
  }
  if (pos.length !== 1 || pos[0] === "-h" || pos[0] === "--help" || (args.includes("--findings") && !findingsPath)) {
    console.error("usage: node validate-coverage.mjs <coverage.json | -> [--findings findings.json]");
    return 2;
  }
  let data;
  let findings = null;
  try {
    data = readJson(pos[0]);
    if (findingsPath) findings = readJson(findingsPath);
  } catch (err) {
    console.error(`error: ${err.message}`);
    return 2;
  }
  if (findingsPath && !Array.isArray(findings)) {
    console.error(`error: ${findingsPath} must be a JSON array (run validate-findings.mjs on it first)`);
    return 2;
  }
  const errors = validateCoverage(data, findings);
  if (errors.length) {
    for (const e of errors) console.error(e);
    console.error(`\n${pos[0]}: INVALID (${errors.length} problem${errors.length === 1 ? "" : "s"})`);
    return 1;
  }
  const by = {};
  for (const u of data) by[u.status] = (by[u.status] || 0) + 1;
  const summary = Object.entries(by).map(([k, v]) => `${v} ${k}`).join(", ");
  console.log(`${pos[0]}: OK (${data.length} units${summary ? `: ${summary}` : ""})`);
  return 0;
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMain()) {
  process.exitCode = main(process.argv);
}
