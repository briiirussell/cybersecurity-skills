#!/usr/bin/env node
// betterleaks-to-findings.mjs: turn a Betterleaks v2 report (.json or .jsonl) into findings.json records. Zero dependencies.
//
// Usage:  node betterleaks-to-findings.mjs <report.json | report.jsonl | -> [-o findings.json]
// Exit:   0 written; 1 the records failed validation (nothing written); 2 usage / read / parse error.
//
// One record per (rule, value): the same key found in five files or commits is one finding with five evidence
// entries. The fingerprint is the scanner-pipeline dedupe key, secret:<rule_id>:<first 12 hex of match.fingerprint>.
// Betterleaks computes match.fingerprint from the value before redacting, so --redact reports still dedupe; an
// HMAC fingerprint (--hmac-key) drops its "hmac-sha256:" prefix first. Every record is imported as
// needs_validation, the scanner-pipeline import rule; finding-triage sets the verdict and severity. A validation
// result from an approved -v / -a run is kept in ext.validation for triage to use.
//
// Run Betterleaks from the repo root so paths are repo-relative. The report must be redacted: a record whose
// match.value isn't "REDACTED" is refused, because findings.json must never hold a secret.

import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { validateFindings } from "./validate-findings.mjs";

/** Parse a Betterleaks v2 report: a JSON object {findings, scan}, or JSON Lines of {finding} / {scan}. */
export function parseReport(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith("{") && !trimmed.includes("\n{")) {
    const doc = JSON.parse(trimmed);
    return { findings: doc.findings ?? [], scan: doc.scan ?? null };
  }
  const findings = [];
  let scan = null;
  for (const line of trimmed.split("\n").filter((l) => l.trim())) {
    const rec = JSON.parse(line);
    if (rec.finding) findings.push(rec.finding);
    else if (rec.scan) scan = rec.scan;
  }
  return { findings, scan };
}

/** First 12 hex chars of the value hash, extended past 12 only if they're all digits (the validator reads `:<digits>` as a line number). */
function shortHash(fp) {
  const hex = String(fp).replace(/^hmac-sha256:/, "");
  if (!/^[0-9a-f]{12,}$/.test(hex)) throw new Error(`unexpected match.fingerprint ${JSON.stringify(fp)}`);
  let n = 12;
  while (n < hex.length && /^\d+$/.test(hex.slice(0, n))) n++;
  return hex.slice(0, n);
}

const relPath = (p) => String(p).replace(/^\.\//, "");
const statusOf = (f) => f.validation?.status ?? f.analysis?.status ?? null;

function evidenceFor(h) {
  const sha = h.attributes?.["git.sha"];
  const commit = sha ? ", commit " + sha.slice(0, 12) : "";
  const conf = h.confidence ?? "unknown";
  return { file: h.path, line: Math.max(1, h.location?.start_line ?? 1), description: "Betterleaks " + h.rule_id + " (confidence " + conf + ")" + commit + "; value redacted" };
}

function planFor(path) {
  const cmd = "betterleaks fs " + path + " -v --redact --silent -o .security/out/validate.json";
  return "After the owner says yes, re-scan with liveness checks: " + cmd + " (secrets-audit, references/betterleaks.md).";
}

/** Convert parsed Betterleaks findings to sorted findings.json records. */
export function toFindings({ findings, scan }) {
  const scanner = `betterleaks@${scan?.betterleaks_version ?? "unknown"}`;
  const groups = new Map();
  for (const f of findings) {
    if (f.match?.value !== undefined && f.match.value !== "REDACTED")
      throw new Error(`unredacted value in a ${f.rule_id} finding at ${f.location?.path}: re-run Betterleaks with --redact`);
    const path = relPath(f.location?.path ?? "");
    if (!path || path.startsWith("/") || path.startsWith("~") || /^[A-Za-z]:/.test(path))
      throw new Error(`path ${JSON.stringify(f.location?.path)} isn't repo-relative: run Betterleaks from the repo root`);
    const fingerprint = `secret:${f.rule_id}:${shortHash(f.match.fingerprint)}`;
    if (!groups.has(fingerprint)) groups.set(fingerprint, { first: f, hits: [] });
    groups.get(fingerprint).hits.push({ ...f, path });
  }
  const out = [];
  for (const [fingerprint, { first, hits }] of groups) {
    const files = [...new Set(hits.map((h) => h.path))];
    const status = hits.map(statusOf).find(Boolean);
    const ext = { detector: first.rule_id, scanner, value_fingerprint: first.match.fingerprint, rule_hash: first.rule_hash };
    if (status) ext.validation = status;
    out.push({
      fingerprint,
      verdict: "needs_validation",
      skill: "scanner-pipeline",
      title: `${first.rule_id} secret in ${files.length === 1 ? files[0] : `${files.length} files`}`,
      location: { file: hits[0].path, line: Math.max(1, hits[0].location?.start_line ?? 1) },
      trace: [],
      evidence: hits.map(evidenceFor),
      counterevidence: "Imported from a Betterleaks scan; not yet triaged. The value was redacted, so nothing here shows whether it is live, a placeholder or a test key.",
      confidence: "medium",
      blockers: ["scanner result, not yet triaged", status === "valid" ? "validated live: rotate first (secrets-audit)" : "whether the key is live"],
      validation_plan: planFor(hits[0].path),
      ext,
    });
  }
  return out.sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
}

function main(argv) {
  const args = argv.slice(2);
  let out = null;
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-o" || args[i] === "--output") out = args[++i] ?? "";
    else pos.push(args[i]);
  }
  if (pos.length !== 1 || pos[0] === "-h" || pos[0] === "--help" || out === "") {
    console.error("usage: node betterleaks-to-findings.mjs <report.json | report.jsonl | -> [-o findings.json]");
    return 2;
  }
  let records;
  try {
    records = toFindings(parseReport(readFileSync(pos[0] === "-" ? 0 : pos[0], "utf8")));
  } catch (err) {
    console.error(`error: ${err.message}`);
    return 2;
  }
  const errors = validateFindings(records);
  if (errors.length) {
    for (const e of errors) console.error(e);
    console.error("error: converted records are invalid; nothing written");
    return 1;
  }
  const text = JSON.stringify(records, null, 2) + "\n";
  if (out) writeFileSync(out, text);
  else process.stdout.write(text);
  return 0;
}

const invokedDirectly = (() => {
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();
if (invokedDirectly) process.exitCode = main(process.argv);
