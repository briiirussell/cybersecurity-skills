#!/usr/bin/env node
// validate-findings.mjs: zero-dependency validator for findings.json.
//
// Usage:  node validate-findings.mjs findings.json      (or "-" to read stdin)
// Exit:   0 valid, 1 invalid (one message per problem on stderr), 2 usage / read / JSON parse error.
//
// Hand-written checks that mirror findings.schema.json and add the rules JSON Schema cannot express:
// sort order, unique fingerprints, path safety, trace order, overall <= impact, and confidence `high`
// requiring a reproduced finding. This script is authoritative where the two disagree.
//
// The verdict-shaped record design and the idea of a zero-dep validator are adapted from
// cloudflare/security-audit-skill (MIT, Copyright (c) Cloudflare, Inc.). The code is this repo's own.

import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const VERDICTS = ["confirmed", "needs_validation", "rejected"];
export const LEVELS = ["low", "medium", "high", "critical"]; // ascending
export const CONFIDENCE = ["high", "medium", "low"];
export const DISPOSITIONS = ["Fixed", "Deferred", "Accepted Risk", "Mitigated (platform/config)", "Requires major migration"];
export const TRACE_KINDS = ["entrypoint", "propagation", "sink"];
export const CONDITION_KINDS = [
  "authentication_level",
  "authorization_role",
  "user_interaction",
  "system_configuration",
  "network_routing",
  "environmental_dependency",
  "data_state",
  "timing_dependency",
  "third_party_dependency",
];

const COMMON = ["fingerprint", "verdict", "skill", "title", "location", "trace", "evidence", "counterevidence", "confidence"];
const OPTIONAL_COMMON = ["cwe", "owasp_category", "ext"];
const SHAPES = {
  confirmed: { required: [...COMMON, "severity", "conditions"], optional: [...OPTIONAL_COMMON, "reproduced", "disposition"] },
  needs_validation: { required: [...COMMON, "blockers", "validation_plan"], optional: OPTIONAL_COMMON },
  rejected: { required: [...COMMON, "ruled_out_by"], optional: OPTIONAL_COMMON },
};

const FINGERPRINT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{2,199}$/;
const SKILL_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const CWE_RE = /^CWE-[1-9][0-9]*$/;
const EXT_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isText = (v) => typeof v === "string" && /\S/.test(v);

/** Returns a reason string if `p` is not a safe repo-relative path, else null. */
export function unsafePathReason(p) {
  if (typeof p !== "string" || p.length === 0) return "must be a non-empty string";
  if (p.includes("\0")) return "contains a NUL byte";
  if (p.includes("\\")) return "uses a backslash (use forward slashes)";
  if (p.startsWith("/")) return "is absolute (must be repo-relative)";
  if (p.startsWith("~")) return "starts with ~ (must be repo-relative)";
  if (/^[A-Za-z]:/.test(p)) return "has a drive letter (must be repo-relative)";
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(p)) return "is a URL (must be a repo-relative file path)";
  if (p.split("/").some((seg) => seg === "..")) return "contains a '..' segment";
  return null;
}

function checkKeys(obj, required, optional, where, errors) {
  for (const k of required) if (!(k in obj)) errors.push(`${where}: missing required field "${k}"`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(obj)) if (!allowed.has(k)) errors.push(`${where}: unexpected field "${k}"`);
}

function checkText(v, where, errors) {
  if (!isText(v)) errors.push(`${where}: must be a non-empty string`);
}

function checkEnum(v, values, where, errors) {
  if (!values.includes(v)) errors.push(`${where}: must be one of ${values.join(" | ")} (got ${JSON.stringify(v)})`);
}

function checkPath(v, where, errors) {
  const reason = unsafePathReason(v);
  if (reason) errors.push(`${where}: path ${JSON.stringify(v)} ${reason}`);
}

function checkLine(v, where, errors) {
  if (!Number.isInteger(v) || v < 1) errors.push(`${where}: must be an integer >= 1 (got ${JSON.stringify(v)})`);
}

function checkLocation(v, where, errors) {
  if (!isObj(v)) return errors.push(`${where}: must be an object {file, line}`);
  checkKeys(v, ["file", "line"], [], where, errors);
  if ("file" in v) checkPath(v.file, `${where}.file`, errors);
  if ("line" in v) checkLine(v.line, `${where}.line`, errors);
}

function checkFileLineDesc(v, where, errors, extraRequired = []) {
  if (!isObj(v)) return errors.push(`${where}: must be an object`);
  checkKeys(v, [...extraRequired, "file", "line", "description"], [], where, errors);
  if ("file" in v) checkPath(v.file, `${where}.file`, errors);
  if ("line" in v) checkLine(v.line, `${where}.line`, errors);
  if ("description" in v) checkText(v.description, `${where}.description`, errors);
}

function checkTrace(trace, where, errors, minItems) {
  if (!Array.isArray(trace)) return errors.push(`${where}: must be an array`);
  if (trace.length < minItems) errors.push(`${where}: needs at least ${minItems} steps (entrypoint ... sink)`);
  trace.forEach((step, i) => {
    checkFileLineDesc(step, `${where}[${i}]`, errors, ["kind"]);
    if (isObj(step) && "kind" in step) checkEnum(step.kind, TRACE_KINDS, `${where}[${i}].kind`, errors);
  });
  if (trace.length > 0) {
    if (trace[0]?.kind !== "entrypoint") errors.push(`${where}: must start with an "entrypoint" step`);
    if (trace[trace.length - 1]?.kind !== "sink") errors.push(`${where}: must end with a "sink" step`);
    trace.slice(1, -1).forEach((step, j) => {
      if (step?.kind === "entrypoint" || step?.kind === "sink")
        errors.push(`${where}[${j + 1}]: "${step.kind}" may only appear at the ${step.kind === "entrypoint" ? "start" : "end"} of the trace`);
    });
  }
}

// ext holds a skill's own fields (a PCI requirement, a cloud account, a MASVS control). Keep it flat so reports and
// SARIF property bags can show it as-is: snake_case keys, scalar values or arrays of scalars.
function checkExt(v, where, errors) {
  if (!isObj(v)) return errors.push(`${where}: must be an object of skill-specific fields`);
  const keys = Object.keys(v);
  if (keys.length === 0) errors.push(`${where}: must not be empty (leave ext out instead)`);
  const scalar = (x) => (typeof x === "string" && x.length > 0) || typeof x === "boolean" || (typeof x === "number" && Number.isFinite(x));
  for (const k of keys) {
    if (!EXT_KEY_RE.test(k)) errors.push(`${where}: key ${JSON.stringify(k)} must be snake_case ([a-z][a-z0-9_]*)`);
    const x = v[k];
    if (Array.isArray(x) ? x.length === 0 || !x.every(scalar) : !scalar(x))
      errors.push(`${where}.${k}: must be a non-empty string, a number, a boolean, or a non-empty array of those`);
  }
}

function checkScored(v, where, errors) {
  if (!isObj(v)) return errors.push(`${where}: must be an object {score, reason}`);
  checkKeys(v, ["score", "reason"], [], where, errors);
  if ("score" in v) checkEnum(v.score, LEVELS, `${where}.score`, errors);
  if ("reason" in v) checkText(v.reason, `${where}.reason`, errors);
}

function checkSeverity(v, where, errors) {
  if (!isObj(v)) return errors.push(`${where}: must be an object {likelihood, impact, overall}`);
  checkKeys(v, ["likelihood", "impact", "overall"], [], where, errors);
  if ("likelihood" in v) checkScored(v.likelihood, `${where}.likelihood`, errors);
  if ("impact" in v) checkScored(v.impact, `${where}.impact`, errors);
  if ("overall" in v) checkEnum(v.overall, LEVELS, `${where}.overall`, errors);
  const o = LEVELS.indexOf(v.overall);
  const i = LEVELS.indexOf(v.impact?.score);
  if (o >= 0 && i >= 0 && o > i)
    errors.push(`${where}.overall: "${v.overall}" exceeds impact "${v.impact.score}" (overall severity must not exceed demonstrated impact)`);
}

/** Validate one record. Returns an array of error strings. */
export function validateRecord(rec, where = "record") {
  const errors = [];
  if (!isObj(rec)) return [`${where}: must be an object`];

  if (!VERDICTS.includes(rec.verdict)) {
    errors.push(`${where}.verdict: must be one of ${VERDICTS.join(" | ")} (got ${JSON.stringify(rec.verdict)})`);
    return errors;
  }
  const shape = SHAPES[rec.verdict];

  // Verdict-specific guidance before the generic unexpected-field message.
  if (rec.verdict !== "confirmed" && "severity" in rec)
    errors.push(`${where}: severity is only allowed on confirmed findings (verdict is "${rec.verdict}")`);
  if (rec.verdict !== "confirmed" && "disposition" in rec)
    errors.push(`${where}: disposition is only allowed on confirmed findings (a false positive is verdict "rejected")`);
  if (rec.verdict !== "needs_validation" && ("blockers" in rec || "validation_plan" in rec))
    errors.push(`${where}: blockers / validation_plan belong only on needs_validation records`);
  if (rec.verdict !== "rejected" && "ruled_out_by" in rec)
    errors.push(`${where}: ruled_out_by belongs only on rejected records`);
  const handled = new Set(["severity", "disposition", "blockers", "validation_plan", "ruled_out_by"]);
  const allowed = new Set([...shape.required, ...shape.optional]);
  for (const k of shape.required) if (!(k in rec)) errors.push(`${where}: missing required field "${k}" for verdict "${rec.verdict}"`);
  for (const k of Object.keys(rec))
    if (!allowed.has(k) && !handled.has(k)) errors.push(`${where}: unexpected field "${k}"`);

  if ("fingerprint" in rec) {
    if (typeof rec.fingerprint !== "string" || !FINGERPRINT_RE.test(rec.fingerprint))
      errors.push(`${where}.fingerprint: must be 3-200 chars of [A-Za-z0-9._:/@+-], starting alphanumeric`);
    else if (/:\d+(?=$|[:/#])/.test(rec.fingerprint))
      errors.push(`${where}.fingerprint: looks like it contains a line number (":${rec.fingerprint.match(/:(\d+)(?=$|[:/#])/)[1]}"); fingerprints identify the root cause and must survive code moving`);
  }
  if ("skill" in rec && (typeof rec.skill !== "string" || !SKILL_RE.test(rec.skill)))
    errors.push(`${where}.skill: must be a lowercase kebab-case skill name`);
  if ("title" in rec) checkText(rec.title, `${where}.title`, errors);
  if ("cwe" in rec && (typeof rec.cwe !== "string" || !CWE_RE.test(rec.cwe)))
    errors.push(`${where}.cwe: must look like "CWE-89"`);
  if ("owasp_category" in rec) checkText(rec.owasp_category, `${where}.owasp_category`, errors);
  if ("ext" in rec) checkExt(rec.ext, `${where}.ext`, errors);
  if ("location" in rec) checkLocation(rec.location, `${where}.location`, errors);
  if ("trace" in rec) checkTrace(rec.trace, `${where}.trace`, errors, rec.verdict === "confirmed" ? 2 : 0);
  if ("evidence" in rec) {
    if (!Array.isArray(rec.evidence)) errors.push(`${where}.evidence: must be an array`);
    else {
      if (rec.verdict === "confirmed" && rec.evidence.length === 0) errors.push(`${where}.evidence: confirmed findings need at least one evidence item`);
      rec.evidence.forEach((e, i) => checkFileLineDesc(e, `${where}.evidence[${i}]`, errors));
    }
  }
  if ("counterevidence" in rec) checkText(rec.counterevidence, `${where}.counterevidence`, errors);
  if ("confidence" in rec) checkEnum(rec.confidence, CONFIDENCE, `${where}.confidence`, errors);

  if (rec.verdict === "confirmed") {
    if ("reproduced" in rec && typeof rec.reproduced !== "boolean") errors.push(`${where}.reproduced: must be a boolean`);
    if (rec.confidence === "high" && rec.reproduced !== true)
      errors.push(`${where}.confidence: "high" requires "reproduced": true (a static-only trace caps confidence at medium)`);
    if ("severity" in rec) checkSeverity(rec.severity, `${where}.severity`, errors);
    if ("conditions" in rec) {
      if (!Array.isArray(rec.conditions)) errors.push(`${where}.conditions: must be an array`);
      else
        rec.conditions.forEach((c, i) => {
          const w = `${where}.conditions[${i}]`;
          if (!isObj(c)) return errors.push(`${w}: must be an object {kind, description}`);
          checkKeys(c, ["kind", "description"], [], w, errors);
          if ("kind" in c) checkEnum(c.kind, CONDITION_KINDS, `${w}.kind`, errors);
          if ("description" in c) checkText(c.description, `${w}.description`, errors);
        });
    }
    if ("disposition" in rec) checkEnum(rec.disposition, DISPOSITIONS, `${where}.disposition`, errors);
  }

  if (rec.verdict === "needs_validation") {
    if ("blockers" in rec) {
      if (!Array.isArray(rec.blockers) || rec.blockers.length === 0)
        errors.push(`${where}.blockers: needs_validation requires a non-empty array of blockers`);
      else rec.blockers.forEach((b, i) => checkText(b, `${where}.blockers[${i}]`, errors));
    }
    if ("validation_plan" in rec) checkText(rec.validation_plan, `${where}.validation_plan`, errors);
  }

  if (rec.verdict === "rejected" && "ruled_out_by" in rec) {
    const r = rec.ruled_out_by;
    const w = `${where}.ruled_out_by`;
    if (!isObj(r)) errors.push(`${w}: must be an object {control, location}`);
    else {
      checkKeys(r, ["control", "location"], [], w, errors);
      if ("control" in r) checkText(r.control, `${w}.control`, errors);
      if ("location" in r) checkLocation(r.location, `${w}.location`, errors);
    }
  }

  return errors;
}

/** Validate a parsed findings.json document. Returns an array of error strings (empty = valid). */
export function validateFindings(data) {
  if (!Array.isArray(data)) return ["top level: findings.json must be a JSON array of records"];
  const errors = [];
  const seen = new Map();
  data.forEach((rec, i) => {
    const fp = isObj(rec) && typeof rec.fingerprint === "string" ? rec.fingerprint : null;
    const where = fp ? `[${i}] (${fp})` : `[${i}]`;
    errors.push(...validateRecord(rec, where));
    if (fp) {
      if (seen.has(fp)) errors.push(`${where}: duplicate fingerprint (also at index ${seen.get(fp)})`);
      else seen.set(fp, i);
    }
  });
  for (let i = 1; i < data.length; i++) {
    const a = data[i - 1]?.fingerprint;
    const b = data[i]?.fingerprint;
    if (typeof a === "string" && typeof b === "string" && a > b) {
      errors.push(`[${i}]: records must be sorted by fingerprint ("${b}" must come before "${a}"); sort with: jq 'sort_by(.fingerprint)'`);
      break;
    }
  }
  return errors;
}

/** Read and parse a findings file ("-" = stdin). Throws on read/parse failure. */
export function readJson(file) {
  const text = readFileSync(file === "-" ? 0 : file, "utf8");
  return JSON.parse(text);
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length !== 1 || args[0] === "-h" || args[0] === "--help") {
    console.error("usage: node validate-findings.mjs <findings.json | ->");
    return 2;
  }
  let data;
  try {
    data = readJson(args[0]);
  } catch (err) {
    console.error(`error: cannot read ${args[0]}: ${err.message}`);
    return 2;
  }
  const errors = validateFindings(data);
  if (errors.length) {
    for (const e of errors) console.error(e);
    console.error(`\n${args[0]}: INVALID (${errors.length} problem${errors.length === 1 ? "" : "s"})`);
    return 1;
  }
  const counts = Object.fromEntries(VERDICTS.map((v) => [v, data.filter((r) => r.verdict === v).length]));
  console.log(`${args[0]}: OK (${data.length} records: ${counts.confirmed} confirmed, ${counts.needs_validation} needs_validation, ${counts.rejected} rejected)`);
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
