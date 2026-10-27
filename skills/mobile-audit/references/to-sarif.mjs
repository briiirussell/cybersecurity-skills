#!/usr/bin/env node
// to-sarif.mjs: convert findings.json to SARIF 2.1.0 (e.g. for GitHub code scanning). Zero dependencies.
//
// Usage:  node to-sarif.mjs findings.json [--include-needs-validation] [-o out.sarif]
//         ("-" reads stdin; output goes to stdout unless -o is given)
// Exit:   0 written, 1 findings.json failed validation (nothing written), 2 usage / read / parse error.
//
// Mapping:
//   - Only `confirmed` records become results by default. `rejected` records are never exported.
//   - --include-needs-validation also exports `needs_validation` records at level "note", with no
//     security-severity, properties.verdict = "needs_validation", and the blockers + validation plan in the message.
//   - Confirmed with disposition "Fixed" is skipped (nothing left to alert on). "Accepted Risk" and
//     "Mitigated (platform/config)" are exported with an accepted external suppression, so they show as dismissed.
//   - fingerprint -> partialFingerprints["cybersecuritySkills/v1"] and the rule id (one rule per finding, so
//     each rule's security-severity matches its single result).
//   - severity.overall -> rule + result property "security-severity" (critical 9.5, high 8.0, medium 5.5, low 3.0)
//     and level (critical/high -> error, medium -> warning, low -> note).
//   - trace[] -> codeFlows[0].threadFlows[0].locations; evidence[] -> relatedLocations.
//   - ext (skill-specific fields) -> result properties.ext, unchanged.
//   - Paths are emitted relative to uriBaseId "%SRCROOT%".

import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { validateFindings, readJson } from "./validate-findings.mjs";

export const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };
export const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };
const FP_KEY = "cybersecuritySkills/v1";
const SUPPRESSED = new Set(["Accepted Risk", "Mitigated (platform/config)"]);

function physical(file, line) {
  return {
    physicalLocation: {
      artifactLocation: { uri: file.split("/").map(encodeURIComponent).join("/"), uriBaseId: "%SRCROOT%" },
      region: { startLine: line },
    },
  };
}

function ruleFor(rec) {
  const tags = ["security"];
  if (rec.cwe) tags.push(`external/cwe/${rec.cwe.toLowerCase()}`);
  if (rec.owasp_category) tags.push(`owasp/${rec.owasp_category}`);
  const properties = { tags, skill: rec.skill };
  if (rec.verdict === "confirmed") properties["security-severity"] = SECURITY_SEVERITY[rec.severity.overall];
  const rule = {
    id: rec.fingerprint,
    shortDescription: { text: rec.title },
    properties,
  };
  if (rec.cwe) rule.helpUri = `https://cwe.mitre.org/data/definitions/${rec.cwe.slice(4)}.html`;
  return rule;
}

function messageFor(rec) {
  if (rec.verdict === "confirmed") {
    const s = rec.severity;
    return `${rec.title}. Severity ${s.overall} (likelihood ${s.likelihood.score}: ${s.likelihood.reason}; impact ${s.impact.score}: ${s.impact.reason}).`;
  }
  return `Needs validation: ${rec.title}. Blockers: ${rec.blockers.join("; ")}. Validation plan: ${rec.validation_plan}`;
}

function resultFor(rec, ruleIndex) {
  const result = {
    ruleId: rec.fingerprint,
    ruleIndex,
    level: rec.verdict === "confirmed" ? LEVEL[rec.severity.overall] : "note",
    message: { text: messageFor(rec) },
    locations: [physical(rec.location.file, rec.location.line)],
    partialFingerprints: { [FP_KEY]: rec.fingerprint },
    properties: { verdict: rec.verdict, confidence: rec.confidence, skill: rec.skill },
  };
  if (rec.verdict === "confirmed") {
    result.properties["security-severity"] = SECURITY_SEVERITY[rec.severity.overall];
    if (rec.disposition) result.properties.disposition = rec.disposition;
    if (SUPPRESSED.has(rec.disposition))
      result.suppressions = [{ kind: "external", status: "accepted", justification: `Disposition: ${rec.disposition}` }];
  }
  if (rec.ext) result.properties.ext = rec.ext;
  if (rec.trace.length > 0) {
    result.codeFlows = [
      {
        threadFlows: [
          {
            locations: rec.trace.map((t) => ({
              location: { ...physical(t.file, t.line), message: { text: t.description } },
              kinds: [t.kind],
            })),
          },
        ],
      },
    ];
  }
  if (rec.evidence.length > 0) {
    result.relatedLocations = rec.evidence.map((e, id) => ({ id, ...physical(e.file, e.line), message: { text: e.description } }));
  }
  return result;
}

/**
 * Convert a findings array (must already be valid) to a SARIF 2.1.0 log object.
 * @param {object[]} findings
 * @param {{includeNeedsValidation?: boolean}} [opts]
 */
export function toSarif(findings, opts = {}) {
  const selected = findings.filter((r) => {
    if (r.verdict === "confirmed") return r.disposition !== "Fixed";
    if (r.verdict === "needs_validation") return Boolean(opts.includeNeedsValidation);
    return false;
  });
  const rules = selected.map(ruleFor);
  const results = selected.map((r, i) => resultFor(r, i));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "cybersecurity-skills",
            informationUri: "https://github.com/briiirussell/cybersecurity-skills",
            rules,
          },
        },
        originalUriBaseIds: { "%SRCROOT%": { description: { text: "Repository root" } } },
        results,
      },
    ],
  };
}

function main(argv) {
  const args = argv.slice(2);
  let out = null;
  let includeNV = false;
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-o" || args[i] === "--output") out = args[++i] ?? "";
    else if (args[i] === "--include-needs-validation") includeNV = true;
    else pos.push(args[i]);
  }
  if (pos.length !== 1 || pos[0] === "-h" || pos[0] === "--help" || out === "") {
    console.error("usage: node to-sarif.mjs <findings.json | -> [--include-needs-validation] [-o out.sarif]");
    return 2;
  }
  let data;
  try {
    data = readJson(pos[0]);
  } catch (err) {
    console.error(`error: cannot read ${pos[0]}: ${err.message}`);
    return 2;
  }
  const errors = validateFindings(data);
  if (errors.length) {
    for (const e of errors) console.error(e);
    console.error(`\n${pos[0]}: INVALID, no SARIF written. Fix the problems above (node validate-findings.mjs ${pos[0]}).`);
    return 1;
  }
  const sarif = JSON.stringify(toSarif(data, { includeNeedsValidation: includeNV }), null, 2) + "\n";
  if (out) {
    writeFileSync(out, sarif);
    console.error(`wrote ${out}`);
  } else process.stdout.write(sarif);
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
