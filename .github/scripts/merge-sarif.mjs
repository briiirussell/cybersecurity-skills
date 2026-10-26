#!/usr/bin/env node

/**
 * Merge per-skill SkillSpector SARIF files into one upload for GitHub code scanning.
 *
 * Each input is named <skill>.sarif and holds results with paths relative to the
 * skill (`SKILL.md`). This rewrites every artifact URI to `skills/<skill>/<uri>` so
 * alerts land on the right file, and gives each run its own automationDetails.id
 * (`skillspector/<skill>/`) so GitHub treats them as distinct analyses.
 *
 * Usage: node .github/scripts/merge-sarif.mjs <dir-of-sarif-files> <out.sarif>
 */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, basename } from "node:path";

const [dir, out] = process.argv.slice(2);
if (!dir || !out) {
  console.error("usage: merge-sarif.mjs <dir> <out.sarif>");
  process.exit(2);
}

const rewrite = (node, skill) => {
  if (Array.isArray(node)) return node.forEach((n) => rewrite(n, skill));
  if (!node || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if (key === "artifactLocation" && value && typeof value.uri === "string" && !/^[a-z]+:|^\//i.test(value.uri)) {
      value.uri = `skills/${skill}/${value.uri.replace(/^\.\//, "")}`;
    } else rewrite(value, skill);
  }
};

const merged = { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [] };
for (const file of readdirSync(dir).filter((f) => f.endsWith(".sarif")).sort()) {
  const skill = basename(file, ".sarif");
  const sarif = JSON.parse(readFileSync(join(dir, file), "utf8"));
  for (const run of sarif.runs ?? []) {
    rewrite(run.results ?? [], skill);
    rewrite(run.artifacts ?? [], skill);
    run.automationDetails = { id: `skillspector/${skill}/` };
    merged.runs.push(run);
  }
}
writeFileSync(out, JSON.stringify(merged, null, 2) + "\n");
console.log(`merged ${merged.runs.length} run(s) into ${out}`);
