#!/usr/bin/env node

/**
 * Merge per-skill SkillSpector SARIF files into one upload for GitHub code scanning.
 *
 * Each input is named <skill>.sarif and holds results with paths relative to the
 * skill (`SKILL.md`). This rewrites every artifact URI to `skills/<skill>/<uri>` so
 * alerts land on the right file, and folds every per-skill run into ONE run: GitHub
 * code scanning rejects uploads with more than 20 runs, and the catalog has more skills
 * than that. Rules are de-duplicated by id and ruleIndex / artifact indexes are remapped.
 *
 * Results SkillSpector already suppressed via .skillspector-baseline.yaml (they carry a
 * `suppressions` entry with the baseline reason) are dropped: code scanning ignores
 * `kind: external` suppressions and would raise every intentional example as an alert.
 * Unbaselined findings still fail the scan job before this step runs.
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

const run = {
  tool: { driver: { name: "skillspector", rules: [] } },
  automationDetails: { id: "skillspector/" },
  artifacts: [],
  results: [],
  invocations: [{ executionSuccessful: true }],
};
const ruleIds = new Map();
let inputs = 0;
let suppressed = 0;
for (const file of readdirSync(dir).filter((f) => f.endsWith(".sarif")).sort()) {
  const skill = basename(file, ".sarif");
  const sarif = JSON.parse(readFileSync(join(dir, file), "utf8"));
  for (const r of sarif.runs ?? []) {
    inputs++;
    const driver = r.tool?.driver ?? {};
    if (driver.version) run.tool.driver.version = driver.version;
    const localRules = driver.rules ?? [];
    for (const rule of localRules) {
      if (!ruleIds.has(rule.id)) {
        ruleIds.set(rule.id, run.tool.driver.rules.length);
        run.tool.driver.rules.push(rule);
      }
    }
    const artifactOffset = run.artifacts.length;
    rewrite(r.artifacts ?? [], skill);
    run.artifacts.push(...(r.artifacts ?? []));
    rewrite(r.results ?? [], skill);
    for (const res of r.results ?? []) {
      if ((res.suppressions ?? []).some((x) => x.status === undefined || x.status === "accepted")) {
        suppressed++;
        continue;
      }
      const id = res.ruleId ?? localRules[res.ruleIndex]?.id;
      if (id !== undefined && ruleIds.has(id)) res.ruleIndex = ruleIds.get(id);
      else delete res.ruleIndex;
      for (const loc of res.locations ?? []) {
        const al = loc.physicalLocation?.artifactLocation;
        if (al && Number.isInteger(al.index)) al.index += artifactOffset;
      }
      run.results.push(res);
    }
    for (const inv of r.invocations ?? []) {
      if (inv.executionSuccessful === false) run.invocations[0].executionSuccessful = false;
    }
  }
}
if (run.tool.driver.rules.length === 0) delete run.tool.driver.rules;
if (run.artifacts.length === 0) delete run.artifacts;
run.properties = { baselineSuppressed: suppressed };
const merged = { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [run] };
writeFileSync(out, JSON.stringify(merged, null, 2) + "\n");
console.log(`merged ${inputs} per-skill run(s) into 1 run with ${run.results.length} result(s) in ${out} (${suppressed} baselined result(s) dropped)`);
