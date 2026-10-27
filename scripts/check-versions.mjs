#!/usr/bin/env node

/**
 * Check that versions are in sync, and (with --base) that a change bumped them. Zero dependencies.
 *
 * Always:
 *   - .claude-plugin/plugin.json `version` equals marketplace.json `metadata.version`
 *   - VERSIONS.md has a `### <version> (YYYY-MM-DD)` entry for that version
 *   - every skills/<name>/ folder has a VERSIONS.md row, and every row has a folder
 *   - every row version is x.y.z
 *
 * With --base <git-ref> (CI passes the PR's base branch):
 *   - the repo version is higher than the base's
 *   - every skill with a changed file under skills/<name>/ has a higher row version than the base's,
 *     except changes that only touch generated copies of shared/ files (skills/<name>/references/<file>
 *     listed in shared/manifest.json), which follow the shared/ change
 *
 * Usage: node scripts/check-versions.mjs [--base origin/development]
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

const ROOT = new URL("..", import.meta.url).pathname;
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

/** Parse VERSIONS.md: { rows: Map(skill -> version), entries: Set(version) }. */
export function parseVersions(text) {
  const rows = new Map();
  const [head] = text.split("## Recent Changes");
  for (const m of head.matchAll(/^\|\s*([a-z][a-z0-9-]*)\s*\|\s*([^|\s]+)\s*\|/gm)) {
    if (m[1] !== "Skill") rows.set(m[1], m[2]);
  }
  const entries = new Set([...text.matchAll(/^### (\d+\.\d+\.\d+) \(\d{4}-\d{2}-\d{2}\)/gm)].map((m) => m[1]));
  return { rows, entries };
}

/** Compare x.y.z strings: <0, 0, >0. */
export function cmpSemver(a, b) {
  const pa = SEMVER.exec(a).slice(1).map(Number);
  const pb = SEMVER.exec(b).slice(1).map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

/** Repo version from plugin.json and marketplace.json text. Returns { plugin, marketplace }. */
export function repoVersions(pluginText, marketplaceText) {
  return { plugin: JSON.parse(pluginText).version, marketplace: JSON.parse(marketplaceText).metadata?.version };
}

/**
 * Pure check. `head` and `base` are { plugin, marketplace, versionsText }; `base` may be null.
 * `skillDirs` lists skills/ folders; `changed` lists changed repo paths; `generated` is a Set of
 * generated shared-copy paths. Returns a list of error strings.
 */
export function check({ head, base = null, skillDirs, changed = [], generated = new Set() }) {
  const errors = [];
  const hv = repoVersions(head.plugin, head.marketplace);
  if (!SEMVER.test(hv.plugin ?? "")) errors.push(`plugin.json version "${hv.plugin}" is not x.y.z`);
  if (hv.plugin !== hv.marketplace)
    errors.push(`plugin.json (${hv.plugin}) and marketplace.json metadata.version (${hv.marketplace}) differ`);

  const { rows, entries } = parseVersions(head.versionsText);
  if (hv.plugin && !entries.has(hv.plugin)) errors.push(`VERSIONS.md has no "### ${hv.plugin} (YYYY-MM-DD)" entry`);
  for (const dir of skillDirs) if (!rows.has(dir)) errors.push(`VERSIONS.md has no row for skills/${dir}/`);
  for (const [name, v] of rows) {
    if (!skillDirs.includes(name)) errors.push(`VERSIONS.md row "${name}" has no skills/${name}/ folder`);
    if (!SEMVER.test(v)) errors.push(`VERSIONS.md row "${name}" version "${v}" is not x.y.z`);
  }

  if (base && changed.length && SEMVER.test(hv.plugin ?? "")) {
    const bv = repoVersions(base.plugin, base.marketplace).plugin;
    if (SEMVER.test(bv ?? "") && cmpSemver(hv.plugin, bv) <= 0)
      errors.push(`repo version ${hv.plugin} is not higher than the base's ${bv}; every merge gets its own version`);

    const baseRows = parseVersions(base.versionsText).rows;
    const touched = new Set();
    for (const path of changed) {
      const m = /^skills\/([^/]+)\//.exec(path);
      if (m && !generated.has(path)) touched.add(m[1]);
    }
    for (const name of touched) {
      const now = rows.get(name);
      const was = baseRows.get(name);
      if (!now || !was || !SEMVER.test(now) || !SEMVER.test(was)) continue; // new or removed skill: covered above
      if (cmpSemver(now, was) <= 0)
        errors.push(`skills/${name}/ changed but its VERSIONS.md row is still ${now}; bump it (fix = PATCH, improvement = MINOR)`);
    }
  }
  return errors;
}

function git(...args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" });
}

function generatedCopies() {
  const manifest = JSON.parse(readFileSync(join(ROOT, "shared", "manifest.json"), "utf8"));
  const out = new Set();
  for (const [file, skills] of Object.entries(manifest.files ?? {}))
    for (const skill of skills) out.add(`skills/${skill}/references/${file}`);
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const i = process.argv.indexOf("--base");
  const baseRef = i > 0 ? process.argv[i + 1] : null;
  const read = (p) => readFileSync(join(ROOT, p), "utf8");
  const head = {
    plugin: read(".claude-plugin/plugin.json"),
    marketplace: read(".claude-plugin/marketplace.json"),
    versionsText: read("VERSIONS.md"),
  };
  const skillDirs = readdirSync(join(ROOT, "skills")).filter((d) => existsSync(join(ROOT, "skills", d, "SKILL.md")));
  let base = null;
  let changed = [];
  if (baseRef) {
    const show = (p) => git("show", `${baseRef}:${p}`);
    base = { plugin: show(".claude-plugin/plugin.json"), marketplace: show(".claude-plugin/marketplace.json"), versionsText: show("VERSIONS.md") };
    changed = git("diff", "--name-only", `${baseRef}...HEAD`).split("\n").filter(Boolean);
  }
  const errors = check({ head, base, skillDirs, changed, generated: generatedCopies() });
  for (const e of errors) console.error(`error: ${e}`);
  const v = repoVersions(head.plugin, head.marketplace).plugin;
  console.log(`check-versions: ${v}${baseRef ? ` vs ${baseRef} (${changed.length} changed file(s))` : ""}, ${errors.length} error(s)`);
  process.exit(errors.length ? 1 : 0);
}
