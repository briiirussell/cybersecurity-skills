#!/usr/bin/env node

/**
 * Narrow the repo-level .skillspector-baseline.yaml to one skill.
 *
 * SkillSpector rejects --baseline on recursive multi-skill scans and reports file
 * paths relative to the scanned skill (`SKILL.md`), so a single repo-wide rule with
 * `path: "SKILL.md"` would match every skill. Instead, rules in the repo baseline
 * carry `path: "<skill>/SKILL.md"`; this script keeps only the rules for <skill>,
 * strips the `<skill>/` prefix, and prints a SkillSpector v2 baseline as JSON.
 *
 * Usage:
 *   node .github/scripts/skillspector-baseline.mjs <skill> > baseline.json
 *   node .github/scripts/skillspector-baseline.mjs --check     # validate the repo baseline
 *
 * A rule may use "*" as its skill segment for findings that repeat in every skill
 * carrying a build-copied shared file. Such a rule must target references/<file>
 * where <file> exists in shared/, or SKILL.md, and its `message` must contain at
 * least 8 literal (non-wildcard) characters. It is emitted into every skill's slice.
 *
 * Reads a restricted YAML subset: `version: N`, `rules:`, and list items whose
 * fields are one-line double-quoted strings. Zero dependencies.
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("../..", import.meta.url).pathname;
// SKILLSPECTOR_BASELINE overrides the file (the self-tests in scripts/test/ use it).
const BASELINE = process.env.SKILLSPECTOR_BASELINE || join(ROOT, ".skillspector-baseline.yaml");
const FIELDS = new Set(["id", "rule_id", "path", "file", "message", "reason"]);

function parse(text) {
  const rules = [];
  let version = null;
  let inRules = false;
  let current = null;
  text.split("\n").forEach((raw, i) => {
    const line = raw.replace(/^\s*#.*$/, ""); // full-line comments only
    if (!line.trim()) return;
    const top = line.match(/^(\w+):\s*(.*)$/);
    if (top) {
      inRules = top[1] === "rules";
      if (top[1] === "version") version = Number(top[2]);
      else if (!["rules", "scanner_version"].includes(top[1]))
        throw new Error(`line ${i + 1}: unsupported top-level key "${top[1]}"`);
      return;
    }
    if (!inRules) throw new Error(`line ${i + 1}: unexpected content outside rules`);
    const item = line.match(/^\s*(-\s+)?(\w+):\s*"((?:[^"\\]|\\.)*)"\s*$/);
    if (!item) throw new Error(`line ${i + 1}: expected  key: "value"`);
    const [, dash, key, value] = item;
    if (!FIELDS.has(key)) throw new Error(`line ${i + 1}: unknown rule field "${key}"`);
    if (dash) rules.push((current = {}));
    if (!current) throw new Error(`line ${i + 1}: field outside a list item`);
    current[key] = value.replace(/\\(.)/g, "$1");
  });
  return { version, rules };
}

function validate({ version, rules }) {
  const problems = [];
  if (version !== 2) problems.push(`version must be 2 (got ${version})`);
  rules.forEach((r, n) => {
    const where = `rule ${n + 1} (${r.id ?? r.rule_id ?? "?"} ${r.path ?? r.file ?? ""})`;
    const path = r.path ?? r.file;
    if (!(r.id ?? r.rule_id)) problems.push(`${where}: missing id`);
    if (!r.reason?.trim()) problems.push(`${where}: missing reason`);
    if (!r.message) problems.push(`${where}: missing message (keep rules narrow)`);
    const m = path?.match(/^([a-z0-9-]+|\*)\/(.+)$/);
    if (!m) problems.push(`${where}: path must be "<skill>/<file>" or "*/<shared file>"`);
    else if (m[1] === "*") {
      const shared = m[2].match(/^references\/([^/*?]+)$/);
      if (m[2] !== "SKILL.md" && !(shared && existsSync(join(ROOT, "shared", shared[1]))))
        problems.push(`${where}: "*/" rules may only target */SKILL.md or */references/<file in shared/>`);
      if ((r.message ?? "").replace(/[*?]/g, "").length < 8)
        problems.push(`${where}: "*/" rules need a message with at least 8 literal characters`);
    } else if (!existsSync(join(ROOT, "skills", m[1], "SKILL.md")))
      problems.push(`${where}: skill "${m[1]}" does not exist`);
    if (/^\*+$/.test(r.message ?? "") || /^\*+$/.test(r.id ?? ""))
      problems.push(`${where}: wildcard-only id/message would hide new findings`);
  });
  return problems;
}

const arg = process.argv[2];
if (!arg) {
  console.error("usage: skillspector-baseline.mjs <skill> | --check");
  process.exit(2);
}

let baseline;
try {
  baseline = parse(readFileSync(BASELINE, "utf8"));
} catch (e) {
  console.error(`.skillspector-baseline.yaml: ${e.message}`);
  process.exit(1);
}
const problems = validate(baseline);
if (problems.length) {
  for (const p of problems) console.error(`.skillspector-baseline.yaml: ${p}`);
  process.exit(1);
}

if (arg === "--check") {
  console.log(`skillspector baseline: ${baseline.rules.length} rule(s) OK`);
  process.exit(0);
}

if (!existsSync(join(ROOT, "skills", arg, "SKILL.md"))) {
  console.error(`unknown skill "${arg}"`);
  process.exit(2);
}
const rules = [];
for (const { file, path, ...rest } of baseline.rules) {
  const p = path ?? file;
  for (const prefix of [`${arg}/`, "*/"]) {
    if (p.startsWith(prefix)) rules.push({ ...rest, path: p.slice(prefix.length) });
  }
}
process.stdout.write(JSON.stringify({ version: 2, rules }, null, 2) + "\n");
