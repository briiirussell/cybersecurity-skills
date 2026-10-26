#!/usr/bin/env node

/**
 * Build adapter files from canonical SKILL.md definitions.
 *
 * 1. Copies shared files (shared/<file>) into skills/<skill>/references/<file> for every skill listed
 *    against that file in shared/manifest.json. Copies are generated: edit shared/, never the copies.
 *    Skills that don't exist yet are skipped with a warning. A stale copy (a file that matches a shared
 *    file name but is no longer mapped to that skill) is removed.
 * 2. Reads skills/<skill-name>/SKILL.md and generates:
 *    - adapters/cursor/<skill-name>.mdc  (Cursor rules format)
 *    - adapters/codex/<skill-name>.md    (Codex instructions format)
 *    Each adapter gets a "Reference files" section linking every skills/<skill>/references/* file on GitHub,
 *    because Cursor/Codex only receive the SKILL.md body.
 *
 * Claude Code adapter is not needed — the canonical SKILL.md files
 * ARE the Claude Code format. Copy skills/ into .claude/skills/ directly.
 *
 * Zero dependencies.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, copyFileSync, rmSync, statSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SKILLS_DIR = join(ROOT, "skills");
const SHARED_DIR = join(ROOT, "shared");
const ADAPTERS_DIR = join(ROOT, "adapters");
const REPO_BLOB = "https://github.com/briiirussell/cybersecurity-skills/blob/main";

// ---------------------------------------------------------------------------
// Frontmatter parsing (small YAML subset, no dependencies)
// ---------------------------------------------------------------------------

/** Parse a YAML scalar: "double" (JSON-style escapes), 'single' ('' escape), or plain. */
function parseScalar(raw) {
  const v = raw.trim();
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
    try {
      return JSON.parse(v);
    } catch {
      return v.slice(1, -1).replace(/\\"/g, '"');
    }
  }
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) return v.slice(1, -1).replace(/''/g, "'");
  // Strip a trailing " # comment" from plain scalars (but not '#' inside a value like "C#").
  return v.replace(/\s+#.*$/, "");
}

/**
 * Parse `---` frontmatter. Supports `key: value` (value may contain colons and parentheses, e.g.
 * `allowed-tools: Read, Bash(git log:*)`), quoted values, block scalars (`|`, `>`, with -/+), and
 * `- item` lists (joined with ", " so list-form allowed-tools reads like the inline form).
 */
export function parseFrontmatter(content) {
  const text = content.replace(/^﻿/, "").replace(/\r\n?/g, "\n");
  const match = text.match(/^---\n([\s\S]*?)\n---[ \t]*(?:\n([\s\S]*))?$/);
  if (!match) return { meta: {}, body: text.trim() };

  const lines = match[1].split("\n");
  const body = (match[2] || "").trim();
  const meta = {};

  for (let i = 0; i < lines.length; i++) {
    const kv = lines[i].match(/^([A-Za-z0-9_-]+):(?:[ \t]+(.*))?$/);
    if (!kv) continue;
    const key = kv[1];
    const rest = (kv[2] || "").trim();

    // Collect following indented lines (block scalar body or list items).
    const block = [];
    while (i + 1 < lines.length && (/^[ \t]+\S/.test(lines[i + 1]) || /^-[ \t]/.test(lines[i + 1]) || lines[i + 1].trim() === "")) {
      if (lines[i + 1].trim() === "" && !(i + 2 < lines.length && /^[ \t]/.test(lines[i + 2]))) break;
      block.push(lines[++i]);
    }

    if (/^[|>][+-]?$/.test(rest)) {
      const indent = Math.min(...block.filter((l) => l.trim()).map((l) => l.match(/^[ \t]*/)[0].length));
      const stripped = block.map((l) => l.slice(Number.isFinite(indent) ? indent : 0));
      meta[key] = rest.startsWith(">")
        ? stripped.join("\n").replace(/([^\n])\n(?=[^\n])/g, "$1 ").trim()
        : stripped.join("\n").trim();
    } else if (rest === "" && block.some((l) => /^\s*-[ \t]/.test(l))) {
      meta[key] = block
        .filter((l) => /^\s*-[ \t]/.test(l))
        .map((l) => parseScalar(l.replace(/^\s*-[ \t]+/, "")))
        .join(", ");
    } else {
      // Plain/quoted scalar, possibly folded across indented continuation lines.
      meta[key] = parseScalar([rest, ...block.map((l) => l.trim())].filter(Boolean).join(" "));
    }
  }

  return { meta, body };
}

function collectSkills(dir) {
  const skills = [];
  for (const entry of readdirSync(dir).sort()) {
    const skillFile = join(dir, entry, "SKILL.md");
    if (existsSync(skillFile)) {
      skills.push({ name: entry, path: skillFile, dir: join(dir, entry) });
    }
  }
  return skills;
}

// ---------------------------------------------------------------------------
// Shared reference copies
// ---------------------------------------------------------------------------

function readManifest() {
  const file = join(SHARED_DIR, "manifest.json");
  if (!existsSync(file)) return null;
  const manifest = JSON.parse(readFileSync(file, "utf-8"));
  if (!manifest || typeof manifest.files !== "object") throw new Error("shared/manifest.json: expected { \"files\": { <file>: [<skill>, ...] } }");
  return manifest.files;
}

/** Copy shared files into skills/<skill>/references/. Returns the number of copies written. */
export function syncSharedReferences({ log = console.log, warn = console.warn } = {}) {
  const files = readManifest();
  if (!files) {
    warn("  (no shared/manifest.json; skipping shared reference copies)");
    return 0;
  }
  const sharedNames = new Set(Object.keys(files));
  const wanted = new Map(); // skill -> Set(file)
  const missingSkills = new Set();
  let copies = 0;

  for (const [file, skills] of Object.entries(files)) {
    const src = join(SHARED_DIR, file);
    if (!existsSync(src)) {
      warn(`  warning: shared/${file} is listed in manifest.json but does not exist; skipping`);
      continue;
    }
    for (const skill of skills) {
      const skillDir = join(SKILLS_DIR, skill);
      if (!existsSync(join(skillDir, "SKILL.md"))) {
        missingSkills.add(skill);
        continue;
      }
      const refDir = join(skillDir, "references");
      mkdirSync(refDir, { recursive: true });
      copyFileSync(src, join(refDir, file));
      if (!wanted.has(skill)) wanted.set(skill, new Set());
      wanted.get(skill).add(file);
      copies++;
    }
  }
  for (const skill of [...missingSkills].sort())
    warn(`  warning: skills/${skill}/SKILL.md not found; skipped its shared reference copies`);

  // Remove stale copies: a shared file name in a skill's references/ that is no longer mapped to it.
  for (const entry of existsSync(SKILLS_DIR) ? readdirSync(SKILLS_DIR) : []) {
    const refDir = join(SKILLS_DIR, entry, "references");
    if (!existsSync(refDir)) continue;
    for (const f of readdirSync(refDir)) {
      if (sharedNames.has(f) && !wanted.get(entry)?.has(f)) {
        rmSync(join(refDir, f));
        log(`  removed stale copy skills/${entry}/references/${f}`);
      }
    }
  }
  log(`Copied ${copies} shared reference file(s).\n`);
  return copies;
}

function listReferences(skill) {
  const refDir = join(skill.dir, "references");
  if (!existsSync(refDir)) return [];
  const out = [];
  const walk = (dir, prefix) => {
    for (const f of readdirSync(dir)) {
      if (f.startsWith(".")) continue;
      const full = join(dir, f);
      if (statSync(full).isDirectory()) walk(full, `${prefix}${f}/`);
      else out.push(`${prefix}${f}`);
    }
  };
  walk(refDir, "");
  return out.sort();
}

// ---------------------------------------------------------------------------
// Adapter generators
// ---------------------------------------------------------------------------

/** "References" section appended to Cursor/Codex adapters, which only receive the SKILL.md body. */
export function buildReferencesSection(skillName, refs) {
  if (refs.length === 0) return "";
  const items = refs.map((f) => `- [references/${f}](${REPO_BLOB}/skills/${skillName}/references/${f})`).join("\n");
  return `\n\n## Reference files

This skill links to supporting files under \`references/\`. They are not inlined in this adapter; open them on GitHub (or in \`skills/${skillName}/references/\` if you have the repo checked out):

${items}
`;
}

function buildCursorRule(meta, body, refsSection) {
  // Escape backslashes and quotes in description for YAML
  const desc = (meta.description || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');

  return `---
description: "${desc}"
globs:
alwaysApply: false
---

${body}${refsSection}`;
}

function buildCodexInstructions(meta, body, refsSection) {
  return `# ${meta.name || "Untitled Skill"}

> ${meta.description || ""}

${body}${refsSection}`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  syncSharedReferences();

  const skills = collectSkills(SKILLS_DIR);

  if (skills.length === 0) {
    console.log("No SKILL.md files found in skills/*/");
    return;
  }

  // Ensure adapter output directories exist
  for (const platform of ["cursor", "codex"]) {
    mkdirSync(join(ADAPTERS_DIR, platform), { recursive: true });
  }

  let count = 0;

  for (const skill of skills) {
    const content = readFileSync(skill.path, "utf-8");
    const { meta, body } = parseFrontmatter(content);
    const refs = listReferences(skill);
    const refsSection = buildReferencesSection(skill.name, refs);

    // Cursor (.mdc)
    const cursorOut = join(ADAPTERS_DIR, "cursor", `${skill.name}.mdc`);
    writeFileSync(cursorOut, buildCursorRule(meta, body, refsSection));

    // Codex (.md)
    const codexOut = join(ADAPTERS_DIR, "codex", `${skill.name}.md`);
    writeFileSync(codexOut, buildCodexInstructions(meta, body, refsSection));

    console.log(`  ${skill.name}/SKILL.md → cursor, codex${refs.length ? ` (+${refs.length} reference link(s))` : ""}`);
    count++;
  }

  console.log(`\nGenerated adapters for ${count} skill(s).`);
}

function isMain() {
  try {
    return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMain()) main();
