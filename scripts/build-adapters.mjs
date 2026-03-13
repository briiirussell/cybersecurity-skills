#!/usr/bin/env node

/**
 * Build adapter files from canonical SKILL.md definitions.
 *
 * Reads skills from skills/<skill-name>/SKILL.md and generates:
 * - adapters/cursor/<skill-name>.mdc  (Cursor rules format)
 * - adapters/codex/<skill-name>.md    (Codex instructions format)
 *
 * Claude Code adapter is not needed — the canonical SKILL.md files
 * ARE the Claude Code format. Copy skills/ into .claude/skills/ directly.
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "fs";
import { join, basename, dirname } from "path";

const ROOT = new URL("..", import.meta.url).pathname;
const SKILLS_DIR = join(ROOT, "skills");
const ADAPTERS_DIR = join(ROOT, "adapters");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) return { meta: {}, body: content };

  const raw = match[1];
  const body = match[2].trim();
  const meta = {};

  for (const line of raw.split("\n")) {
    // Match key: "value" or key: value
    const kvMatch = line.match(/^([\w-]+):\s*"?(.*?)"?\s*$/);
    if (kvMatch) {
      meta[kvMatch[1]] = kvMatch[2];
    }
  }

  return { meta, body };
}

function collectSkills(dir) {
  const skills = [];
  for (const entry of readdirSync(dir)) {
    const skillFile = join(dir, entry, "SKILL.md");
    if (existsSync(skillFile)) {
      skills.push({ name: entry, path: skillFile });
    }
  }
  return skills;
}

// ---------------------------------------------------------------------------
// Adapter generators
// ---------------------------------------------------------------------------

function buildCursorRule(meta, body) {
  // Escape quotes in description for YAML
  const desc = (meta.description || "").replace(/"/g, '\\"');

  return `---
description: "${desc}"
globs:
alwaysApply: false
---

${body}`;
}

function buildCodexInstructions(meta, body) {
  return `# ${meta.name || "Untitled Skill"}

> ${meta.description || ""}

${body}`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
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

    // Cursor (.mdc)
    const cursorOut = join(ADAPTERS_DIR, "cursor", `${skill.name}.mdc`);
    writeFileSync(cursorOut, buildCursorRule(meta, body));

    // Codex (.md)
    const codexOut = join(ADAPTERS_DIR, "codex", `${skill.name}.md`);
    writeFileSync(codexOut, buildCodexInstructions(meta, body));

    console.log(`  ${skill.name}/SKILL.md → cursor, codex`);
    count++;
  }

  console.log(`\nGenerated adapters for ${count} skill(s).`);
}

main();
