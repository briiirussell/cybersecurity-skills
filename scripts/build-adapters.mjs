#!/usr/bin/env node

/**
 * Build adapter files from canonical skill definitions.
 *
 * Reads all skills from skills/<domain>/<skill>.md and generates:
 * - adapters/claude-code/<skill>.md   (Claude Code skill format)
 * - adapters/cursor/<skill>.mdc       (Cursor rules format)
 * - adapters/codex/<skill>.md         (Codex instructions format)
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "fs";
import { join, basename, relative } from "path";

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
  const body = match[2];
  const meta = {};

  let currentKey = null;
  let currentList = null;

  for (const line of raw.split("\n")) {
    const kvMatch = line.match(/^(\w+):\s*"?(.*?)"?\s*$/);
    const listItemMatch = line.match(/^\s+-\s*"?(.*?)"?\s*$/);

    if (kvMatch && !listItemMatch) {
      if (currentKey && currentList) {
        meta[currentKey] = currentList;
      }
      currentKey = kvMatch[1];
      const val = kvMatch[2];
      if (val === "") {
        currentList = [];
      } else {
        meta[currentKey] = val;
        currentKey = null;
        currentList = null;
      }
    } else if (listItemMatch && currentKey) {
      currentList = currentList || [];
      currentList.push(listItemMatch[1]);
    }
  }

  if (currentKey && currentList) {
    meta[currentKey] = currentList;
  }

  return { meta, body };
}

function collectSkillFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      files.push(...collectSkillFiles(full));
    } else if (entry.endsWith(".md")) {
      files.push(full);
    }
  }
  return files;
}

// ---------------------------------------------------------------------------
// Adapter generators
// ---------------------------------------------------------------------------

function buildClaudeCodeSkill(meta, body) {
  const triggers = Array.isArray(meta.triggers) ? meta.triggers : [];
  const triggerLine = triggers.map((t) => `'${t}'`).join(", ");

  return `---
# Claude Code Skill
# Generated from canonical skill — do not edit directly
---

# ${meta.name}

${meta.description}

**Triggers:** ${triggerLine}
**Domain:** ${meta.domain}
**Authorization:** ${meta.authorization || "Requires explicit authorization."}

${body}`;
}

function buildCursorRule(meta, body) {
  const triggers = Array.isArray(meta.triggers) ? meta.triggers : [];

  // Extract the system prompt section from the body
  const promptMatch = body.match(/## System Prompt\n\n```\n([\s\S]*?)```/);
  const systemPrompt = promptMatch ? promptMatch[1].trim() : "";

  return `---
description: "${meta.description}"
globs:
alwaysApply: false
---

# ${meta.name}

${meta.description}

## When to Use

Activate when the user mentions: ${triggers.join(", ")}

## Authorization

${meta.authorization || "Requires explicit authorization."}

## Instructions

${systemPrompt || body}`;
}

function buildCodexInstructions(meta, body) {
  const triggers = Array.isArray(meta.triggers) ? meta.triggers : [];

  // Extract the system prompt section from the body
  const promptMatch = body.match(/## System Prompt\n\n```\n([\s\S]*?)```/);
  const systemPrompt = promptMatch ? promptMatch[1].trim() : "";

  return `# ${meta.name}

> ${meta.description}

## Activation

Use this instruction set when the task involves: ${triggers.join(", ")}

## Authorization

${meta.authorization || "Requires explicit authorization."}

## Instructions

${systemPrompt || body}`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const skillFiles = collectSkillFiles(SKILLS_DIR);

  if (skillFiles.length === 0) {
    console.log("No skill files found in skills/");
    return;
  }

  // Ensure adapter output directories exist
  for (const platform of ["claude-code", "cursor", "codex"]) {
    mkdirSync(join(ADAPTERS_DIR, platform), { recursive: true });
  }

  let count = 0;

  for (const file of skillFiles) {
    const content = readFileSync(file, "utf-8");
    const { meta, body } = parseFrontmatter(content);
    const slug = basename(file, ".md");
    const rel = relative(SKILLS_DIR, file);

    // Claude Code
    const ccOut = join(ADAPTERS_DIR, "claude-code", `${slug}.md`);
    writeFileSync(ccOut, buildClaudeCodeSkill(meta, body));

    // Cursor
    const cursorOut = join(ADAPTERS_DIR, "cursor", `${slug}.mdc`);
    writeFileSync(cursorOut, buildCursorRule(meta, body));

    // Codex
    const codexOut = join(ADAPTERS_DIR, "codex", `${slug}.md`);
    writeFileSync(codexOut, buildCodexInstructions(meta, body));

    console.log(`  ${rel} → claude-code, cursor, codex`);
    count++;
  }

  console.log(`\nGenerated adapters for ${count} skill(s).`);
}

main();
