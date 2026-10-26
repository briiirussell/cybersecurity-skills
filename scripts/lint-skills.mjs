#!/usr/bin/env node

/**
 * Lint every skills/<name>/SKILL.md. Zero dependencies.
 *
 * Errors (exit 1):
 *   - frontmatter missing, or `name` / `description` / `allowed-tools` absent
 *   - `name` does not match the folder, or is not lowercase-hyphen (max 64)
 *   - `description` outside 200–1024 characters
 *   - SKILL.md is 500 lines or longer
 *   - `allowed-tools` pre-approves WebFetch together with unscoped Bash
 *   - a Bash grant pre-approves a write: unscoped Bash, a write verb in the rule, a prefix
 *     that also matches a destructive subcommand (`heroku releases:*` → `releases:rollback`),
 *     a wildcard on a bare multi-command CLI, or a wildcard on a source-rewriting tool
 *     (see scripts/grant-check.mjs)
 *   - a backticked skill name in a cross-reference context does not resolve to skills/<name>/
 *   - a relative markdown link does not resolve (links to shared copies under
 *     references/ are allowed even before the build has copied them)
 *   - the same single-quoted trigger phrase appears in two or more descriptions
 *     (the request would be ambiguous between skills; SkillSpector TR2). Keep the
 *     phrase in the skill that owns the work and narrow or drop it in the other.
 *
 * Usage: node scripts/lint-skills.mjs [--quiet]
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, basename, normalize, relative } from "node:path";
import { checkGrant } from "./grant-check.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
const SKILLS_DIR = join(ROOT, "skills");
const QUIET = process.argv.includes("--quiet");

const MAX_LINES = 500; // SKILL.md must be strictly under this
const DESC_MIN = 200;
const DESC_MAX = 1024;

// Shared files the build copies into skills/<skill>/references/. Kept in sync with
// shared/manifest.json; this list is the fallback while the manifest is absent.
const SHARED_FALLBACK = [
  "findings.schema.json",
  "validate-findings.mjs",
  "to-sarif.mjs",
  "findings-format.md",
  "severity-calibration.md",
  "coverage.schema.json",
  "validate-coverage.mjs",
  "verification.md",
  "recon-and-coverage.md",
  "orchestration.md",
  "diff-review.md",
];

const errors = [];
const warnings = [];
const err = (file, msg) => errors.push(`${relative(ROOT, file)}: ${msg}`);
const warn = (file, msg) => warnings.push(`${relative(ROOT, file)}: ${msg}`);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n/);
  if (!match) return null;
  const meta = {};
  for (const line of match[1].split("\n")) {
    const kv = line.match(/^([\w-]+):\s*(.*?)\s*$/);
    if (!kv) continue;
    let value = kv[2];
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\"/g, '"');
    }
    meta[kv[1]] = value;
  }
  return meta;
}

/** Split an allowed-tools string on commas/spaces, keeping `Tool(...)` groups intact. */
export function parseAllowedTools(value) {
  const tools = [];
  let current = "";
  let depth = 0;
  for (const ch of value.trim().replace(/^\[|\]$/g, "")) {
    if (ch === "(") depth++;
    if (ch === ")") depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === "," || ch === " ")) {
      if (current.trim()) tools.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) tools.push(current.trim());
  return tools.map((t) => t.replace(/^["']|["']$/g, ""));
}

function isUnscopedBash(tool) {
  return tool === "Bash" || /^Bash\(\s*(\*|:\*)?\s*\)$/.test(tool);
}

/** Strip fenced code blocks so examples inside them are not linted as prose. */
function stripFences(text) {
  const out = [];
  let inFence = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      out.push("");
      continue;
    }
    out.push(inFence ? "" : line);
  }
  return out;
}

function loadSharedFiles() {
  const names = new Set(SHARED_FALLBACK);
  const manifest = join(ROOT, "shared", "manifest.json");
  if (existsSync(manifest)) {
    try {
      const walk = (node) => {
        if (typeof node === "string") {
          if (/\.(md|json|mjs|js|cjs)$/.test(node)) names.add(basename(node));
        } else if (Array.isArray(node)) {
          node.forEach(walk);
        } else if (node && typeof node === "object") {
          for (const [key, value] of Object.entries(node)) {
            if (/\.(md|json|mjs|js|cjs)$/.test(key)) names.add(basename(key));
            walk(value);
          }
        }
      };
      walk(JSON.parse(readFileSync(manifest, "utf8")));
    } catch (e) {
      err(manifest, `could not parse: ${e.message}`);
    }
  }
  return names;
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

const skillNames = readdirSync(SKILLS_DIR)
  .filter((d) => existsSync(join(SKILLS_DIR, d, "SKILL.md")))
  .sort();
const knownSkills = new Set(skillNames);
const sharedFiles = loadSharedFiles();
const triggerPhrases = new Map(); // phrase -> Set(skill)

// A backticked token is treated as a skill reference only when it is lowercase-hyphenated
// and sits on a line that is talking about skills.
const SKILL_TOKEN = /`([a-z][a-z0-9]*(?:-[a-z0-9]+)+)`/g;
const XREF_CONTEXT = /cross-references?|\bsee\b|\bskills?\b|hand(?:s)? off|\bpair(?:s|ed)? with\b|\bfeeds?\b|\bthen run\b|\buse `/i;
// Suffixes used by skill names in this catalog. Tokens with these suffixes are checked
// anywhere in a cross-reference context; other hyphenated tokens only on explicit
// "Cross-references:" lines (avoids flagging things like `server-only`).
const SKILL_SUFFIX = /-(audit|recon|triage|patterns|mapping|engineering|injection|engagement|comms|detection|operations|hunting|modeling|research|pentest|forensics|management|testing|watch|sweep|pipeline|opsec)$/;

function lintSkill(name) {
  const file = join(SKILLS_DIR, name, "SKILL.md");
  const content = readFileSync(file, "utf8");
  const lines = content.split("\n");
  const lineCount = content.endsWith("\n") ? lines.length - 1 : lines.length;

  if (lineCount >= MAX_LINES) err(file, `${lineCount} lines (must be under ${MAX_LINES})`);

  const meta = parseFrontmatter(content);
  if (!meta) {
    err(file, "missing YAML frontmatter");
    return;
  }

  // name
  if (!meta.name) err(file, "frontmatter `name` missing");
  else {
    if (meta.name !== name) err(file, `name "${meta.name}" does not match folder "${name}"`);
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.name) || meta.name.length > 64)
      err(file, `name "${meta.name}" must be lowercase-hyphen, max 64 chars`);
  }

  // description
  const desc = meta.description ?? "";
  if (!desc) err(file, "frontmatter `description` missing");
  else if (desc.length < DESC_MIN || desc.length > DESC_MAX)
    err(file, `description is ${desc.length} chars (must be ${DESC_MIN}-${DESC_MAX})`);
  for (const m of desc.matchAll(/'([^']{3,}?)[,.]?'/g)) {
    const phrase = m[1].toLowerCase().replace(/[,.;]+$/, "").trim();
    if (!triggerPhrases.has(phrase)) triggerPhrases.set(phrase, new Set());
    triggerPhrases.get(phrase).add(name);
  }

  // allowed-tools
  if (meta["allowed-tools"] === undefined) err(file, "frontmatter `allowed-tools` missing");
  else {
    const tools = parseAllowedTools(meta["allowed-tools"]);
    if (tools.includes("WebFetch") && tools.some(isUnscopedBash))
      err(file, "allowed-tools pre-approves WebFetch together with unscoped Bash; scope Bash, e.g. Bash(dig:*)");
    for (const tool of tools)
      for (const reason of checkGrant(tool))
        err(file, `allowed-tools ${tool}: ${reason}. Use an exact rule or a narrower read-only prefix`);
  }

  // Body checks run on prose only (fenced code removed).
  const prose = stripFences(content);
  prose.forEach((line, i) => {
    const ln = i + 1;
    if (i < 5) return; // frontmatter

    // Cross-referenced skill names
    if (XREF_CONTEXT.test(line)) {
      const explicit = /cross-references?/i.test(line);
      for (const m of line.matchAll(SKILL_TOKEN)) {
        const token = m[1];
        if (knownSkills.has(token)) continue;
        if (explicit || SKILL_SUFFIX.test(token))
          err(file, `line ${ln}: cross-referenced skill \`${token}\` has no skills/${token}/ folder`);
      }
    }

    // Relative markdown links
    for (const m of line.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const target = m[1];
      if (/^(https?:|mailto:|#|<)/i.test(target)) continue;
      const pathPart = decodeURI(target.split("#")[0]);
      if (!pathPart) continue;
      const resolved = normalize(join(dirname(file), pathPart));
      if (existsSync(resolved)) continue;
      const rel = relative(join(SKILLS_DIR, name), resolved);
      if (/^references\/[^/]+$/.test(rel) && sharedFiles.has(basename(rel))) continue; // copied at build time
      err(file, `line ${ln}: relative link "${target}" does not resolve`);
    }
  });
}

for (const name of skillNames) lintSkill(name);

// Every folder under skills/ must carry a SKILL.md.
for (const entry of readdirSync(SKILLS_DIR)) {
  const dir = join(SKILLS_DIR, entry);
  if (statSync(dir).isDirectory() && !knownSkills.has(entry)) err(dir, "folder has no SKILL.md");
}

for (const [phrase, skills] of triggerPhrases) {
  if (skills.size > 1)
    err(SKILLS_DIR, `trigger phrase '${phrase}' appears in ${[...skills].sort().join(", ")} — keep it in the skill that owns the work, narrow or drop it in the other`);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

if (!QUIET) for (const w of warnings) console.warn(`warning: ${w}`);
for (const e of errors) console.error(`error: ${e}`);
console.log(
  `lint-skills: ${skillNames.length} skills, ${errors.length} error(s), ${warnings.length} warning(s)`
);
process.exit(errors.length ? 1 : 0);
