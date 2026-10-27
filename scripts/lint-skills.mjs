#!/usr/bin/env node

/**
 * Lint every skills/<name>/SKILL.md. Zero dependencies.
 *
 * Errors (exit 1):
 *   - frontmatter missing, or `name` / `description` / `allowed-tools` absent
 *   - `name` does not match the folder, or is not lowercase-hyphen (max 64)
 *   - `description` outside 200–1024 characters
 *   - SKILL.md is 500 lines or longer
 *   - no level-2 heading containing "Authorization" (e.g. `## Authorization`, `## Authorization and Mode`)
 *   - no `## Boundaries` or `## References` section, or an output section not spelled `## Output Format`
 *     (`## Report Format`, `## Output format`); see templates/skill-template.md
 *   - `allowed-tools` pre-approves WebFetch together with unscoped Bash
 *   - a Bash grant pre-approves a write: unscoped Bash, a write verb in the rule, a prefix
 *     that also matches a destructive subcommand (`heroku releases:*` → `releases:rollback`),
 *     a wildcard on a bare multi-command CLI, or a wildcard on a source-rewriting tool
 *     (see scripts/grant-check.mjs)
 *   - a backticked skill name in a cross-reference context does not resolve to skills/<name>/
 *   - a relative markdown link does not resolve (links to shared copies under
 *     references/ are allowed even before the build has copied them)
 *   - a link's `#anchor` names no heading in the target .md file (GitHub slug rules).
 *     Checked in SKILL.md, the skill's references (any depth) and shared/
 *   - the same single-quoted trigger phrase appears in two or more descriptions
 *     (the request would be ambiguous between skills; SkillSpector TR2). Keep the
 *     phrase in the skill that owns the work and narrow or drop it in the other.
 *
 * Plugin subagents in agents/*.md (Claude Code only; the Cursor and Codex adapters don't get them):
 *   - frontmatter missing, or `name` / `description` / `tools` absent
 *   - `name` does not match the file name, or is not lowercase-hyphen (max 64)
 *   - `tools` grants a tool that writes or executes (Write, Edit, MultiEdit, NotebookEdit, Bash):
 *     the agents here are read-only verifiers
 *
 * Usage: node scripts/lint-skills.mjs [--quiet] [--skills-dir <dir>] [--agents-dir <dir>]
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, basename, normalize, relative } from "node:path";
import { checkGrant } from "./grant-check.mjs";

const ROOT = new URL("..", import.meta.url).pathname;
// --skills-dir <dir> lints another tree (the self-tests in scripts/test/ use it); shared/ still comes from the repo.
const SKILLS_ARG = process.argv.indexOf("--skills-dir");
const SKILLS_DIR = SKILLS_ARG > 0 ? process.argv[SKILLS_ARG + 1] : join(ROOT, "skills");
const QUIET = process.argv.includes("--quiet");
const AGENTS_ARG = process.argv.indexOf("--agents-dir");
const AGENTS_DIR = AGENTS_ARG > 0 ? process.argv[AGENTS_ARG + 1] : join(ROOT, "agents");
// Tools a plugin agent here may not have: they write files or run commands.
const AGENT_FORBIDDEN_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"]);

const AUTH_HEADING = /^##\s+.*\bauthori[sz]ation\b/im; // every skill needs one (CLAUDE.md)
// Standard section names (templates/skill-template.md). Every skill has these two:
const REQUIRED_SECTIONS = ["## Boundaries", "## References"];
// ...and an output section, when there is one, is spelled exactly "## Output Format".
const OUTPUT_VARIANT = /^##\s+(?:report|output)\s+format\s*$/i;
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

const SHARED_DIR = join(ROOT, "shared");
const LINK_RE = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;

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

/** GitHub-style heading anchors for a markdown file (fenced code ignored), plus explicit <a id> / <a name>. */
const slugCache = new Map();
export function headingSlugs(file) {
  if (slugCache.has(file)) return slugCache.get(file);
  const out = new Set();
  const seen = new Map();
  for (const line of stripFences(readFileSync(file, "utf8"))) {
    for (const a of line.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) out.add(a[1]);
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    const slug = m[1]
      .replace(/<[^>]+>/g, "")
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/ /g, "-");
    const n = seen.get(slug) ?? 0;
    seen.set(slug, n + 1);
    out.add(n ? `${slug}-${n}` : slug);
  }
  slugCache.set(file, out);
  return out;
}

/** Report links in `file` whose #anchor names no heading in the target markdown file. */
function checkAnchors(file, lines = stripFences(readFileSync(file, "utf8"))) {
  lines.forEach((line, i) => {
    for (const m of line.matchAll(LINK_RE)) {
      const target = m[1];
      if (/^(https?:|mailto:|<)/i.test(target) || !target.includes("#")) continue;
      const [pathPart, anchor] = target.split("#", 2);
      const resolved = pathPart ? normalize(join(dirname(file), decodeURI(pathPart))) : file;
      if (!resolved.endsWith(".md") || !existsSync(resolved) || !anchor) continue;
      if (!headingSlugs(resolved).has(decodeURIComponent(anchor)))
        err(file, `line ${i + 1}: link "${target}" points at no heading "#${anchor}"`);
    }
  });
}

function mdFilesUnder(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? mdFilesUnder(p) : p.endsWith(".md") ? [p] : [];
  });
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
  if (!AUTH_HEADING.test(prose.join("\n")))
    err(file, "no `## Authorization` section; say whose systems the skill may touch and what needs the owner's go-ahead (CLAUDE.md)");
  for (const h of REQUIRED_SECTIONS)
    if (!prose.some((l) => l.trim() === h)) err(file, `no \`${h}\` section (standard section names: templates/skill-template.md)`);
  prose.forEach((l, i) => {
    if (OUTPUT_VARIANT.test(l.trim()) && l.trim() !== "## Output Format")
      err(file, `line ${i + 1}: "${l.trim()}" should be "## Output Format" (standard section names: templates/skill-template.md)`);
  });
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
    for (const m of line.matchAll(LINK_RE)) {
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
  checkAnchors(file, prose);
  for (const ref of mdFilesUnder(join(SKILLS_DIR, name, "references"))) checkAnchors(ref);
}

for (const name of skillNames) lintSkill(name);
for (const f of mdFilesUnder(SHARED_DIR)) checkAnchors(f);

// Every folder under skills/ must carry a SKILL.md.
for (const entry of readdirSync(SKILLS_DIR)) {
  const dir = join(SKILLS_DIR, entry);
  if (statSync(dir).isDirectory() && !knownSkills.has(entry)) err(dir, "folder has no SKILL.md");
}

// Plugin subagents (agents/*.md). Claude Code discovers them at the plugin root.
function lintAgent(file) {
  const content = readFileSync(file, "utf8");
  const meta = parseFrontmatter(content);
  if (!meta) return err(file, "missing YAML frontmatter");
  const stem = basename(file, ".md");
  if (!meta.name) err(file, "frontmatter `name` missing");
  else {
    if (meta.name !== stem) err(file, `name "${meta.name}" does not match file name "${stem}"`);
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.name) || meta.name.length > 64)
      err(file, `name "${meta.name}" must be lowercase-hyphen, max 64 chars`);
  }
  if (!meta.description) err(file, "frontmatter `description` missing");
  if (!meta.tools) err(file, "frontmatter `tools` missing (list the tools explicitly; an agent without it inherits every tool)");
  else
    for (const tool of parseAllowedTools(meta.tools)) {
      const base = tool.replace(/\(.*$/, "");
      if (AGENT_FORBIDDEN_TOOLS.has(base)) err(file, `tools grants ${tool}; agents here are read-only (Read, Grep, Glob)`);
    }
}

const agentFiles = existsSync(AGENTS_DIR)
  ? readdirSync(AGENTS_DIR).filter((f) => f.endsWith(".md")).sort().map((f) => join(AGENTS_DIR, f))
  : [];
for (const f of agentFiles) lintAgent(f);

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
  `lint-skills: ${skillNames.length} skills, ${agentFiles.length} agent(s), ${errors.length} error(s), ${warnings.length} warning(s)`
);
process.exit(errors.length ? 1 : 0);
