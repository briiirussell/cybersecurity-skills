#!/usr/bin/env node

/**
 * Offline trigger eval: does a prompt rank the right skill's description first? Zero dependencies, no API calls.
 *
 * Each evals/triggers/<skill>.json holds prompts that should fire the skill and near-miss prompts that
 * belong to another skill (`owner`). Every prompt is ranked against all 35 descriptions with BM25.
 * This is a proxy for real routing (the model reads descriptions, not term counts); the
 * `claude plugin eval` cases in evals/cases/ check real routing on demand.
 *
 * Fails (exit 1) when:
 *   - a skill has no triggers file, or a file has fewer than 5 should-fire or 5 near-miss prompts,
 *     names an unknown owner, or names itself as owner
 *   - fewer than MIN_TOP1 of all should-fire prompts rank their skill first
 *   - fewer than MIN_NEAR_MISS of all near-miss prompts rank the owner above the skill they were written for
 *   - any one skill ranks first for fewer than MIN_SKILL_TOP1 of its own should-fire prompts
 *   - two descriptions are more similar than MAX_SIMILARITY (TF-IDF cosine)
 *
 * The floors sit a little under what the current descriptions score, so they catch a description edit
 * that steals or loses prompts. Raise them when descriptions improve; don't lower them to pass.
 *
 * Usage: node scripts/eval-triggers.mjs [--verbose] [--skills-dir <dir>] [--triggers-dir <dir>]
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parseFrontmatter } from "./build-adapters.mjs";

export const MIN_TOP1 = 0.85;
export const MIN_NEAR_MISS = 0.9;
export const MIN_SKILL_TOP1 = 0.6;
export const MAX_SIMILARITY = 0.55;
export const MIN_PROMPTS = 5;

const STOPWORDS = new Set(
  ("a an and are as at be been but by can could do does for from had has have how i if in into is it its " +
    "me my of on or our out so that the their them then there these they this to up us was we what when " +
    "where which who why will with would you your use user mentions needs wants any all just about also " +
    "here help some get got not no did don't it's we're i'm").split(" ")
);

/** Light suffix stemmer: enough that 'scanners'/'scanning'/'scan' and 'policies'/'policy' meet. */
export function stem(w) {
  if (w.length <= 4) return w;
  if (w.endsWith("ies")) return w.slice(0, -3) + "y";
  if (w.endsWith("ing") && w.length > 6) return w.slice(0, -3).replace(/(.)\1$/, "$1");
  if (w.endsWith("ed") && w.length > 5) return w.slice(0, -2).replace(/(.)\1$/, "$1");
  if (w.endsWith("es") && /(ss|x|ch|sh)es$/.test(w)) return w.slice(0, -2);
  if (w.endsWith("s") && !w.endsWith("ss")) return w.slice(0, -1);
  return w;
}

export function tokenize(text) {
  return (text.toLowerCase().match(/[a-z0-9][a-z0-9.+#-]*[a-z0-9+#]|[a-z0-9]/g) ?? [])
    .flatMap((t) => (t.includes("-") ? [t, ...t.split("-")] : [t]))
    .filter((t) => !STOPWORDS.has(t))
    .map(stem);
}

/** BM25 index over { name, text } docs. Returns rank(prompt) -> [{ name, score }] best first. */
export function bm25(docs, { k1 = 1.2, b = 0.75 } = {}) {
  const toks = docs.map((d) => tokenize(`${d.name} ${d.text}`));
  const avg = toks.reduce((n, t) => n + t.length, 0) / toks.length;
  const df = new Map();
  for (const t of toks) for (const w of new Set(t)) df.set(w, (df.get(w) ?? 0) + 1);
  const tf = toks.map((t) => t.reduce((m, w) => m.set(w, (m.get(w) ?? 0) + 1), new Map()));
  const idf = (w) => Math.log(1 + (docs.length - (df.get(w) ?? 0) + 0.5) / ((df.get(w) ?? 0) + 0.5));
  return (prompt) => {
    const q = new Set(tokenize(prompt));
    return docs
      .map((d, i) => {
        let s = 0;
        for (const w of q) {
          const f = tf[i].get(w);
          if (f) s += idf(w) * ((f * (k1 + 1)) / (f + k1 * (1 - b + (b * toks[i].length) / avg)));
        }
        return { name: d.name, score: s };
      })
      .sort((x, y) => y.score - x.score || x.name.localeCompare(y.name));
  };
}

/** Pairwise TF-IDF cosine similarity between docs. Returns [{ a, b, sim }] most similar first. */
export function similarities(docs) {
  const toks = docs.map((d) => tokenize(d.text));
  const df = new Map();
  for (const t of toks) for (const w of new Set(t)) df.set(w, (df.get(w) ?? 0) + 1);
  const vecs = toks.map((t) => {
    const v = new Map();
    for (const w of t) v.set(w, (v.get(w) ?? 0) + 1);
    for (const [w, f] of v) v.set(w, f * Math.log(docs.length / df.get(w)));
    const norm = Math.hypot(...v.values()) || 1;
    for (const [w, x] of v) v.set(w, x / norm);
    return v;
  });
  const out = [];
  for (let i = 0; i < docs.length; i++)
    for (let j = i + 1; j < docs.length; j++) {
      let s = 0;
      for (const [w, x] of vecs[i]) s += x * (vecs[j].get(w) ?? 0);
      out.push({ a: docs[i].name, b: docs[j].name, sim: s });
    }
  return out.sort((x, y) => y.sim - x.sim);
}

/**
 * Pure evaluation. `docs` is [{ name, text }]; `triggers` maps skill -> { should_fire, near_miss } or undefined.
 * Returns { errors, stats, misses } where misses lists every prompt that ranked wrong.
 */
export function evaluate(docs, triggers, limits = {}) {
  const { minTop1 = MIN_TOP1, minNearMiss = MIN_NEAR_MISS, minSkillTop1 = MIN_SKILL_TOP1,
    maxSimilarity = MAX_SIMILARITY, minPrompts = MIN_PROMPTS } = limits;
  const errors = [];
  const misses = [];
  const names = new Set(docs.map((d) => d.name));
  const rank = bm25(docs);
  let fire = 0, fireTop1 = 0, fireTop3 = 0, near = 0, nearOk = 0;

  for (const { name } of docs) {
    const t = triggers[name];
    if (!t) { errors.push(`${name}: no evals/triggers/${name}.json`); continue; }
    const shouldFire = t.should_fire ?? [];
    const nearMiss = t.near_miss ?? [];
    if (shouldFire.length < minPrompts) errors.push(`${name}: ${shouldFire.length} should_fire prompts (need ${minPrompts})`);
    if (nearMiss.length < minPrompts) errors.push(`${name}: ${nearMiss.length} near_miss prompts (need ${minPrompts})`);

    let own = 0;
    for (const prompt of shouldFire) {
      const ranked = rank(prompt);
      const pos = ranked.findIndex((r) => r.name === name);
      fire++;
      if (pos === 0) { fireTop1++; own++; } else misses.push({ kind: "should_fire", skill: name, prompt, got: ranked[0].name, pos: pos + 1 });
      if (pos < 3) fireTop3++;
    }
    if (shouldFire.length && own / shouldFire.length < minSkillTop1)
      errors.push(`${name}: ranks first for ${own}/${shouldFire.length} of its own prompts (need ${Math.round(minSkillTop1 * 100)}%)`);

    for (const { prompt, owner } of nearMiss) {
      if (!names.has(owner)) { errors.push(`${name}: near_miss owner "${owner}" is not a skill`); continue; }
      if (owner === name) { errors.push(`${name}: near_miss owner is the skill itself`); continue; }
      const ranked = rank(prompt);
      const pos = (n) => ranked.findIndex((r) => r.name === n);
      near++;
      if (pos(owner) < pos(name)) nearOk++;
      else misses.push({ kind: "near_miss", skill: name, prompt, owner, got: ranked[0].name, pos: pos(owner) + 1 });
    }
  }

  const pct = (a, b) => (b ? a / b : 1);
  if (pct(fireTop1, fire) < minTop1)
    errors.push(`should-fire top-1 is ${fireTop1}/${fire} (${(pct(fireTop1, fire) * 100).toFixed(1)}%, need ${minTop1 * 100}%)`);
  if (pct(nearOk, near) < minNearMiss)
    errors.push(`near-miss owner-above-skill is ${nearOk}/${near} (${(pct(nearOk, near) * 100).toFixed(1)}%, need ${minNearMiss * 100}%)`);

  const sims = similarities(docs);
  for (const s of sims.filter((x) => x.sim > maxSimilarity))
    errors.push(`descriptions of ${s.a} and ${s.b} are ${s.sim.toFixed(2)} similar (max ${maxSimilarity}); sharpen what each one owns`);

  return { errors, misses, stats: { fire, fireTop1, fireTop3, near, nearOk, mostSimilar: sims.slice(0, 3) } };
}

export function loadDocs(skillsDir) {
  return readdirSync(skillsDir)
    .filter((d) => existsSync(join(skillsDir, d, "SKILL.md")))
    .sort()
    .map((name) => ({ name, text: parseFrontmatter(readFileSync(join(skillsDir, name, "SKILL.md"), "utf8")).meta.description ?? "" }));
}

export function loadTriggers(dir, names) {
  const out = {};
  for (const name of names) {
    const file = join(dir, `${name}.json`);
    if (existsSync(file)) out[name] = JSON.parse(readFileSync(file, "utf8"));
  }
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ROOT = new URL("..", import.meta.url).pathname;
  const arg = (flag, dflt) => (process.argv.indexOf(flag) > 0 ? process.argv[process.argv.indexOf(flag) + 1] : dflt);
  const docs = loadDocs(arg("--skills-dir", join(ROOT, "skills")));
  const triggersDir = arg("--triggers-dir", join(ROOT, "evals", "triggers"));
  const known = new Set(docs.map((d) => d.name));
  const orphans = readdirSync(triggersDir).filter((f) => f.endsWith(".json") && !known.has(f.slice(0, -5)));

  const { errors, misses, stats } = evaluate(docs, loadTriggers(triggersDir, docs.map((d) => d.name)));
  for (const f of orphans) errors.push(`evals/triggers/${f} has no skills/${f.slice(0, -5)}/ folder`);

  if (process.argv.includes("--verbose"))
    for (const m of misses)
      console.log(m.kind === "should_fire"
        ? `miss  ${m.skill} ranked #${m.pos}, ${m.got} first: ${JSON.stringify(m.prompt.slice(0, 90))}`
        : `near  ${m.skill} above owner ${m.owner} (#${m.pos}), ${m.got} first: ${JSON.stringify(m.prompt.slice(0, 90))}`);
  for (const e of errors) console.error(`error: ${e}`);
  const p = (a, b) => `${a}/${b} (${((a / b) * 100).toFixed(1)}%)`;
  const top = stats.mostSimilar[0];
  console.log(`eval-triggers: should-fire top-1 ${p(stats.fireTop1, stats.fire)}, top-3 ${p(stats.fireTop3, stats.fire)}; ` +
    `near-miss ${p(stats.nearOk, stats.near)}; most similar ${top.a} / ${top.b} ${top.sim.toFixed(2)}; ${errors.length} error(s)`);
  process.exit(errors.length ? 1 : 0);
}
