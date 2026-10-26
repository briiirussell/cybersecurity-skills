#!/usr/bin/env node

/**
 * Run `claude plugin validate --json .` and fail on any error or warning, except the
 * ones listed in ALLOWED with a reason. This is `--strict` with named exceptions:
 * plain `--strict` can't be used because the repo's contributor CLAUDE.md sits at the
 * plugin root and always draws a warning.
 *
 * Usage: node .github/scripts/plugin-validate.mjs            (needs `claude` on PATH)
 *        node .github/scripts/plugin-validate.mjs report.json (check a saved --json report)
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const ROOT = new URL("../..", import.meta.url).pathname;

/** Warnings we accept, each with the reason. Match on path + message prefix. */
export const ALLOWED = [
  {
    path: "root",
    message: "CLAUDE.md at the plugin root is not loaded as project context",
    reason: "CLAUDE.md is contributor guidance for working on this repo, not plugin context; the skills ship in skills/.",
  },
];

/** Return { problems, accepted } from a parsed `claude plugin validate --json` report. */
export function evaluate(report) {
  const problems = [];
  const accepted = [];
  for (const part of [report.manifest, ...(report.contents ?? [])].filter(Boolean)) {
    for (const e of part.errors ?? []) problems.push(`error ${part.file}: ${e.path}: ${e.message}`);
    for (const w of part.warnings ?? []) {
      const ok = ALLOWED.find((a) => a.path === w.path && w.message.startsWith(a.message));
      (ok ? accepted : problems).push(`warning ${part.file}: ${w.path}: ${w.message}`);
    }
  }
  if (report.success === false && problems.length === 0) problems.push("validator reported failure with no listed error");
  return { problems, accepted };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let text;
  if (process.argv[2]) text = readFileSync(process.argv[2], "utf8");
  else {
    try {
      text = execFileSync("claude", ["plugin", "validate", "--json", "."], { cwd: ROOT, encoding: "utf8" });
    } catch (e) {
      text = e.stdout; // non-zero exit still prints the JSON report
      if (!text) {
        console.error(`::error::claude plugin validate printed no report: ${(e.stderr || e.message).trim().split("\n")[0]}`);
        process.exit(1);
      }
    }
  }
  const report = JSON.parse(text);
  const { problems, accepted } = evaluate(report);
  for (const a of accepted) console.log(`accepted: ${a}`);
  for (const adv of report.advice ?? []) console.log(`advice: ${adv.message}`);
  for (const p of problems) console.error(`::error::${p}`);
  console.log(`plugin validate: ${problems.length} problem(s), ${accepted.length} accepted warning(s)`);
  process.exit(problems.length ? 1 : 0);
}
