#!/usr/bin/env node

/**
 * Summarize a `claude plugin eval` aggregate-result.json as a markdown table (for $GITHUB_STEP_SUMMARY)
 * and fail on runs the CLI may still have graded. Zero dependencies.
 *
 * Claude Code before v2.1.299 grades runs that ended on an API error, so an outage would show up as
 * "the skill didn't fire". This script fails (exit 1) when any run has an `error` or was `aborted`, or
 * when the document is `partial` (cost ceiling, interrupted, auth failure), so those never pass as results.
 * Unknown fields are ignored, as the eval docs ask.
 *
 * Usage: node .github/scripts/eval-summary.mjs <aggregate-result.json>
 */

import { readFileSync } from "node:fs";

/** Pure: report -> { markdown, problems }. */
export function summarize(report) {
  const problems = [];
  const cases = report.cases ?? [];
  const rows = cases.map((c) => {
    const runs = c.arms?.with ?? [];
    const errored = runs.filter((r) => r.error || r.aborted);
    if (errored.length) problems.push(`${c.name}: ${errored.length}/${runs.length} run(s) ended in an error or were aborted`);
    const score = c.aggregates?.score;
    return `| ${c.name} | ${typeof score === "number" ? score.toFixed(2) : "–"} | ${runs.length} | ${errored.length} |`;
  });
  if (report.partial) problems.push(`partial run (${report.partialReason ?? "unknown reason"}); results are incomplete`);
  if (!cases.length) problems.push("no cases in the report");

  const a = report.aggregates ?? {};
  const head = [
    `**${a.casesPassed ?? "?"}/${a.casesTotal ?? cases.length} cases passed**, overall score ${typeof a.overallScore === "number" ? a.overallScore.toFixed(2) : "?"}` +
      ` · Claude Code ${report.claudeVersion ?? "?"} · ${typeof report.costUsd === "number" ? `$${report.costUsd.toFixed(2)}` : "cost ?"}` +
      ` · ${typeof report.durationSeconds === "number" ? `${Math.round(report.durationSeconds)}s` : ""}`,
    "",
    "| Case | Score | Runs | Errored |",
    "|---|---|---|---|",
  ];
  const tail = problems.length ? ["", ...problems.map((p) => `- :warning: ${p}`)] : [];
  return { markdown: [...head, ...rows, ...tail].join("\n") + "\n", problems };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: eval-summary.mjs <aggregate-result.json>");
    process.exit(2);
  }
  const { markdown, problems } = summarize(JSON.parse(readFileSync(file, "utf8")));
  process.stdout.write(markdown);
  for (const p of problems) console.error(`error: ${p}`);
  process.exit(problems.length ? 1 : 0);
}
