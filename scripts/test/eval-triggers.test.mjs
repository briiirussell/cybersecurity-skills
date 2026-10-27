import { test } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stem, tokenize, bm25, similarities, evaluate, loadDocs, loadTriggers } from "../eval-triggers.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const docs = [
  { name: "alpha", text: "Audit Dockerfiles and Kubernetes manifests for privileged pods and container hardening." },
  { name: "beta", text: "Find leaked secrets and API keys in git history with gitleaks and trufflehog." },
  { name: "gamma", text: "Write Sigma and KQL detection rules mapped to MITRE ATT&CK for the SIEM." },
];
const five = (xs) => [...xs, ...xs, ...xs, ...xs, ...xs].slice(0, 5);
const good = {
  alpha: { should_fire: five(["is this pod privileged in the kubernetes manifest", "harden my Dockerfile"]),
    near_miss: five([{ prompt: "gitleaks found a key in git history", owner: "beta" }]) },
  beta: { should_fire: five(["did we leak API keys in git history", "run trufflehog"]),
    near_miss: five([{ prompt: "write a Sigma rule", owner: "gamma" }]) },
  gamma: { should_fire: five(["write a KQL detection rule", "map detections to ATT&CK"]),
    near_miss: five([{ prompt: "privileged pods in kubernetes", owner: "alpha" }]) },
};

test("stem and tokenize: plurals and -ing meet, stopwords and hyphen parts handled", () => {
  assert.equal(stem("scanners"), "scanner");
  assert.equal(stem("policies"), "policy");
  assert.equal(stem("scanning"), "scan");
  assert.deepEqual(tokenize("Is the S3 bucket public?"), ["s3", "bucket", "public"]);
  assert.ok(tokenize("least-privilege roles").includes("privilege"));
});

test("bm25 ranks the matching doc first", () => {
  const rank = bm25(docs);
  assert.equal(rank("leaked API keys in git")[0].name, "beta");
  assert.equal(rank("Sigma detection rule")[0].name, "gamma");
});

test("similarities: identical texts score 1, unrelated near 0", () => {
  const s = similarities([{ name: "a", text: "audit kubernetes pods" }, { name: "b", text: "audit kubernetes pods" }, { name: "c", text: "write sigma rules" }]);
  assert.equal(s[0].a + s[0].b, "ab");
  assert.ok(Math.abs(s[0].sim - 1) < 1e-9);
  assert.ok(s.at(-1).sim < 0.01);
});

test("evaluate: a well-separated set passes", () => {
  const r = evaluate(docs, good);
  assert.deepEqual(r.errors, []);
  assert.equal(r.stats.fireTop1, 15);
});

test("evaluate: missing file, too few prompts, bad owners, low accuracy and similar descriptions fail", () => {
  const bad = {
    alpha: { should_fire: ["write a Sigma rule"], near_miss: [{ prompt: "x", owner: "nope" }, { prompt: "y", owner: "alpha" }] },
    beta: good.beta,
  };
  const twins = [...docs, { name: "delta", text: docs[2].text }];
  const errs = evaluate(twins, bad).errors.join("\n");
  assert.match(errs, /gamma: no evals\/triggers\/gamma.json/);
  assert.match(errs, /alpha: 1 should_fire prompts/);
  assert.match(errs, /owner "nope" is not a skill/);
  assert.match(errs, /owner is the skill itself/);
  assert.match(errs, /alpha: ranks first for 0\/1/);
  assert.match(errs, /should-fire top-1 is/);
  assert.match(errs, /descriptions of gamma and delta are 1.00 similar/);
});

test("evaluate: a near-miss whose owner ranks below the skill counts against the floor", () => {
  const swapped = { ...good, alpha: { ...good.alpha, near_miss: five([{ prompt: "privileged pods in kubernetes", owner: "beta" }]) } };
  const r = evaluate(docs, swapped, { minNearMiss: 0.9 });
  assert.equal(r.stats.nearOk, 10);
  assert.match(r.errors.join(), /near-miss owner-above-skill is 10\/15/);
});

test("the repo's descriptions pass the trigger eval", () => {
  const repoDocs = loadDocs(join(ROOT, "skills"));
  const r = evaluate(repoDocs, loadTriggers(join(ROOT, "evals", "triggers"), repoDocs.map((d) => d.name)));
  assert.deepEqual(r.errors, []);
});
