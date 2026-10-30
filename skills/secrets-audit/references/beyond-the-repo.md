# Beyond the Repo

Companion to `secrets-audit` Part 1. For small teams and vibe-coded apps, the repo is often not where the key leaked.
It leaked in an issue ("here's my .env, why doesn't Stripe work?"), a CI log (`echo $SECRET`, a debug dump), a gist, a
release asset, an image layer, or an agent transcript. Betterleaks v2 has a source for each. The safety rules in
[betterleaks.md](betterleaks.md#safety-rules) apply to all of them: detection only, `--redact`, report to a file, ask
before `-v` / `-a`, never `revoke`.

These sources need v2 (`betterleaks version`). Every remote source makes network requests even in detection-only mode,
and each needs a token for an account the user owns. None is pre-approved, so each command prompts and the user sees
the target.

Checked against Betterleaks' scanning guide on 2026-10-30.

## Scope first

Remote sources only for orgs, users, projects and buckets the user owns or administers, **named explicitly** in this
conversation. Not "every org this token can see." A bucket scan uses the owner's credentials and a prefix they name.

## 1. GitHub, outside git history

Needs `GITHUB_TOKEN` in the environment. `--include` / `--exclude` take `repos` (the default), `forks`, `prs`,
`pr-comments` (included with `prs`), `issues`, `issue-comments`, `actions`, `action-artifacts`, `discussions`,
`releases`, `release-assets` and `gists`.

```bash
F="--validate=false --analyze=false --redact"
# Issue and PR text, with comments (org-wide, or one repo)
betterleaks github --include=issues,issue-comments,prs,discussions --exclude=repos $F -o .security/out/gh-text.json https://github.com/<org-or-repo>
# Actions run logs and artifacts (the "echo $SECRET" / debug-dump class)
betterleaks github --include=actions,action-artifacts --exclude=repos $F -o .security/out/gh-actions.json https://github.com/<org>/<repo>
# Releases, their assets, and gists
betterleaks github --include=releases,release-assets,gists --exclude=repos $F -o .security/out/gh-releases-gists.json https://github.com/<org-or-user>
```

- `prs` scans PR **text** (title, description, comments), not the PR's commits. For the commits:
  `betterleaks git https://github.com/<org>/<repo> --clone-ref=refs/pull/<n>/head --revision=main..refs/pull/<n>/head $F -o …`.
- `--since` / `--until` on `github` filter API items, not commits. "Since we went public" is a good window, and it
  feeds triage step 3 (exposure window).
- `--include=forks` adds forks to the repository list. A key in a public fork stays exposed after you clean the main
  repo, which is one more reason to rotate first.
- `--exclude-repo '<org>/*-archive'` skips repos by glob.

## 2. GitLab

```bash
betterleaks gitlab --include=issues,mrs,releases,ci-jobs $F -o .security/out/gl.json https://gitlab.com/<group>/<project>
```

## 3. Container images

```bash
# By digest, so the finding points at one exact artifact
betterleaks container $F -o .security/out/image.json <registry>/<image>@sha256:<digest>
betterleaks container --archive image.tar $F -o .security/out/image.json
```

It scans every platform and every historical layer, including files a later layer deleted or replaced. Each finding
says whether its file is `visible`, `overwritten`, `deleted` or `unknown`, and names the layer that hid it.
Copying a dotenv file in one layer and deleting it in the next leaves the key in the lower layer, and this is how it shows up. Anyone who can pull the
image can extract a deleted layer, so a `deleted` finding is as exposed as a `visible` one. Without v2, use
`trivy image --scanners secret` and `docker history --no-trunc`. `container-audit` sends layer secrets here.

## 4. Agent transcripts and local agent state

The `rg -c` sweep in SKILL.md is a fast count, but it knows about ten key prefixes. Run a second pass for generic
secrets, database URLs with passwords and JWT signing keys:

```bash
for d in ~/.claude/projects ~/.codex/sessions ~/.gemini/tmp; do
  [ -d "$d" ] && betterleaks fs "$d" $F -o ".security/out/transcripts-$(basename "$d").json"
done
```

Transcripts are mostly natural language, which is where entropy-only scanners drown in false positives; Betterleaks'
filtering is what makes this pass usable. **Read only counts and locations from the reports.** Summarize by rule id
and file. Never `cat` a report or open a matching line in this session, because that copies it into this session's
transcript. Then follow SKILL.md: rotate first, scrub the session file, shorten `cleanupPeriodDays`.

## 5. Hugging Face and object storage

```bash
# Models, datasets, Spaces, and their discussions / PRs (HF_TOKEN or HUGGINGFACE_TOKEN for private ones)
betterleaks hf --include=repos,discussions,prs $F -o .security/out/hf.json https://huggingface.co/<org>
# A bucket prefix the owner named, with their credentials from AWS_* env vars (it never reads the shared AWS credentials file)
betterleaks s3 $F -o .security/out/bucket.json s3://<bucket>/<prefix>/
```

Datasets and Spaces often hold a `.env`, notebooks with keys in cell output, or a `config.json` with provider tokens.
For R2, MinIO and other S3-compatible stores, pass the endpoint URL and `--region`.

## Cleaning up surfaces that aren't git

The key is exposed from the moment it was posted, so rotate first everywhere. Then:

| Surface | Clean up | Can it be fully purged? |
|---|---|---|
| Issue or PR comment | Edit the comment, then delete the old revision from its edit history (GitHub lets people with write access remove revisions), or delete the comment | Only from GitHub itself. Notification emails, API caches and anyone who already read it keep a copy |
| Actions run log | Delete the run's logs, or the run (`gh run delete <id>`) | Only from GitHub. A fork's runs and downloaded logs are separate |
| Actions artifact | Delete it through the artifacts API or the run page | Only from GitHub; anyone who downloaded it keeps it |
| Release asset | Replace the asset, or delete the release | Mirrors and package registries that copied it keep it |
| Gist | Delete it. A secret gist is unlisted, not private: anyone with the URL can read it | Forks of the gist keep it |
| Image layer | Rebuild without the file (BuildKit `--mount=type=secret`), push, and delete the old tag and digest from the registry | Any pull of the old digest keeps it |
| Transcript | Scrub or delete the session file | Backups and synced copies keep it |
| Hugging Face repo | Remove the file and rewrite the repo's history, or delete and recreate the repo | Downloads and duplicates keep it |
| Bucket object | Delete the object and its old versions if versioning is on | Access logs show whether it was read |

Every cleanup here deletes or edits something the owner controls. Each is the owner's call and prompts.

## Recording the surface

Add `ext.surface` to each finding. Who could read it, and whether it can be purged at all, depends on the surface, so
it feeds triage steps 3 (exposure window) and 7 (clean):

`repo-head`, `git-history`, `issue`, `pr`, `discussion`, `actions-log`, `artifact`, `release-asset`, `gist`,
`image-layer`, `transcript`, `hf`, `bucket`.

## Sources

- Betterleaks [scanning guide](https://github.com/betterleaks/betterleaks/blob/main/docs/scanning.md) (sources and
  flags)
- GitHub docs: managing a comment's edit history, deleting workflow run logs, and the Actions artifacts REST API
- Proposed by @coreyhaines31 in issue #215
