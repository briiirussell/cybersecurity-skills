# Active Storage ImageMagick and FFmpeg — the fix has to reach the app

Fleet row for Step 4, next to the libvips / `VIPS_BLOCK_UNTRUSTED` case. Facts re-checked 2026-11-15 against the
Rails advisories and the CISA KEV catalog. Not on KEV that day (cve.now: `kev` false, `exploits` 0,
`epssReached` false for both CVEs). The per-app greps, the traps, and the policy snippet are in `owasp-audit`'s
Rails playbook, check 6 (`skills/owasp-audit/references/frameworks/rails.md`). This page is the sweep rule.

| Id | Severity | Vulnerable `activestorage` | Fixed |
|---|---|---|---|
| [GHSA-f3w6-w445-fwh9](https://github.com/rails/rails/security/advisories/GHSA-f3w6-w445-fwh9) / CVE-2026-122006 | Critical, CVSS 9.8 | `< 8.0.5.2`, and `>= 8.1, < 8.1.4.1` | **8.0.5.2** or **8.1.4.1** (2026-11-04) |
| [GHSA-v924-7rp8-4mxh](https://github.com/rails/rails/security/advisories/GHSA-v924-7rp8-4mxh) / CVE-2026-126186 | High, CVSS 8.8 | same ranges | same releases |

## Per app

```bash
bundle exec gem list activestorage
```

Compare the loaded gem with 8.0.5.2 and 8.1.4.1. An app is affected by the ImageMagick bug only when all three hold:
`config.active_storage.variant_processor` is `:mini_magick` (the default for `load_defaults 6.1` or earlier; `:vips`
from 7.0), the host ImageMagick policy does not already deny the coders (Debian and Ubuntu do not), and untrusted
users can upload. The FFmpeg bug needs untrusted uploads plus the default video or audio analyzers, or ImageMagick
processing. The AviSynth chain inside it also needs FFmpeg built with `--enable-avisynth`, which upstream, distro,
and Homebrew builds do not enable. The GPL builds from ffmpeg.org do.

- Below the floor and the code path is present → bump. Rails older than 8.0 has no gem fix (7.2's security window
  ended 2026-08-10). Copy the policy denies into the host `policy.xml` and record `Requires major migration` for the
  gem. Rails 8.0's security window ended 2026-11-07; 8.0.5.2 shipped inside it (2026-11-04). Take that gem, and plan
  the move to 8.1. Do not expect a newer 8.0 security release as of 2026-11-15.
- `:vips`, no MiniMagick, and the FFmpeg analyzers removed → `not affected` for these two advisories. The libvips
  kill switch is a different bug.

## The fix has to reach ImageMagick

A bumped gem is not done until the shipped policy is what ImageMagick actually loads.

- `mini_magick` older than 5.1: a fixed Rails raises at boot on a `:mini_magick` app. Bump the gem to 5.1 or newer.
- The app replaces `MiniMagick.cli_env`, clears the environment via `cli_prefix`, or installs its own
  `MiniMagick::Shell`: the shipped policy never starts. Put the denies in the system `policy.xml`.
- GraphicsMagick does not read ImageMagick policies.
- A host allow, including `pattern="*"`, re-enables a coder the shipped policy denies. Re-allow `gs` and its coders
  only when the app really renders PDF or PostScript, and say so on the row.
- Confirm on the running app: `bin/rails runner 'puts MiniMagick.identify { |i| i.list "policy" }'`.

While the bump is in flight, the same host-policy denies are the mitigation for the ImageMagick advisory. For the
FFmpeg advisory, remove `VideoPreviewer` from `config.active_storage.previewers` and `VideoAnalyzer` /
`AudioAnalyzer` from `config.active_storage.analyzers`. A mitigation does not close the row.

## Secrets, before the row closes

Upgrading closes the hole and does not undo a read that already happened.

- ImageMagick advisory: if attachments use the Disk service and the app was reachable while vulnerable, rotate
  `secret_key_base`, the master key, every value in the encrypted Rails credentials file, storage and database credentials,
  and third-party tokens. Do not keep the old secret as a fallback.
- FFmpeg advisory: rotate that set when the host FFmpeg was built with `--enable-avisynth`. Do not rotate every Disk
  app for this advisory alone.
- Say plainly, before rotating, that a new `secret_key_base` logs everyone out and invalidates signed and encrypted
  cookies, signed global IDs, and Active Storage URLs.

Record the rotation date on the board. "Gem bumped" with the old `secret_key_base` still deployed, on an app that
met the Disk rule, is not `Fixed`.
