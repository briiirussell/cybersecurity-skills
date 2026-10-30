# Vendor Severity for OS Packages

Companion to `container-audit` "Verify, then record". Image scanners rate OS-package CVEs mostly by NVD. For a
distro base image, NVD is often the wrong source. Distros backport fixes without changing the upstream version, build
with different options, and rate CVEs for the package they actually ship. Before recording an OS-package CVE from
`trivy image`, check what the distro says about its own package.

Every source here is public and needs no key. They were checked on 2026-10-29.

## Red Hat (RHEL and UBI images)

```bash
curl -s https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-0286.json \
  | jq '{threat_severity, package_state: [.package_state[] | {product_name, package_name, fix_state}],
         affected_release: [.affected_release[]? | {product_name, advisory, package}]}'
```

- `threat_severity`: Red Hat's rating (`Low`, `Moderate`, `Important`, `Critical`) for its build.
- `package_state[].fix_state`, per product: `Affected`, `Not affected`, `Will not fix`, `Fix deferred`,
  `Out of support scope`.
- `affected_release[]`: products where a fix shipped, with the RHSA advisory and the fixed package version.

Match the product to the image: UBI 8 is Red Hat Enterprise Linux 8, UBI 9 is RHEL 9.

## Debian and Ubuntu

OSV carries both distros' own data. One query per package and installed version (the version as `dpkg` reports it):

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"ecosystem":"Debian:12","name":"openssl"},"version":"3.0.11-1~deb12u2"}'
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"openssl"},"version":"3.0.2-0ubuntu1"}'
```

These return only the advisories that apply to that distro version of the package. For Debian's status notes on
one CVE (`not-affected`, `no-dsa`, `ignored` and the reason), read its page:
`https://security-tracker.debian.org/tracker/CVE-…`. The tracker's full JSON export is about 87 MB, so don't fetch
it for one lookup.

## How the vendor's answer maps to verdicts

| Vendor says | Record |
|---|---|
| **Not affected** for the image's product or release | `rejected`. `ruled_out_by.control` names the vendor statement ("Red Hat: Not affected in RHEL 9"); `location` points at the saved response under `<audit dir>/evidence/` |
| **Fixed**, and the installed package is at or above the fixed version (an RHSA's package, the distro's fixed version) | `rejected`: the backport is in. Same evidence rule. This is the most common trivy false positive on UBI images |
| **Affected**, or **Fix deferred** | The finding stands; the usual reachability rule decides `confirmed` or `needs_validation`. No vendor fix exists yet, so the plan is a mitigation or a different base image |
| **Will not fix** | The finding stands. The fix plan is a different base image (`Requires major migration`), or the owner signs off on `Accepted Risk`. The vendor's decision is input to that call, not the call itself |

For severity, use the vendor's rating when it describes the shipped build, and note NVD's next to it. Exploitation
signals (CISA KEV, EPSS) still apply to the CVE. Run `node references/enrich-advisories.mjs findings.json -o
findings.json` once the records are written.

## `ext` keys

| Key | Example |
|---|---|
| `vendor` | `"redhat"`, `"debian"`, `"ubuntu"` |
| `vendor_severity` | `"Moderate"` |
| `vendor_fix_state` | `"Not affected"`, `"Will not fix"`, `"Fixed"` |
| `vendor_advisory` | `"RHSA-2023:3354"` |

## Sources

- Red Hat, [Security Data API](https://docs.redhat.com/en/documentation/red_hat_security_data_api/)
- [OSV API](https://google.github.io/osv.dev/api/) (Debian and Ubuntu ecosystems), and the
  [Debian security tracker](https://security-tracker.debian.org/tracker/)
- Proposed by @coreyhaines31 in issue #207
