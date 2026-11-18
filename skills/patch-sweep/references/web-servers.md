# Web Servers and Reverse Proxies in a Sweep

Companion to `patch-sweep`, for an advisory set that includes nginx or another front proxy. The usual sweep maps repos
to deployed apps and reads lockfiles. The proxy in front of those apps isn't in any lockfile, and it hides in places the
usual map never lists:

1. **Distro packages on hosts.** `nginx`, `nginx-core`, `nginx-full`, `openresty`, installed by the OS package manager.
2. **Container images.** nginx baked into an app image, a sidecar, or a static-site image (`FROM nginx:…`,
   `FROM openresty/…`, or `apt-get install nginx` inside a Dockerfile).
3. **Kubernetes ingress controllers that bundle their own nginx.** Updating nginx on the nodes doesn't touch them.
4. **Managed platforms.** Vercel, Heroku, Render, Netlify and similar run their own edge. The customer doesn't manage
   that nginx, but a repo can still ship its own proxy in a Dockerfile.

## Scope

Hosts, images and clusters the user owns or administers, in accounts named in the Authorization step. Reloads,
restarts, config changes and redeploys prompt and are the owner's call. Hosts follow
[linux-hosts.md](linux-hosts.md): same inventory commands, same reboot and window rules.

## Step 1 — Inventory every front proxy

One row per **place nginx runs**: host package, image (by digest), or ingress controller. A host and the images it runs
are separate rows. A fixed host package does not fix an image, and a rebuilt image does not fix the host.

```bash
# Repo side: images, compose files, Helm values and config files that ship a proxy
grep -rnE '^FROM .*(nginx|openresty)' --include='Dockerfile*' --include='Containerfile*' .
grep -rnE 'apt-get install.*nginx|apk add.*nginx|dnf install.*nginx|yum install.*nginx' --include='Dockerfile*' .
grep -rnE 'image: .*(nginx|openresty)' --include='*.yml' --include='*.yaml' .
find . -name 'nginx.conf' -o -path '*/nginx/*.conf' -o -path '*/deploy/*' -name '*.conf'
```

```bash
# Host side (read-only, over the user's own SSH session)
dpkg-query -W -f='${Package} ${Version}\n' 'nginx*' 'openresty*' 2>/dev/null   # Debian / Ubuntu
rpm -qa 'nginx*' 'openresty*' 2>/dev/null                                      # RHEL / Fedora / Amazon Linux
apk info -v 2>/dev/null | grep -E '^(nginx|openresty)'                         # Alpine
nginx -V 2>&1 | head -5      # upstream version and build flags (--with-http_v2_module, --with-http_v3_module, --with-mail)
```

```bash
# Cluster side: running images by digest, and the ingress controllers
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.imageID}{" "}{end}{"\n"}{end}' | grep -iE 'nginx|openresty|ingress'
kubectl get ingressclass
```

**Managed platforms:** mark `not affected (platform-managed edge)` only after checking the repo for a self-hosted proxy
(a Dockerfile, an `nginx.conf`, a `deploy/` directory). A Heroku app with an nginx buildpack or a Render Docker service
that starts nginx is a customer-managed proxy.

## Step 4 — Is each row affected?

A row is affected only if both line up: **the nginx build is in the vulnerable range** and **the advisory's config
precondition is present**. Write down which one rules a row out.

**Version: trust the distro tracker, not `nginx -v`.** Debian, Ubuntu, RHEL and Amazon backport fixes into the version
they shipped, so a patched host can still print the old upstream version (Ubuntu 22.04 ships `1.18.0-6ubuntu14.x`,
24.04 ships `1.24.0-2ubuntu7.x`, Debian 12 ships `1.22.1-9+deb12u…`). Look the installed **package** version up in the
tracker, the same rule [linux-hosts.md](linux-hosts.md#step-4--is-each-host-affected) uses for kernels:

| Distro | Tracker |
|---|---|
| Debian | `https://security-tracker.debian.org/tracker/<CVE>` |
| Ubuntu | `https://ubuntu.com/security/<CVE>` (JSON: `https://ubuntu.com/security/cves/<CVE>.json`) |
| RHEL, Alma, Rocky | `https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json` |
| Amazon Linux | `https://alas.aws.amazon.com/cve/html/<CVE>.html` |
| Alpine | `https://security.alpinelinux.org/vuln/<CVE>` |
| nginx.org packages, source builds | upstream ranges on `https://nginx.org/en/security_advisories.html` |

Images: read the image's package database with the scanner (`trivy image`, `syft`; see `scanner-pipeline`), then apply
the same rule. An image that installs the distro package needs the distro tracker. An image built from nginx.org
packages or source reports the upstream version, and the upstream range applies directly.

**Config: read the effective config, not one file.** `nginx -T` prints the merged config including every `include`
(read-only; it tests and dumps). For a repo, read its `nginx.conf` and the files it includes. Grep for the
preconditions:

```bash
nginx -T 2>/dev/null | grep -nE 'http2|listen .*quic|http3|resolver|proxy_pass .*\$|^\s*mail|auth_http|\bssi on|mirror '
```

Mark each row `affected`, `affected — fix not shipped (distro)`, `in range, precondition absent`, or
`not affected (reason)`. "Precondition absent" rows still get the patch; they move down the queue, not off the board.

**Exploitation signals:** look up KEV and EPSS once for the advisory set (Step 4 of `SKILL.md`). Offline, write
`not checked`; never fill KEV from memory. When a working exploit is reported or public, rank internet-facing rows
with the precondition first even before a KEV listing, and re-run the KEV lookup on the next sweep pass instead of
assuming the status hasn't changed.

## Step 5 — Mitigate while the patch waits

Each stopgap needs a **verify** line, a **persist** line (the config file in git or config management, not a hand
edit), and a **removal date**. A disabled protocol left off "for now" tends to stay off.

- **Turn off the protocol or feature the advisory names**, per server block, then `nginx -t` and reload (prompts).
- **Confirm no old workers remain.** After a reload, old workers keep serving their existing connections with the old
  config until they exit, and a reload never loads a new binary. Check worker start times:
  `ps -o pid,lstart,cmd -C nginx`. Workers older than the reload mean the stopgap isn't fully live yet; a restart in
  the owner's window clears them.
- **A CDN or WAF in front** that terminates the affected protocol may reduce exposure. It doesn't if the origin is
  reachable directly; check that before counting it.
- **Ingress controllers:** apply the stopgap through the controller's own config (its ConfigMap or annotations), not by
  editing the generated `nginx.conf` in the pod, which the controller overwrites.

## Step 6 — Patch, rebuild, redeploy, verify

1. **Hosts:** update the distro package once the tracker lists a fixed version (prompts), restart nginx (a reload
   keeps the old binary), re-check the package version against the tracker, and confirm worker start times are after
   the restart.
2. **Images:** rebuild on a fixed base with a fresh pull (`docker build --pull`, or bump the pinned base digest), then
   redeploy. Record the image digest before and after. Confirm running pods use the new digest (the `imageID` column
   from Step 1), not just that the tag moved.
3. **Ingress controllers:** upgrade the controller to a release whose bundled nginx is fixed, per that controller's own
   release notes. If the project no longer ships releases, the row is `Requires major migration` (another
   controller, or Gateway API), with the stopgap applied meanwhile and an owner and date for the migration.
4. Turn the stopgap off on its removal date once the row is fixed, and record that you did.

## Board

```markdown
## Front proxies

| where | kind | nginx (pkg / upstream) | in range? | precondition | stopgap | patched? | status | owner action |
|---|---|---|---|---|---|---|---|---|
| web-1 | host, Ubuntu 24.04 | 1.24.0-2ubuntu7.19 | yes (tracker: needed) | http2 on :443 | http2 off, remove 2026-12-02 | **no fix shipped** | Mitigated (platform/config) | re-check tracker daily |
| acme/site:prod | image | nginx 1.31.8 | yes | http2 + proxy_pass | — | yes | patched (rebuilt image digest sha256:4f1c…) | — |
| acme/api:prod | image on web-1 | distro pkg, old base | yes | http2 | — | **no** | host patched, image not rebuilt | rebuild with --pull, redeploy |
| cluster-a | ingress-nginx v1.15.1 | bundled 1.27.1 | yes | http2 (default on) | use-http2 "false" | no upstream fix | Requires major migration | migrate controller by <date> |
| marketing | vercel | platform edge | n/a | — | — | n/a | not affected (platform-managed edge, no proxy in repo) | — |
```

`patched (rebuilt image digest X)` and `host patched, image not rebuilt` are different statuses. Never collapse an
image row into its host row. Sort: internet-facing with the precondition and no fix shipped, then internet-facing
waiting on a rebuild or restart, then everything else.

## Worked example: nginx2root (nginx 1.31.9 / 1.30.7, 2026-11-18)

Checked 2026-11-18 against nginx.org's security advisories and `CHANGES`, the F5 CNA records on NVD, the fix commit,
the Ubuntu and Debian trackers, Wiz, Aikido, and Xint's announcement. The F5 article K000163926 did not render for
automated reading; its content here comes only through the NVD records F5 filed. Tracker statuses change; re-check.

**What it is.** Xint's name for five nginx bugs it reports as "each capable of unauthenticated remote code execution
under affected conditions", fixed in **1.31.9** (mainline) and **1.30.7** (stable), released 2026-11-18. The worst,
CVE-2026-123007, is an HTTP/2 flow-control window overflow that leads to memory corruption (fix commit
[b89c410](https://github.com/nginx/nginx/commit/b89c4100bf6762a45e4a6463eaf4b70368277c94), "HTTP/2: account for queued
frames when validating WINDOW_UPDATE"; GHSA-m4q8-cf44-f42r). Xint says one of the five affects "nginx's most common
configuration".

| CVE | Bug (nginx.org) | Applies when | Vulnerable (nginx.org) | `http2 off` blocks it? | Stopgap |
|---|---|---|---|---|---|
| CVE-2026-123007 | Memory corruption in HTTP/2 flow control | HTTP/2 enabled and reachable | 1.9.5–1.31.8 | Yes | `http2 off;` in each server block (1.25.1+); on older versions remove `http2` from `listen` |
| CVE-2026-123633 | Use-after-free in HTTP/2 | HTTP/2 + requests proxied to an upstream; CHANGES: "if worker_connections were not enough" | 1.19.7–1.31.8 | Yes | same as above |
| CVE-2026-121810 | Use-after-free in HTTP/3 | HTTP/3 (QUIC) + upstream | 1.25.0–1.31.8 | No | remove the QUIC listeners and set `http3 off;` |
| CVE-2026-123634 | Use-after-free in resolver | `resolver` set, `proxy_pass` with a variable, and a subrequest (SSI or `mirror`) resolving the same name | 0.6.18–1.31.8 | No | point `proxy_pass` at a fixed `upstream` group instead of request-time DNS |
| CVE-2026-113425 | Use-after-free in mail proxy | mail `proxy on` + `auth_http` | 0.5.33–1.31.8 | No | bind mail proxy listeners to loopback, or allow only trusted IPs at the firewall |

"Applies when" and the stopgaps are per Aikido, with CVE-2026-123634's subrequest condition from F5's NVD description.
Aikido gives earlier first-affected versions for two rows (1.13.4 for CVE-2026-123634, 0.5.15 for CVE-2026-113425);
the table uses nginx.org's ranges. Disabling HTTP/2 makes clients fall back to HTTP/1.1, and breaks anything that
needs HTTP/2 to this server, such as gRPC.

**The same release fixes five more** (nginx.org ranges; fixed 1.31.9+ / 1.30.7+ unless noted). A bump to the fixed
release covers them; a protocol stopgap above does not:
CVE-2026-118899 (endless loop reading the request body over TLS 1.3, major, 1.13.0–1.31.8),
CVE-2026-125283 (buffer overflow with `alias` + `try_files`, minor, 0.9.6–1.31.8),
CVE-2026-120967 (stream SNI bypass with client certificate validation, medium, 1.25.5–1.31.8),
CVE-2026-123640 (stream `ssl_preread` ClientHello parsing, minor, 1.15.2–1.31.8),
CVE-2026-120993 (NULL dereference with PROXY protocol v2 and dynamic certificates, minor, 1.31.4–1.31.8; fixed in
1.31.9, the 1.30 stable line is not in range).

**Severity.** nginx.org rates CVE-2026-123007 and CVE-2026-113425 major, and CVE-2026-123633, CVE-2026-121810 and
CVE-2026-123634 medium. F5's CNA records on NVD score each of the five CVSS 4.0 9.2 (`AV:N/AC:H/AT:N/PR:N/UI:N`).
Ubuntu rates CVE-2026-123007 priority High, CVSS 3 8.1. Quote the source next to any score you copy.

**NGINX Plus** (F5 CNA records on NVD; Wiz's table matches for the two HTTP/2 CVEs): R33 is affected. Fixed in
37.0.8.1 and 37.3.0.1 for CVE-2026-123007, CVE-2026-121810, CVE-2026-123634 and CVE-2026-113425, and in 37.0.7.1 and
37.2.0.1 for CVE-2026-123633.

**Distros on 2026-11-18:**

| Distro | Status |
|---|---|
| Ubuntu | CVE-2026-123007, -123633, -123634, -113425: needed on 16.04 through 26.10, no fixed package yet. CVE-2026-121810: not affected (code not present) through 24.04, needed on 26.04 and 26.10. 14.04: not affected by the two HTTP/2 CVEs (no HTTP/2), needed for -123634 and -113425 |
| Debian | CVE-2026-123007 and -123633: bookworm (`1.22.1-9+deb12u10`), trixie (`1.26.3-3+deb13u10`), forky and sid (`1.30.6-3`) vulnerable, unfixed. The other three had no tracker entry yet |

Until a distro ships, distro-package rows are `affected — fix not shipped (distro)` with a stopgap from the table.

**ingress-nginx.** `kubernetes/ingress-nginx` is archived; its last release is `controller-v1.15.1` (2026-03-19), and
that tag's build script sets `NGINX_VERSION=1.27.1`, inside the ranges of both HTTP/2 CVEs. Aikido says it is
vulnerable to CVE-2026-123633 and "won't get a patch". Rows go to `Requires major migration`. Meanwhile, HTTP/2 can be
turned off with the controller ConfigMap key `use-http2: "false"` (default `"true"`). Aikido offers its own patched
build of v1.15.1; taking a third-party build is an owner decision, recorded on the board, not an upstream fix.

**Exploitation.** Wiz says it built proof-of-concept exploits and ran them against common configurations in a lab, and
won't release them. Xint says it "demonstrated a fully remote, unauthenticated exploit chain that escalates from nginx
RCE to root access on the underlying server, using a separate Linux kernel vulnerability". Per Aikido, that kernel bug
is a use-after-free in the SCTP send path, introduced in Linux 4.15, and the chain works "including from inside a
Docker container". No kernel CVE ID was published as of 2026-11-18. Public exploit and checker repos were reported
when this was written; nothing here is taken from them. KEV and EPSS: `not checked` in this file; run the Step 4
lookup for the sweep, and rank internet-facing HTTP/2 rows first whatever it returns.

**Kernel half of the chain.** On hosts that don't use SCTP, Aikido's stopgap is `install sctp /bin/false` in a `.conf`
file under `/etc/modprobe.d/`. It "does not unload a module that is already loaded or affect SCTP compiled into the
kernel". Verify with `lsmod | grep -w sctp` (loaded already: unloading it or rebooting is the owner's call) and
`grep CONFIG_IP_SCTP= /boot/config-$(uname -r)` (`=y` is built in, and the modprobe rule does nothing there).
Containers share the host kernel, so this is set on the host, not in images. The verify, persist and removal-date rules
are in [linux-hosts.md Step 5](linux-hosts.md#step-5--mitigate-while-the-distro-hasnt-shipped); when a kernel CVE is
published, the kernel gets its own host rows there.

**Sources:** [nginx security advisories](https://nginx.org/en/security_advisories.html);
[nginx CHANGES](https://nginx.org/en/CHANGES); NVD
[CVE-2026-123007](https://nvd.nist.gov/vuln/detail/CVE-2026-123007) and
[CVE-2026-123633](https://nvd.nist.gov/vuln/detail/CVE-2026-123633) (F5 CNA records); F5
[K000163926](https://my.f5.com/manage/s/article/K000163926); Wiz,
["nginx HTTP/2 RCE vulnerabilities"](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities); Aikido,
["nginx2root"](https://www.aikido.dev/blog/nginx2root-critical-nginx-rce-vulnerabilities); Xint on
[infosec.exchange](https://infosec.exchange/@xint/117638122562604983);
[Ubuntu CVE-2026-123007](https://ubuntu.com/security/CVE-2026-123007); the Debian tracker; `kubernetes/ingress-nginx`
at `controller-v1.15.1`. Proposed by @coreyhaines31 in issue #301.
