# Linux Hosts and Kernel CVEs

Companion to `patch-sweep`, for self-managed Linux hosts: VPSes and droplets, EC2 and Lightsail, bare metal, home
servers, Bitcoin or Lightning nodes, Nostr relays, self-hosted CI runners, and Kubernetes nodes. A kernel CVE isn't in
any lockfile, can't be fixed by a redeploy, and isn't fixed until the host reboots into the patched kernel.

## Scope

Hosts the user owns or administers, in accounts named in the Authorization step. Every command on a host is run over
the user's own SSH session, or by the user, and prompts. **Reboots and firewall changes are the owner's call**, made
in a window they choose. On a node with peers or uptime commitments (Lightning channels, validators, relays), the
skill asks first and never reboots on its own.

## Step 1 — Inventory hosts

```bash
# Instances in each account, project and region the user named
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PlatformDetails,PublicIpAddress,Tags[?Key==`Name`]|[0].Value]' --output text
doctl compute droplet list --format ID,Name,PublicIPv4,Image
hcloud server list
gcloud compute instances list
```

Then **ask** about the rest: home servers, nodes and relays, self-hosted runners, and Kubernetes node pools
(`cloud-audit` covers the cluster side). One row per host: provider, distro and release, **running** kernel,
**installed** kernel, internet-facing listeners, owner.

## Step 4 — Is each host affected?

Read-only, on each host:

```bash
uname -r                                                   # RUNNING kernel: what counts until the next reboot
grep -E '^(ID|VERSION_ID)=' /etc/os-release
dpkg -l 'linux-image-*' | awk '/^ii/{print $2, $3}'        # Debian / Ubuntu: installed kernels
rpm -q kernel kernel-core                                  # RHEL / Fedora / Amazon Linux
needrestart -k -b 2>/dev/null                              # Debian / Ubuntu: NEEDRESTART-KSTA 3 = newer kernel installed, reboot pending
[ -f /var/run/reboot-required ] && echo REBOOT-REQUIRED
dnf needs-restarting -r 2>/dev/null                        # RHEL family
```

**Look the running kernel package up in the distro's tracker, never against upstream version numbers.** Ubuntu, RHEL
and Amazon kernels carry their own versions (`5.15.0-125-generic`, `5.14.0-503.el9`,
`6.1.112-122.189.amzn2023`) with fixes backported, so an upstream `6.1.190` tells you nothing about them.

| Distro | Tracker |
|---|---|
| Debian | `https://security-tracker.debian.org/tracker/<CVE>` |
| Ubuntu | `https://ubuntu.com/security/<CVE>` (JSON: `https://ubuntu.com/security/cves/<CVE>.json`) |
| RHEL, Alma, Rocky | `https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json` (`container-audit`'s `references/vendor-severity.md`) |
| Amazon Linux | `https://alas.aws.amazon.com/cve/html/<CVE>.html` |
| SUSE, openSUSE | `https://www.suse.com/security/cve/<CVE>.html` |
| Upstream and others | OSV `Kernel` ranges: `https://api.osv.dev/v1/vulns/<CVE>` |

Use the distro's severity next to NVD's (`severity-calibration.md`, exploitation signals; KEV and EPSS still apply).

**Exposure:** does the vulnerable code path apply on this host? For a network-reachable kernel bug, start with what
listens on public interfaces (`ss -ltnp`), then the advisory's preconditions. Mark each row `affected`,
`affected — fix not shipped`, `patched on disk, reboot pending`, or `not affected (reason)`.

## Step 5 — Mitigate while the distro hasn't shipped

Each mitigation needs a **verify** line and a **persist** line, and a date for when it comes off. A mitigation added
"for now" tends to stay forever.

- **Livepatch** where the host has it (Ubuntu Pro Livepatch, kpatch, Amazon Kernel Live Patching). Check the
  livepatch status for this CVE; don't assume it's covered.
- **Turn off the vulnerable feature** with a sysctl or module setting, when the advisory names one. Persist it in
  `/etc/sysctl.d/`. Many network sysctls are **per network namespace**, so containers keep their own value (see
  `container-audit`).
- **Filter the trigger at the host firewall**, when the trigger has a packet shape normal traffic doesn't use. Cloud
  firewalls and security groups match addresses and ports, not packet contents, so this has to live on the host.
  Use the host's firewall manager (ufw, firewalld, `/etc/nftables.conf`). A raw `nft` rule added beside a manager is
  wiped on its next reload. Syntax-check with `nft -c -f` first.
- **App-level switches** (a runtime flag that stops apps using the feature) are a supplement, never the fix.

## Step 6 — Patch: update, reboot, verify

1. Update the kernel package (prompts).
2. **Reboot** in the owner's window. A host that installed the fix but didn't reboot is still vulnerable. That's the
   most common way a kernel sweep goes wrong.
3. Confirm `uname -r` is the fixed package version, and re-check the tracker row.
4. Re-check every mitigation after the reboot (`sysctl …`, `nft list table …`). Keep it or remove it on the date you
   set, and record which.
5. **Kubernetes:** cordon, drain and replace node pools with the patched node image; check the node image's kernel
   version, not the pod images. Managed node groups need the provider's patched image.
6. **Lightning nodes:** shut the node daemon down cleanly before the reboot, and check that channels come back.

## Board

```markdown
## Hosts

| host | provider | distro | running kernel | fixed pkg available? | mitigations | exposure | rebooted? | status | owner action |
|---|---|---|---|---|---|---|---|---|---|
| node-2 | droplet | Ubuntu 24.04 | 6.8.0-71 | **pending (Ubuntu)** | mptcp off + nft ipopt drop | MPTCP listener (lnd?) | n/a | Mitigated (platform/config) | re-check tracker daily |
| runner-3 | ec2 | AL2023 | 6.1.112-… | yes (ALAS2023-2026-3365) | — | public SSH only | **no** | Patched on disk, reboot pending | reboot window |
| relay-1 | hetzner | Debian 12 | 6.1.180-1 → 6.1.190-1 | yes | — | no | yes | Fixed | — |
```

Sort: internet-facing with no fix shipped and the exploit's precondition present, then internet-facing with a reboot
pending, then everything else.

## Prevention

- `unattended-upgrades` (decide `Unattended-Upgrade::Automatic-Reboot` on purpose), `dnf-automatic`, or
  `dnf upgrade --security` on Amazon Linux, plus an alert when a reboot is pending (`needrestart`,
  `/var/run/reboot-required`).
- Livepatch where reboots are expensive.
- A weekly check on every host that the running kernel matches the newest installed one.

## Worked example: CVE-2026-98432 (facts as of 2026-10-30; tracker statuses change)

**What it is.** A use-after-free in IPv4 TCP connection setup. `ireq_opt` (the IP options saved from a SYN) is handed
to the child socket without a copy, and freed without an RCU grace period while another CPU can still be building a
SYN-ACK in `ip_options_build()`. The fix ("ipv4: free inet_opt and ireq_opt after an RCU grace period") uses
`kfree_rcu()`. A second path goes through request-socket migration (`net.ipv4.tcp_migrate_req=1`, or a
`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` program). IPv6 isn't affected by the first path. Remote and unauthenticated.

**Exploitation.** Anthropic's write-up shows remote code execution as root against "Linux servers with a multipath TCP
listener" (about 48 minutes to leak a kernel pointer, then a few more to run a command). The Go security team adds
that "the underlying bug is not specific to MPTCP". Not in CISA KEV (catalog 2026.10.30); EPSS 0.00445.

**Severity.** CVSS 9.8 (OSV, Ubuntu), but Red Hat and Amazon score it 8.1 (`AC:H`). Red Hat rates it Important.

**Fixed upstream** in 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56 and 7.2.10 (mainline 7.3-rc7). OSV's
ranges start at 4.4. A popular fixed-version list left out 5.10 and 5.15. Ubuntu 22.04's GA kernel is 5.15, and many
older hosts and appliances run 5.10.

| Distro | Status on 2026-10-30 |
|---|---|
| Debian | bookworm fixed in `6.1.190-1` (DLA-4841-1; `linux-6.12` in `6.12.113-1~deb12u1`), trixie in `6.12.113-1` (DSA-6568-1), forky and sid fixed |
| Ubuntu | No release fixed. 22.04, 24.04, 26.04 and 26.10: pending. 18.04 and 20.04: needed |
| Red Hat | RHEL 8, 9, 10 (kernel and kernel-rt) and OpenShift node images: Affected, no erratum. RHEL 6, 7: Not affected. Red Hat says no mitigation meets its criteria |
| Amazon Linux | AL2023 fixed (kernel ALAS2023-2026-3365, kernel6.12, kernel6.18); AL2 core kernel fixed (ALAS2-2026-4065); AL2 extra 5.4, 5.10, 5.15 kernels: pending |
| SUSE | Mixed: SLES 16 and SLE Micro 5 released; openSUSE Leap 15 and SLE Micro 6 partly affected. Check per product |

**Exposure check:**

```bash
sysctl net.mptcp.enabled              # 1 = MPTCP sockets can be created in this network namespace
ss -Mltnp                             # MPTCP listening sockets and the process that owns each
sysctl net.ipv4.tcp_migrate_req       # 1 = the second trigger path is on (default 0)
```

Go 1.24 and later enable MPTCP on Linux listen sockets by default, so every Go server is a candidate. Finding which
services and images those are → `dependency-audit` and `container-audit` (runtime defaults).

**Mitigations while the fix isn't shipped** (each with verify and persist):

1. **Turn MPTCP off** where nothing needs it: `sysctl -w net.mptcp.enabled=0`, persisted in
   `/etc/sysctl.d/99-mptcp-off.conf` (`net.mptcp.enabled = 0`). Verify with `ss -Mltn` (no MPTCP listeners after the
   services restart). This closes the demonstrated exploit's precondition, not the bug. It's per network namespace:
   set it inside each container's namespace too.
2. **Go services:** `GODEBUG=multipathtcp=0` in the service's environment, or `godebug multipathtcp=0` in the main
   module's `go.mod`. Per the Go team this is "a fragile mitigation": a single MPTCP listener left exposed is enough,
   and it assumes every viable exploit needs MPTCP. Use it alongside (1) and the kernel fix, never alone.
3. **Keep `net.ipv4.tcp_migrate_req` at 0** unless something needs it.
4. **Drop inbound IPv4 TCP that carries IP options.** No vendor has published this, so it's our reasoning from the
   fix, not a vendor mitigation: `ireq_opt` only holds anything when the SYN carried IP options, and ordinary TCP
   traffic doesn't use them. It blocks that trigger path, not every path, and it's a stopgap until the reboot.
   ```
   table inet ipopt_guard {
     chain prerouting {
       type filter hook prerouting priority raw; policy accept;
       ip hdrlength > 5 meta l4proto tcp limit rate 10/second log prefix "ipopt-drop " counter drop
       ip hdrlength > 5 meta l4proto tcp counter drop
     }
   }
   ```
   `priority raw` drops before connection tracking, and the log is rate-limited so a probe flood can't fill the disk.
   Verify with `nft list table inet ipopt_guard` (the counters), and from an outside host if one is available.
   Persist through the host's firewall manager.
5. **Livepatch:** check whether the provider's livepatch covers this CVE.

**Sources:** OSV `CVE-2026-98432`; the Debian, Ubuntu, Red Hat, Amazon Linux and SUSE trackers; FIRST EPSS; CISA
KEV; Anthropic, ["Discovering vulnerabilities with Claude"](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude);
Go security team on [oss-security, 2026-10-30](https://www.openwall.com/lists/oss-security/2026/10/30/1). Proposed by
@coreyhaines31 in issue #220.
