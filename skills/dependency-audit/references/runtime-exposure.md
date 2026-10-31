# Runtime Defaults That Widen Kernel Exposure

Shared by `dependency-audit` (which services expose the feature) and `container-audit` (which images and pods). Some
kernel CVEs depend on **how applications open sockets**, and the trigger comes from a language runtime's default, not
from a dependency with an advisory. A lockfile audit never shows it. The host side (kernel version, distro tracker,
reboot) is `patch-sweep`'s Linux hosts track.

## Go and MPTCP (worked example: CVE-2026-98432)

The public exploit for CVE-2026-98432, a Linux IPv4 TCP use-after-free, needs an **MPTCP listener**. Go turns MPTCP
on for Linux listen sockets by default:

- Go's `multipathtcp` setting: `0` off, `1` dialers and listeners, `2` **listeners only (the default since Go 1.24)**,
  `3` dialers only. Listeners are exposed under `1` or `2`.
- **The default follows the main module's `go` line, not the toolchain.** A module that says `go 1.23` keeps the old
  default (`0`) even when built with Go 1.25. `godebug multipathtcp=0` in `go.mod`, or `//go:debug multipathtcp=0` in
  the main package, sets it at build time. `GODEBUG=multipathtcp=0` in the environment sets it at run time.
- `net.ListenConfig.SetMultipathTCP(true)` on a socket wins over all of the above.

The Go security team calls per-program opt-outs "a fragile mitigation": one MPTCP listener left exposed is enough, and
they assume every viable exploit needs MPTCP ([oss-security, 2026-10-30](https://www.openwall.com/lists/oss-security/2026/10/30/1)).
The kernel fix is still required.

### Check the source

```bash
rg -n '^(go|toolchain) ' go.mod                                          # go >= 1.24 → listener default is on
rg -n 'godebug\s+multipathtcp=|^godebug \(' go.mod                       # build-time opt-out (or a godebug block)
rg -n '//go:debug multipathtcp=' --glob '*.go'                          # main-package directive
rg -n 'SetMultipathTCP\(' --glob '*.go'                                  # per-socket override, either way
rg -n 'GODEBUG=.*multipathtcp' Dockerfile* *.service docker-compose*.yml k8s/ deploy/ 2>/dev/null   # run-time opt-out
```

### Check the binary (authoritative)

What the build actually did is in the binary. `go version -m` reads it without running it:

```bash
go version -m ./path/to/binary | rg -i 'go1\.|DefaultGODEBUG|multipathtcp'
```

A binary built with Go 1.24 or later whose `DefaultGODEBUG` doesn't include `multipathtcp=0` (or `3`) listens with
MPTCP unless its environment sets `GODEBUG=multipathtcp=0`.

| Situation | Exposure |
|---|---|
| Built with Go ≥ 1.24, no opt-out in the binary or the environment, Linux, listens on a reachable port | **Exposed** when the host kernel is vulnerable and `net.mptcp.enabled=1` in the service's network namespace |
| `SetMultipathTCP(true)` on a listener | Exposed, whatever GODEBUG says |
| `multipathtcp=0` in `DefaultGODEBUG`, or in the service's environment | `Mitigated (platform/config)`, and fragile: the kernel fix is still required |
| Deployed only to PaaS or serverless, no host control | A platform question: `needs_validation`, blocker "the provider's kernel patch status" |

### Finding shape

This is **not** a dependency-advisory row. Record it as `needs_validation`, with blockers "host kernel version against
the distro fix" and "`net.mptcp.enabled` in the service's network namespace", and hand it to `patch-sweep`. It
becomes `confirmed` only when the host side is confirmed vulnerable.

```markdown
#### [needs_validation] Go 1.25 service listens with MPTCP by default (CVE-2026-98432 exposure path)
**Component:** cmd/relay (built with go1.25.3; DefaultGODEBUG has no multipathtcp=0)
**Issue:** Go ≥ 1.24 enables MPTCP on Linux listeners by default; the public exploit for CVE-2026-98432 needs an MPTCP listener.
**Blockers:** host kernel version against the distro fix; `net.mptcp.enabled` in the service's network namespace.
**Remediation:** patch the kernel (patch-sweep). Meanwhile `GODEBUG=multipathtcp=0` in the unit or env, or `godebug multipathtcp=0` in go.mod, plus `net.mptcp.enabled=0` in the host's and each container's namespace.
```

### Other runtimes

MPTCP isn't a default elsewhere today, but the same check finds explicit use: `IPPROTO_MPTCP` (262) in C or Rust,
`socket.IPPROTO_MPTCP` in Python, `mptcpize run` wrappers in unit files, and `net.mptcp.*` sysctls set in
Dockerfiles, compose files or pod specs.

## Containers share the host kernel

**An image can't patch a kernel CVE.** Rebuilding images doesn't help: the node's kernel is what's exposed. For a
kernel advisory, every container on the host is in scope through the host. Hand it to `patch-sweep`'s host track, and
record the image as "not the fix location".

**MPTCP is per network namespace, and a new namespace starts with it on.** The kernel sets `mptcp_enabled = 1` for
every new namespace (`net/mptcp/ctrl.c`), so `net.mptcp.enabled=0` on the host doesn't reach containers. Check
inside each running container's namespace:

```bash
docker exec <container> sysctl net.mptcp.enabled          # needs sysctl in the image
nsenter -t <pid> -n sysctl net.mptcp.enabled               # from the host, using the container's PID
nsenter -t <pid> -n ss -Mltn                               # MPTCP listeners in that namespace
```

These need access to the host or the container runtime; they prompt.

- **Compose:** `sysctls: { net.mptcp.enabled: 0 }` per service.
- **Kubernetes:** `securityContext.sysctls` per pod. `net.mptcp.enabled` isn't in the kubelet's safe set, so a pod that
  sets it fails to start unless the node's kubelet allows it (`--allowed-unsafe-sysctls=net.mptcp.enabled`). The
  mitigation is per workload, so it has to be checked per workload.
- **`hostNetwork: true` / `--network host`:** the container uses the host's namespace and its value. Per-pod `net.*`
  sysctls aren't allowed there; the host setting is what counts.

**Go binaries in images.** Extract the main binary without running the image (`docker create` then `docker cp`, or
`crane export`), run `go version -m` on it, and apply the table above to every image that exposes a port.

## Sources

- Go: [GODEBUG history](https://go.dev/doc/godebug) (`multipathtcp` values and defaults; go-line rule), Go security
  team on [oss-security](https://www.openwall.com/lists/oss-security/2026/10/30/1)
- Linux `net/mptcp/ctrl.c` (`mptcp_pernet_set_defaults`)
- Kubernetes, [Using sysctls in a Kubernetes Cluster](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)
- Proposed by @coreyhaines31 in issue #221
