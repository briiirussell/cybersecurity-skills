---
name: container-audit
description: "Audit container images, Dockerfiles, and Kubernetes manifests for misconfigurations, excessive privileges, exposed secrets, and runtime risks. Use when the user mentions 'container security,' 'Docker security,' 'Dockerfile audit,' 'Kubernetes security,' 'K8s security,' 'pod security,' 'container hardening,' 'kubectl audit,' 'image scanning,' 'distroless,' 'rootless containers,' 'pod security policy,' 'pod security standards,' 'PSS,' 'network policy,' 'OPA Gatekeeper,' 'Kyverno,' 'runtime security,' or needs to review container or orchestration security."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
---

# Container Audit — Docker & Kubernetes Security Review

Audit container images, Dockerfiles, Helm charts, Kustomize overlays, and Kubernetes manifests for misconfiguration, excessive privilege, exposed secrets, and runtime security gaps. Distinct from `cloud-audit` (cloud-provider IAM and managed services) and `dependency-audit` (package CVEs in the application). This skill is the container/orchestration layer between them.

## Scope the Audit

1. Inventory the surface — Dockerfiles, base images, registries, Helm charts, K8s manifests, Kustomize overlays, CI build pipelines that produce images
2. Identify the runtime — vanilla K8s, EKS, GKE, AKS, OpenShift, ECS Fargate, Cloud Run, Fly.io
3. Identify the network model — service mesh, ingress controller, default-deny vs default-allow
4. Identify the secret model — K8s Secrets (base64-only), External Secrets Operator, sealed-secrets, Vault, Doppler

## Audit Checklist — Dockerfile

### Base image & supply chain

- Pinned by digest, not tag — `FROM node:20@sha256:abc...` not `FROM node:20` (which can move)
- Distroless / minimal where possible — `gcr.io/distroless/nodejs20`, `alpine` (be aware of musl quirks), `chainguard/*`
- Not using `:latest` — non-reproducible builds
- Multi-stage builds discard build-time tooling — `FROM build AS builder` → `FROM runtime` final stage
- Grep for: `FROM .*:latest`, `FROM .*:[0-9]+$` (tag without digest)

### Build-time exposure

- Secrets passed via `--build-arg` end up in image layers visible to anyone who pulls the image — use BuildKit secrets (`--mount=type=secret`) or runtime env vars instead
- `COPY . .` ships everything in the build context — `.dockerignore` should exclude `.git`, `.env`, `node_modules`, `*.pem`, `.aws/`, `.ssh/`
- `ADD <url>` follows redirects and disables checksum verification — prefer `RUN curl ... && sha256sum -c`
- Grep for: `ARG .*KEY`, `ARG .*TOKEN`, `ARG .*SECRET`, `ENV .*=.*[A-Za-z0-9]{32,}`, `ADD http`

### Runtime posture

- Non-root user — `USER 1001` (or any non-zero UID) before `CMD`
- No `chmod 4755` SUID binaries in the final image
- No unnecessary shells / package managers in the final stage — distroless / FROM scratch is the strong default
- `HEALTHCHECK` defined so orchestrator can detect unhealthy containers
- Read-only root filesystem at runtime (set via K8s; verify nothing in the image writes outside `/tmp` or a declared volume)
- Grep for: `USER root` (or absence of any `USER` directive), `chmod 4755`, `apt-get install.*sudo`

## Audit Checklist — Kubernetes manifests

### Pod security

- `securityContext.runAsNonRoot: true` and `runAsUser` set to a non-zero UID
- `securityContext.allowPrivilegeEscalation: false`
- `securityContext.readOnlyRootFilesystem: true` with explicit `emptyDir` mounts where the app needs to write
- `securityContext.capabilities.drop: ["ALL"]` then add only what's needed
- `securityContext.privileged` is never `true` in app workloads (Falco, kube-proxy, some CSI drivers are the rare legit exceptions)
- `hostNetwork`, `hostPID`, `hostIPC` all `false` — yes on these is "container can see / talk to the node"
- `hostPath` volumes — every one is a node-escape risk; review case by case
- Grep for: `privileged: true`, `runAsUser: 0`, `hostNetwork: true`, `hostPath:`

### Pod Security Standards (PSS) / admission

- Cluster enforces `restricted` profile via PSS admission, or equivalent via OPA Gatekeeper / Kyverno
- Pod Security Policies (deprecated since 1.21, removed in 1.25) are NOT what's enforcing this — confirm a current admission controller
- No workloads in the `kube-system` namespace running app code

### Network

- `NetworkPolicy` exists for every namespace running app workloads — default-deny ingress AND egress, then allow specific pods
- Missing NetworkPolicy = every pod can talk to every other pod on every port, including kube-apiserver and metadata service
- Service mesh (Istio, Linkerd) mTLS in STRICT mode for sensitive namespaces, not PERMISSIVE
- Ingress controllers terminate TLS properly; backend `tls.crt` / `tls.key` in K8s Secrets rotate

### Secrets

- K8s Secrets are base64-encoded, NOT encrypted — by default they're plain bytes in etcd
- etcd encryption at rest enabled — `--encryption-provider-config` on kube-apiserver
- Workloads consume secrets via projected volumes, not environment variables (env vars leak via `/proc/<pid>/environ`, error reports, crash dumps)
- External Secrets Operator / Vault / sealed-secrets bridge so the Git repo never contains plaintext
- Grep for: `kind: Secret` in Git with `data:` fields (base64-encoded values committed)

### RBAC

- No `ClusterRole` with `*` verbs on `*` resources except `cluster-admin` (audit who's bound to it)
- `ServiceAccount` per workload, not shared "default" SA
- `automountServiceAccountToken: false` on workloads that don't need API access
- Bindings of `system:authenticated` group are visible to every legitimate workload — almost always wrong
- Grep for: `verbs: ["*"]`, `resources: ["*"]`, `apiGroups: ["*"]`, `system:authenticated`

### Resource limits

- Every container has `resources.requests` and `resources.limits` set — missing limits = noisy neighbor + DoS surface (one pod can starve the node)
- `LimitRange` per namespace as a backstop
- `ResourceQuota` per namespace prevents tenant-vs-tenant resource exhaustion

### Image policy

- `imagePullPolicy: Always` for `:latest` (you shouldn't use :latest, but if you do) — otherwise the node caches stale images
- Cluster-level policy that all images come from approved registries (your own + a small allow-list); enforced via Gatekeeper / Kyverno / image-policy-webhook
- Image signature verification — cosign + sigstore policy controller, or Notary v2

## Audit Checklist — runtime

- Image scanning in CI — `trivy image`, `grype`, `docker scout cves`. Must run on every build; advisories should not block but should surface
- Runtime detection — Falco / Tracee / Tetragon catches "shell spawned in a pod that has never opened a shell" patterns
- Audit logs enabled — kube-apiserver audit log captures `exec`, `attach`, `port-forward` events for incident response
- `kubectl exec` access tracked — not free for any cluster-admin to silently shell into prod

## Useful one-liners

```bash
# All Dockerfiles in the repo + their first FROM line
git ls-files | grep -E '(^|/)Dockerfile(\.|$)' | xargs -I{} sh -c 'echo "==> {}"; grep ^FROM "{}"'

# Manifests missing securityContext
grep -rL "securityContext" --include="*.yaml" --include="*.yml" .

# Manifests with privileged containers
grep -rln "privileged: *true" --include="*.yaml" --include="*.yml" .

# Manifests with hostPath volumes
grep -rln "hostPath:" --include="*.yaml" --include="*.yml" .

# Secrets in Git (base64-encoded but readable)
grep -rln "kind: *Secret" --include="*.yaml" --include="*.yml" . | xargs grep -l "^data:"

# Image scan (Trivy)
trivy image --severity HIGH,CRITICAL --exit-code 0 <image>

# Manifest scan (Trivy)
trivy config --severity HIGH,CRITICAL .

# Cluster posture (kube-bench, run inside the cluster)
kube-bench run --targets master,node,policies
```

## Verify Fixes at Runtime

- `runAsNonRoot: true` — verify the pod restarts cleanly and stays Running; if the image's `ENTRYPOINT` calls `chown` it'll crashloop
- NetworkPolicy default-deny — verify legitimate traffic still works (run an in-cluster `kubectl run -it --rm debug ... curl`); silent partial outages are common after default-deny rollout
- `readOnlyRootFilesystem: true` — verify the app doesn't write outside declared `emptyDir` mounts; log writes, PID files, and tmp files are common breakers
- Image-policy enforcement — try to deploy an unsigned / off-list image; verify admission rejects it

## Report Format

```markdown
# Container Security Audit
## Target: [cluster name / image registry / repo path]
## Date: [date]

### Summary
- Dockerfiles audited: N
- Manifests audited: N
- Cluster posture checks: pass / fail counts

### Findings
| ID | Severity | Category | Location | Issue |
|----|----------|----------|----------|-------|

### Per-finding detail
#### [SEVERITY] [Title]
**File:** `path/to/manifest.yaml:42`
**Category:** Dockerfile | Pod security | RBAC | NetworkPolicy | Secrets | Resource limits | Image policy | Runtime

**Description:** [what the issue is]

**Vulnerable config:**
```yaml
[snippet]
```

**Remediation:**
```yaml
[fixed snippet]
```

**Verification:** [observed behavior proving the fix holds]
```

Disposition rule (Fixed / Deferred / Accepted Risk) matches `owasp-audit`.

## Boundaries

- Only audit clusters and registries the user provides or has authorization for
- Never `kubectl delete` or modify cluster state during an audit — read-only operations only (`get`, `describe`, `auth can-i`)
- For runtime evidence, prefer non-disruptive checks (a `kubectl run -it --rm` ephemeral debug pod) over modifying running workloads
- Refuse cluster-takeover scenarios — escalating from a found weakness to a full pivot is exploitation, not audit
- Flag low-confidence findings as "Potential" rather than confirmed

## References

- CIS Docker Benchmark
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guide
- Pod Security Standards (PSS) — restricted, baseline, privileged
- OWASP Docker Security Cheat Sheet
- OWASP Kubernetes Security Cheat Sheet
- MITRE ATT&CK for Containers
