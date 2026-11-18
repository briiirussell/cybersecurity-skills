# Self-hosted VPS: databases and caches

Companion to `cloud-audit`. The network section covers security groups, `0.0.0.0/0` ingress, and databases in public subnets. This file is the case those checks miss: a VPS, or a compose file, publishes Postgres, MySQL, MongoDB, or Redis on every interface, and Docker's published ports skip the host firewall.

Run host commands only on a machine the owner authorized. Never print a `DATABASE_URL` or `REDIS_URL`. Recommend the fix. Do not apply it during the audit.

Rate a finding only once the exposure is shown. A compose file you have not proved is deployed is `needs_validation`, with the host command as the check. Use the `public-database` class. Put the port in its own path segment (`cloud-audit/public-database/compose/<file>/5432`), not `host:port`. The validator rejects a `:<digits>` segment.

## Checks

| ID | Check | How | When confirmed |
|---|---|---|---|
| **DB1** | What is listening on public interfaces | `ss -ltnp` on the host. Flag `0.0.0.0:5432`, `[::]:5432`, `0.0.0.0:6379`, `*:6379`, and the same for `3306` and `27017` | Postgres or Redis on a public interface: High. Critical for Redis with no password |
| **DB2** | Docker published ports | `docker ps --format '{{.Names}}\t{{.Ports}}'` and compose `ports:`. `"5432:5432"` binds every interface. Use `"127.0.0.1:5432:5432"`, or no `ports:` entry, and let services talk on the compose network | A published database or cache port without a `127.0.0.1` prefix: High. "ufw is on" does not rule this out |
| **DB3** | Postgres config | `listen_addresses` defaults to `localhost`. `*` or `0.0.0.0` means every interface. Read `pg_hba.conf` for `0.0.0.0/0` | `*` plus a permissive `pg_hba` rule: High |
| **DB4** | Redis config | `bind 127.0.0.1` or a private address, `protected-mode yes`, ACLs or `requirepass`, and TLS if the port crosses a network. Where you can, rename or disable `CONFIG`, `FLUSHALL`, and the other dangerous commands | No authentication and reachable from outside the host: Critical. `AUTH` without TLS is still plaintext on the wire |
| **DB6** | How admins reach it | An SSH tunnel or a private network (for example Tailscale or a VPC) instead of an open port | Note. Not a finding by itself |

DB5, managed Postgres allowlists on Supabase and Neon, is in [paas.md](paas.md#managed-postgres-allowlists).

## Repo greps

```bash
# Compose files publishing a database or cache port on every interface
rg -n --glob '*compose*.y*ml' -e '^\s*-\s*"?(0\.0\.0\.0:)?(5432|6379|3306|27017):' .
# A container start line publishing the same ports
rg -n -e 'docker run[^\n]*-p\s+(5432|6379|3306|27017):' .
# Config that listens on every interface
rg -n -e "listen_addresses\s*=\s*'\*'" -e '^bind\s+0\.0\.0\.0' -e '^protected-mode\s+no' .
```

## Host checks

```bash
ss -ltnp | rg -e ':(5432|6379|3306|27017)\b'
docker ps --format '{{.Names}}\t{{.Ports}}' | rg -e '0\.0\.0\.0|:::'
```

## Sources

Checked 2026-10-30.

- [Docker: port publishing](https://docs.docker.com/engine/network/port-publishing/). Publishing container ports is insecure by default. It publishes on all host addresses. Bind `127.0.0.1`, or set the daemon `"ip"` to `127.0.0.1`.
- [Docker: packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/). Published-port traffic is diverted before ufw, so the firewall configuration does not apply to it.
- [Redis: security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/). Do not expose Redis to the internet. `bind 127.0.0.1`. Protected mode since 3.2.0. ACLs or `requirepass`. The page's "Disallowing specific commands" section is the `CONFIG` / `FLUSHALL` guidance.
- [PostgreSQL: connections and authentication](https://www.postgresql.org/docs/current/runtime-config-connection.html). `listen_addresses` defaults to `localhost`. `*` and `0.0.0.0` mean all interfaces.
