# GraphQL Authorization Playbook

Deep-dive companion to the "GraphQL-specific" section of `api-audit`. The basics in SKILL.md (introspection, field-level auth, depth/complexity, batching, error leakage) catch misconfiguration. The techniques here catch the authorization bugs, which in GraphQL almost always live in a resolver that assumed someone else did the check.

Everything below follows the same rules as the rest of `api-audit`:

- Only test schemas and endpoints you are authorized to test. Prefer a local or staging instance seeded with two test accounts you control (owner `A`, non-owner `B`, and where relevant a second tenant).
- Source first. Each technique lists what to grep for in the resolver code; live requests confirm what the code suggests.
- A finding is only `confirmed` with **paired evidence**: the same operation, same variables, same headers, sent once with owner A's token and once with non-owner B's token. The only difference between the two requests is the token. See [Paired evidence for GraphQL](#paired-evidence-for-graphql) at the bottom.

## Contents

1. [Map the schema when introspection is off](#1-map-the-schema-when-introspection-is-off)
2. [Owned vs. foreign IDOR in one request (aliases)](#2-owned-vs-foreign-idor-in-one-request-aliases)
3. [Resolver cascade: parent checks, child assumes](#3-resolver-cascade-parent-checks-child-assumes)
4. [Relay `node(id:)` and global ID swaps](#4-relay-nodeid-and-global-id-swaps)
5. [Federation: `_entities` and `_service`](#5-federation-_entities-and-_service)
6. [Incremental delivery: `@defer` / `@stream`](#6-incremental-delivery-defer--stream)
7. [Subscriptions: per-message authorization](#7-subscriptions-per-message-authorization)
8. [Persisted queries (APQ and allow-lists)](#8-persisted-queries-apq-and-allow-lists)
9. [`@oneOf` input objects](#9-oneof-input-objects)
10. [Cursor decoding and tampering](#10-cursor-decoding-and-tampering)
11. [Aliases and batching against rate limits](#11-aliases-and-batching-against-rate-limits)
12. [WAF and filter evasion via fragments](#12-waf-and-filter-evasion-via-fragments)
13. [Paired evidence for GraphQL](#paired-evidence-for-graphql)

---

## 1. Map the schema when introspection is off

Disabling introspection hides the schema document, not the schema. Most servers still leak it one error at a time. If you have source, read the SDL or code-first type definitions directly and skip this; it matters when auditing a deployed endpoint, or when you need to confirm that what is in the repo is what is deployed.

**Field suggestions.** Many servers (graphql-js and descendants by default) answer a misspelled field with a "Did you mean …?" hint. Send near-miss names (`usr`, `admn`, `passwrd`, `internalNote`) on each known type and harvest the suggestions. Repeat on each type you discover. Whether the server leaks suggestions is itself a hardening note, not a finding.

**Enum leaks.** Pass an invalid value to an enum argument. Validation errors commonly list the allowed values ("expected one of …"), which exposes hidden roles, statuses and feature flags (`ADMIN`, `SUPPORT_IMPERSONATE`, `INTERNAL`).

**Existence oracles.** Compare error text and shape for: a field that exists but you can't access, a field that doesn't exist, and an object ID that exists but isn't yours vs. one that doesn't exist at all. Distinct messages ("not authorized" vs. "not found") turn the endpoint into an enumeration oracle.

**Type probing.** `__typename` is almost always allowed even with introspection disabled. Requesting it on unions and interfaces reveals concrete types. Inline fragments on guessed type names (`... on AdminUser { id }`) produce different errors for real vs. invented types.

**Other leaks.** Client bundles (`gql\`` tags, `.graphql` files, persisted-query manifests), mobile app binaries, GraphiQL/Playground left on a staging host, and `_service { sdl }` on federated subgraphs (section 5).

Grep for: `introspection:`, `NoSchemaIntrospectionCustomRule`, `didYouMean`, `formatError`, `maskedErrors`, `debug:` in the server config.

Report: suggestion and enum leaks alone are **hardening notes**. They become part of a finding only when the leaked name leads to a field or operation that is actually reachable without authorization.

## 2. Owned vs. foreign IDOR in one request (aliases)
GraphQL aliases let one operation request the same field twice under different names. This is the cleanest BOLA/BOPLA test in the language: fetch an object owner A is allowed to see and one they are not, side by side, so the authorization decision for both is made inside a single request under a single token. If the "foreign" alias returns data, the per-object check is missing.

```graphql
query {
  mine:   order(id: "<A's own order>")      { id total customerEmail }
  theirs: order(id: "<B's order, not A's>") { id total customerEmail }
}
```

Interpretation: with A's token, `mine` populated and `theirs` null/error is the correct outcome. `theirs` returning data is the finding. Confirm it as a pair (section 13): the identical operation under B's token should show the mirror image.

Grep the resolvers for the real question — does the resolver re-check ownership on the looked-up object, or does it only check that *a* session exists? Look for `.findUnique({ where: { id } })` / `.findById(id)` with no tenant or owner predicate, and for context auth that stops at "is logged in".

## 3. Resolver cascade: parent checks, child assumes

A graph is a tree of resolvers. A common bug: the parent (`user`, `order`, `project`) enforces authorization, but a child/related-field resolver (`user.paymentMethods`, `order.internalNotes`, `project.members`) assumes that if you reached it, the parent already vouched for you. Reach the child through a *different* parent that does not guard it and the check never runs.

Audit every resolver that returns sensitive data or another entity: does it make its own authorization decision from context, or does it trust `parent`? Pay special attention to fields that traverse a relation to a different owner/tenant than the root object. Field-level authorization (checked on each resolver) is the fix; a single gate at the query root is not.

Grep for: resolver maps (`Query:`, `Mutation:`, type resolver objects), `parent`/`root`/`source` args used to fetch related rows, dataloaders keyed only by id, directives like `@auth` applied to some fields but not siblings.

## 4. Relay `node(id:)` and global ID swaps

Relay-style schemas expose a top-level `node(id: ID!)` that returns any object by an opaque global ID. Those IDs are usually just `base64("TypeName:123")` — reversible, not a secret. If `node` (or `nodes`) resolves objects without re-checking ownership, it becomes a universal object-read bypass that sidesteps the per-type resolvers you carefully audited.

Decode a global ID you legitimately hold to learn the encoding, then test `node` with an ID for an object owned by B. As always, confirm as a pair. Treat the ID as a user-controlled identifier, exactly like a REST `:id`.

Grep for: `nodeResolver`, `fromGlobalId`, `toGlobalId`, `node(id:`, `interface Node`, `globalIdField`.

## 5. Federation: `_entities` and `_service`

Apollo Federation subgraphs expose two machine fields for the gateway: `_service { sdl }` returns the full subgraph SDL (schema disclosure even with introspection off), and `_entities(representations: [...])` resolves entities by key via each type's `__resolveReference`. If a subgraph is reachable directly (not only through the gateway) and `__resolveReference` trusts the gateway to have authorized the request, you can resolve arbitrary entities by posting representations straight to the subgraph.

Audit: are subgraphs network-isolated from clients (gateway-only)? Does each `__resolveReference` make its own authorization decision rather than assuming the gateway did? Is `_service`/SDL exposure acceptable for that deployment?

Grep for: `buildSubgraphSchema`, `__resolveReference`, `_entities`, `@key`, `representations`.

## 6. Incremental delivery: `@defer` / `@stream`

`@defer` and `@stream` split a response into an initial payload plus later chunks. The risk is a server that authorizes the initial selection but applies a weaker (or no) check to the deferred fragment, or that leaks gated data in a later chunk before a late-running guard would have removed it. Move a sensitive, normally-gated selection into a deferred fragment and compare what arrives against the non-deferred request.

Grep for: `@defer`, `@stream`, `deferStream`, incremental-delivery or multipart response handling, `hasNext`.

## 7. Subscriptions: per-message authorization

WebSocket/SSE subscriptions commonly authenticate once, at `connectionInit`/handshake, and never re-check. Problems: authorization evaluated only at subscribe time so later revocation or role changes don't take effect; a topic/channel argument that isn't scoped to the subscriber (subscribe to another tenant's channel); events fanned out to all subscribers of a topic without filtering per recipient. Subscribe as B to a resource owned by A and watch whether A's events arrive.

Grep for: `onConnect`, `connectionParams`, `graphql-ws`, `subscriptions-transport-ws`, `subscribe:` resolvers, `withFilter`, `pubsub.asyncIterator`.

## 8. Persisted queries (APQ and allow-lists)

Automatic Persisted Queries map a SHA-256 hash to a query the server has seen. Two distinct things get called "persisted queries":

- **APQ (optimization):** the server still accepts arbitrary full queries, so it is not an access control. Don't treat its presence as a mitigation.
- **Persisted-query allow-list (security):** only pre-registered hashes are accepted. Here, test whether arbitrary full queries are *also* still accepted (allow-list not actually enforced), and whether the registration/manifest endpoint is writable by clients.

Note the APQ registration flow (send hash + query once to register) is normal protocol use, not a bypass. The finding is an allow-list that fails open, or a registry an unauthorized client can add to.

Grep for: `persistedQueries`, `APQ`, `sha256Hash`, `PersistedQueryNotFound`, allow-list/manifest config.

## 9. `@oneOf` input objects

`@oneOf` input objects require exactly one of their fields to be set — often a "look up by X or Y" selector (`{ byId }` / `{ byEmail }` / `{ bySlug }`). Two things to check: coercion/validation (does the server actually reject zero or multiple keys, or does an extra key change behaviour?), and whether authorization is applied consistently across every selector. A lookup that is guarded `byId` but not `byEmail` lets you pivot to the unguarded path.

Grep for: `@oneOf`, `oneOf: true`, input types whose fields are all optional and mutually exclusive.

## 10. Cursor decoding and tampering

Pagination cursors are usually base64 of an offset, a row id, or a JSON keyset (`{"id":123,"createdAt":...}`). They are opaque to clients but rarely signed. Decode one, then test: does editing it move into another tenant's rows, cause an offset/keyset error that leaks row data, or skip an ownership filter that only applies to the first page? A cursor that carries a filter the server trusts without re-applying tenant scope is the finding.

Grep for: `Buffer.from(cursor`, `atob(`, `fromCursor`, `encodeCursor`, `after:`/`before:` arg handling, keyset pagination builders.

## 11. Aliases and batching against rate limits

Aliases multiply work inside one operation; array batching (a JSON array of operations in one HTTP request) multiplies operations. If rate limiting counts HTTP requests rather than fields/operations/cost, one request can run hundreds of logins, OTP checks, coupon redemptions or expensive resolvers. This is the GraphQL form of API4/API6.

Test by sending one request with many aliases of a rate-limited mutation and watching whether each executes. Fixes: cost analysis (not request counting), alias/batch caps, disabling array batching where unused.

```graphql
mutation {
  a: redeem(code:"AAAA"){ok}  b: redeem(code:"AAAB"){ok}  c: redeem(code:"AAAC"){ok}
  # ... one request, many attempts
}
```

Grep for: `allowBatchedHttpRequests`, `createComplexityRule`, `costAnalysis`, `graphql-query-complexity`, `depthLimit`, per-field rate limiters.

## 12. WAF and filter evasion via fragments

When a WAF or a naive allow-list matches on query text, the structure of GraphQL gives many equivalent spellings: pushing a flagged selection into a named fragment or inline fragment, aliasing a blocked field, reordering, or exploiting whitespace/comment handling. The point for an audit is not to defeat the WAF — it is to show that text-matching is the wrong layer. Authorization and cost limits must live in resolvers and schema rules, not in a request-text filter. If a fragment-wrapped version of a blocked operation succeeds, the real finding is the missing resolver-level control, with the filter noted as ineffective.

Grep for: WAF rules keyed on `query`/`mutation` strings, regex-based GraphQL filtering, blocked-field lists in middleware.

## Paired evidence for GraphQL

Every `confirmed` authorization finding carries two exchanges that differ only in the credential (see `references/verification.md` and the SKILL.md "Paired baseline-vs-attack evidence" rule). For GraphQL specifically:

- Keep the operation string and variables **byte-identical** between the two requests. Change only the `Authorization` header (owner A vs. non-owner B; or authenticated vs. unauthenticated for an auth-required field).
- Capture both full exchanges (request headers minus secrets, body, response). The pair is the proof: A sees the data, B does not — or, for a bug, B also sees it.
- For the aliased single-request test (section 2), the pair is the same operation sent under A's token and under B's token; the `theirs` alias returning data under a token that shouldn't see it is the finding.

```bash
# Owner A (baseline — expected: authorized)
curl -s https://TARGET/graphql \
  -H 'content-type: application/json' -H "authorization: Bearer $A_TOKEN" \
  -d '{"query":"query($id:ID!){ order(id:$id){ id total customerEmail } }","variables":{"id":"<B_ORDER_ID>"}}'

# Non-owner B (attack — same query/vars, only the token changed)
curl -s https://TARGET/graphql \
  -H 'content-type: application/json' -H "authorization: Bearer $B_TOKEN" \
  -d '{"query":"query($id:ID!){ order(id:$id){ id total customerEmail } }","variables":{"id":"<B_ORDER_ID>"}}'
```

A result of `needs_validation` (not `confirmed`) is correct when the decisive fact lives outside the code you can read — e.g. a gateway strips `_entities` before it reaches the subgraph, or an edge WAF blocks batching in the deployed environment but not locally. Record the blocker and the owner-runnable check per `references/verification.md`.

## Sources

- Strix (Apache-2.0) — GraphQL protocol notes (`strix/skills/protocols/graphql.md`) and IDOR validation steps (`strix/skills/vulnerabilities/idor.md`). Paraphrased, not copied.
- OWASP GraphQL Cheat Sheet.
- Relay Global Object Identification spec; Apollo Federation subgraph spec (`_service`, `_entities`); GraphQL incremental-delivery (`@defer`/`@stream`) and `@oneOf` proposals.
