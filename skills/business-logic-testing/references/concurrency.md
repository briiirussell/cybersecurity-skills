# Concurrency testing — tooling and worked examples

Companion to `business-logic-testing/SKILL.md` Step 6. Everything here assumes the authorization check has passed: written scope for concurrency testing, a staging / test-mode target, an agreed request-count cap, and accounts you own. Keep every burst small — a double-spend proof needs tens of parallel requests, not thousands. These are measurement tools for a proof, not extraction or load tools.

## Choosing a synchronization method

| Transport | Method | Why |
|---|---|---|
| HTTP/2 (or HTTP/3) | Single-packet attack — many requests' final frames in one TCP packet | Removes network jitter; all requests arrive in one server read |
| HTTP/1.1 keep-alive | Last-byte synchronization — send all but the last byte early, release the last bytes together | Best available when HTTP/2 is unavailable |
| Either | Connection warming | Do TLS/connection setup and lazy init with a throwaway request first, so it does not pollute the timed window |

Confirm the protocol first (`curl -sI --http2 https://target` shows `HTTP/2` on success). Prefer the single-packet approach on HTTP/2 because it is immune to per-connection jitter.

## Burp Suite — Turbo Intruder / Repeater group

- **Repeater "Send group in parallel"** (single-packet attack): put the candidate request in a tab, duplicate it into a group, and choose *Send group (parallel)*. Burp batches the final frames into one packet automatically on HTTP/2. This is the fastest way to test a dozen-request double-spend by hand.
- **Turbo Intruder** for a scripted, capped burst. Keep `concurrentConnections` modest and the request count at or under the agreed cap:

```python
# Turbo Intruder — authorized staging test only. Caps the burst at 20.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,   # single-packet batches on one conn
                           engine=Engine.BURP2)        # HTTP/2 single-packet
    for i in range(20):                                # <= agreed request cap
        engine.queue(target.req, gate='go')
    engine.openGate('go')                              # release all at once

def handleResponse(req, interesting):
    table.add(req)                                     # inspect status, but prove via DB state
```

## Minimal standalone runners

Use these only when a proxy is not available. Both cap the burst explicitly.

**`curl --parallel`** — crude but dependency-free. Writes N identical requests, releases them together:

```bash
# Authorized staging test. 15 parallel copies of one request, capped.
curl --parallel --parallel-immediate --parallel-max 15 \
  --http2 \
  $(for i in $(seq 15); do \
      printf ' -H "Authorization: Bearer $TOKEN" -X POST https://staging.target/redeem -d {"code":"PROMO"}'; \
    done)
```

**Python `httpx` (HTTP/2)** — more control over timing and reading state back:

```python
# Authorized staging test only. Fires a capped, synchronized burst, then
# reads durable state back — the status codes are not the proof.
import asyncio, httpx

N = 15                                   # <= agreed request cap
URL = "https://staging.target/redeem"
HEADERS = {"Authorization": "Bearer ..."}  # account you own
BODY = {"code": "PROMO"}

async def main():
    async with httpx.AsyncClient(http2=True) as client:
        await client.get("https://staging.target/health")   # connection warming
        start = asyncio.Event()
        async def one():
            await start.wait()
            return await client.post(URL, json=BODY, headers=HEADERS)
        tasks = [asyncio.create_task(one()) for _ in range(N)]
        start.set()                                           # release together
        results = await asyncio.gather(*tasks, return_exceptions=True)
    print("statuses:", [getattr(r, "status_code", repr(r)) for r in results])
    # Now read the durable state back (coupon remaining uses, balance) and
    # compare against the invariant. That read is the finding, not the above.

asyncio.run(main())
```

Run any downloaded or third-party script in isolation (`python3 -I`), never from a directory holding untrusted files.

## The `h2`/raw single-packet note

A hand-rolled single-packet attack buffers each request's HEADERS/DATA frames and withholds the final frame, then flushes all final frames in one `send()`. Burp's engine and PortSwigger's `turbo-intruder` already implement this correctly, so prefer them over a bespoke socket script — a subtly wrong flush reintroduces the jitter you are trying to remove and produces false negatives.

## Reading durable state back (the actual proof)

The parallel burst only *creates the opportunity*. The finding is the state read afterward:

- Coupon: query remaining uses / redemption rows — more redemptions than allowed.
- Balance / wallet: the net change exceeds any single authorized action, or the ledger no longer sums to zero.
- Inventory: units sold exceed units that existed.
- Uniqueness: two rows where a unique constraint should have permitted one.

If the durable state is correct despite many 200s, it is a false positive (idempotent op, DB UNIQUE/`ON CONFLICT`, atomic decrement) — record it as such so a re-run does not re-raise it.
