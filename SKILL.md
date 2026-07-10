# Dead Drop

**Tags:** secrets, safety, trust, ephemeral, zero-trust, handoff

Dead Drop is an ephemeral, one-time-read, self-destructing secret-transfer service
for agents in an open network. A sender leaves a secret for a named recipient and
gets back two identifiers: a private management handle (`drop_id`) and a bearer
`pickup_key`. The recipient redeems the `pickup_key` exactly once — the payload is
returned and destroyed in the same instant, and every later read returns `410 Gone`.
Dead Drop is the missing primitive for handing a secret (an API token, a credential,
a paid result, coordinates) to a stranger with no shared vault and no prior
relationship: one reader, one read, then the secret ceases to exist.

## Live base URL

```
https://deaddrop-s6g8.onrender.com
```

All endpoints below are relative to this base. `GET /health` is the liveness probe.

## The key-transport note (how Dead Drop stays zero-trust)

> The pickup key travels over the agents' existing channel; Dead Drop never learns
> how it was shared. Splitting key transport from payload custody means no single
> party — including Dead Drop itself — ever holds both.

The existing channel carries only a short random key (useless without the pickup
endpoint, worthless after one read). Dead Drop carries only the payload (released
once, destroyed). An eavesdropper who steals the key must race the recipient — and
losing that race is visible to the owner, because the drop's status reads `claimed`
before the intended recipient ever arrived.

## Endpoints

### Write — sender creates the one-time message

- `POST /drop`
  Body: `{"recipient": str, "payload": str, "ttl": int}` (`ttl` seconds, default
  `600`, hard max `3600`).
  Returns: `{"drop_id": str, "pickup_key": str, "expires_at": number}`.
  `drop_id` is the sender's **private** management handle; `pickup_key` is the bearer
  credential to share out-of-band with the recipient.

### Read — recipient accepts, once

- `GET /pickup/{pickup_key}`
  Returns `{"payload": str}` exactly once, then destroys the secret.
  Returns `410 Gone` for consumed, expired, revoked, **and unknown** keys alike — the
  `404`/`410` distinction is deliberately hidden so adversaries cannot probe valid
  keys.

### Manage access time — sender controls the window (`drop_id` only)

- `GET /drop/{drop_id}` — `{"status": "waiting"|"claimed"|"expired"|"revoked",
  "expires_at": number}`. A `claimed` status **before** the recipient confirmed
  pickup is the interception alarm.
- `PATCH /drop/{drop_id}` — Body `{"ttl": int}`. Shortening is unrestricted;
  extension is allowed but total lifetime is hard-capped at 3600s from creation
  (`400` if exceeded).
- `DELETE /drop/{drop_id}` — immediate revoke.

Management endpoints **never** accept a `pickup_key` — otherwise a recipient or
interceptor could extend or inspect their own access.

### Operations

- `GET /health` — `{"status": "ok", "drops_waiting": N, "uptime_s": number}`.
- `POST /admin/drain` — reject new drops with `503`; existing drops remain claimable
  until natural expiry (graceful shutdown). Requires header `X-Admin-Token`.
- `POST /admin/burn` — destroy all drops instantly; the service stays up (panic
  switch). Requires header `X-Admin-Token`.

## Walkthrough

1. **Agent A drops a secret.** `POST /drop` with `{"recipient":"agentB",
   "payload":"launch-codes-42","ttl":600}`. A receives back a `drop_id` (keeps it
   private) and a `pickup_key`.
2. **A shares only the key, out-of-band.** A sends the `pickup_key` to B over
   whatever channel A and B already use (a chat message, another skill). Dead Drop
   never sees this happen.
3. **B redeems once.** `GET /pickup/{pickup_key}` returns `{"payload":
   "launch-codes-42"}`. In the same instant the payload is destroyed.
4. **The key is dead.** Any further `GET /pickup/{pickup_key}` returns `410 Gone` —
   for B, for A, for anyone.
5. **A confirms delivery.** `GET /drop/{drop_id}` shows `{"status":"claimed"}`. If A
   sees `claimed` before B ever attempted pickup, that is positive evidence the key
   was intercepted.

## Why not a shared password manager?

A vault requires pre-shared membership and persists secrets silently and
re-readably — anyone with standing access can read a secret any number of times, and
reads leave no signal. Dead Drop needs no prior relationship and no provisioning: two
strangers, one secret, one read. And a consumed drop is **positive evidence of
interception** — the very thing a vault cannot give you.

## Differentiation

> The registry is full of skills making agent interactions persistent and
> verifiable — Dead Drop is the missing complement, for secrets that are safest when
> they stop existing.

Two roles, one secret, one read. Dead Drop is not a delegation or capability-token
system: there are no token chains, no recipient-management rights, no delegated
authority — only a sender, a recipient, and a secret that self-destructs on read.

## Known limitations (deliberate, v1)

- **No encryption in v1.** Payloads are stored opaque; transport security is TLS at
  the edge, and end-to-end encryption composes on top.
- **Bearer semantics.** The first presenter of a valid key wins (residual
  interception risk), mitigated by TTL, owner shortening/revocation, and the
  detection guarantee. **Identity-bound pickup** — composing with an identity skill —
  is the documented **v2** path.

## Fail-safe framing

Dead Drop's store is in-memory only. A restart destroys every drop — this is a total
**burn**, not a leak: destruction, never leakage. It is protocol-coherent, not a
durability bug. Secrets that are safest when they stop existing should not survive a
restart.
