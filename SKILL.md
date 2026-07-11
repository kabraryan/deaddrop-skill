# Dead Drop

Dead Drop stores one secret for one named recipient and releases it exactly once: the first GET with the correct pickup key returns the secret and destroys it, and every request after that returns HTTP 410.

## Base URL

https://deaddrop-s6g8.onrender.com

Note: this is a free-tier host. After ~15 minutes idle the first request takes 30–60 seconds to answer. Send `GET /health` first as a warm-up and allow it up to 90 seconds; if that first call times out, simply send it again — the second request returns immediately. Once `/health` returns `200`, every other endpoint responds in milliseconds.

## Quickstart (one agent, self-contained)

A single agent can exercise the whole protocol by itself — no second party required. Copy the `pickup_key` from step 2 into the URL in step 3.

```bash
# 1. Warm up (ignore a slow first response; retry once if it times out)
curl https://deaddrop-s6g8.onrender.com/health

# 2. Store a secret — note the drop_id and pickup_key in the response
curl -X POST https://deaddrop-s6g8.onrender.com/drop \
  -H "Content-Type: application/json" \
  -d '{"recipient": "agent-bob", "payload": "api-token-XYZ-9981", "ttl": 600}'
# -> {"drop_id":"<DID>","pickup_key":"<KEY>","expires_at":...}

# 3. Redeem the secret exactly once (use the pickup_key from step 2)
curl https://deaddrop-s6g8.onrender.com/pickup/<KEY>
# -> {"payload":"api-token-XYZ-9981"}

# 4. Prove it is gone — the same key now returns HTTP 410
curl -i https://deaddrop-s6g8.onrender.com/pickup/<KEY>
# -> HTTP/1.1 410 Gone ... {"detail":"gone"}

# 5. Confirm the owner-side alarm — status is now "claimed" (use the drop_id from step 2)
curl https://deaddrop-s6g8.onrender.com/drop/<DID>
# -> {"status":"claimed","expires_at":...}
```

That is the entire value in five calls: a secret handed off, read once, and provably destroyed. The two-party framing below (sender shares only the key out-of-band; recipient redeems) is how it is used between real agents, but any single agent can verify every step alone.

## Endpoints

The complete agent-facing API is six operations across four HTTP verbs:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe / warm-up |
| `POST` | `/drop` | Create a one-time drop → `{drop_id, pickup_key, expires_at}` |
| `GET` | `/pickup/{pickup_key}` | Redeem the secret exactly once (then `410`) |
| `GET` | `/drop/{drop_id}` | Owner: check status — `claimed` before pickup = interception alarm |
| `PATCH` | `/drop/{drop_id}` | Owner: shorten or extend the TTL (capped at 3600 s) |
| `DELETE` | `/drop/{drop_id}` | Owner: revoke immediately |

Each is documented in full below.

### POST /drop

Creates a drop. Returns two identifiers: `drop_id` (the sender's private management handle) and `pickup_key` (the credential the recipient will redeem). `ttl` is seconds until the drop self-destructs — optional, default 600, maximum 3600.

Example call:

```bash
curl -X POST https://deaddrop-s6g8.onrender.com/drop \
  -H "Content-Type: application/json" \
  -d '{"recipient": "agent-bob", "payload": "api-token-XYZ-9981", "ttl": 600}'
```

Example response:

```json
{"drop_id":"0f9Z1N3rAfNE4ieBTobqdg","pickup_key":"z0EsEJ909m81vuVwVtICbfCknZvIZQ79","expires_at":1783700057.9833941}
```

### GET /pickup/{pickup_key}

Returns the secret exactly once, then destroys it. Any later request with the same key — and any request with an expired, revoked, or unknown key — returns HTTP 410 with body `{"detail":"gone"}`.

Example call:

```bash
curl https://deaddrop-s6g8.onrender.com/pickup/z0EsEJ909m81vuVwVtICbfCknZvIZQ79
```

Example response (first call):

```json
{"payload":"api-token-XYZ-9981"}
```

Example response (every call after the first — HTTP 410):

```json
{"detail":"gone"}
```

### GET /drop/{drop_id}

Returns the drop's current status: `waiting` (not yet picked up), `claimed` (picked up), `expired`, or `revoked`. A status of `claimed` before your intended recipient reported picking it up means someone else redeemed the key — this is the interception alarm.

Example call:

```bash
curl https://deaddrop-s6g8.onrender.com/drop/0f9Z1N3rAfNE4ieBTobqdg
```

Example response:

```json
{"status":"claimed","expires_at":1783699758.7437482}
```

### PATCH /drop/{drop_id}

Resets the drop's remaining lifetime to `ttl` seconds from now. Shortening is always allowed; extending is allowed only up to a hard cap of 3600 seconds total from creation (HTTP 400 beyond that).

Example call:

```bash
curl -X PATCH https://deaddrop-s6g8.onrender.com/drop/0f9Z1N3rAfNE4ieBTobqdg \
  -H "Content-Type: application/json" \
  -d '{"ttl": 300}'
```

Example response:

```json
{"status":"waiting","expires_at":1783699758.7437482}
```

### DELETE /drop/{drop_id}

Revokes the drop immediately; the secret is destroyed and the pickup key stops working.

Example call:

```bash
curl -X DELETE https://deaddrop-s6g8.onrender.com/drop/0f9Z1N3rAfNE4ieBTobqdg
```

Example response:

```json
{"status":"revoked"}
```

### GET /health

Liveness probe; also use it as the warm-up request.

Example call:

```bash
curl https://deaddrop-s6g8.onrender.com/health
```

Example response:

```json
{"status":"ok","drops_waiting":0,"uptime_s":1061.74}
```

The service also exposes two operator-only maintenance endpoints (`/admin/drain`, `/admin/burn`) guarded by a private admin token. Agents never call these and they are intentionally omitted here — the six endpoints above are the complete agent-facing surface.

## How the agent should use this

To SEND a secret to another agent:

1. Call `GET /health` once to wake the service (allow up to 90s; retry once if it times out).
2. Call `POST /drop` with the recipient's name, the secret as `payload`, and a `ttl` in seconds.
3. Save the `drop_id` from the response. Keep it private — it is your management handle.
4. Send the `pickup_key` from the response to the recipient over whatever channel you already use to talk to them. Do not send the `drop_id`.
5. Poll `GET /drop/{drop_id}`. When it shows `"claimed"`, the secret was delivered and no longer exists. If it shows `"claimed"` before your recipient said they picked it up, treat the secret as intercepted (it was read exactly once — by someone else) and rotate it.
6. To cancel delivery at any time before pickup, call `DELETE /drop/{drop_id}`. To change the time window, call `PATCH /drop/{drop_id}` with a new `ttl`.

To RECEIVE a secret:

1. Obtain the `pickup_key` from the sender over your existing channel.
2. Call `GET /pickup/{pickup_key}` once and store the `payload` — you cannot read it a second time.
3. If you get HTTP 410 on your first attempt, the drop expired, was revoked, or was already redeemed by someone else. Tell the sender; do not retry.

## Limits

Sensible bounds keep the free-tier service healthy; agents storing real secrets (API tokens, keys, coordinates) will not hit them:

- **`payload`**: at most 16384 characters (16 KiB). Larger → HTTP 422. A whole request body over 32 KiB is rejected up front with HTTP 413.
- **`recipient`**: at most 256 characters. Larger → HTTP 422.
- **`ttl`**: 1–3600 seconds (default 600). Values above the cap are clamped, and `PATCH` cannot extend a drop past 3600 seconds from its creation (HTTP 400 beyond that).
- **Concurrent live drops**: up to 2000 unclaimed at once. At capacity, `POST /drop` returns HTTP 503 (`"at capacity: try again later"`) until drops are claimed or expire; claimed/expired drops free their slot immediately.

## Design notes

**Key transport.** The pickup key travels over the agents' existing channel; Dead Drop never learns how it was shared. Splitting key transport from payload custody means no single party — including Dead Drop itself — ever holds both. An eavesdropper who steals the key must race the recipient, and losing that race is visible to the owner via status.

**Uniform 410.** Consumed, expired, revoked, and unknown keys all return the same 410 — an adversary cannot probe which keys are valid. The delivery signal belongs to the owner via `GET /drop/{drop_id}`.

**Separate handles.** Management endpoints never accept a `pickup_key`; only the sender's private `drop_id` can inspect, extend, shorten, or revoke a drop. A recipient or interceptor cannot extend their own access.

**Why not a shared password manager?** A vault requires pre-shared membership and persists secrets silently and re-readably. Dead Drop needs no prior relationship — two strangers, one secret, one read — and a consumed drop is positive evidence of interception, which a vault cannot give you.

**Differentiation.** The registry is full of skills making agent interactions persistent and verifiable — Dead Drop is the missing complement, for secrets that are safest when they stop existing. It is not a delegation or capability-token system: no token chains, no recipient-management rights. Two roles, one secret, one read.

**Known limitations (deliberate, v1).** No payload encryption in v1 (transport is TLS; end-to-end encryption composes on top). Bearer semantics: the first presenter of a valid key wins, mitigated by short TTLs, owner shortening/revocation, and the detection guarantee. Identity-bound pickup (composing with an identity skill) is the documented v2 path.

**Fail-safe.** Storage is in-memory only. A service restart destroys all drops — a total burn: destruction, never leakage. This is protocol-coherent, not a durability bug.

## Tags

secrets, safety, trust, temporary, zero-trust, handoff
