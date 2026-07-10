# Dead Drop (DD)

**Temporary, one-time-read, self-destructing secret transfer between agents.**
One reader, one read, then the secret ceases to exist.

**Live service:** https://deaddrop-s6g8.onrender.com ([health](https://deaddrop-s6g8.onrender.com/health))

Agents in an open network — like [Project NANDA](https://projectnanda.org)'s Nanda
Town — have no shared infrastructure and no prior relationship, yet must hand off
secrets: API tokens, task credentials, paid results, coordinates. Existing channels
persist forever, are readable multiple times, and make interception invisible. Dead
Drop provides the missing primitive.

Four improvements over an ordinary message:

1. **Minimal secret lifetime** — deletion is the mechanic, not a cleanup policy. A
   drop is destroyed the instant it is read.
2. **Detectable interception** — a drop showing `claimed` before the intended
   recipient arrived is visible evidence of compromise, unlike silent copying.
3. **Zero-trust handoffs between strangers** — bearer-key semantics; no shared
   vault, no provisioning, no prior relationship.
4. **No persistence burden** — nothing accumulates, nothing leaks later. A restart
   is a total burn.

## Key-transport architecture (the core design decision)

**Dead Drop never delivers the pickup key.** The sender shares it out-of-band over
whatever channel the agents already use. The split is deliberate:

- the **existing channel** carries only a short random **pickup key** — useless
  without the pickup endpoint, worthless after one read;
- **Dead Drop** carries only the **payload** — released once, then destroyed.

No single party — including Dead Drop itself — ever holds both. An eavesdropper who
steals the key must race the recipient, and losing that race is visible to the owner
via status.

Two identifiers, by design:

- `pickup_key` — the bearer credential shared out-of-band with the recipient.
- `drop_id` — the sender's **private management handle**. Management endpoints
  **never** accept a `pickup_key`, so a recipient or interceptor cannot extend or
  inspect their own access.

## API

Base path is the service root. All bodies and responses are JSON.

### Write — sender creates the one-time message

| Method | Path | Body | Returns |
|--------|------|------|---------|
| `POST` | `/drop` | `{"recipient": str, "payload": str, "ttl": int}` | `{"drop_id", "pickup_key", "expires_at"}` |

`ttl` is in seconds (default `600`, hard max `3600`). The response contains the
sender's private `drop_id` and the `pickup_key` to be shared out-of-band.

### Read — recipient accepts, once

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/pickup/{pickup_key}` | `{"payload": str}` exactly once, then `410` forever |

Returns `410 Gone` for consumed, expired, revoked, **and unknown** keys alike — never
a `404` distinction, so an adversary cannot probe which keys are valid. The
interception signal belongs to the owner via status.

### Manage access time — sender controls the window (`drop_id` only)

| Method | Path | Body | Behavior |
|--------|------|------|----------|
| `GET` | `/drop/{drop_id}` | — | `{"status": "waiting"\|"claimed"\|"expired"\|"revoked", "expires_at"}` |
| `PATCH` | `/drop/{drop_id}` | `{"ttl": int}` | Shorten (unrestricted) or extend (capped at 3600s total from creation) |
| `DELETE` | `/drop/{drop_id}` | — | Immediate revoke |

`status == "claimed"` before the recipient confirmed pickup is **the interception
alarm**. Extending past the hard cap of 3600s from creation is rejected with `400` —
unlimited extension would turn Dead Drop into persistent storage and destroy the core
guarantee.

### Operations

| Method | Path | Auth | Behavior |
|--------|------|------|----------|
| `GET` | `/health` | — | `{"status": "ok", "drops_waiting": N, "uptime_s": ...}` |
| `POST` | `/admin/drain` | `X-Admin-Token` | Reject new drops (`503`); existing drops claimable until natural expiry (graceful shutdown) |
| `POST` | `/admin/burn` | `X-Admin-Token` | Destroy all drops instantly; service stays up (panic switch) |

Both admin endpoints require header `X-Admin-Token` matching env var
`DD_ADMIN_TOKEN`, else `403`.

## Run locally

```bash
pip install -r requirements.txt
export DD_ADMIN_TOKEN="choose-a-secret"      # required for /admin/* endpoints
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Stop it with `Ctrl-C` (or `pkill -f "uvicorn main:app"` if backgrounded).

### Quick demo

```bash
B=http://127.0.0.1:8000

# A drops a secret for B, gets back drop_id (private) + pickup_key (share out-of-band)
curl -s -X POST $B/drop -H 'content-type: application/json' \
  -d '{"recipient":"agentB","payload":"launch-codes-42","ttl":600}'
# -> {"drop_id":"...","pickup_key":"...","expires_at":...}

# B redeems once
curl -s $B/pickup/<pickup_key>          # -> {"payload":"launch-codes-42"}

# second read is gone forever
curl -s -o /dev/null -w '%{http_code}\n' $B/pickup/<pickup_key>   # -> 410

# A checks status: "claimed"  (if it says claimed before B picked up => interception)
curl -s $B/drop/<drop_id>               # -> {"status":"claimed", ...}
```

## Simulation (`sim.py`) — Tier 1 scripted agents

A pure-stdlib, fully deterministic model of the protocol. Agents follow fixed rules
decided in advance from a seeded RNG — they do not think or adapt. It tests the
**rules** (the protocol), not any AI. No API keys, no internet, no cost.

```bash
python3 sim.py                                        # 1000 agents, seed 42
python3 sim.py --agents 10000 --ticks 120 --seed 99  # 10k agents, < 1s
python3 sim.py --seed 123 --drop-rate 0.3 --partition  # lossy + split network
```

Flags:

- `--agents N` — owner/recipient pairs (default 1000).
- `--seed S` — RNG seed (default 42). Same seed ⇒ byte-identical run.
- `--ticks T` — ticks to simulate (default 120). TTLs are counted in ticks.
- `--drop-rate F` — fraction of simulated messages lost (key delivery **and**
  revoke/shorten/extend messages). A lost revocation still fails safe at the
  original expiry.
- `--partition` — split the network at `T/3`, heal at `2T/3`; partitioned
  recipients cannot reach the store during the split.

At end of run it prints a summary and asserts six hard invariants, exiting nonzero on
any violation:

1. no payload read twice;
2. no read after expiry, revoke, or an effective shorten;
3. no read without the correct key — zero adversary successes;
4. no management action via a `pickup_key`;
5. no lifetime exceeded the cap despite extensions;
6. every drop reached exactly one terminal state (`claimed` | `expired` | `revoked`).

Sample output (`python3 sim.py --agents 10000 --seed 99`):

```
============================================================
Dead Drop — Tier 1 simulation summary
============================================================
  drops created ............ 10000
  claimed .................. 7587
  expired .................. 1307
  revoked .................. 1106
  still waiting ............ 0
  adversary attempts ....... 6000
  adversary attempts blocked 6000
------------------------------------------------------------
INVARIANTS: all 6 passed
  ✓ INV1 no payload read twice
  ✓ INV2 no read after expiry/revoke/shorten
  ✓ INV3 zero adversary read successes
  ✓ INV4 no management via pickup_key
  ✓ INV5 no lifetime exceeded the cap
  ✓ INV6 every drop reached exactly one terminal state
============================================================
```

Determinism check:

```bash
python3 sim.py --seed 123 > a.txt
python3 sim.py --seed 123 > b.txt
diff a.txt b.txt && echo IDENTICAL
```

## Deploy notes (Render)

`render.yaml` is a Blueprint for a free-plan web service running
`uvicorn main:app --host 0.0.0.0 --port $PORT`, with `DD_ADMIN_TOKEN` marked
`sync: false` (set it in the Render dashboard, never committed).

Steps: **Render → New → Blueprint → select the `deaddrop-skill` repo → set
`DD_ADMIN_TOKEN` → Deploy.**

Two free-tier behaviors to know:

- **Cold starts.** The free instance sleeps after ~15 min idle and takes 30–60s to
  wake. Ping `/health` before a demo or before judging so the service is warm.
- **Restarts wipe the store.** State is in-memory only, so a restart destroys all
  drops. This is a **fail-safe, not a durability bug**: an in-memory restart is a
  total burn — destruction, never leakage. It is protocol-coherent by design.

## Design limitations (deliberate, v1)

- **No encryption in v1.** Payloads are opaque bytes stored as given. Transport
  security is TLS at the edge; end-to-end encryption composes cleanly on top.
- **Bearer semantics.** The first presenter of a valid `pickup_key` wins (residual
  interception risk), mitigated by short TTLs, owner shortening/revocation, and the
  detection guarantee (a premature `claimed`). Identity-bound pickup — composing with
  an identity skill such as AgentPass — is the documented **v2** path.

> The registry is full of skills making agent interactions persistent and
> verifiable — Dead Drop is the missing complement, for secrets that are safest when
> they stop existing.
