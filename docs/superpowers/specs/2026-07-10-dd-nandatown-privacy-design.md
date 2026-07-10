# Dead Drop as a Nanda Town Privacy Layer — Design

Date: 2026-07-10
Status: approved by user (sections 1–3)

## Goal

Run Nanda Town locally with Dead Drop (DD) plugged in as the Privacy layer, and
watch agents hand off secrets autonomously in a spy-vs-courier scenario:
couriers pass secrets through DD, eavesdropper spies race to steal pickups, and
every interception is detectable. Zero cost end to end: Tier 1 scripted agents
first, then Tier 2 in Nanda Town's free `mock` LLM mode.

## Constraints

- **Zero cost.** No paid API calls. Tier 2 uses `llm_provider: mock`; a real
  `ANTHROPIC_API_KEY` is an optional user-supplied upgrade, never required.
- **In-process DD engine.** The plugin ports DD's rules; it does not call the
  FastAPI service. The live Render deployment stays untouched for judging.
- **Deterministic Tier 1.** All randomness from seeded RNGs (`ctx.rng` in
  agents, one seeded RNG in the store). Same seed, byte-identical trace. No
  `secrets` module, no wall clock.
- **All changes local to the nandatown clone.** Nothing is pushed unless the
  user later decides to PR it.
- **`make ci-local` stays green** in the clone (ruff, pyright, pytest).

## Files

All inside the local `projnanda/nandatown` clone:

| File | Purpose |
|---|---|
| `packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py` | `DeadDropPrivacy` plugin |
| `packages/nest-plugins-reference/pyproject.toml` | add entry point `dead_drop` under `nest.plugins.privacy` |
| `packages/nest-core/nest_core/scenarios_builtin/spy_courier.py` | scenario module (agents + factory + validator) |
| `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier.yaml` | Tier 1 config |
| `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier_llm.yaml` | Tier 2 config (`brain: shell`, `llm_provider: mock`) |
| `packages/nest-core/nest_core/scenarios.py` | register `spy_courier` factory (mirrors existing built-ins) |
| `packages/nest-plugins-reference/tests/test_dead_drop_privacy.py` | plugin unit tests |
| templates for courier/recipient (Tier 2), per `nest templates` layout | shell-agent prompts |

## Component 1: `DeadDropPrivacy` plugin

Implements the `Privacy` protocol (`encrypt`, `decrypt`, `prove`,
`verify_proof`). Registered as `privacy: dead_drop`. All instances share one
in-process store (constructor-injected shared dicts, mirroring the
`PrepaidCredits` shared-ledger pattern).

Semantics ported 1:1 from DD's `main.py`, with time in ticks:

- `encrypt(data, audience) -> bytes`: store the payload with TTL (default 20
  ticks, hard cap 60 from creation), generate `pickup_key` and private
  `drop_id` from the store's seeded RNG, return envelope bytes
  `b"dd1:<pickup_key>"`. The envelope — never the secret — travels over the
  normal message channel.
- `decrypt(envelope) -> bytes`: one-time redemption. First valid call returns
  the plaintext, destroys the payload, marks the tombstone `claimed`.
  Consumed, expired, revoked, and unknown envelopes all raise the same
  `ValueError("gone")` (uniform-410 rule; no probing).
- Owner methods (beyond the protocol, used by couriers): `status(drop_id)`
  (`waiting|claimed|expired|revoked`, tombstone retained after destruction),
  `set_ttl(drop_id, ttl)` (shorten unrestricted; extension capped at 60 ticks
  from creation), `revoke(drop_id)`. Management accepts `drop_id` only, never
  a pickup key.
- `prove`/`verify_proof`: honest stubs, same as the shipped `noop` plugin.
- Expiry is lazy: checked on every access against the current tick. Clock
  wiring: the shared store exposes `set_time(tick)`, and every scenario agent
  calls `store.set_time(ctx.time)` at the top of each callback before touching
  DD. Since only agent callbacks drive DD operations, the store's clock is
  always current at operation time, with no dependency on a global clock.

## Component 2: `spy_courier` scenario

Tier 1 roles (`StateMachineAgent`), default counts in YAML — 6 couriers, 6
recipients, 3 spies, seed 42:

- **Courier** (paired 1:1 with a recipient): at a staggered start tick,
  `encrypt`s its mission secret, sends the envelope to its recipient over the
  normal channel, then polls `status(drop_id)` every few ticks.
  - `claimed` + recipient ack received → mission delivered.
  - `claimed` + no ack → **interception detected**: log alarm, warn recipient.
  - ~20% (rng) revoke mid-window; some shorten TTL; unclaimed drops expire.
- **Recipient**: on envelope receipt, wait a small rng delay (creates the race
  window), `decrypt`. Success → ack courier. `ValueError` → report failure.
- **Spy**: receives copies of envelope messages with probability
  `intercept_rate` (default 0.3, modeled as an explicit cc in the scenario —
  the wiretap). After its own delay, races to `decrypt` the stolen envelope.
  Also performs always-fail attacks: replay consumed envelopes, guess random
  keys, attempt management calls with a pickup key.

Every action is a trace event (`drop-created`, `envelope-sent`, `pickup-ok`,
`pickup-gone`, `interception-detected`, `revoked`, `expired`, spy attempts) so
`nest inspect` / `report` / `dashboard` work unmodified.

End-of-run summary: missions delivered / intercepted-and-detected / revoked /
expired / spy wins / spy attempts blocked.

**Honest framing:** spies can win the race (bearer semantics, same as the real
API). The guarantee demonstrated is that theft is loud (courier detects it;
recipient gets nothing) and capped at one read — not that theft is impossible.

## Component 3: Validation

Post-run validator over the shared store + counters; exit nonzero on failure:

1. No payload read twice.
2. No read after expiry, revoke, or effective shorten.
3. Zero reads without a valid envelope (all guesses/replays fail).
4. No management action via pickup key.
5. No lifetime exceeded the 60-tick cap.
6. Every drop reached exactly one terminal state.
7. **Every spy win was detected by the owning courier** (no silent
   interception).

Plus pytest unit tests for the plugin (one-time decrypt, uniform error,
tombstone status transitions, TTL cap, revoke), in the repo's existing test
style. `make ci-local` must pass.

Determinism check: run the same seed twice, diff traces — must be identical.

## Component 4: Tier 2 (free mock mode)

`spy_courier_llm.yaml`: identical layers (`privacy: dead_drop`), ~8 agents,
`brain: shell`, `llm_provider: mock`. Courier and recipient templates whose
prompts describe the DD tools plainly (envelope in, one-time decrypt out,
claimed-without-ack = interception). Zero cost; swapping in a real
`ANTHROPIC_API_KEY` upgrades the same YAML to real Claude-driven agents.

**Risk + fallback:** Tier 2 is marked experimental upstream. If the shell-agent
subsystem blocks us, deliver Tier 1 fully working plus a written recipe for the
Tier 2 flip; do not sink unbounded time into upstream experimental code.

## Error handling

- Dead envelopes raise `ValueError` (their layer convention); agents treat it
  as a story event, never a crash.
- Lost messages (`message_drop` knob) fail safe: an envelope that never
  arrives expires; a lost ack shows up as claimed-without-ack (counted as
  detection working, since the courier cannot distinguish — documented in the
  summary output).
- Revoke/shorten of an already-terminal drop is a no-op returning the terminal
  status, matching the API.

## How the user runs it

```bash
cd <nandatown clone>
uv sync
uv run nest run spy_courier                       # Tier 1
uv run nest inspect traces/spy_courier.jsonl
uv run nest dashboard traces/spy_courier.jsonl    # browser view
uv run nest run spy_courier_llm                   # Tier 2, mock LLM, free
```

## Out of scope

- Calling the live FastAPI service from the sim.
- Real-money LLM runs (user may opt in later by setting a key).
- Upstreaming as a PR (possible later; not part of this work).
- ZK proofs (`prove`/`verify_proof` remain stubs).
