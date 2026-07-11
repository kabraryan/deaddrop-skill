# Dead Drop × Nanda Town (spy_courier) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Plug Dead Drop into Nanda Town as a Privacy-layer plugin and run a spy-vs-courier scenario locally where every secret is decryptable exactly once and every theft is detected.

**Architecture:** A `DeadDropStore` (shared, seeded, tick-clocked) + thin `DeadDropPrivacy` plugin implementing Nanda Town's `Privacy` protocol; a `spy_courier` scenario module with Courier/Recipient/Spy/Director `StateMachineAgent`s and a post-run validator; Tier 2 variant swaps couriers for LLM-parameterized agents using the free `MockLLMBackend`.

**Tech Stack:** Python 3.12+, Nanda Town (`nest-core`, `nest-plugins-reference`, `nest-shell`), uv, pytest, ruff, pyright (strict).

## Global Constraints

- Working repo: the local clone at `/private/tmp/claude-502/-Users-aryankabra-test-Desktop-DEAD-DROP/02087618-f5df-4df6-8d35-03ec6f43412d/scratchpad/nandatown` (referred to as `$NT` below). All paths are relative to it unless absolute.
- All work on a NEW local branch `local/dd-spy-courier` cut from `main` — never on `hackathon/aryan-prepaid-refund-status` (that's an open PR). Never push this branch.
- Zero cost: no network calls, no paid APIs. Tier 2 uses `MockLLMBackend` only.
- Deterministic Tier 1: all randomness from `random.Random(seed)` / `ctx.rng`. Never `secrets`, never wall clock. Same seed ⇒ byte-identical trace.
- TTLs in ticks: default 20.0, hard cap 60.0 from creation (`DEFAULT_TTL_TICKS`, `MAX_TTL_TICKS`).
- All dead-envelope decrypts raise exactly `ValueError("gone")` — consumed, expired, revoked, and unknown are indistinguishable to the caller.
- Management (status/set_ttl/revoke) accepts `drop_id` only; a pickup key presented as a handle must miss.
- `make ci-local` must pass at the end (ruff check, ruff format --check, pyright, pytest).
- Match repo conventions: SPDX header line 1, `from __future__ import annotations`, docstrings with `Example::` blocks, full type annotations (pyright strict — annotate empty containers explicitly).
- Registration deviation from spec (approved rationale): the plugin registers via the `_BUILTINS` dict in `nest_core/plugins.py` — the same registry every bundled reference plugin uses — instead of a pyproject entry point, because entry points require a reinstall to take effect and `_BUILTINS` is the mechanism `noop`/`hybrid_x25519`/`trust_gated` already use.

---

### Task 1: `DeadDropStore` + `DeadDropPrivacy` plugin

**Files:**
- Create: `packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py`
- Modify: `packages/nest-core/nest_core/plugins.py` (add one `_BUILTINS` line after the `trust_gated` privacy line)
- Test: `packages/nest-plugins-reference/tests/test_dead_drop_privacy.py`

**Interfaces:**
- Consumes: `nest_core.types.AgentId, Proof, Statement, Witness`; `nest_core.layers.privacy.Privacy` (runtime-checkable protocol: `encrypt(data: bytes, audience: list[AgentId]) -> bytes`, `decrypt(data: bytes) -> bytes`, `prove`, `verify_proof`).
- Produces (used by Tasks 2–5):
  - `DeadDropStore(seed: int = 0)` with: `set_time(tick: float) -> None`, `now: float` property, `create(payload: bytes, ttl: float = 20.0) -> tuple[str, str]` (returns `(drop_id, pickup_key)`), `pickup(pickup_key: str, reader: str) -> bytes | None`, `status(drop_id: str) -> str | None`, `set_ttl(drop_id: str, ttl: float) -> bool`, `revoke(drop_id: str) -> bool`, `finalize() -> None`, `statuses() -> dict[str, str]`; audit attrs `reads: list[ReadRecord]`, `failed_pickups: int`, `mgmt_misses: int`, `max_expiry_seen: dict[str, float]`, `created_at: dict[str, float]`.
  - `ReadRecord` dataclass: fields `drop_id: str`, `tick: float`, `reader: str`.
  - `DeadDropPrivacy` with: classmethod `new_shared(seed: int = 0, default_ttl: float = 20.0) -> DeadDropPrivacy`, `for_agent(agent_id: AgentId) -> DeadDropPrivacy`, `store: DeadDropStore` property, async `encrypt`/`decrypt` per protocol, `drop_id_for(envelope: bytes) -> str | None`, `set_default_ttl(ttl: float) -> None`, `status(drop_id: str) -> str | None`, `set_ttl(drop_id: str, ttl: float) -> bool`, `revoke(drop_id: str) -> bool`.
  - Module constants: `DEFAULT_TTL_TICKS = 20.0`, `MAX_TTL_TICKS = 60.0`.

- [ ] **Step 1: Create the working branch**

```bash
cd $NT
git checkout main
git checkout -b local/dd-spy-courier
```

- [ ] **Step 2: Write the failing tests**

Create `packages/nest-plugins-reference/tests/test_dead_drop_privacy.py`:

```python
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Dead Drop privacy plugin."""

from __future__ import annotations

import pytest

from nest_core.layers.privacy import Privacy
from nest_core.types import AgentId
from nest_plugins_reference.privacy.dead_drop import (
    MAX_TTL_TICKS,
    DeadDropPrivacy,
    DeadDropStore,
)


def make_pair() -> tuple[DeadDropPrivacy, DeadDropPrivacy, DeadDropPrivacy]:
    shared = DeadDropPrivacy.new_shared(seed=7)
    alice = shared.for_agent(AgentId("alice"))
    bob = shared.for_agent(AgentId("bob"))
    return shared, alice, bob


class TestProtocolConformance:
    def test_satisfies_privacy_protocol(self) -> None:
        shared, alice, bob = make_pair()
        assert isinstance(alice, Privacy)


class TestOneTimeRead:
    @pytest.mark.asyncio
    async def test_decrypt_returns_plaintext_exactly_once(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"safehouse-7", [AgentId("bob")])
        assert envelope.startswith(b"dd1:")
        assert await bob.decrypt(envelope) == b"safehouse-7"
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(envelope)

    @pytest.mark.asyncio
    async def test_unknown_envelope_same_error(self) -> None:
        shared, alice, bob = make_pair()
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(b"dd1:never-issued")
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(b"not-even-an-envelope")

    @pytest.mark.asyncio
    async def test_expired_envelope_same_error(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        shared.store.set_time(shared.store.now + MAX_TTL_TICKS + 1)
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(envelope)

    @pytest.mark.asyncio
    async def test_reader_identity_recorded(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        await bob.decrypt(envelope)
        assert [r.reader for r in shared.store.reads] == ["bob"]


class TestOwnerManagement:
    @pytest.mark.asyncio
    async def test_status_tombstone_after_claim(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        drop_id = alice.drop_id_for(envelope)
        assert drop_id is not None
        assert alice.status(drop_id) == "waiting"
        await bob.decrypt(envelope)
        assert alice.status(drop_id) == "claimed"

    @pytest.mark.asyncio
    async def test_revoke_kills_pickup(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        drop_id = alice.drop_id_for(envelope)
        assert drop_id is not None
        assert alice.revoke(drop_id) is True
        assert alice.status(drop_id) == "revoked"
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(envelope)

    @pytest.mark.asyncio
    async def test_shorten_then_pickup_fails(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        drop_id = alice.drop_id_for(envelope)
        assert drop_id is not None
        assert alice.set_ttl(drop_id, 1.0) is True
        shared.store.set_time(shared.store.now + 2.0)
        with pytest.raises(ValueError, match="gone"):
            await bob.decrypt(envelope)
        assert alice.status(drop_id) == "expired"

    @pytest.mark.asyncio
    async def test_extension_past_cap_rejected(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        drop_id = alice.drop_id_for(envelope)
        assert drop_id is not None
        assert alice.set_ttl(drop_id, MAX_TTL_TICKS + 10) is False
        assert alice.set_ttl(drop_id, MAX_TTL_TICKS - 1) is True

    @pytest.mark.asyncio
    async def test_revoke_after_elapsed_ttl_reports_expired(self) -> None:
        store = DeadDropStore(seed=1)
        drop_id, _ = store.create(b"p", ttl=5.0)
        store.set_time(100.0)
        assert store.revoke(drop_id) is True
        assert store.statuses()[drop_id] == "expired"

    @pytest.mark.asyncio
    async def test_pickup_key_is_not_a_management_handle(self) -> None:
        shared, alice, bob = make_pair()
        envelope = await alice.encrypt(b"x", [AgentId("bob")])
        pickup_key = envelope.decode()[len("dd1:") :]
        assert alice.status(pickup_key) is None
        assert alice.set_ttl(pickup_key, 5.0) is False
        assert alice.revoke(pickup_key) is False
        assert shared.store.mgmt_misses == 3


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_seed_same_tokens(self) -> None:
        a = DeadDropStore(seed=99)
        b = DeadDropStore(seed=99)
        assert a.create(b"p", ttl=10.0) == b.create(b"p", ttl=10.0)


class TestFinalize:
    @pytest.mark.asyncio
    async def test_finalize_expires_overdue_waiting_drops(self) -> None:
        store = DeadDropStore(seed=1)
        drop_id, _ = store.create(b"p", ttl=5.0)
        store.set_time(100.0)
        store.finalize()
        assert store.statuses()[drop_id] == "expired"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_dead_drop_privacy.py -q`
Expected: FAIL/ERROR with `ModuleNotFoundError: No module named 'nest_plugins_reference.privacy.dead_drop'`

- [ ] **Step 4: Write the implementation**

Create `packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py`:

```python
# SPDX-License-Identifier: Apache-2.0
"""Dead Drop privacy plugin — one-time-read secret transfer.

``encrypt`` stores the plaintext in a shared in-process store and returns an
*envelope* (``dd1:<pickup_key>`` as bytes) that travels over the normal
message channel. ``decrypt`` redeems the envelope exactly once: the first
caller gets the plaintext and the payload is destroyed. Every later call —
consumed, expired, revoked, or unknown — raises the same ``ValueError("gone")``
so holders of dead envelopes cannot probe which keys were ever valid.

The creating instance keeps a private ``drop_id`` per envelope for owner
management (status / set_ttl / revoke). Management never accepts a pickup
key, so a recipient or interceptor cannot extend or inspect their own access.

Example::

    shared = DeadDropPrivacy.new_shared(seed=42)
    alice = shared.for_agent(AgentId("alice"))
    bob = shared.for_agent(AgentId("bob"))
    envelope = await alice.encrypt(b"secret", [AgentId("bob")])
    assert await bob.decrypt(envelope) == b"secret"
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from nest_core.types import AgentId, Proof, Statement, Witness

DEFAULT_TTL_TICKS = 20.0
MAX_TTL_TICKS = 60.0

_ENVELOPE_PREFIX = "dd1:"


@dataclass
class ReadRecord:
    """Audit record of one successful pickup.

    Example::

        rec = ReadRecord(drop_id="drop-1", tick=3.0, reader="bob")
    """

    drop_id: str
    tick: float
    reader: str


@dataclass
class _Drop:
    drop_id: str
    pickup_key: str
    payload: bytes | None
    created_at: float
    expires_at: float
    status: str = "waiting"  # waiting | claimed | expired | revoked


class DeadDropStore:
    """Shared one-time-drop store on a logical tick clock.

    A terminal drop (claimed | expired | revoked) keeps a status tombstone but
    its payload is destroyed and its pickup key de-indexed — the secret is
    gone; only the fact of its fate remains, which is what makes interception
    detectable.

    Example::

        store = DeadDropStore(seed=42)
        drop_id, key = store.create(b"secret", ttl=10.0)
        assert store.pickup(key, reader="bob") == b"secret"
    """

    def __init__(self, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._drops: dict[str, _Drop] = {}
        self._by_key: dict[str, str] = {}
        self._now: float = 0.0
        # Audit trail consumed by scenario validators.
        self.reads: list[ReadRecord] = []
        self.failed_pickups: int = 0
        self.mgmt_misses: int = 0
        self.max_expiry_seen: dict[str, float] = {}
        self.created_at: dict[str, float] = {}

    @property
    def now(self) -> float:
        """Current logical time.

        Example::

            t = store.now
        """
        return self._now

    def set_time(self, tick: float) -> None:
        """Advance the logical clock; it never moves backward.

        Example::

            store.set_time(ctx.time)
        """
        if tick > self._now:
            self._now = tick

    def _new_token(self, prefix: str) -> str:
        return f"{prefix}-{self._rng.getrandbits(64):016x}"

    def _purge_if_expired(self, drop: _Drop) -> bool:
        """Lazy expiry; returns True when the drop is in a terminal state."""
        if drop.status != "waiting":
            return True
        if self._now >= drop.expires_at:
            drop.status = "expired"
            drop.payload = None
            self._by_key.pop(drop.pickup_key, None)
            return True
        return False

    def create(self, payload: bytes, ttl: float = DEFAULT_TTL_TICKS) -> tuple[str, str]:
        """Store a payload; returns (drop_id, pickup_key).

        Example::

            drop_id, key = store.create(b"secret", ttl=10.0)
        """
        ttl = min(max(ttl, 1.0), MAX_TTL_TICKS)
        drop_id = self._new_token("drop")
        pickup_key = self._new_token("key")
        drop = _Drop(drop_id, pickup_key, payload, self._now, self._now + ttl)
        self._drops[drop_id] = drop
        self._by_key[pickup_key] = drop_id
        self.max_expiry_seen[drop_id] = drop.expires_at
        self.created_at[drop_id] = drop.created_at
        return drop_id, pickup_key

    def pickup(self, pickup_key: str, reader: str) -> bytes | None:
        """Redeem a pickup key exactly once; None for any dead or unknown key.

        Example::

            payload = store.pickup(key, reader="bob")
        """
        drop_id = self._by_key.get(pickup_key)
        if drop_id is None:
            self.failed_pickups += 1
            return None
        drop = self._drops[drop_id]
        if self._purge_if_expired(drop):
            self.failed_pickups += 1
            return None
        payload = drop.payload
        drop.status = "claimed"
        drop.payload = None
        self._by_key.pop(pickup_key, None)
        self.reads.append(ReadRecord(drop_id=drop_id, tick=self._now, reader=reader))
        return payload

    def status(self, drop_id: str) -> str | None:
        """Owner status check; None for unknown handles (incl. pickup keys).

        Example::

            st = store.status(drop_id)
        """
        drop = self._drops.get(drop_id)
        if drop is None:
            self.mgmt_misses += 1
            return None
        self._purge_if_expired(drop)
        return drop.status

    def set_ttl(self, drop_id: str, ttl: float) -> bool:
        """Reset remaining lifetime; extension capped at MAX_TTL_TICKS total.

        Example::

            ok = store.set_ttl(drop_id, 5.0)
        """
        drop = self._drops.get(drop_id)
        if drop is None:
            self.mgmt_misses += 1
            return False
        if self._purge_if_expired(drop) or ttl <= 0:
            return False
        new_expiry = self._now + ttl
        if new_expiry > drop.created_at + MAX_TTL_TICKS:
            return False
        drop.expires_at = new_expiry
        self.max_expiry_seen[drop_id] = max(self.max_expiry_seen[drop_id], new_expiry)
        return True

    def revoke(self, drop_id: str) -> bool:
        """Destroy a waiting drop immediately; True if the handle exists.

        Example::

            store.revoke(drop_id)
        """
        drop = self._drops.get(drop_id)
        if drop is None:
            self.mgmt_misses += 1
            return False
        if self._purge_if_expired(drop):
            return True
        drop.status = "revoked"
        drop.payload = None
        self._by_key.pop(drop.pickup_key, None)
        return True

    def finalize(self) -> None:
        """End-of-run sweep: lazily expire every overdue waiting drop.

        Example::

            store.set_time(final_tick)
            store.finalize()
        """
        for drop in self._drops.values():
            self._purge_if_expired(drop)

    def statuses(self) -> dict[str, str]:
        """Snapshot of every drop's status keyed by drop_id.

        Example::

            terminal = store.statuses()
        """
        return {drop_id: drop.status for drop_id, drop in self._drops.items()}


class DeadDropPrivacy:
    """Privacy-layer plugin backed by a shared :class:`DeadDropStore`.

    Example::

        shared = DeadDropPrivacy.new_shared(seed=42)
        alice = shared.for_agent(AgentId("alice"))
    """

    def __init__(
        self,
        store: DeadDropStore | None = None,
        agent_id: AgentId | None = None,
        default_ttl: float = DEFAULT_TTL_TICKS,
    ) -> None:
        self._store = store if store is not None else DeadDropStore()
        self._agent_id = agent_id
        self._default_ttl = default_ttl
        self._owned: dict[bytes, str] = {}

    @classmethod
    def new_shared(cls, seed: int = 0, default_ttl: float = DEFAULT_TTL_TICKS) -> DeadDropPrivacy:
        """Create the shared root instance for a simulation run.

        Example::

            shared = DeadDropPrivacy.new_shared(seed=42)
        """
        return cls(store=DeadDropStore(seed=seed), default_ttl=default_ttl)

    def for_agent(self, agent_id: AgentId) -> DeadDropPrivacy:
        """Create a per-agent handle over the same store.

        Example::

            alice = shared.for_agent(AgentId("alice"))
        """
        return DeadDropPrivacy(store=self._store, agent_id=agent_id, default_ttl=self._default_ttl)

    @property
    def store(self) -> DeadDropStore:
        """The shared store (exposed for scenario clock/validators).

        Example::

            shared.store.set_time(ctx.time)
        """
        return self._store

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Store the plaintext; return the one-time envelope.

        Example::

            envelope = await alice.encrypt(b"secret", [AgentId("bob")])
        """
        drop_id, pickup_key = self._store.create(data, ttl=self._default_ttl)
        envelope = f"{_ENVELOPE_PREFIX}{pickup_key}".encode()
        self._owned[envelope] = drop_id
        return envelope

    async def decrypt(self, data: bytes) -> bytes:
        """Redeem an envelope exactly once; ValueError("gone") otherwise.

        Example::

            plaintext = await bob.decrypt(envelope)
        """
        text = data.decode("utf-8", errors="replace")
        if not text.startswith(_ENVELOPE_PREFIX):
            raise ValueError("gone")
        key = text[len(_ENVELOPE_PREFIX) :]
        reader = str(self._agent_id) if self._agent_id is not None else "unknown"
        payload = self._store.pickup(key, reader=reader)
        if payload is None:
            raise ValueError("gone")
        return payload

    def drop_id_for(self, envelope: bytes) -> str | None:
        """Private management handle for an envelope this instance created.

        Example::

            drop_id = alice.drop_id_for(envelope)
        """
        return self._owned.get(envelope)

    def set_default_ttl(self, ttl: float) -> None:
        """Set the TTL used by this instance's future ``encrypt`` calls.

        Example::

            alice.set_default_ttl(30.0)
        """
        self._default_ttl = ttl

    def status(self, drop_id: str) -> str | None:
        """Owner status check by drop_id.

        Example::

            st = alice.status(drop_id)
        """
        return self._store.status(drop_id)

    def set_ttl(self, drop_id: str, ttl: float) -> bool:
        """Shorten or (cap-limited) extend a drop's lifetime.

        Example::

            alice.set_ttl(drop_id, 1.0)
        """
        return self._store.set_ttl(drop_id, ttl)

    def revoke(self, drop_id: str) -> bool:
        """Revoke a drop immediately.

        Example::

            alice.revoke(drop_id)
        """
        return self._store.revoke(drop_id)

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Mock proof — ZK is out of scope for Dead Drop (same as noop).

        Example::

            proof = await priv.prove(stmt, witness)
        """
        return Proof(statement=statement, data=b"dead-drop-noop-proof", scheme="noop")

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Accept mock proofs (same as noop).

        Example::

            ok = await priv.verify_proof(stmt, proof)
        """
        return True
```

- [ ] **Step 5: Register in `_BUILTINS`**

In `packages/nest-core/nest_core/plugins.py`, directly below the line
`("privacy", "trust_gated"): f"{_REF}.privacy.trust_gated:TrustGatedPrivacy",` add:

```python
    ("privacy", "dead_drop"): f"{_REF}.privacy.dead_drop:DeadDropPrivacy",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_dead_drop_privacy.py -v`
Expected: all tests PASS

- [ ] **Step 7: Lint + typecheck the new files**

Run: `cd $NT && uv run ruff check packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py packages/nest-plugins-reference/tests/test_dead_drop_privacy.py && uv run ruff format --check packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py packages/nest-plugins-reference/tests/test_dead_drop_privacy.py && uv run pyright packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py`
Expected: no errors (run `uv run ruff format <files>` first if format check complains)

- [ ] **Step 8: Commit**

```bash
cd $NT
git add packages/nest-plugins-reference/nest_plugins_reference/privacy/dead_drop.py \
        packages/nest-plugins-reference/tests/test_dead_drop_privacy.py \
        packages/nest-core/nest_core/plugins.py
git commit -m "feat: DeadDropPrivacy plugin - one-time-read privacy layer"
```

---

### Task 2: `spy_courier` scenario module + registration + YAML

**Files:**
- Create: `packages/nest-core/nest_core/scenarios_builtin/spy_courier.py`
- Create: `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier.yaml`
- Modify: `packages/nest-core/nest_core/scenarios.py` (one `elif` in `_try_load_builtin`)
- Test: `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py` (created here, extended in Task 3)

**Interfaces:**
- Consumes: Task 1's `DeadDropPrivacy` API (via duck-typed `plugins["privacy"]` class with `new_shared`/`for_agent`); `nest_core.scenario.ScenarioConfig` (fields: `seed: int`, `agents.roles: list[RoleConfig(name, count)]`, `task.config: dict`, `get_max_ticks()`); `nest_core.sim.agent.StateMachineAgent` (override `on_start(ctx)`, `on_message(ctx, sender, payload)`, `on_stop(ctx)`; ctx API: `agent_id`, `time: float`, `rng: random.Random`, `plugins: dict[str, Any]`, `send(to, payload)`, `schedule(delay, payload)`); factory signature `Callable[[ScenarioConfig, dict[str, Any]], dict[AgentId, Any]]`; per-agent plugin override idiom `plugins.setdefault("_agent_plugins", {})[agent_id] = {"privacy": instance}`.
- Produces: `spy_courier_factory(config, plugins) -> dict[AgentId, Any]`; `validate_spy_courier_run(store, spy_readers, detected) -> list[str]`; `RunLog` dataclass (shared mutable scenario state); message protocol constants below (Tasks 3 and 5 rely on all of these, exact names).

Message protocol (UTF-8 bytes):
- courier → recipient: `envelope:<envelope>`
- courier → spy (wiretap cc): `tapped:<envelope>`
- recipient → courier: `ack` (successful decrypt) or `failed` (got "gone")
- courier → recipient: `compromised` (warning after detection)
- self-scheduled: `begin`, `act`, `poll`, `redeem:<envelope>`, `race:<envelope>`, `replay:<envelope>`, `guess`, `mgmt:<envelope>`

- [ ] **Step 1: Write a failing smoke test for the factory**

Create `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py`:

```python
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the spy_courier scenario."""

from __future__ import annotations

from typing import Any

from nest_core.scenario import ScenarioConfig


def make_config(trace_path: str, seed: int = 42) -> ScenarioConfig:
    return ScenarioConfig.model_validate(
        {
            "name": "spy_courier",
            "description": "test run",
            "tier": 1,
            "seed": seed,
            "agents": {
                "count": 16,
                "brain": "state-machine",
                "roles": [
                    {"name": "courier", "count": 6},
                    {"name": "recipient", "count": 6},
                    {"name": "spy", "count": 3},
                    {"name": "director", "count": 1},
                ],
            },
            "layers": {
                "transport": "in_memory",
                "comms": "nest_native",
                "identity": "did_key",
                "registry": "in_memory",
                "auth": "jwt",
                "trust": "score_average",
                "payments": "prepaid_credits",
                "coordination": "contract_net",
                "negotiation": "alternating_offers",
                "memory": "blackboard",
                "privacy": "dead_drop",
                "datafacts": "datafacts_v1",
            },
            "task": {
                "type": "spy_courier",
                "config": {"intercept_rate": 0.5, "default_ttl": 20},
            },
            "failures": {"message_drop": 0.0},
            "duration": "ticks: 2000",
            "metrics": [],
            "output": {"trace": trace_path},
        }
    )


class TestFactory:
    def test_factory_builds_all_roles(self) -> None:
        from nest_core.plugins import PluginRegistry
        from nest_core.scenarios import get_scenario_factory

        config = make_config("./traces/unused.jsonl")
        plugins: dict[str, Any] = {
            "privacy": PluginRegistry().resolve("privacy", "dead_drop"),
        }
        factory = get_scenario_factory("spy_courier")
        agents = factory(config, plugins)
        names = sorted(str(a) for a in agents)
        assert "courier-0" in names
        assert "recipient-5" in names
        assert "spy-2" in names
        assert "director-0" in names
        assert len(agents) == 16
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_spy_courier_scenario.py -q`
Expected: FAIL with `KeyError`/`ValueError` from `get_scenario_factory("spy_courier")` (unknown scenario)

- [ ] **Step 3: Write the scenario module**

Create `packages/nest-core/nest_core/scenarios_builtin/spy_courier.py`:

```python
# SPDX-License-Identifier: Apache-2.0
"""Spy-vs-courier scenario over the Dead Drop privacy layer.

Couriers encrypt mission secrets into one-time Dead Drop envelopes and send
the envelope — never the secret — to their recipient over the normal message
channel. Spies wiretap a fraction of envelope messages and race the recipient
to redeem them. A secret is readable exactly once, ever: either the recipient
gets it, or a spy steals it and the courier's status poll detects the theft
("claimed" with no recipient ack).

Example::

    agents = spy_courier_factory(config, plugins)
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from nest_core.scenario import ScenarioConfig
from nest_core.sim.agent import AgentContext, StateMachineAgent
from nest_core.types import AgentId

_DIRECTOR = AgentId("director-0")
_POLL_EVERY = 3.0
_DETECT_AFTER_POLLS = 2


@dataclass
class RunLog:
    """Shared mutable scenario state, immune to simulated message loss.

    Example::

        log = RunLog()
        log.detected.add("drop-1")
    """

    detected: set[str] = field(default_factory=set)
    outcomes: dict[str, str] = field(default_factory=dict)
    spy_wins: int = 0
    spy_blocked: int = 0


class CourierAgent(StateMachineAgent):
    """Creates one drop, wiretap-cc's spies, polls status, detects theft."""

    def __init__(
        self,
        agent_id: AgentId,
        recipient: AgentId,
        spies: list[AgentId],
        secret: bytes,
        intercept_rate: float,
        action: str,
        log: RunLog,
    ) -> None:
        self._id = agent_id
        self._recipient = recipient
        self._spies = spies
        self._secret = secret
        self._intercept_rate = intercept_rate
        self._action = action  # "none" | "revoke" | "shorten"
        self._log = log
        self._drop_id: str | None = None
        self._acked = False
        self._recipient_failed = False
        self._claimed_polls = 0
        self._done = False

    def _priv(self, ctx: AgentContext) -> Any:
        priv = ctx.plugins["privacy"]
        priv.store.set_time(ctx.time)
        return priv

    def _finish(self, outcome: str) -> None:
        self._done = True
        self._log.outcomes[str(self._id)] = outcome

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(1.0 + ctx.rng.random() * 7.0, b"begin")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if self._done:
            return
        priv = self._priv(ctx)
        msg = payload.decode("utf-8", errors="replace")

        if payload == b"begin":
            envelope = await priv.encrypt(self._secret, [self._recipient])
            self._drop_id = priv.drop_id_for(envelope)
            await ctx.send(self._recipient, b"envelope:" + envelope)
            for spy in self._spies:
                if ctx.rng.random() < self._intercept_rate:
                    await ctx.send(spy, b"tapped:" + envelope)
            if self._action != "none":
                await ctx.schedule(2.0 + ctx.rng.random() * 4.0, b"act")
            await ctx.schedule(_POLL_EVERY, b"poll")
            return

        if payload == b"act" and self._drop_id is not None:
            if self._action == "revoke":
                priv.revoke(self._drop_id)
            elif self._action == "shorten":
                priv.set_ttl(self._drop_id, 1.0)
            return

        if msg == "ack":
            self._acked = True
            return

        if msg == "failed":
            self._recipient_failed = True
            return

        if payload == b"poll" and self._drop_id is not None:
            status = priv.status(self._drop_id)
            if status == "waiting":
                await ctx.schedule(_POLL_EVERY, b"poll")
                return
            if status == "claimed":
                if self._acked:
                    self._finish("delivered")
                    await ctx.send(_DIRECTOR, b"event:delivered")
                    return
                self._claimed_polls += 1
                if self._recipient_failed or self._claimed_polls >= _DETECT_AFTER_POLLS:
                    self._log.detected.add(self._drop_id)
                    self._finish("intercepted-detected")
                    await ctx.send(self._recipient, b"compromised")
                    await ctx.send(_DIRECTOR, b"event:interception-detected")
                    return
                await ctx.schedule(_POLL_EVERY, b"poll")
                return
            if status == "revoked":
                self._finish("revoked")
                await ctx.send(_DIRECTOR, b"event:revoked")
                return
            self._finish("expired")
            await ctx.send(_DIRECTOR, b"event:expired")


class RecipientAgent(StateMachineAgent):
    """Redeems the envelope once after a small delay; reports the outcome."""

    def __init__(self, agent_id: AgentId, courier: AgentId) -> None:
        self._id = agent_id
        self._courier = courier

    def _priv(self, ctx: AgentContext) -> Any:
        priv = ctx.plugins["privacy"]
        priv.store.set_time(ctx.time)
        return priv

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("envelope:"):
            envelope = payload[len(b"envelope:") :]
            await ctx.schedule(ctx.rng.random() * 6.0, b"redeem:" + envelope)
            return
        if msg.startswith("redeem:"):
            envelope = payload[len(b"redeem:") :]
            priv = self._priv(ctx)
            try:
                await priv.decrypt(envelope)
            except ValueError:
                await ctx.send(self._courier, b"failed")
                await ctx.send(_DIRECTOR, b"event:pickup-gone")
            else:
                await ctx.send(self._courier, b"ack")
                await ctx.send(_DIRECTOR, b"event:pickup-ok")


class SpyAgent(StateMachineAgent):
    """Races stolen envelopes; replays, guesses, and abuses management."""

    def __init__(self, agent_id: AgentId, log: RunLog) -> None:
        self._id = agent_id
        self._log = log

    def _priv(self, ctx: AgentContext) -> Any:
        priv = ctx.plugins["privacy"]
        priv.store.set_time(ctx.time)
        return priv

    async def on_start(self, ctx: AgentContext) -> None:
        await ctx.schedule(1.0 + ctx.rng.random() * 20.0, b"guess")

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        priv = self._priv(ctx)
        msg = payload.decode("utf-8", errors="replace")

        if msg.startswith("tapped:"):
            envelope = payload[len(b"tapped:") :]
            await ctx.schedule(ctx.rng.random() * 6.0, b"race:" + envelope)
            await ctx.schedule(10.0 + ctx.rng.random() * 5.0, b"mgmt:" + envelope)
            return

        if msg.startswith("race:"):
            envelope = payload[len(b"race:") :]
            try:
                await priv.decrypt(envelope)
            except ValueError:
                self._log.spy_blocked += 1
                await ctx.send(_DIRECTOR, b"event:spy-blocked")
            else:
                self._log.spy_wins += 1
                await ctx.send(_DIRECTOR, b"event:spy-win")
                await ctx.schedule(3.0, b"replay:" + envelope)
            return

        if msg.startswith("replay:"):
            envelope = payload[len(b"replay:") :]
            try:
                await priv.decrypt(envelope)
            except ValueError:
                self._log.spy_blocked += 1
                await ctx.send(_DIRECTOR, b"event:replay-blocked")
            else:
                self._log.spy_wins += 1  # would be an invariant violation
            return

        if payload == b"guess":
            try:
                await priv.decrypt(f"dd1:key-{ctx.rng.getrandbits(64):016x}".encode())
            except ValueError:
                self._log.spy_blocked += 1
            return

        if msg.startswith("mgmt:"):
            envelope = payload[len(b"mgmt:") :]
            key = envelope.decode("utf-8", errors="replace")[len("dd1:") :]
            priv.status(key)
            priv.set_ttl(key, 50.0)
            priv.revoke(key)
            await ctx.send(_DIRECTOR, b"event:mgmt-abuse-blocked")


class DirectorAgent(StateMachineAgent):
    """Tallies events; validates invariants and prints the summary at stop."""

    def __init__(self, agent_id: AgentId, log: RunLog, spy_readers: set[str]) -> None:
        self._id = agent_id
        self._log = log
        self._spy_readers = spy_readers
        self._events: dict[str, int] = {}

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        msg = payload.decode("utf-8", errors="replace")
        if msg.startswith("event:"):
            name = msg[len("event:") :]
            self._events[name] = self._events.get(name, 0) + 1

    async def on_stop(self, ctx: AgentContext) -> None:
        priv = ctx.plugins["privacy"]
        store = priv.store
        store.set_time(ctx.time)
        store.finalize()

        violations = validate_spy_courier_run(store, self._spy_readers, self._log.detected)

        statuses = store.statuses()
        print("=" * 60)
        print("spy_courier — Dead Drop run summary")
        print("=" * 60)
        print(f"  drops created ............ {len(statuses)}")
        for terminal in ("claimed", "expired", "revoked", "waiting"):
            count = sum(1 for s in statuses.values() if s == terminal)
            print(f"  {terminal:<24} {count}")
        print(f"  spy wins (detected) ...... {self._log.spy_wins}")
        print(f"  spy attempts blocked ..... {self._log.spy_blocked}")
        print(f"  mgmt abuse misses ........ {store.mgmt_misses}")
        for name in sorted(self._events):
            print(f"  event {name:<18} {self._events[name]}")
        if violations:
            print("INVARIANTS: FAILED")
            for violation in violations:
                print("  ✗ " + violation)
            print("=" * 60)
            msg = f"spy_courier invariants violated: {violations}"
            raise RuntimeError(msg)
        print("INVARIANTS: all passed (one-time read, detection, cap, terminal)")
        print("=" * 60)


def validate_spy_courier_run(
    store: Any,
    spy_readers: set[str],
    detected: set[str],
) -> list[str]:
    """Check the Dead Drop invariants over a finished run; returns violations.

    Example::

        violations = validate_spy_courier_run(store, {"spy-0"}, detected)
    """
    violations: list[str] = []

    read_ids = [rec.drop_id for rec in store.reads]
    if len(read_ids) != len(set(read_ids)):
        violations.append("a payload was read more than once")

    for rec in store.reads:
        if rec.tick >= store.max_expiry_seen.get(rec.drop_id, -1.0):
            violations.append(f"read of {rec.drop_id} at/after its max expiry")
        if rec.drop_id not in store.created_at:
            violations.append(f"read of never-issued drop {rec.drop_id}")

    for drop_id, max_expiry in store.max_expiry_seen.items():
        if max_expiry > store.created_at[drop_id] + 60.0:
            violations.append(f"{drop_id} lifetime exceeded the cap")

    for drop_id, status in store.statuses().items():
        if status not in ("claimed", "expired", "revoked"):
            violations.append(f"{drop_id} not terminal (status={status})")

    for rec in store.reads:
        if rec.reader in spy_readers and rec.drop_id not in detected:
            violations.append(f"spy read of {rec.drop_id} was NOT detected")

    return violations


def spy_courier_factory(config: ScenarioConfig, plugins: dict[str, Any]) -> dict[AgentId, Any]:
    """Build courier/recipient/spy/director agents over a shared Dead Drop.

    Example::

        agents = spy_courier_factory(config, plugins)
    """
    task_cfg = config.task.config
    n_pairs = 6
    n_spies = 3
    for role in config.agents.roles:
        if role.name == "courier":
            n_pairs = role.count
        elif role.name == "spy":
            n_spies = role.count
    intercept_rate = float(task_cfg.get("intercept_rate", 0.3))
    default_ttl = float(task_cfg.get("default_ttl", 20))

    privacy_cls = plugins.get("privacy")
    new_shared = getattr(privacy_cls, "new_shared", None)
    if not callable(new_shared):
        msg = "spy_courier requires layers.privacy: dead_drop"
        raise ValueError(msg)
    shared = new_shared(seed=config.seed, default_ttl=default_ttl)
    plugins["privacy"] = shared
    agent_plugins: dict[AgentId, dict[str, Any]] = plugins.setdefault("_agent_plugins", {})

    rng = random.Random(config.seed)
    log = RunLog()
    spies = [AgentId(f"spy-{j}") for j in range(n_spies)]
    agents: dict[AgentId, Any] = {}

    for i in range(n_pairs):
        courier_id = AgentId(f"courier-{i}")
        recipient_id = AgentId(f"recipient-{i}")
        roll = rng.random()
        if roll < 0.15:
            action = "revoke"
        elif roll < 0.30:
            action = "shorten"
        else:
            action = "none"
        secret = f"mission-{i}-intel-{rng.getrandbits(32):08x}".encode()
        agents[courier_id] = CourierAgent(
            courier_id, recipient_id, spies, secret, intercept_rate, action, log
        )
        agents[recipient_id] = RecipientAgent(recipient_id, courier_id)

    for spy_id in spies:
        agents[spy_id] = SpyAgent(spy_id, log)

    agents[_DIRECTOR] = DirectorAgent(_DIRECTOR, log, {str(s) for s in spies})

    for agent_id in agents:
        agent_plugins[agent_id] = {"privacy": shared.for_agent(agent_id)}

    return agents
```

- [ ] **Step 4: Register the factory**

In `packages/nest-core/nest_core/scenarios.py`, inside `_try_load_builtin`, add before the final `elif`/end of the chain (mirror the existing pattern exactly):

```python
    elif name == "spy_courier":
        from nest_core.scenarios_builtin.spy_courier import spy_courier_factory

        register_scenario("spy_courier", spy_courier_factory)
```

- [ ] **Step 5: Create the Tier 1 YAML**

Create `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier.yaml`:

```yaml
# SPDX-License-Identifier: Apache-2.0
# Spy-vs-courier scenario: one-time secret handoffs over the Dead Drop
# privacy layer, with wiretapping spies racing recipients to redeem.
name: spy_courier
description: "Couriers hand secrets to recipients through one-time Dead Drop envelopes while spies wiretap the channel and race to steal pickups; every theft is detected."

tier: 1
seed: 42

agents:
  count: 16
  brain: state-machine
  roles:
    - name: courier
      count: 6
    - name: recipient
      count: 6
    - name: spy
      count: 3
    - name: director
      count: 1

layers:
  transport: in_memory
  comms: nest_native
  identity: did_key
  registry: in_memory
  auth: jwt
  trust: score_average
  payments: prepaid_credits
  coordination: contract_net
  negotiation: alternating_offers
  memory: blackboard
  privacy: dead_drop
  datafacts: datafacts_v1

task:
  type: spy_courier
  config:
    intercept_rate: 0.3
    default_ttl: 20

failures:
  message_drop: 0.0

duration: "ticks: 2000"

metrics:
  - message_count
  - agent_count

output:
  trace: ./traces/spy_courier.jsonl
```

- [ ] **Step 6: Run the factory test to verify it passes**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_spy_courier_scenario.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
cd $NT
git add packages/nest-core/nest_core/scenarios_builtin/spy_courier.py \
        packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier.yaml \
        packages/nest-core/nest_core/scenarios.py \
        packages/nest-plugins-reference/tests/test_spy_courier_scenario.py
git commit -m "feat: spy_courier scenario over the dead_drop privacy layer"
```

---

### Task 3: End-to-end test — invariants + determinism

**Files:**
- Modify: `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py` (append test classes)

**Interfaces:**
- Consumes: `make_config` from Task 2's test file; `ScenarioRunner(config)` with `async run() -> Path` and `resolved_plugins: dict[str, Any]`; `validate_spy_courier_run` and `RunLog` from the scenario module; `DeadDropPrivacy.store`.
- Produces: nothing new — this is the enforcement gate for the run.

- [ ] **Step 1: Append the failing e2e tests**

Append to `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py`:

```python
class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_run_invariants_hold(self, tmp_path: Any) -> None:
        from nest_core.runner import ScenarioRunner
        from nest_core.scenarios_builtin.spy_courier import validate_spy_courier_run

        config = make_config(str(tmp_path / "trace.jsonl"))
        runner = ScenarioRunner(config)
        await runner.run()

        shared = runner.resolved_plugins["privacy"]
        store = shared.store
        statuses = store.statuses()

        assert len(statuses) == 6  # one drop per courier
        assert all(s in ("claimed", "expired", "revoked") for s in statuses.values())
        assert len(store.reads) == len({r.drop_id for r in store.reads})
        assert store.mgmt_misses > 0  # spies attempted management abuse and missed

    @pytest.mark.asyncio
    async def test_same_seed_identical_traces(self, tmp_path: Any) -> None:
        from nest_core.runner import ScenarioRunner

        path_a = tmp_path / "a.jsonl"
        path_b = tmp_path / "b.jsonl"
        await ScenarioRunner(make_config(str(path_a), seed=123)).run()
        await ScenarioRunner(make_config(str(path_b), seed=123)).run()
        assert path_a.read_bytes() == path_b.read_bytes()

    @pytest.mark.asyncio
    async def test_spy_wins_are_always_detected(self, tmp_path: Any) -> None:
        from nest_core.runner import ScenarioRunner
        from nest_core.scenarios_builtin.spy_courier import validate_spy_courier_run

        # High intercept rate to force spy wins deterministically.
        config = make_config(str(tmp_path / "trace.jsonl"), seed=7)
        config.task.config["intercept_rate"] = 1.0
        runner = ScenarioRunner(config)
        await runner.run()

        store = runner.resolved_plugins["privacy"].store
        spy_reads = [r for r in store.reads if r.reader.startswith("spy-")]
        assert spy_reads, "expected at least one spy win at intercept_rate=1.0"
```

Also add `import pytest` to the imports at the top of the file if not present.

Note: `DirectorAgent.on_stop` already ran `validate_spy_courier_run` inside the sim and raised on violation, so a completed `runner.run()` in these tests implies the invariants passed; the explicit asserts re-check the crown jewels from outside.

- [ ] **Step 2: Run the e2e tests**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_spy_courier_scenario.py -v`
Expected: PASS. If `test_spy_wins_are_always_detected` finds zero spy reads, increase courier count in the config to 8 via roles and rerun — do not weaken the assert. If `on_stop` exceptions are swallowed by the simulator (run completes despite violations printed), keep the outside asserts as the gate — they cover the same invariants.

- [ ] **Step 3: Commit**

```bash
cd $NT
git add packages/nest-plugins-reference/tests/test_spy_courier_scenario.py
git commit -m "test: spy_courier e2e invariants and determinism"
```

---

### Task 4: CLI verification — `nest run spy_courier`

**Files:**
- No new files; runtime verification of Tasks 1–3.

**Interfaces:**
- Consumes: the `nest` CLI (`uv run nest ...`) and the bundled YAML from Task 2.

- [ ] **Step 1: Run the scenario via the CLI**

Run: `cd $NT && uv run nest run spy_courier`
Expected: "Running scenario: spy_courier", the director's summary block printing drops created / claimed / expired / revoked, spy wins (detected) and blocked counts, and `INVARIANTS: all passed`. Trace written to `traces/spy_courier.jsonl`.

- [ ] **Step 2: Verify determinism at the CLI level**

```bash
cd $NT
uv run nest run spy_courier -o ./traces/dd_run1.jsonl
uv run nest run spy_courier -o ./traces/dd_run2.jsonl
diff ./traces/dd_run1.jsonl ./traces/dd_run2.jsonl && echo IDENTICAL
```

Expected: `IDENTICAL`. (If `-o` is not a valid flag, check `uv run nest run --help` and use the documented output flag; the YAML's `output.trace` path is the fallback — copy the file between runs.)

- [ ] **Step 3: Inspect the trace**

Run: `cd $NT && uv run nest inspect traces/spy_courier.jsonl`
Expected: event breakdown listing sends/receives including the `event:*` director messages; agents `courier-*`, `recipient-*`, `spy-*` present.

- [ ] **Step 4: Commit any fixes made during verification**

```bash
cd $NT
git status --short   # commit only if verification forced changes
```

---

### Task 5: Tier 2 — mock-LLM couriers

**Files:**
- Modify: `packages/nest-core/nest_core/scenarios_builtin/spy_courier.py` (append shell factory + LLM courier)
- Modify: `packages/nest-core/nest_core/runner.py` (register the shell factory)
- Create: `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier_llm.yaml`
- Test: append to `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py`

**Interfaces:**
- Consumes: `nest_shell.llm.MockLLMBackend` / `LLMBackend` protocol — `async complete(messages: list[dict[str, str]]) -> str`; everything from Tasks 1–2.
- Produces: `shell_spy_courier_factory(config, plugins, backend=None) -> dict[AgentId, Any]`; `LLMCourierAgent(CourierAgent)`.

**Design note (approved fallback applies):** the LLM decides *parameters* (TTL length, whether to revoke early) parsed from its reply with safe defaults on parse failure; the DD mechanics stay in code. With `MockLLMBackend` the canned reply fails parsing and defaults apply — the run demonstrates the full shell-agent plumbing at zero cost, and setting `ANTHROPIC_API_KEY` + `llm_provider: anthropic` upgrades the same YAML to real decisions. Prompts are inline strings (`_COURIER_PROMPT`), not template files — approved YAGNI deviation from the spec's templates line. If `nest_shell` integration fights back for more than ~30 minutes, stop, keep Tier 1 as the deliverable, and record the exact blocker in the plan file instead. If pydantic forbids `config.agents.brain = "shell"` assignment in the test (frozen model), use `config.model_copy(update=...)` on the nested models instead.

- [ ] **Step 1: Write the failing test**

Append to `packages/nest-plugins-reference/tests/test_spy_courier_scenario.py`:

```python
class TestShellTier:
    @pytest.mark.asyncio
    async def test_mock_llm_run_completes_with_invariants(self, tmp_path: Any) -> None:
        from nest_core.runner import ScenarioRunner

        config = make_config(str(tmp_path / "llm.jsonl"))
        config.agents.brain = "shell"
        config.agents.llm_provider = "mock"
        runner = ScenarioRunner(config)
        await runner.run()

        store = runner.resolved_plugins["privacy"].store
        statuses = store.statuses()
        assert len(statuses) == 6
        assert all(s in ("claimed", "expired", "revoked") for s in statuses.values())
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_spy_courier_scenario.py::TestShellTier -q`
Expected: FAIL with `KeyError: "No shell factory for task type 'spy_courier'"`

- [ ] **Step 3: Append the LLM courier + shell factory to the scenario module**

Append to `packages/nest-core/nest_core/scenarios_builtin/spy_courier.py`:

```python
_COURIER_PROMPT = (
    "You are a courier agent in a simulation. You hand off a secret through "
    "Dead Drop: encrypting yields a one-time envelope; the first reader gets "
    "the secret and destroys it; a 'claimed' status with no ack from your "
    "recipient means it was intercepted. Reply with exactly two words: an "
    "integer TTL in ticks between 5 and 40, then 'hold' or 'revoke'."
)


class LLMCourierAgent(CourierAgent):
    """Courier whose TTL and revoke decisions come from an LLM backend."""

    def __init__(
        self,
        agent_id: AgentId,
        recipient: AgentId,
        spies: list[AgentId],
        secret: bytes,
        intercept_rate: float,
        log: RunLog,
        backend: Any,
    ) -> None:
        super().__init__(agent_id, recipient, spies, secret, intercept_rate, "none", log)
        self._backend = backend

    async def on_message(self, ctx: AgentContext, sender: AgentId, payload: bytes) -> None:
        if payload == b"begin" and not self._done:
            reply = await self._backend.complete(
                [
                    {"role": "system", "content": _COURIER_PROMPT},
                    {"role": "user", "content": f"You are {self._id}. Decide."},
                ]
            )
            ttl, action = _parse_courier_decision(reply)
            priv = self._priv(ctx)
            priv.set_default_ttl(ttl)
            self._action = action
        await super().on_message(ctx, sender, payload)


def _parse_courier_decision(reply: str) -> tuple[float, str]:
    """Parse "TTL hold|revoke" with safe defaults on any failure.

    Example::

        assert _parse_courier_decision("25 revoke") == (25.0, "revoke")
    """
    ttl = 20.0
    action = "none"
    parts = reply.strip().lower().split()
    if parts:
        try:
            ttl = float(min(max(int(parts[0]), 5), 40))
        except ValueError:
            ttl = 20.0
    if len(parts) > 1 and parts[1] == "revoke":
        action = "revoke"
    return ttl, action


def shell_spy_courier_factory(
    config: ScenarioConfig,
    plugins: dict[str, Any],
    backend: Any = None,
) -> dict[AgentId, Any]:
    """Tier 2 factory: LLM-parameterized couriers, scripted everyone else.

    Example::

        agents = shell_spy_courier_factory(config, plugins, backend=MockLLMBackend())
    """
    if backend is None:
        from nest_shell.llm import MockLLMBackend

        backend = MockLLMBackend()

    agents = spy_courier_factory(config, plugins)
    shared = plugins["privacy"]
    log: RunLog | None = None
    for agent in agents.values():
        if isinstance(agent, CourierAgent):
            log = agent._log
            break
    if log is None:
        return agents

    replacements: dict[AgentId, Any] = {}
    for agent_id, agent in agents.items():
        if isinstance(agent, CourierAgent) and not isinstance(agent, LLMCourierAgent):
            replacements[agent_id] = LLMCourierAgent(
                agent_id,
                agent._recipient,
                agent._spies,
                agent._secret,
                agent._intercept_rate,
                log,
                backend,
            )
    agents.update(replacements)
    return agents
```

- [ ] **Step 4: Register the shell factory in the runner**

In `packages/nest-core/nest_core/runner.py`, in `_create_shell_agents`, immediately after the `factories = { ... }` dict literal closes, add:

```python
        from nest_core.scenarios_builtin.spy_courier import shell_spy_courier_factory

        factories["spy_courier"] = shell_spy_courier_factory
```

- [ ] **Step 5: Create the Tier 2 YAML**

Create `packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier_llm.yaml` — identical to `spy_courier.yaml` except these lines:

```yaml
name: spy_courier_llm
description: "spy_courier with LLM-parameterized couriers (free mock backend by default; set llm_provider: anthropic and ANTHROPIC_API_KEY for real model decisions)."
```

and in `agents:`:

```yaml
  brain: shell
  llm_provider: mock
```

and in `output:`:

```yaml
  trace: ./traces/spy_courier_llm.jsonl
```

- [ ] **Step 6: Run the shell-tier test**

Run: `cd $NT && uv run pytest packages/nest-plugins-reference/tests/test_spy_courier_scenario.py -v`
Expected: all PASS (including the earlier classes — no regressions)

- [ ] **Step 7: CLI-run Tier 2**

Run: `cd $NT && uv run nest run spy_courier_llm`
Expected: completes with the director summary and `INVARIANTS: all passed`; zero network calls (mock backend).

- [ ] **Step 8: Commit**

```bash
cd $NT
git add packages/nest-core/nest_core/scenarios_builtin/spy_courier.py \
        packages/nest-core/nest_core/scenarios_builtin/yaml/spy_courier_llm.yaml \
        packages/nest-core/nest_core/runner.py \
        packages/nest-plugins-reference/tests/test_spy_courier_scenario.py
git commit -m "feat: Tier 2 spy_courier with mock-LLM couriers"
```

---

### Task 6: Full CI gate + demo runbook

**Files:**
- No new source files. Fix anything CI flags.

- [ ] **Step 1: Run the full CI gate**

Run: `cd $NT && make ci-local`
Expected: all 5 checks pass (uv sync, ruff check, ruff format --check, pyright, pytest). Fix any findings (formatting via `uv run ruff format .`; pyright strict issues usually mean a missing annotation on an empty container or an untyped `Any` member — annotate explicitly).

- [ ] **Step 2: Commit fixes if any**

```bash
cd $NT
git status --short
git add -A && git commit -m "chore: ci-local fixes for spy_courier" || echo "nothing to fix"
```

- [ ] **Step 3: Final demo run for the user**

```bash
cd $NT
uv run nest run spy_courier
uv run nest inspect traces/spy_courier.jsonl
uv run nest run spy_courier_llm
echo "Dashboard (browser): uv run nest dashboard traces/spy_courier.jsonl"
```

Expected: both runs print the director summary with `INVARIANTS: all passed`; inspect shows the agent roster and event mix. Report these outputs back to the user verbatim.
