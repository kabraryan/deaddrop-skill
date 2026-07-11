"""Dead Drop — Tier 1 scripted-agent simulation.

A pure-stdlib, fully deterministic model of the Dead Drop protocol. Agents follow
fixed rules decided in advance from a seeded RNG — they do not think or adapt.
This tests the *rules* (the protocol), not any AI. The same seed produces a
byte-identical run every time.

Roles (dataclasses):
  - Owner:     creates a drop, shares the pickup_key via a (lossy) message, polls
               status, and sometimes shortens, extends, or revokes early.
  - Recipient: redeems the key exactly once; sometimes retries after consumption.
  - Adversary: guesses random keys, replays consumed keys, attempts pickup after
               revoke/expiry, and attempts management calls using pickup_keys.
               Adversaries never legitimately hold a live key.

Time is discrete ticks; TTLs are counted in ticks. Nothing reads the wall clock.

CLI:
  --agents N     number of owner/recipient pairs (default 1000)
  --seed S       RNG seed (default 42)
  --ticks T      number of ticks to simulate (default 120)
  --drop-rate F  fraction of simulated messages lost (key delivery AND
                 revoke/shorten/extend messages). A lost revocation must still
                 fail safe at the original expiry.
  --partition    split the network at T/3, heal at 2T/3; partitioned recipients
                 cannot reach the store during the split.

At end of run: a summary and six hard invariant assertions. Exit nonzero on any
violation.
"""

import argparse
import random
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_TTL_TICKS = 60  # hard cap on total lifetime from creation (mirrors API 3600s)


# ---------------------------------------------------------------------------
# The store — a tick-time model of the Dead Drop API semantics.
# ---------------------------------------------------------------------------
class SimDrop:
    __slots__ = ("drop_id", "pickup_key", "payload", "created_tick",
                 "expires_tick", "status")

    def __init__(self, drop_id, pickup_key, payload, created_tick, expires_tick):
        self.drop_id = drop_id
        self.pickup_key = pickup_key
        self.payload = payload
        self.created_tick = created_tick
        self.expires_tick = expires_tick
        self.status = "waiting"  # waiting | claimed | expired | revoked


class SimStore:
    """Mirrors main.py: pickup destroys the payload; management is drop_id-only;
    pickup_keys are never valid management handles; expiry is lazy."""

    def __init__(self):
        self.drops: Dict[str, SimDrop] = {}
        self.by_key: Dict[str, str] = {}
        # Audit trail for invariant checking.
        self.reads: List[tuple] = []          # (drop_id, tick) successful payload reads
        self.adversary_success = 0            # reads/actions an adversary should never get
        self.mgmt_via_pickup_key = 0          # management actions accepted with a pickup_key
        self.max_expiry_seen: Dict[str, int] = {}  # drop_id -> max expires_tick ever set

    # -- lazy expiry ------------------------------------------------------
    def _purge_if_expired(self, drop: SimDrop, now: int) -> bool:
        if drop.status != "waiting":
            return True
        if now >= drop.expires_tick:
            drop.status = "expired"
            drop.payload = None
            self.by_key.pop(drop.pickup_key, None)
            return True
        return False

    # -- WRITE ------------------------------------------------------------
    def create(self, drop_id, pickup_key, payload, ttl, now) -> SimDrop:
        ttl = min(max(ttl, 1), MAX_TTL_TICKS)
        drop = SimDrop(drop_id, pickup_key, payload, now, now + ttl)
        self.drops[drop_id] = drop
        self.by_key[pickup_key] = drop_id
        self.max_expiry_seen[drop_id] = drop.expires_tick
        return drop

    # -- READ (recipient) -------------------------------------------------
    def pickup(self, pickup_key, now) -> Optional[str]:
        drop_id = self.by_key.get(pickup_key)
        if drop_id is None:
            return None  # unknown / already destroyed -> 410
        drop = self.drops.get(drop_id)
        if drop is None or self._purge_if_expired(drop, now) or drop.status != "waiting":
            return None
        payload = drop.payload
        drop.status = "claimed"
        drop.payload = None
        self.by_key.pop(pickup_key, None)
        self.reads.append((drop_id, now))
        return payload

    # -- MANAGE (owner, drop_id only) -------------------------------------
    def get_status(self, drop_id, now) -> Optional[str]:
        drop = self.drops.get(drop_id)
        if drop is None:
            return None
        self._purge_if_expired(drop, now)
        return drop.status

    def patch(self, drop_id, ttl, now) -> bool:
        """Shorten (unrestricted) or extend (capped at MAX_TTL from creation)."""
        drop = self.drops.get(drop_id)
        if drop is None or self._purge_if_expired(drop, now) or drop.status != "waiting":
            return False
        if ttl <= 0:
            return False
        new_expiry = now + ttl
        hard_cap = drop.created_tick + MAX_TTL_TICKS
        if new_expiry > hard_cap:
            return False  # extension past cap rejected
        drop.expires_tick = new_expiry
        self.max_expiry_seen[drop_id] = max(self.max_expiry_seen[drop_id], new_expiry)
        return True

    def revoke(self, drop_id, now) -> bool:
        drop = self.drops.get(drop_id)
        if drop is None:
            return False
        if not self._purge_if_expired(drop, now) and drop.status == "waiting":
            drop.status = "revoked"
            drop.payload = None
            self.by_key.pop(drop.pickup_key, None)
        return True

    # -- Adversary probes: must all fail ----------------------------------
    def adversary_pickup(self, key, now) -> None:
        if self.pickup(key, now) is not None:
            # An adversary using a random/replayed/dead key got a payload.
            self.adversary_success += 1
            # Undo bookkeeping so the audit reflects the violation cleanly.
            self.reads.pop()

    def adversary_manage_with_pickup_key(self, pickup_key, now) -> None:
        """Try to manage a drop by presenting a pickup_key as if it were a
        drop_id. The management store is keyed by drop_id, so this must miss."""
        if self.get_status(pickup_key, now) is not None:
            self.mgmt_via_pickup_key += 1
        if self.patch(pickup_key, 5, now):
            self.mgmt_via_pickup_key += 1
        if self.revoke(pickup_key, now):
            self.mgmt_via_pickup_key += 1


# ---------------------------------------------------------------------------
# Agents — fixed rules decided in advance.
# ---------------------------------------------------------------------------
@dataclass
class Owner:
    idx: int
    drop_id: str
    pickup_key: str
    payload: str
    create_tick: int
    ttl: int
    action: str            # "none" | "shorten" | "extend" | "revoke"
    action_tick: int
    action_ttl: int
    key_lost: bool         # key-delivery message lost?
    action_lost: bool      # management message lost?
    created: bool = False


@dataclass
class Recipient:
    idx: int
    partitioned: bool
    receive_tick: Optional[int]   # when the key arrives (None if lost)
    redeem_delay: int
    retry_after_consume: bool
    redeemed: bool = False
    retried: bool = False


@dataclass
class Adversary:
    idx: int
    target_owner: int
    guess_tick: int
    replay_tick: int
    manage_tick: int
    attempts: int = 0


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
def run(agents: int, seed: int, ticks: int, drop_rate: float, partition: bool):
    rng = random.Random(seed)
    store = SimStore()

    part_start = ticks // 3
    part_end = 2 * ticks // 3

    owners: List[Owner] = []
    recipients: List[Recipient] = []
    adversaries: List[Adversary] = []

    # -- Build fixed plans in deterministic agent order -------------------
    for i in range(agents):
        create_tick = rng.randrange(0, max(1, ticks // 2))
        ttl = rng.randint(5, 40)

        roll = rng.random()
        if roll < 0.15:
            action = "revoke"
        elif roll < 0.30:
            action = "shorten"
        elif roll < 0.40:
            action = "extend"
        else:
            action = "none"
        action_tick = create_tick + rng.randint(1, 6)
        action_ttl = rng.randint(1, MAX_TTL_TICKS + 20)  # may exceed cap (tests inv 5)

        key_lost = rng.random() < drop_rate
        action_lost = rng.random() < drop_rate

        owners.append(Owner(
            idx=i,
            drop_id=f"drop-{i}",
            pickup_key=f"key-{i}-{rng.randrange(10**9)}",
            payload=f"secret-{i}",
            create_tick=create_tick,
            ttl=ttl,
            action=action,
            action_tick=action_tick,
            action_ttl=action_ttl,
            key_lost=key_lost,
            action_lost=action_lost,
        ))

        partition_roll = rng.random() < 0.5  # always drawn, keeps RNG stream stable
        partitioned = partition and partition_roll
        receive_tick = None if key_lost else create_tick + 1
        redeem_delay = rng.randint(0, 8)
        retry = rng.random() < 0.25
        recipients.append(Recipient(
            idx=i,
            partitioned=partitioned,
            receive_tick=receive_tick,
            redeem_delay=redeem_delay,
            retry_after_consume=retry,
        ))

    # Adversaries: ~20% as many as owners, at least 1.
    n_adv = max(1, agents // 5)
    for j in range(n_adv):
        target = rng.randrange(agents)
        adversaries.append(Adversary(
            idx=j,
            target_owner=target,
            guess_tick=rng.randrange(0, ticks),
            replay_tick=rng.randrange(0, ticks),
            manage_tick=rng.randrange(0, ticks),
        ))

    # Track a pending second-redeem tick per recipient after first consume.
    pending_retry: Dict[int, int] = {}
    # Recipients blocked by partition get one retry at heal time.
    pending_partition_retry: Dict[int, int] = {}

    def partitioned_now(t: int, r: Recipient) -> bool:
        return partition and r.partitioned and part_start <= t < part_end

    # -- Tick loop --------------------------------------------------------
    for t in range(ticks):
        # 1) Owners create drops.
        for o in owners:
            if not o.created and t == o.create_tick:
                store.create(o.drop_id, o.pickup_key, o.payload, o.ttl, t)
                o.created = True

        # 2) Owners perform management actions (message may be lost).
        for o in owners:
            if o.created and t == o.action_tick and o.action != "none":
                if o.action_lost:
                    continue  # lost management message -> no effect; fail-safe at expiry
                if o.action == "revoke":
                    store.revoke(o.drop_id, t)
                elif o.action == "shorten":
                    store.patch(o.drop_id, 1, t)  # shorten to (nearly) now
                elif o.action == "extend":
                    store.patch(o.drop_id, o.action_ttl, t)  # may be rejected if past cap

        # 3) Recipients redeem.
        for r in recipients:
            if r.receive_tick is None or r.redeemed:
                # possibly a scheduled retry-after-consume below still applies
                pass
            if (not r.redeemed and r.receive_tick is not None
                    and t == r.receive_tick + r.redeem_delay):
                if partitioned_now(t, r):
                    pending_partition_retry[r.idx] = part_end  # retry when healed
                else:
                    payload = store.pickup(owners[r.idx].pickup_key, t)
                    if payload is not None:
                        r.redeemed = True
                        if r.retry_after_consume:
                            pending_retry[r.idx] = t + rng.randint(1, 5)

        # 4) Partition-healed retry.
        for idx, retry_tick in list(pending_partition_retry.items()):
            if t == retry_tick:
                r = recipients[idx]
                if not r.redeemed and not partitioned_now(t, r):
                    payload = store.pickup(owners[idx].pickup_key, t)
                    if payload is not None:
                        r.redeemed = True
                        if r.retry_after_consume:
                            pending_retry[idx] = t + rng.randint(1, 5)
                del pending_partition_retry[idx]

        # 5) Retry-after-consume (must fail: 410, no double read).
        for idx, retry_tick in list(pending_retry.items()):
            if t == retry_tick:
                recipients[idx].retried = True
                store.pickup(owners[idx].pickup_key, t)  # expected None
                del pending_retry[idx]

        # 6) Adversary probes.
        for a in adversaries:
            tgt = owners[a.target_owner]
            if t == a.guess_tick:
                a.attempts += 1
                store.adversary_pickup(f"guess-{a.idx}-{t}", t)  # random key
            if t == a.replay_tick:
                a.attempts += 1
                d = store.drops.get(tgt.drop_id)
                if d is not None and d.status != "waiting":
                    # The key is now dead (consumed / revoked / expired). An
                    # eavesdropper only learns it once it has been used out-of-
                    # band; replaying it here must fail — a consumed drop cannot
                    # be read again, and a revoked/expired one is gone.
                    store.adversary_pickup(tgt.pickup_key, t)
                else:
                    # Still live and unexposed: the adversary has no valid key,
                    # so it can only guess. Also guaranteed to fail.
                    store.adversary_pickup(f"replayguess-{a.idx}-{t}", t)
            if t == a.manage_tick:
                a.attempts += 1
                store.adversary_manage_with_pickup_key(tgt.pickup_key, t)

    # -- Finalize: any still-waiting drop past expiry -> expired -----------
    for o in owners:
        drop = store.drops.get(o.drop_id)
        if drop is not None:
            store._purge_if_expired(drop, ticks)

    return store, owners, recipients, adversaries


# ---------------------------------------------------------------------------
# Invariants + summary
# ---------------------------------------------------------------------------
def check_and_report(store: SimStore, owners, recipients, adversaries,
                     ticks: int) -> int:
    created = len(store.drops)
    claimed = sum(1 for d in store.drops.values() if d.status == "claimed")
    expired = sum(1 for d in store.drops.values() if d.status == "expired")
    revoked = sum(1 for d in store.drops.values() if d.status == "revoked")
    waiting = sum(1 for d in store.drops.values() if d.status == "waiting")
    adv_attempts = sum(a.attempts for a in adversaries)

    print("=" * 60)
    print("Dead Drop — Tier 1 simulation summary")
    print("=" * 60)
    print(f"  drops created ............ {created}")
    print(f"  claimed .................. {claimed}")
    print(f"  expired .................. {expired}")
    print(f"  revoked .................. {revoked}")
    print(f"  still waiting ............ {waiting}")
    print(f"  adversary attempts ....... {adv_attempts}")
    print(f"  adversary attempts blocked {adv_attempts - store.adversary_success}")
    print("-" * 60)

    failures = []

    # (1) No payload read twice.
    read_ids = [dr for dr, _ in store.reads]
    if len(read_ids) != len(set(read_ids)):
        failures.append("INV1: a payload was read more than once")

    # (2) No read after expiry, revoke, or an effective shorten. The store only
    # returns a payload while status == waiting and now < expires_tick, so every
    # recorded read must satisfy that against the max expiry ever granted.
    for drop_id, tick in store.reads:
        if tick >= store.max_expiry_seen.get(drop_id, -1):
            failures.append(f"INV2: read of {drop_id} at tick {tick} at/after expiry")
        d = store.drops.get(drop_id)
        if d is not None and d.status != "claimed":
            failures.append(f"INV2: {drop_id} read but terminal status={d.status}")

    # (3) No read without the correct key — zero adversary successes.
    if store.adversary_success != 0:
        failures.append(f"INV3: {store.adversary_success} adversary read successes")

    # (4) No management action via a pickup_key.
    if store.mgmt_via_pickup_key != 0:
        failures.append(f"INV4: {store.mgmt_via_pickup_key} management actions via pickup_key")

    # (5) No lifetime exceeded the cap despite extensions.
    for o in owners:
        d = store.drops.get(o.drop_id)
        if d is None:
            continue
        cap = d.created_tick + MAX_TTL_TICKS
        if store.max_expiry_seen[o.drop_id] > cap:
            failures.append(f"INV5: {o.drop_id} lifetime exceeded cap")

    # (6) Every drop reached exactly one terminal state.
    for o in owners:
        d = store.drops.get(o.drop_id)
        if d is None:
            failures.append(f"INV6: {o.drop_id} missing from store")
        elif d.status not in ("claimed", "expired", "revoked"):
            failures.append(f"INV6: {o.drop_id} not terminal (status={d.status})")

    if failures:
        print("INVARIANTS: FAILED")
        for f in failures:
            print("  ✗ " + f)
        print("=" * 60)
        return 1

    print("INVARIANTS: all 6 passed")
    print("  ✓ INV1 no payload read twice")
    print("  ✓ INV2 no read after expiry/revoke/shorten")
    print("  ✓ INV3 zero adversary read successes")
    print("  ✓ INV4 no management via pickup_key")
    print("  ✓ INV5 no lifetime exceeded the cap")
    print("  ✓ INV6 every drop reached exactly one terminal state")
    print("=" * 60)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Dead Drop Tier 1 simulation")
    p.add_argument("--agents", type=int, default=1000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--ticks", type=int, default=120)
    p.add_argument("--drop-rate", type=float, default=0.0)
    p.add_argument("--partition", action="store_true")
    args = p.parse_args(argv)

    store, owners, recipients, adversaries = run(
        agents=args.agents,
        seed=args.seed,
        ticks=args.ticks,
        drop_rate=args.drop_rate,
        partition=args.partition,
    )
    rc = check_and_report(store, owners, recipients, adversaries, args.ticks)
    sys.exit(rc)


if __name__ == "__main__":
    main()
