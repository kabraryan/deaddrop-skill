"""Dead Drop (DD) — temporary, one-time-read, self-destructing secret transfer.

Core design: DD never delivers the pickup key. The sender shares the pickup_key
out-of-band over whatever channel the agents already use; DD only ever holds the
payload (released once, then destroyed). No single party — including DD itself —
ever holds both the key and the payload.

Two identifiers by design:
  - pickup_key: bearer credential, shared out-of-band, redeems the payload once.
  - drop_id:    the sender's private management handle. Management endpoints NEVER
                accept a pickup_key, so a recipient/interceptor cannot extend or
                inspect their own access.

In-memory only. A restart is a total burn — destruction, never leakage. This is
protocol-coherent, not a durability bug.
"""

import os
import secrets
import threading
import time
from typing import Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, Field

DEFAULT_TTL = 600
MAX_TTL = 3600  # hard cap on total lifetime from creation
MAX_DROPS = 2000  # cap on concurrently-stored drops; with the payload cap this bounds worst-case memory well under the free-tier limit

app = FastAPI(
    title="Dead Drop",
    description=(
        "Temporary, one-time-read, self-destructing secret transfer between agents. "
        "One reader, one read, then the secret ceases to exist."
    ),
    version="1.0.0",
    # Public API docs are disabled: the auto-generated schema enumerates the
    # operator-only /admin/* endpoints (and the X-Admin-Token header name),
    # which are intentionally not part of the agent-facing surface. Agents use
    # the curl calls documented in SKILL.md; they never need interactive docs.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_START_TIME = time.time()


class Drop:
    """A single one-time secret. Lives in memory only.

    Once a drop reaches a terminal state (claimed | expired | revoked) the
    payload is destroyed (set to None) and the pickup_key is de-indexed so it can
    never be read again. A tiny status tombstone (drop_id -> status) is retained
    so the owner can still observe the terminal state — this is what makes
    interception *detectable* ("claimed" before the recipient arrived). The
    secret itself is gone; only the fact of its fate remains.
    """

    __slots__ = ("drop_id", "pickup_key", "recipient", "payload",
                 "created_at", "expires_at", "status")

    def __init__(self, drop_id: str, pickup_key: str, recipient: str,
                 payload: str, created_at: float, expires_at: float):
        self.drop_id = drop_id
        self.pickup_key = pickup_key
        self.recipient = recipient
        self.payload = payload
        self.created_at = created_at
        self.expires_at = expires_at
        self.status = "waiting"  # waiting | claimed | expired | revoked


# Primary store keyed by drop_id (owner's private handle).
_drops: Dict[str, Drop] = {}
# Index from pickup_key -> drop_id for O(1) recipient lookup.
_key_index: Dict[str, str] = {}
# Graceful-shutdown flag: when draining, reject new drops but honor existing.
_draining = False

# The route handlers are declared `def` (sync), so Starlette runs them in a
# threadpool — real thread concurrency over the shared dicts above. Pickup is a
# check-then-act (read status, then flip to "claimed"); without mutual exclusion
# two concurrent redemptions of the same key could BOTH observe "waiting" and
# both receive the payload, breaking the one-time-read guarantee. This lock
# serializes every state transition. Helpers below assume the caller holds it.
_lock = threading.Lock()


def _now() -> float:
    return time.time()


def _destroy_payload(drop: Drop) -> None:
    """Destroy the secret. The payload ceases to exist and the pickup_key is
    de-indexed so it can never be read again. The status tombstone (keyed by the
    owner's private drop_id) is retained for detection."""
    drop.payload = None
    _key_index.pop(drop.pickup_key, None)


def _purge_if_expired(drop: Drop) -> bool:
    """Lazy expiry check. Marks an expired waiting drop and destroys its payload.

    Returns True if the drop is (now) in a terminal state, False if still live.
    """
    if drop.status != "waiting":
        return True
    if _now() >= drop.expires_at:
        drop.status = "expired"
        _destroy_payload(drop)
        return True
    return False


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class DropRequest(BaseModel):
    # Length caps bound per-request memory on a public, unauthenticated endpoint.
    # 16 KiB is far larger than any realistic secret (tokens, keys, certs are <4 KiB) while blocking memory-exhaustion payloads.
    recipient: str = Field(max_length=256)
    payload: str = Field(max_length=16384)
    ttl: int = Field(default=DEFAULT_TTL)


class PatchRequest(BaseModel):
    ttl: int


# ---------------------------------------------------------------------------
# WRITE — sender creates the one-time message
# ---------------------------------------------------------------------------
@app.post("/drop")
def create_drop(req: DropRequest):
    if _draining:
        raise HTTPException(status_code=503, detail="draining: not accepting new drops")

    # Reject new drops when the store is full so a flood of POSTs cannot exhaust
    # memory on the free tier. The len() read is intentionally outside the lock:
    # this is a coarse safety bound, not an invariant. The service runs a single
    # uvicorn worker whose sync routes share one ~40-thread limiter, so the worst
    # case is a small bounded overshoot (~tens of drops), which is harmless.
    if len(_drops) >= MAX_DROPS:
        raise HTTPException(status_code=503, detail="at capacity: try again later")

    ttl = req.ttl if req.ttl and req.ttl > 0 else DEFAULT_TTL
    ttl = min(ttl, MAX_TTL)

    drop_id = secrets.token_urlsafe(16)
    pickup_key = secrets.token_urlsafe(24)
    created_at = _now()
    expires_at = created_at + ttl

    drop = Drop(drop_id, pickup_key, req.recipient, req.payload, created_at, expires_at)
    with _lock:
        _drops[drop_id] = drop
        _key_index[pickup_key] = drop_id

    return {
        "drop_id": drop_id,
        "pickup_key": pickup_key,
        "expires_at": expires_at,
    }


# ---------------------------------------------------------------------------
# READ — recipient accepts, once
# ---------------------------------------------------------------------------
@app.get("/pickup/{pickup_key}")
def pickup(pickup_key: str):
    """Return the payload exactly once, then destroy it.

    Returns 410 for consumed, expired, revoked, AND unknown keys alike — never a
    404 distinction, so adversaries cannot probe which keys are valid. The
    interception signal belongs to the owner via GET /drop/{drop_id}.
    """
    with _lock:
        drop_id = _key_index.get(pickup_key)
        if drop_id is None:
            # Unknown / already-destroyed key. Indistinguishable to caller.
            raise HTTPException(status_code=410, detail="gone")

        drop = _drops.get(drop_id)
        if drop is None:
            raise HTTPException(status_code=410, detail="gone")

        if _purge_if_expired(drop):
            raise HTTPException(status_code=410, detail="gone")

        if drop.status != "waiting":
            raise HTTPException(status_code=410, detail="gone")

        # Success: capture payload, mark claimed, destroy the secret immediately.
        # Holding the lock across check-and-flip is what makes this exactly-once.
        payload = drop.payload
        drop.status = "claimed"
        _destroy_payload(drop)
    return {"payload": payload}


# ---------------------------------------------------------------------------
# MANAGE ACCESS TIME — sender controls the window (drop_id only, never pickup_key)
# ---------------------------------------------------------------------------
@app.get("/drop/{drop_id}")
def status(drop_id: str):
    with _lock:
        drop = _drops.get(drop_id)
        if drop is None:
            raise HTTPException(status_code=404, detail="unknown drop_id")

        _purge_if_expired(drop)
        return {"status": drop.status, "expires_at": drop.expires_at}


@app.patch("/drop/{drop_id}")
def patch_drop(drop_id: str, req: PatchRequest):
    with _lock:
        drop = _drops.get(drop_id)
        if drop is None:
            raise HTTPException(status_code=404, detail="unknown drop_id")

        if _purge_if_expired(drop):
            raise HTTPException(status_code=410, detail="gone")
        if drop.status != "waiting":
            raise HTTPException(status_code=410, detail="gone")

        if req.ttl is None or req.ttl <= 0:
            raise HTTPException(status_code=400, detail="ttl must be a positive integer")

        new_expiry = _now() + req.ttl
        hard_cap = drop.created_at + MAX_TTL
        # Shortening is unrestricted; extension is capped at MAX_TTL from creation.
        if new_expiry > hard_cap:
            raise HTTPException(
                status_code=400,
                detail=f"extension exceeds hard cap of {MAX_TTL}s from creation",
            )

        drop.expires_at = new_expiry
        return {"status": drop.status, "expires_at": drop.expires_at}


@app.delete("/drop/{drop_id}")
def revoke_drop(drop_id: str):
    with _lock:
        drop = _drops.get(drop_id)
        if drop is None:
            raise HTTPException(status_code=404, detail="unknown drop_id")

        if not _purge_if_expired(drop) and drop.status == "waiting":
            drop.status = "revoked"
            _destroy_payload(drop)
        return {"status": drop.status}


# ---------------------------------------------------------------------------
# OPERATIONS
# ---------------------------------------------------------------------------
def _count_waiting() -> int:
    """Count genuinely-live waiting drops, lazily purging expired ones as we scan."""
    with _lock:
        waiting = 0
        for drop in list(_drops.values()):
            if not _purge_if_expired(drop) and drop.status == "waiting":
                waiting += 1
        return waiting


@app.get("/health")
def health():
    return {
        "status": "ok",
        "drops_waiting": _count_waiting(),
        "uptime_s": round(_now() - _START_TIME, 3),
    }


def _require_admin(token: Optional[str]) -> None:
    expected = os.environ.get("DD_ADMIN_TOKEN")
    # Fail closed when unset, and use a constant-time compare so the token can't
    # be recovered byte-by-byte via response-timing on these public endpoints.
    if not expected or token is None or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="forbidden")


@app.post("/admin/drain")
def drain(x_admin_token: Optional[str] = Header(default=None)):
    _require_admin(x_admin_token)
    global _draining
    _draining = True
    return {"status": "draining", "drops_waiting": _count_waiting()}


@app.post("/admin/burn")
def burn(x_admin_token: Optional[str] = Header(default=None)):
    _require_admin(x_admin_token)
    with _lock:
        burned = sum(
            1
            for drop in _drops.values()
            if not _purge_if_expired(drop) and drop.status == "waiting"
        )
        _drops.clear()
        _key_index.clear()
    return {"status": "burned", "destroyed": burned}
