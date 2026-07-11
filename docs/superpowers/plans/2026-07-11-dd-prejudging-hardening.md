# Dead Drop Pre-Judging Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the three freeze-safe fixes the go/no-go council flagged — close the public OpenAPI/docs admin-endpoint leak, cap request/store size against a memory-exhaustion DoS, and add a laptop-independent keep-warm cron — without touching the already-hardened lock/compare logic.

**Architecture:** Small, surgical edits to the single-file FastAPI service `main.py` plus one new GitHub Actions workflow. Each task is independently testable with `TestClient` (matching the existing `test_concurrency.py`) and independently deployable; none alters the concurrency lock, the token compare, or any documented response shape a judge's stock agent depends on.

**Tech Stack:** Python 3.13, FastAPI 0.139, pydantic 2.13, `fastapi.testclient.TestClient` (httpx 0.28) for tests, GitHub Actions for the cron.

## Global Constraints

- Repository: `/Users/aryankabra_test/Desktop/DEAD_DROP` (the live-service repo, remote `origin` = `github.com/kabraryan/deaddrop-skill`, default branch `main`). This is the Phase 2 graded service.
- Do NOT modify: the `threading.Lock` (`_lock`) usage, `_require_admin`'s `secrets.compare_digest` logic, or any 2xx/4xx response body a documented endpoint returns. These are frozen.
- Do NOT add new runtime dependencies. `requirements.txt` must stay exactly `fastapi` + `uvicorn`. No `slowapi`, no rate-limit middleware (council: too risky at this hour).
- Every documented endpoint in SKILL.md (`POST /drop`, `GET /pickup/{pickup_key}`, `GET /drop/{drop_id}`, `PATCH /drop/{drop_id}`, `DELETE /drop/{drop_id}`, `GET /health`) must keep its exact current success behavior. Verify with the existing suite after every task.
- Tests run with `python3 -m pytest <file> -v` from the repo root. The existing suite is `test_concurrency.py`; new tests are their own files.
- Each task ends with a commit. Pushing to `origin main` triggers a Render redeploy (~2–3 min) — push only when told to in the task, and warm `GET /health` after each deploy.
- Work directly on `main` (this repo's normal workflow; the branch is already the deploy source). Do not create feature branches — Render deploys `main`.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `main.py` (`FastAPI(...)` init, lines 30-37) | Disable public API docs / OpenAPI schema so `/admin/*` isn't enumerable | 1 |
| `main.py` (`DropRequest`, `create_drop`) | Enforce payload/recipient size caps and a total-drop-count cap | 2 |
| `test_limits.py` (new) | Prove the caps reject oversized/over-count input and still accept normal input | 2 |
| `.github/workflows/keepwarm.yml` (new) | Redundant 5-minute `GET /health` ping independent of the laptop | 3 |

---

### Task 1: Disable public API docs and OpenAPI schema

**Why:** The Security council member confirmed live that `GET /docs` → 200 and `/openapi.json` publicly lists `/admin/drain` and `/admin/burn` with the `X-Admin-Token` header name. Removing them from SKILL.md was cosmetic; the schema still leaks them. Disabling the auto-docs removes the enumeration surface at zero functional cost — the judge's stock agent only ever calls the curl commands in SKILL.md, never the interactive docs.

**Files:**
- Modify: `main.py:30-37` (the `app = FastAPI(...)` constructor)
- Test: `test_docs_disabled.py` (new)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: the `app` object still serves all six documented endpoints; `/docs`, `/redoc`, `/openapi.json` now return 404. Later tasks and the existing `test_concurrency.py` continue to import `main.app` unchanged.

- [ ] **Step 1: Write the failing test**

Create `test_docs_disabled.py`:

```python
"""The interactive API docs and OpenAPI schema must not be publicly served:
they enumerate the /admin/* endpoints (and the X-Admin-Token header name),
which are deliberately excluded from the agent-facing surface. The documented
endpoints must still work.
"""

from fastapi.testclient import TestClient

import main


def _client() -> TestClient:
    main._drops.clear()
    main._key_index.clear()
    main._draining = False
    return TestClient(main.app)


def test_openapi_schema_not_served() -> None:
    client = _client()
    assert client.get("/openapi.json").status_code == 404


def test_swagger_docs_not_served() -> None:
    client = _client()
    assert client.get("/docs").status_code == 404


def test_redoc_not_served() -> None:
    client = _client()
    assert client.get("/redoc").status_code == 404


def test_documented_endpoints_still_work() -> None:
    client = _client()
    r = client.post("/drop", json={"recipient": "b", "payload": "SECRET", "ttl": 600})
    assert r.status_code == 200
    body = r.json()
    assert client.get(f"/pickup/{body['pickup_key']}").json() == {"payload": "SECRET"}
    assert client.get("/health").status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_docs_disabled.py -v`
Expected: `test_openapi_schema_not_served`, `test_swagger_docs_not_served`, `test_redoc_not_served` FAIL (they return 200, not 404); `test_documented_endpoints_still_work` PASSES.

- [ ] **Step 3: Disable the docs in the FastAPI constructor**

In `main.py`, replace the `app = FastAPI(...)` block (currently lines 30-37):

```python
app = FastAPI(
    title="Dead Drop",
    description=(
        "Temporary, one-time-read, self-destructing secret transfer between agents. "
        "One reader, one read, then the secret ceases to exist."
    ),
    version="1.0.0",
)
```

with:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_docs_disabled.py -v`
Expected: all four tests PASS.

- [ ] **Step 5: Run the existing suite to confirm no regression**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_concurrency.py -v`
Expected: both concurrency tests still PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/aryankabra_test/Desktop/DEAD_DROP
git add main.py test_docs_disabled.py
git commit -m "security: disable public /docs and /openapi.json (stops admin-endpoint enumeration)"
```

---

### Task 2: Cap payload/recipient size and total drop count

**Why:** The Security council member confirmed `DropRequest` has no `max_length` on `payload`/`recipient` and `create_drop` has no cap on total `_drops` — so any unauthenticated client can POST multi-MB payloads in a loop and OOM the ~512MB Render free tier for the whole judging window. Bounding input size and store count blunts the worst case without adding a dependency or touching the lock.

**Files:**
- Modify: `main.py:112-115` (`DropRequest` model) and `main.py:125-147` (`create_drop`)
- Test: `test_limits.py` (new)

**Interfaces:**
- Consumes: nothing from Task 1 (independent; both edit `main.py` but different regions).
- Produces: `POST /drop` now returns `422` for oversized `payload`/`recipient`, and `503` when the store is at capacity. Normal drops (small payloads, well under the cap) behave exactly as before — same `{drop_id, pickup_key, expires_at}` response. Module constant `MAX_DROPS = 10000`; field caps `payload` ≤ 65536 chars, `recipient` ≤ 256 chars.

- [ ] **Step 1: Write the failing test**

Create `test_limits.py`:

```python
"""Abuse limits: an unauthenticated public /drop must not let a caller exhaust
memory. Payload/recipient are length-bounded and the total live store is capped.
Normal-sized drops are unaffected.
"""

from fastapi.testclient import TestClient

import main


def _client() -> TestClient:
    main._drops.clear()
    main._key_index.clear()
    main._draining = False
    return TestClient(main.app)


def test_oversized_payload_rejected() -> None:
    client = _client()
    r = client.post("/drop", json={"recipient": "b", "payload": "A" * 70000, "ttl": 600})
    assert r.status_code == 422


def test_oversized_recipient_rejected() -> None:
    client = _client()
    r = client.post("/drop", json={"recipient": "b" * 300, "payload": "x", "ttl": 600})
    assert r.status_code == 422


def test_normal_drop_still_accepted() -> None:
    client = _client()
    r = client.post("/drop", json={"recipient": "agent-bob", "payload": "api-token-XYZ", "ttl": 600})
    assert r.status_code == 200
    assert set(r.json()) == {"drop_id", "pickup_key", "expires_at"}


def test_max_payload_boundary_accepted() -> None:
    client = _client()
    # Exactly at the 65536 cap must still be accepted.
    r = client.post("/drop", json={"recipient": "b", "payload": "A" * 65536, "ttl": 600})
    assert r.status_code == 200


def test_store_count_cap_returns_503() -> None:
    client = _client()
    # Shrink the cap for the test so we don't create 10k drops.
    original = main.MAX_DROPS
    main.MAX_DROPS = 3
    try:
        for _ in range(3):
            assert client.post("/drop", json={"recipient": "b", "payload": "x", "ttl": 600}).status_code == 200
        r = client.post("/drop", json={"recipient": "b", "payload": "x", "ttl": 600})
        assert r.status_code == 503
    finally:
        main.MAX_DROPS = original
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_limits.py -v`
Expected: `test_oversized_payload_rejected`, `test_oversized_recipient_rejected`, and `test_store_count_cap_returns_503` FAIL — the first two because oversized input currently returns 200 instead of 422; the cap test because the 4th POST returns 200 instead of 503 (the test's `main.MAX_DROPS = 3` line creates the attribute, so it does not error). `test_normal_drop_still_accepted` and `test_max_payload_boundary_accepted` already PASS (no cap exists yet, so both return 200).

- [ ] **Step 3: Add the size caps to `DropRequest`**

In `main.py`, replace the `DropRequest` model (currently lines 112-115):

```python
class DropRequest(BaseModel):
    recipient: str
    payload: str
    ttl: int = Field(default=DEFAULT_TTL)
```

with:

```python
class DropRequest(BaseModel):
    # Length caps bound per-request memory on a public, unauthenticated endpoint.
    # 64 KiB is comfortably larger than any realistic secret (tokens, keys,
    # coordinates) while blocking multi-MB memory-exhaustion payloads.
    recipient: str = Field(max_length=256)
    payload: str = Field(max_length=65536)
    ttl: int = Field(default=DEFAULT_TTL)
```

- [ ] **Step 4: Add the store-count cap constant and guard**

In `main.py`, add a constant next to the existing TTL constants. Replace (currently lines 27-28):

```python
DEFAULT_TTL = 600
MAX_TTL = 3600  # hard cap on total lifetime from creation
```

with:

```python
DEFAULT_TTL = 600
MAX_TTL = 3600  # hard cap on total lifetime from creation
MAX_DROPS = 10000  # cap on concurrently-stored drops; guards free-tier memory
```

Then, in `create_drop`, add the capacity guard immediately after the existing `_draining` check. Replace (currently lines 126-131):

```python
def create_drop(req: DropRequest):
    if _draining:
        raise HTTPException(status_code=503, detail="draining: not accepting new drops")

    ttl = req.ttl if req.ttl and req.ttl > 0 else DEFAULT_TTL
    ttl = min(ttl, MAX_TTL)
```

with:

```python
def create_drop(req: DropRequest):
    if _draining:
        raise HTTPException(status_code=503, detail="draining: not accepting new drops")

    # Reject new drops when the store is full so a flood of POSTs cannot exhaust
    # memory on the free tier. Reading len() is atomic under CPython; a stale
    # read here is harmless (the cap is a coarse safety bound, not an invariant).
    if len(_drops) >= MAX_DROPS:
        raise HTTPException(status_code=503, detail="at capacity: try again later")

    ttl = req.ttl if req.ttl and req.ttl > 0 else DEFAULT_TTL
    ttl = min(ttl, MAX_TTL)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_limits.py -v`
Expected: all five tests PASS.

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -m pytest test_concurrency.py test_docs_disabled.py test_limits.py -v`
Expected: every test PASSES (Task 1's file is included only if Task 1 already landed; if running Task 2 standalone, run `test_concurrency.py test_limits.py`).

- [ ] **Step 7: Commit**

```bash
cd /Users/aryankabra_test/Desktop/DEAD_DROP
git add main.py test_limits.py
git commit -m "security: cap payload/recipient size and total drop count (memory-exhaustion DoS guard)"
```

---

### Task 3: Laptop-independent keep-warm cron (GitHub Actions)

**Why:** Both the Scalability and Simplicity council members named the laptop-tethered pinger as the single biggest remaining point of failure (lid closes → judging window fails, with no alert). A GitHub Actions scheduled workflow pings `GET /health` independently of the laptop. Note the tradeoff the council raised: GitHub's cron scheduler has multi-minute slop, so this is a *redundant backstop* to the laptop loop and (ideally) an external uptime monitor, not a sole guarantee. It touches zero application code, so it carries no regression risk to the service.

**Files:**
- Create: `.github/workflows/keepwarm.yml`

**Interfaces:**
- Consumes: nothing. Runs entirely on GitHub's infrastructure against the public URL.
- Produces: a scheduled + manually-dispatchable workflow that curls `https://deaddrop-s6g8.onrender.com/health`.

- [ ] **Step 1: Create the workflow file**

Create `.github/workflows/keepwarm.yml`:

```yaml
name: keep-warm

# Redundant backstop to the local pinger during the judging window. GitHub's
# scheduler can run several minutes late, so this supplements (does not replace)
# the laptop loop and any external uptime monitor. Also runnable on demand.
on:
  schedule:
    - cron: "*/5 * * * *"   # every 5 minutes (best effort; GitHub may delay)
  workflow_dispatch: {}

jobs:
  ping:
    runs-on: ubuntu-latest
    steps:
      - name: Warm the Dead Drop service
        run: |
          for i in 1 2 3; do
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 90 \
              https://deaddrop-s6g8.onrender.com/health || echo "000")
            echo "attempt $i -> HTTP $code"
            if [ "$code" = "200" ]; then exit 0; fi
            sleep 10
          done
          echo "health check did not return 200 after 3 attempts"
          exit 1
```

- [ ] **Step 2: Validate the YAML locally**

Run: `cd /Users/aryankabra_test/Desktop/DEAD_DROP && python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/keepwarm.yml')); print('YAML OK')"`
Expected: `YAML OK` (if `yaml` is unavailable, instead run `python3 -c "import json; print('skip')"` and rely on the GitHub Actions parser after push).

- [ ] **Step 3: Commit**

```bash
cd /Users/aryankabra_test/Desktop/DEAD_DROP
git add .github/workflows/keepwarm.yml
git commit -m "ops: add GitHub Actions keep-warm cron as redundant health pinger"
```

- [ ] **Step 4: Push and confirm the workflow registers**

This push also deploys Tasks 1–2 (see the deploy note below). After pushing:

```bash
cd /Users/aryankabra_test/Desktop/DEAD_DROP
git push origin main
gh workflow list
gh workflow run keep-warm      # trigger one run immediately to confirm it works
sleep 20
gh run list --workflow=keep-warm --limit 1
```

Expected: `keep-warm` appears in `gh workflow list`; the manual run shows `completed` / `success` in `gh run list`. (The `schedule:` trigger only becomes active after the workflow file is on the default branch, which this push accomplishes.)

---

### Deploy & verify (run once, after all three tasks are committed)

Pushing `main` redeploys the live Render service with Tasks 1–2. Do this deliberately and re-verify, because it briefly restarts the judged service.

- [ ] **Step 1: Push (if not already pushed in Task 3 Step 4)**

```bash
cd /Users/aryankabra_test/Desktop/DEAD_DROP
git push origin main
```

- [ ] **Step 2: Wait for redeploy, then warm and verify the live service**

Poll until the new version is live (uptime resets), then confirm the fixes are live and the documented flow still works:

```bash
B=https://deaddrop-s6g8.onrender.com
# wait for redeploy (uptime small again), warming as we go
for i in $(seq 1 20); do
  sleep 15
  up=$(curl -s --max-time 60 $B/health | python3 -c "import sys,json;print(json.load(sys.stdin).get('uptime_s','?'))" 2>/dev/null)
  echo "try $i uptime_s=$up"
  python3 -c "import sys; sys.exit(0 if '$up' not in ('?','') and float('$up')<120 else 1)" 2>/dev/null && break
done
echo "== docs now closed (expect 404) =="
curl -s -o /dev/null -w "/docs -> %{http_code}\n" $B/docs
curl -s -o /dev/null -w "/openapi.json -> %{http_code}\n" $B/openapi.json
echo "== oversized payload rejected (expect 422) =="
curl -s -o /dev/null -w "big /drop -> %{http_code}\n" -X POST $B/drop \
  -H 'content-type: application/json' \
  -d "{\"recipient\":\"b\",\"payload\":\"$(python3 -c 'print("A"*70000)')\",\"ttl\":60}"
echo "== documented flow still works (expect payload then 410) =="
R=$(curl -s -X POST $B/drop -H 'content-type: application/json' -d '{"recipient":"b","payload":"live-check","ttl":120}')
KEY=$(echo $R | python3 -c "import sys,json;print(json.load(sys.stdin)['pickup_key'])")
curl -s $B/pickup/$KEY; echo
curl -s -o /dev/null -w "second pickup -> %{http_code}\n" $B/pickup/$KEY
```

Expected: `/docs` and `/openapi.json` → `404`; oversized `/drop` → `422`; the live-check pickup returns `{"payload":"live-check"}` then `410`. If any documented-flow check regresses, roll back with `git revert` and re-push before judging.

---

## Out of scope (deliberately, per the council)

- **External uptime monitor signup** (UptimeRobot / cron-job.org): recommended by the council but requires a browser signup, not code — hand this to the user as a manual step; Task 3 is the codeable redundant backstop.
- **Rate-limiting middleware / `slowapi`**: the Security member explicitly advised against adding a dependency hours before judging; the size + count caps cover the worst case.
- **Demo video content** (showing the two-party interception path): a recording task, not an implementation-plan task.
- **Any change to** the `_lock`, `secrets.compare_digest`, `sim.py`, or the Nanda Town integration: frozen / irrelevant to the graded service.
