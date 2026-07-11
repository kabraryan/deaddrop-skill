"""Concurrency guard: the one-time-read guarantee must hold under real thread
races, not just sequential access.

The route handlers are sync (`def`), so Starlette runs them in a threadpool.
Without a lock around pickup's check-then-act, two simultaneous redemptions of
the same key could both observe "waiting" and both receive the payload. These
tests fire many concurrent requests at one key and assert exactly one success.

Run: python3 -m pytest test_concurrency.py -v   (or: python3 test_concurrency.py)
"""

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

import main


def _fresh_client() -> TestClient:
    main._drops.clear()
    main._key_index.clear()
    main._draining = False
    return TestClient(main.app)


def test_concurrent_pickup_delivers_exactly_once() -> None:
    client = _fresh_client()
    r = client.post("/drop", json={"recipient": "b", "payload": "SECRET", "ttl": 600})
    key = r.json()["pickup_key"]

    n = 64
    with ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(lambda _: client.get(f"/pickup/{key}"), range(n)))

    ok = [x for x in responses if x.status_code == 200]
    gone = [x for x in responses if x.status_code == 410]

    assert len(ok) == 1, f"expected exactly one 200, got {len(ok)}"
    assert ok[0].json() == {"payload": "SECRET"}
    assert len(gone) == n - 1, f"expected {n - 1} 410s, got {len(gone)}"


def test_concurrent_pickups_across_many_keys_each_once() -> None:
    client = _fresh_client()
    keys = [
        client.post("/drop", json={"recipient": "b", "payload": f"s{i}", "ttl": 600}).json()["pickup_key"]
        for i in range(20)
    ]
    # Two concurrent redemptions per key; each key must yield exactly one payload.
    jobs = keys * 2
    with ThreadPoolExecutor(max_workers=16) as pool:
        responses = list(pool.map(lambda k: client.get(f"/pickup/{k}"), jobs))

    ok = [x for x in responses if x.status_code == 200]
    assert len(ok) == 20, f"expected 20 unique successful reads, got {len(ok)}"
    assert {x.json()["payload"] for x in ok} == {f"s{i}" for i in range(20)}


if __name__ == "__main__":
    test_concurrent_pickup_delivers_exactly_once()
    test_concurrent_pickups_across_many_keys_each_once()
    print("concurrency: exactly-once under 64-way and 40-way races — PASS")
