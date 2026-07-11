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
    r = client.post("/drop", json={"recipient": "b", "payload": "A" * 20000, "ttl": 600})
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
    # Exactly at the 16384 cap must still be accepted.
    r = client.post("/drop", json={"recipient": "b", "payload": "A" * 16384, "ttl": 600})
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
