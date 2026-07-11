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
