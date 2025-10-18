"""
E2E-like health check test using Flask's test client.
Ensures /healthz endpoint is present and returns an OK status and JSON payload.
"""

from src.dashboard import app


def test_healthz_returns_ok():
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert data.get("status") == "ok"
    assert "time" in data
