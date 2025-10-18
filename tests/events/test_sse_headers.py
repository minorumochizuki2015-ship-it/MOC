import requests

BASE = "http://127.0.0.1:5000"


def test_events_headers():
    # Use HEAD to avoid consuming the streaming body
    resp = requests.head(f"{BASE}/events", timeout=3)
    # Content-Type should be text/event-stream
    ct = resp.headers.get("Content-Type", "")
    assert ct.startswith("text/event-stream"), ct
    # Cache-Control should include no-cache
    cc = resp.headers.get("Cache-Control", "")
    assert "no-cache" in cc, cc


def test_events_health_ok():
    resp = requests.get(f"{BASE}/events/health", timeout=3)
    assert resp.status_code == 200
