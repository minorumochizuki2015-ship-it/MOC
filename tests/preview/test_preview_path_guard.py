import requests

BASE = "http://127.0.0.1:5000"


def test_preview_blocks_traversal():
    # Attempt path traversal outside static
    url = f"{BASE}/preview?target={BASE}/static/../app.py"
    resp = requests.get(url, timeout=5)
    assert resp.status_code == 400
    assert resp.text.strip() == "blocked"
