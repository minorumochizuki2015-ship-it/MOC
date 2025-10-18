from src.dashboard import app

def _contains_all(header_value: str, items):
    if not header_value:
        return False
    hv = header_value.lower()
    return all(item.lower() in hv for item in items)


def test_options_preflight_headers_with_origin():
    client = app.test_client()
    origin = "http://example.com"
    resp = client.open(
        "/api/test",
        method="OPTIONS",
        headers={"Origin": origin},
    )
    # CORS origin reflection with credentials and Vary
    assert resp.headers.get("Access-Control-Allow-Origin") == origin
    assert "Origin" in (resp.headers.get("Vary") or "")
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"
    # Expose headers must include preview-related headers consistently
    expose = resp.headers.get("Access-Control-Expose-Headers") or ""
    assert _contains_all(
        expose,
        [
            "X-Preview-Origin",
            "X-Preview-Target",
            "X-Disable-ServiceWorker",
            "X-Preview-Same-Origin",
        ],
    )


def test_regular_response_headers_with_origin():
    client = app.test_client()
    origin = "http://example.com"
    resp = client.get("/debug-headers", headers={"Origin": origin})
    assert resp.status_code == 200
    # CORS applied on normal responses too
    assert resp.headers.get("Access-Control-Allow-Origin") == origin
    assert "Origin" in (resp.headers.get("Vary") or "")
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"
    # Expose headers present
    expose = resp.headers.get("Access-Control-Expose-Headers") or ""
    assert _contains_all(
        expose,
        [
            "X-Preview-Origin",
            "X-Preview-Target",
            "X-Disable-ServiceWorker",
            "X-Preview-Same-Origin",
        ],
    )


def test_regular_response_headers_without_origin():
    client = app.test_client()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers.get("Access-Control-Allow-Origin") == "*"


def test_preview_response_expose_and_cors(monkeypatch):
    # Mock requests.get to avoid network and ensure 200
    class FakeResp:
        status_code = 200
        text = "<html><head></head><body>ok</body></html>"
        headers = {"Content-Type": "text/html; charset=utf-8"}

    def fake_get(url, timeout=10):
        return FakeResp()

    import src.dashboard as dashboard_mod
    monkeypatch.setattr(dashboard_mod.requests, "get", fake_get)

    client = app.test_client()
    origin = "http://example.com"
    resp = client.get("/preview?target=http://example.com/page", headers={"Origin": origin})
    assert resp.status_code == 200
    # CORS and Expose applied
    assert resp.headers.get("Access-Control-Allow-Origin") == origin
    assert "Origin" in (resp.headers.get("Vary") or "")
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"
    expose = resp.headers.get("Access-Control-Expose-Headers") or ""
    assert _contains_all(
        expose,
        [
            "X-Preview-Origin",
            "X-Preview-Target",
            "X-Disable-ServiceWorker",
            "X-Preview-Same-Origin",
        ],
    )
