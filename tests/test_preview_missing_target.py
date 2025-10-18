from src.dashboard import app


def test_preview_missing_target_headers():
    client = app.test_client()
    resp = client.get("/preview")
    assert resp.status_code == 400
    # Preview enforcement headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("X-Preview-Target") == ""
    # Origin is computed from request host; just ensure it looks like an http origin
    origin_hdr = resp.headers.get("X-Preview-Origin") or ""
    assert origin_hdr.startswith("http://") or origin_hdr.startswith("https://")
    # Service worker suppression and same-origin flag applied via after_request
    assert resp.headers.get("X-Disable-ServiceWorker") == "true"
    assert resp.headers.get("X-Preview-Same-Origin") == "true"
    # Expose headers include preview-related ones so Fetch can read them
    expose = resp.headers.get("Access-Control-Expose-Headers") or ""
    for item in [
        "X-Preview-Origin",
        "X-Preview-Target",
        "X-Disable-ServiceWorker",
        "X-Preview-Same-Origin",
    ]:
        assert item in expose
