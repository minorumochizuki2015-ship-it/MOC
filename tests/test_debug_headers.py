import src.dashboard as d


def test_debug_headers_visibility():
    app = d.app
    with app.test_client() as c:
        r = c.get("/debug-headers")
        assert r.status_code == 200
        assert r.headers.get("X-Debug") == "1"
        assert r.headers.get("ETag") == "123"
