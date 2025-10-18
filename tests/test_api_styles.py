import src.dashboard as d


def test_styles_etag_and_headers():
    app = d.app
    with app.test_client() as c:
        r1 = c.get("/api/styles")
        assert r1.status_code == 200
        assert r1.headers.get("Content-Type") == "application/json; charset=utf-8"
        assert r1.headers.get("X-Source") == "dashboard"
        assert r1.headers.get("Cache-Control") == "private, max-age=0, must-revalidate"
        etag = r1.headers.get("ETag")
        assert etag
        r2 = c.get("/api/styles", headers={"If-None-Match": etag})
        assert r2.status_code == 304
        assert not r2.data


def test_styles_etag_stability_same_content():
    app = d.app
    with app.test_client() as c:
        r1 = c.get("/api/styles")
        r2 = c.get("/api/styles")
        assert r1.headers.get("ETag") == r2.headers.get("ETag")
