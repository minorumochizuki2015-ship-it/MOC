import src.dashboard as d


def test_pages_contract_and_headers():
    app = d.app
    with app.test_client() as c:
        r = c.get("/api/pages")
        assert r.status_code == 200
        assert r.headers.get("X-Pages-Source") == "dashboard"
        data = r.get_json()
        assert isinstance(data, list)
        assert data
        first = data[0]
        assert "url" in first and "name" in first and "description" in first
        assert "path" in first and "title" in first and "protected" in first
