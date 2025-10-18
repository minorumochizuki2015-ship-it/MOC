import pytest

try:
    from orch_dashboard import OrchDashboard
except ModuleNotFoundError as e:
    pytest.skip(f"orch_dashboard 依存関係不足のためスキップ: {e}", allow_module_level=True)


def test_dashboard_route_redirect_or_ok():
    d = OrchDashboard()
    app = d.app
    app.testing = True
    c = app.test_client()
    r = c.get("/dashboard", follow_redirects=False)
    assert r.status_code in (200, 302)
    if r.status_code == 302:
        r2 = c.get("/dashboard", follow_redirects=True)
        assert r2.status_code == 200