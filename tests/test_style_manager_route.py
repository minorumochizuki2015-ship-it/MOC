import re
from src.dashboard import app


def test_style_manager_route_status():
    client = app.test_client()
    resp = client.get('/style-manager')
    assert resp.status_code == 200
    body = resp.data.decode('utf-8', errors='ignore')
    assert 'スタイル管理システム' in body or 'Style Manager' in body


def test_preview_proxy_rewrites(monkeypatch):
    # モックレスポンス
    class FakeResp:
        text = '<html><head></head><body><a href="/x">x</a><script src="/s.js"></script></body></html>'

    def fake_get(url, timeout=10):
        return FakeResp()

    # requests.get をモック
    import src.dashboard as dashboard_mod
    monkeypatch.setattr(dashboard_mod.requests, 'get', fake_get)

    client = app.test_client()
    resp = client.get('/preview?target=http://example.com/page')
    assert resp.status_code == 200
    body = resp.data.decode('utf-8', errors='ignore')
    # <base> が挿入され、絶対化されていること
    assert '<base href="http://example.com/"' in body
    assert 'href="http://example.com/x"' in body
    assert 'src="http://example.com/s.js"' in body