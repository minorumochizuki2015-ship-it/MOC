import re
from types import SimpleNamespace

import src.dashboard as d


def test_preview_base_injection_and_sw_disable(monkeypatch):
    app = d.app

    remote_html = (
        """
        <html>
        <head>
          <base href=\"http://old.example/\">
          <script>console.log('hello');</script>
        </head>
        <body>
          <a href=\"/abs\">A</a>
          <img src=\"/img.png\" srcset=\"/a.png 1x, /b.png 2x\">
          <form action=\"/post\"></form>
        </body>
        </html>
        """
    )

    import requests

    def fake_get(url, *args, **kwargs):
        return SimpleNamespace(status_code=200, text=remote_html)

    monkeypatch.setattr(requests, "get", fake_get)

    with app.test_client() as c:
        r = c.get("/preview", query_string={"target": "http://example.com"})
        assert r.status_code == 200
        html = r.data.decode("utf-8", errors="ignore")

        bases = re.findall(r"<base href=\"https?://[^\"]+/\"", html)
        assert len(bases) == 1

        origin = re.search(r"<base href=\"(https?://[^\"]+)/\"", html).group(1)
        for m in re.findall(r"href=\"/[^\"]*\"", html):
            assert m.startswith(f"href=\"{origin}/")
        for m in re.findall(r"src=\"/[^\"]*\"", html):
            assert m.startswith(f"src=\"{origin}/")
        for m in re.findall(r"srcset=\"([^\"]+)\"", html):
            parts = [p.strip().split()[0] for p in m.split(",")]
            for p in parts:
                assert p.startswith(f"{origin}/")

        assert "navigator.serviceWorker.register = function" in html
        assert "getRegistration = async () => undefined" in html or "getRegistration() { return undefined" in html
