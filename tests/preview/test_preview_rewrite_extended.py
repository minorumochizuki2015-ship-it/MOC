import urllib.parse as _up
import pytest

requests = pytest.importorskip("requests")

BASE = "http://127.0.0.1:5000"
TARGET = f"{BASE}/static/test_preview_ext.html"


def test_preview_rewrite_extended_attributes_and_exceptions():
    url = f"{BASE}/preview?target={_up.quote(TARGET, safe='')}"
    r = requests.get(url)
    assert r.status_code == 200
    html = r.text

    # 書換え: 同一オリジンへ絶対化
    origin = BASE
    # link rel=preload/modulepreload/icon
    assert f'<link rel="preload" href="{origin}/static/assets/app.css" as="style">' in html
    assert f'<link rel="modulepreload" href="{origin}/static/assets/app.mjs" crossorigin="anonymous">' in html
    assert f'<link rel="icon" href="{origin}/static/images/favicon.ico">' in html

    # 追加フィクスチャ検証: 単一引用と無引用属性の絶対化
    assert f"<link rel=\"stylesheet\" href='{origin}/static/a.css'>" in html
    assert f"<script src={origin}/static/a.js></script>" in html

    # script[type=module] の integrity/crossorigin を保持
    assert f'<script type="module" src="{origin}/static/assets/app.mjs" integrity="sha256-abc" crossorigin="anonymous"></script>' in html

    # iframe/src, object/data, embed/src
    assert f'<iframe src="{origin}/static/frame/page.html"></iframe>' in html
    assert f'<object data="{origin}/static/obj/doc.pdf"></object>' in html
    assert f'<embed src="{origin}/static/media/sample.mp4">' in html

    # meta[http-equiv=refresh] 引用符保持検証
    assert f"<meta http-equiv=\"refresh\" content=\"0;url='{origin}/static/next.html'\">" in html

    # form[action]
    assert f'<form action="{origin}/static/submit" method="post">' in html

    # 例外: a[href^="#"], use[href^="#"], CSS/SVG の url(#id) は不変
    assert '<a href="#section">Jump</a>' in html
    assert '<use href="#marker" />' in html
    # スタイル内の fragment は維持
    assert 'url(#marker)' in html

    # 例外: script内のurl()は不変であること
    assert 'const s="url(/x.png)"' in html

    # 例外: 相対 ./images/... と images/... は不変（CSS内）
    assert ".icon { background-image: url('./images/logo.png'); }" in html

    # CSS内の @import url(...) を最低1例検証（同一オリジンに絶対化）
    assert "@import url('" + origin + "/static/assets/imp.css');" in html
