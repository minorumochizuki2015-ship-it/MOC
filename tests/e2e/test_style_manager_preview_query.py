import os
import urllib.parse as _up

import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")


@pytest.mark.e2e
def test_preview_iframe_includes_style_base_url_query():
    """
    /style-manager でページ読み込み時、iframe.src の /preview クエリに
    style_base_url が付与されることを検証する。
    - localStorage.STYLE_BASE_URL に BASE_URL を保存
    - ページ一覧から最初のページを選択して「読み込み」
    - iframe#previewFrame の src を取得し、`style_base_url` が存在し BASE_URL と一致すること
    """
    test_base = f"{BASE_URL}/"
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # Navigate
        resp = page.goto(f"{BASE_URL}/style-manager", wait_until="domcontentloaded")
        assert resp is not None and resp.ok, f"/style-manager status {resp.status if resp else 'None'}"

        # Save STYLE_BASE_URL to localStorage
        page.evaluate("(u) => localStorage.setItem('STYLE_BASE_URL', u)", test_base)

        # 待機：ページ一覧がロードされ select に option が追加される
        # 空でない value を持つ option が存在するまで待機
        page.wait_for_function(
            "() => { const s = document.getElementById('pageSelect'); return s && s.options.length > 1 && s.options[1].value !== ''; }",
            timeout=10000
        )

        # 最初の候補を選択して読み込みボタンを押す
        # 直接 value を設定し、loadPageBtn をクリック
        first_value = page.evaluate(
            "() => { const s = document.getElementById('pageSelect'); return (s.options.length > 1) ? s.options[1].value : ''; }"
        )
        assert first_value, "No page option available in #pageSelect"

        page.evaluate(
            "(val) => { const s = document.getElementById('pageSelect'); s.value = val; s.dispatchEvent(new Event('change', { bubbles: true })); }",
            first_value,
        )

        # クリックで読み込み実行
        page.click("#loadPageBtn")

        # iframe が表示され、src が設定されるのを待機
        page.wait_for_selector("#previewFrame", timeout=5000)
        src_val = page.evaluate("() => document.getElementById('previewFrame').src")
        assert "/preview?" in src_val and "target=" in src_val, f"Unexpected iframe src: {src_val}"

        # クエリ解析
        parsed = _up.urlparse(src_val)
        qs = dict(_up.parse_qsl(parsed.query))
        assert "style_base_url" in qs, f"style_base_url missing in iframe src: {src_val}"
        # Normalize trailing slash
        got = (qs["style_base_url"] or "").rstrip("/")
        expect = test_base.rstrip("/")
        assert got == expect, f"style_base_url mismatch: got={got} expect={expect}"

        browser.close()