import os
import sys
import time
import pytest
from urllib.request import urlopen
from urllib.error import URLError
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("DASHBOARD_BASE_URL", "http://127.0.0.1:5000")
STYLE_MANAGER_URL = f"{BASE_URL}/style-manager"


def is_server_up(url: str, timeout: float = 3.0) -> bool:
    try:
        with urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except URLError:
        return False


@pytest.mark.e2e
def test_style_manager_smoke():
    if not is_server_up(STYLE_MANAGER_URL):
        pytest.skip(f"Server not reachable at {STYLE_MANAGER_URL} - start Flask server before running E2E smoke tests")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(STYLE_MANAGER_URL, wait_until="domcontentloaded")

            # タイトルに「スタイル管理」が含まれること
            title = page.title()
            assert "スタイル管理" in title

            # ステータスインジケータが初期表示されていること
            status = page.wait_for_selector("#baseUrlStatus", timeout=5000)
            assert status.is_visible()

            # 接続設定の入力が存在し、保存ボタンでローカルストレージに保存されること
            base_input = page.locator("#baseUrlInput")
            assert base_input.is_visible()
            save_btn = page.locator("#saveBaseUrlBtn")
            assert save_btn.is_visible()

            test_base = f"{BASE_URL}/"
            base_input.fill(test_base)
            save_btn.click()

            # 保存後のステータスに接続先が反映される（接続テスト前のため '接続先:' 表示）
            page.wait_for_function("document.getElementById('baseUrlStatus').innerText.includes('接続先')")

            saved = page.evaluate("localStorage.getItem('STYLE_BASE_URL') || ''")
            assert saved.strip() == test_base.strip()

            # 接続テストボタンで到達性チェック表示が出ること
            ping_btn = page.locator("#pingBaseUrlBtn")
            assert ping_btn.is_visible()
            ping_btn.click()
            page.wait_for_function("document.getElementById('baseUrlStatus').innerText.includes('到達性OK')", timeout=5000)

        finally:
            browser.close()
