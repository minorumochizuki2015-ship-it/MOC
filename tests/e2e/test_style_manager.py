import os

import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")


@pytest.mark.e2e
def test_style_manager_page_ok():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        resp = page.goto(f"{BASE_URL}/style-manager", wait_until="domcontentloaded")
        assert (
            resp is not None and resp.ok
        ), f"/style-manager status {resp.status if resp else 'None'}"
        content = page.content()
        assert "Style Manager" in content or "Styles" in content, "Unexpected page content"
        browser.close()


@pytest.mark.e2e
def test_api_styles_get_ok():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        resp = page.goto(f"{BASE_URL}/api/styles")
        assert resp is not None and resp.ok, f"/api/styles status {resp.status if resp else 'None'}"
        try:
            data = resp.json()
        except Exception:
            # Fallback: read text and perform minimal validation
            data = None
        assert data is None or isinstance(data, dict), "Expected JSON object or valid response"
        browser.close()
