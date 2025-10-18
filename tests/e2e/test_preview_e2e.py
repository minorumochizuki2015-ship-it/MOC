import os
import pytest
import requests  # type: ignore
from urllib.request import urlopen
from urllib.error import URLError

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except ModuleNotFoundError:
    pytest.skip(
        "playwright not installed; run `pip install playwright` and then `playwright install`",
        allow_module_level=True,
    )

BASE_URL = os.environ.get("DASHBOARD_BASE_URL", "http://127.0.0.1:5000")


def is_server_up(url: str, timeout: float = 3.0) -> bool:
    try:
        with urlopen(url, timeout=timeout) as resp:
            return resp.status == 200
    except URLError:
        return False


@pytest.mark.e2e
def test_preview_same_origin_and_meta_refresh_and_sw_disabled():
    # 前提: サーバが起動している
    if not is_server_up(f"{BASE_URL}/healthz"):
        pytest.skip(
            f"Server not reachable at {BASE_URL} - start Flask server before running E2E tests"
        )

    target = f"{BASE_URL}/static/test_preview_ext.html"
    preview_url = f"{BASE_URL}/preview?target={target}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(preview_url, wait_until="domcontentloaded")

            # /preview 応答ヘッダーの検証（観測容易化のための付与）
            r = requests.get(preview_url, timeout=5)
            assert r.status_code == 200
            assert r.headers.get("X-Preview-Target") == target
            assert r.headers.get("X-Preview-Origin") == BASE_URL
            assert r.headers.get("X-Disable-ServiceWorker") == "true"
            assert r.headers.get("X-Preview-Same-Origin") == "true"

            # meta refresh により next.html へ遷移すること
            page.wait_for_url("**/static/next.html", timeout=5000)

            # 同一オリジン確認（遷移後も BASE_URL のまま）
            origin = page.evaluate("location.origin")
            assert origin == BASE_URL

            # Service Worker 無効化確認（遷移後のページでも controller が nullであること）
            controller = page.evaluate(
                "navigator.serviceWorker ? navigator.serviceWorker.controller : null"
            )
            assert controller is None

            # static 実体の直アクセスが 200 であること
            with urlopen(f"{BASE_URL}/static/next.html", timeout=5) as resp:
                assert resp.status == 200
        finally:
            browser.close()


@pytest.mark.e2e
def test_preview_upstream_error_headers():
    # 前提: サーバが起動している
    if not is_server_up(f"{BASE_URL}/healthz"):
        pytest.skip(
            f"Server not reachable at {BASE_URL} - start Flask server before running E2E tests"
        )

    target = f"{BASE_URL}/static/notfound.html"
    preview_url = f"{BASE_URL}/preview?target={target}"

    # 非2xxの上流応答は 502 にマッピングされ、ヘッダーに X-Upstream-Status と X-Preview-Target が付与される
    r = requests.get(preview_url, timeout=5)
    assert r.status_code == 502
    assert r.headers.get("X-Upstream-Status") == "404"
    assert r.headers.get("X-Preview-Target") == target
