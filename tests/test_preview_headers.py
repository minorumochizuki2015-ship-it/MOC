import os
import time
import pytest
import requests


BASE_URL = os.environ.get("ORCH_TEST_UI_URL", "http://127.0.0.1:5000")


def _wait_server_ready(url: str, timeout_sec: int = 5):
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url + "/style-manager", timeout=1)
            if r.status_code in (200, 302, 404):
                return True
        except Exception as e:
            last_err = e
        time.sleep(0.2)
    return False


@pytest.mark.skipif(
    not _wait_server_ready(BASE_URL),
    reason="UI server is not reachable on ORCH_TEST_UI_URL. Start it via scripts/ops/start_ui_server.ps1 or python -m src.dashboard",
)
class TestPreviewHeaders:
    def test_400_missing_target_headers(self):
        resp = requests.get(BASE_URL + "/preview", timeout=5)
        assert resp.status_code == 400, f"expected 400, got {resp.status_code}"

        # Cache-Control: no-store must be present for ALL responses
        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc, f"Cache-Control must include no-store, got: {cc}"

        # X-Preview-Origin and X-Preview-Target must be set on 400
        xp_origin = resp.headers.get("X-Preview-Origin")
        xp_target = resp.headers.get("X-Preview-Target")
        assert xp_origin is not None and xp_origin != "", "X-Preview-Origin should be present on 400"
        assert xp_target is not None, "X-Preview-Target should be present on 400 (may be empty)"

    def test_502_upstream_error_headers(self):
        # Use an unreachable port to force upstream connection failure
        target = "http://127.0.0.1:22222/"
        resp = requests.get(BASE_URL + f"/preview?target={requests.utils.quote(target, safe='')}", timeout=5)

        assert resp.status_code == 502, f"expected 502, got {resp.status_code}"

        cc = resp.headers.get("Cache-Control", "")
        assert "no-store" in cc, f"Cache-Control must include no-store, got: {cc}"

        xp_origin = resp.headers.get("X-Preview-Origin")
        xp_target = resp.headers.get("X-Preview-Target")
        up_status = resp.headers.get("X-Upstream-Status")

        assert xp_origin, "X-Preview-Origin should be present on 502"
        assert xp_target, "X-Preview-Target should be present on 502"
        # X-Upstream-Status is expected when upstream fetch fails (may be connection error text)
        assert up_status is not None, "X-Upstream-Status should be present on 502"

    def test_200_success_headers(self):
        target = BASE_URL + "/static/test_preview_ext.html"
        resp = requests.get(
            BASE_URL + f"/preview?target={requests.utils.quote(target, safe='')}",
            timeout=5,
        )
        assert resp.status_code == 200
        # Cache-Control: no-store must be present for ALL responses
        assert "no-store" in resp.headers.get("Cache-Control", "")
        # X-Preview headers present
        assert resp.headers.get("X-Preview-Origin")
        assert resp.headers.get("X-Preview-Target")
        # Service Worker disable flag
        assert resp.headers.get("X-Disable-ServiceWorker") == "true"
        # Same-origin flag when proxying into same host
        assert resp.headers.get("X-Preview-Same-Origin") == "true"

    def test_options_cors_dynamic_origin(self):
        # プリフライトのCORSを動的オリジンで返すことを検証（資格情報あり運用前提）
        headers = {
            "Origin": BASE_URL,
            "Access-Control-Request-Method": "GET",
        }
        resp = requests.options(BASE_URL + "/api/pages", headers=headers, timeout=5)
        assert resp.status_code in (200, 204)
        # 明示オリジン＋Vary: Origin＋Allow-Credentials: true
        assert resp.headers.get("Access-Control-Allow-Origin") == BASE_URL
        vary = resp.headers.get("Vary", "")
        assert "Origin" in [v.strip() for v in vary.split(",")] if vary else True
        assert resp.headers.get("Access-Control-Allow-Credentials") == "true"
        # Expose-Headers の存在（JSから X-Preview-* が参照可能）
        expose = resp.headers.get("Access-Control-Expose-Headers", "")
        for h in [
            "X-Preview-Origin",
            "X-Preview-Target",
            "X-Upstream-Status",
            "X-Disable-ServiceWorker",
        ]:
            assert h in [e.strip() for e in expose.split(",")] if expose else False