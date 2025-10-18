import os
import time
import pytest
import requests


BASE_URL = os.environ.get("ORCH_TEST_UI_URL", "http://127.0.0.1:5000")


def _wait_sse_ready(url: str, timeout_sec: int = 5):
    """Check if an SSE endpoint appears to be available.
    We try /events/health first (single-frame in test_mode),
    then fall back to /events.
    """
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url + "/events/health", timeout=1)
            if r.status_code in (200, 204):
                return True
        except Exception as e:
            last_err = e
        try:
            r2 = requests.get(url + "/events", timeout=1)
            # Even for streaming, initial headers should be available quickly
            if r2.status_code in (200, 204):
                return True
        except Exception as e:
            last_err = e
        time.sleep(0.2)
    return False


@pytest.mark.skipif(
    not _wait_sse_ready(BASE_URL),
    reason="SSE server is not reachable on ORCH_TEST_UI_URL. Start it via python -m src.realtime_dashboard or register sse_bp in src.dashboard",
)
class TestSSEHeaders:
    def test_sse_health_no_cache_headers(self):
        """Verify SSE health endpoint responds with expected headers for EventSource."""
        # Prefer /events/health (single-frame under test_mode), fallback to /events
        resp = None
        try:
            resp = requests.get(BASE_URL + "/events/health", timeout=5)
        except Exception:
            resp = requests.get(BASE_URL + "/events", timeout=5)

        assert resp is not None and resp.status_code in (200, 204), f"unexpected status: {getattr(resp, 'status_code', 'n/a')}"

        # SSE should use no-cache to avoid browser caching of event stream
        cc = resp.headers.get("Cache-Control", "")
        assert "no-cache" in cc, f"SSE Cache-Control must include no-cache, got: {cc}"

        # Content-Type must be text/event-stream
        ctype = resp.headers.get("Content-Type", "")
        assert "text/event-stream" in ctype, f"Content-Type should be text/event-stream, got: {ctype}"

        # Connection: keep-alive is common for SSE
        conn = resp.headers.get("Connection", "")
        assert "keep-alive" in conn.lower(), f"Connection should be keep-alive for SSE, got: {conn}"

        # X-Accel-Buffering: no is recommended to avoid proxy buffering
        xaccel = resp.headers.get("X-Accel-Buffering", "")
        assert xaccel.lower() == "no", f"X-Accel-Buffering should be 'no' for SSE, got: {xaccel}"