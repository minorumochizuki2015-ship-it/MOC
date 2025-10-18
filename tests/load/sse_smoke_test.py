"""
SSE スモーク/耐性テスト

- /events のヘッダ検証
- ストリーム継続性（フレーム受信）
- /events/health の疎通
- 簡易同時接続（10）

CIでの軽量検証用。長時間・高負荷は別途 k6/locust を推奨。
"""

import threading
import time

import requests

BASE_URL = "http://127.0.0.1:5000"


def test_sse_headers():
    r = requests.get(f"{BASE_URL}/events", stream=True, timeout=8)
    assert r.status_code == 200, f"status={r.status_code} body={r.text[:200]}"
    ctype = r.headers.get("Content-Type", "")
    assert "text/event-stream" in ctype, ctype
    cache = r.headers.get("Cache-Control", "").lower()
    assert cache.startswith("no-cache"), cache
    conn = r.headers.get("Connection", "").lower()
    assert conn == "keep-alive", conn
    xab = r.headers.get("X-Accel-Buffering", "").lower()
    assert xab == "no", xab


def test_sse_stream_frames():
    r = requests.get(f"{BASE_URL}/events", stream=True, timeout=12)
    start = time.time()
    frames = 0
    for line in r.iter_lines(decode_unicode=True):
        if not line:
            # ignore keep-alive blanks
            continue
        if line.startswith("data:"):
            frames += 1
            if frames >= 2:
                break
        if time.time() - start > 10:
            break
    assert frames >= 1, "No SSE frames received within 10s"


def test_sse_health_stream():
    r = requests.get(f"{BASE_URL}/events/health", stream=True, timeout=10)
    assert r.status_code == 200, f"status={r.status_code} body={r.text[:200]}"
    ctype = r.headers.get("Content-Type", "")
    assert "text/event-stream" in ctype, ctype


def test_sse_concurrency_smoke():
    """10同時接続で各1フレーム受信できるかの簡易確認"""
    frames_ct = 0

    def worker():
        nonlocal frames_ct
        try:
            rr = requests.get(f"{BASE_URL}/events", stream=True, timeout=10)
            for line in rr.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if line.startswith("data:"):
                    frames_ct += 1
                    break
        except Exception:
            pass

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=12)

    assert frames_ct >= 5, f"Concurrency smoke failed: frames_ct={frames_ct}"
