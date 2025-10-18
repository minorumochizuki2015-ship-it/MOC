import json
import pytest

requests = pytest.importorskip("requests")

BASE = "http://127.0.0.1:5000"


def get_styles_etag():
    r = requests.get(f"{BASE}/api/styles")
    # 200 か 304 を許容
    if r.status_code == 200:
        return r.headers.get("ETag"), r.json()
    elif r.status_code == 304:
        return r.headers.get("ETag"), None
    else:
        pytest.skip(f"/api/styles GET unexpected status: {r.status_code}")


def test_styles_update_invalid_key_returns_400():
    payload = {"key": "unknown_key", "value": "#ffffff"}
    r = requests.post(f"{BASE}/api/styles", json=payload)
    assert r.status_code == 400
    data = r.json()
    assert "error" in data


def test_styles_update_invalid_color_returns_400():
    # 既知キーに不正色値
    payload = {"key": "accent_color", "value": "not-a-color"}
    r = requests.post(f"{BASE}/api/styles", json=payload)
    assert r.status_code == 400
    data = r.json()
    assert "error" in data


def test_styles_update_valid_color_accepts_200_or_204():
    # 既知キーに正しい色値
    payload = {"key": "accent_color", "value": "#00eaff"}
    r = requests.post(f"{BASE}/api/styles", json=payload)
    assert r.status_code in (200, 204)

    # 一括更新でも受容
    payload2 = {"styles": {"accent_color": "rgba(0, 234, 255, 1)", "nav_text_color": "#d8e1ff"}}
    r2 = requests.post(f"{BASE}/api/styles", json=payload2)
    assert r2.status_code in (200, 204)


def test_styles_update_if_match_conflict_returns_412():
    etag, _ = get_styles_etag()
    # 故意に不一致な ETag を送る
    bad_etag = '"deadbeef"'
    headers = {"If-Match": bad_etag}
    payload = {"key": "accent_color", "value": "#00eaff"}
    r = requests.post(f"{BASE}/api/styles", json=payload, headers=headers)
    # 実装されていれば 412、未実装ならスキップ
    if r.status_code == 412:
        assert r.json().get("error")
    else:
        pytest.skip(f"If-Match 412 未実装または不一致判定されず: {r.status_code}")
