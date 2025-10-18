import pytest

requests = pytest.importorskip("requests")

BASE = "http://127.0.0.1:5000"


def normalize(u: str) -> str:
    u = (u or "").strip().lower()
    if u.endswith("/"):
        u = u[:-1]
    return u


def test_pages_uniqueness_and_required_set_and_order():
    r = requests.get(f"{BASE}/api/pages")
    assert r.status_code == 200
    assert r.headers.get("X-Pages-Source") == "dashboard"

    pages = r.json()
    # 正規化後の一意性
    urls = [normalize(p.get("url")) for p in pages]
    paths = [normalize(p.get("path")) for p in pages]
    assert len(urls) == len(set(urls))
    assert len(paths) == len(set(paths))

    # 必須ページ集合（少なくともこれらが含まれる）
    required = ["/style-manager", "/tasks", "/agents"]
    normalized_urls = set(urls)
    for req in required:
        assert normalize(req) in normalized_urls

    # 表示順（必須集合間の相対順序を確認）
    idx = {normalize(p.get("url")): i for i, p in enumerate(pages)}
    # サーバ定義の順序に合わせて Tasks -> Agents -> Style Manager の順を検証
    assert idx[normalize("/tasks")] < idx[normalize("/agents")] < idx[normalize("/style-manager")]
