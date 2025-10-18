import os
from flask import Flask
import pytest

from src.dashboard import app as dashboard_app
from src.utils.headers import apply_options_cors_headers


@pytest.fixture(scope="module")
def app():
    # 既存のダッシュボードアプリをそのまま利用
    return dashboard_app


def test_options_preflight_includes_dynamic_origin_and_expose_headers(app):
    client = app.test_client()
    origin = "http://127.0.0.1:5000"
    # /preview に対するプリフライトで検証
    resp = client.open(
        "/preview",
        method="OPTIONS",
        headers={"Origin": origin},
    )

    # CORS 動的 Origin
    assert resp.headers.get("Access-Control-Allow-Origin") == origin
    assert "Origin" in (resp.headers.get("Vary", ""))
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"

    # Expose ヘッダはプリフライトでも一貫して提示
    expose = resp.headers.get("Access-Control-Expose-Headers", "")
    assert "ETag" in expose
    assert "X-Preview-" in expose

    # Allow-Methods/Allow-Headers の基本設定
    assert "OPTIONS" in (resp.headers.get("Access-Control-Allow-Methods", ""))
    assert "Content-Type" in (resp.headers.get("Access-Control-Allow-Headers", ""))
    # Max-Age によるプリフライト最適化（監査是正: 600 秒）
    assert resp.headers.get("Access-Control-Max-Age") == "600"