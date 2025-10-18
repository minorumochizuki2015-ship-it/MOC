import pytest
from app.intake_service.api import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.mark.parametrize("path", ["/", "/health", "/metrics", "/api/intake/pipelines"])
def test_basic_get_endpoints(path):
    resp = client.get(path)
    assert resp.status_code == 200
    # 返却が JSON であることを確認（metrics/pipelines は辞書）
    assert resp.headers.get("content-type", "").startswith("application/json")
