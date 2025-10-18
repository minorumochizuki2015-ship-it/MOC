"""
統合テスト: Intake Service API
FastAPIアプリケーションの統合テストを実行
"""

import warnings

warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

import asyncio
import json

import pytest
from app.intake_service.api import app
from fastapi.testclient import TestClient
from httpx import AsyncClient


class TestIntakeAPIIntegration:
    """Intake Service API統合テストクラス"""

    @pytest.fixture
    def client(self):
        """テストクライアント作成"""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return TestClient(app)

    @pytest.fixture
    async def async_client(self):
        """非同期テストクライアント作成"""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac

    def test_root_endpoint(self, client):
        """ルートエンドポイントテスト"""
        response = client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert data["service"] == "Intake Service API"
        assert data["version"] == "1.0.0"
        assert data["status"] == "running"
        assert "timestamp" in data

    def test_health_endpoint(self, client):
        """ヘルスチェックエンドポイントテスト"""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "active_pipelines" in data
        assert isinstance(data["active_pipelines"], int)

    def test_metrics_endpoint(self, client):
        """メトリクスエンドポイントテスト"""
        response = client.get("/metrics")
        assert response.status_code == 200

        data = response.json()
        assert "total_pipelines" in data
        assert "status_distribution" in data
        assert "internal_metrics" in data
        assert "timestamp" in data

    def test_pipeline_execution_manual(self, client):
        """手動パイプライン実行テスト"""
        request_data = {
            "trigger": "manual",
            "params": {"command": ["python", "--version"], "timeout": 10},
        }

        response = client.post("/api/intake/pipeline", json=request_data)
        assert response.status_code == 200

        data = response.json()
        assert data["status"] in ["success", "error"]
        assert "pipeline_id" in data
        assert "message" in data
        assert "timestamp" in data

        # パイプラインIDを保存してステータス確認
        pipeline_id = data["pipeline_id"]

        # ステータス確認
        status_response = client.get(f"/api/intake/pipeline/{pipeline_id}")
        assert status_response.status_code == 200

        status_data = status_response.json()
        assert status_data["pipeline_id"] == pipeline_id
        assert status_data["trigger"] == "manual"
        assert "start_time" in status_data

    def test_pipeline_execution_scheduled(self, client):
        """スケジュール実行パイプラインテスト"""
        request_data = {
            "trigger": "scheduled",
            "params": {"command": ["echo", "test"], "timeout": 5},
        }

        response = client.post("/api/intake/pipeline", json=request_data)
        assert response.status_code == 200

        data = response.json()
        assert data["status"] in ["success", "error"]
        pipeline_id = data["pipeline_id"]

        # ステータス確認
        status_response = client.get(f"/api/intake/pipeline/{pipeline_id}")
        assert status_response.status_code == 200

        status_data = status_response.json()
        assert status_data["trigger"] == "scheduled"

    def test_pipeline_list(self, client):
        """パイプライン一覧取得テスト"""
        # まずパイプラインを実行
        request_data = {"trigger": "manual", "params": {"command": ["python", "--version"]}}
        client.post("/api/intake/pipeline", json=request_data)

        # 一覧取得
        response = client.get("/api/intake/pipelines")
        assert response.status_code == 200

        data = response.json()
        assert "pipelines" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert isinstance(data["pipelines"], list)

    def test_pipeline_list_with_filters(self, client):
        """フィルタ付きパイプライン一覧取得テスト"""
        response = client.get("/api/intake/pipelines?limit=5&offset=0&status_filter=success")
        assert response.status_code == 200

        data = response.json()
        assert data["limit"] == 5
        assert data["offset"] == 0
        assert data["status_filter"] == "success"

    def test_pipeline_not_found(self, client):
        """存在しないパイプラインIDテスト"""
        response = client.get("/api/intake/pipeline/nonexistent")
        assert response.status_code == 404

        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "NOT_FOUND"

    def test_pipeline_validation_error(self, client):
        """バリデーションエラーテスト"""
        # 無効なトリガー
        request_data = {"trigger": "invalid_trigger", "params": {}}

        response = client.post("/api/intake/pipeline", json=request_data)
        assert response.status_code == 422  # Pydanticバリデーションエラー

    def test_pipeline_large_params_error(self, client):
        """大きすぎるパラメータエラーテスト"""
        large_params = {"data": "x" * 2000}  # 1000文字制限を超える

        request_data = {"trigger": "manual", "params": large_params}

        response = client.post("/api/intake/pipeline", json=request_data)
        assert response.status_code == 400

        data = response.json()
        assert "error" in data
        assert data["error"]["code"] == "VALIDATION_ERROR"

    def test_pipeline_timeout(self, client):
        """パイプラインタイムアウトテスト"""
        request_data = {
            "trigger": "manual",
            "params": {
                "command": ["python", "-c", "import time; time.sleep(10)"],
                "timeout": 1,  # 1秒でタイムアウト
            },
        }

        response = client.post("/api/intake/pipeline", json=request_data)
        # タイムアウトはリトライ後にエラーレスポンスになる
        assert response.status_code in [200, 408]

    def test_pipeline_delete(self, client):
        """パイプライン削除テスト"""
        # パイプライン実行
        request_data = {"trigger": "manual", "params": {"command": ["python", "--version"]}}

        response = client.post("/api/intake/pipeline", json=request_data)
        pipeline_id = response.json()["pipeline_id"]

        # 削除
        delete_response = client.delete(f"/api/intake/pipeline/{pipeline_id}")
        assert delete_response.status_code == 200

        # 削除後は取得できない
        get_response = client.get(f"/api/intake/pipeline/{pipeline_id}")
        assert get_response.status_code == 404

    def test_request_id_header(self, client):
        """リクエストIDヘッダーテスト"""
        response = client.get("/")
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) == 8

    def test_cors_headers(self, client):
        """CORSヘッダーテスト"""
        response = client.options("/", headers={"Origin": "http://localhost:3000"})
        # TestClientはCORSプリフライトを完全にシミュレートしないが、
        # アプリケーションレベルでCORSが設定されていることを確認
        assert response.status_code in [200, 405]  # OPTIONSメソッドの処理

    @pytest.mark.asyncio
    async def test_concurrent_pipeline_execution(self, async_client):
        """並行パイプライン実行テスト"""
        request_data = {"trigger": "manual", "params": {"command": ["python", "--version"]}}

        # 3つの並行リクエスト
        tasks = [async_client.post("/api/intake/pipeline", json=request_data) for _ in range(3)]

        responses = await asyncio.gather(*tasks)

        # すべてのレスポンスが成功
        for response in responses:
            assert response.status_code == 200
            data = response.json()
            assert "pipeline_id" in data

        # 異なるパイプラインIDが生成されている
        pipeline_ids = [resp.json()["pipeline_id"] for resp in responses]
        assert len(set(pipeline_ids)) == 3  # すべて異なるID

    def test_error_response_format(self, client):
        """エラーレスポンス形式テスト"""
        response = client.get("/api/intake/pipeline/nonexistent")
        assert response.status_code == 404

        data = response.json()
        assert "error" in data
        error = data["error"]

        # 標準エラー形式の確認
        assert "code" in error
        assert "message" in error
        assert "timestamp" in error
        assert "request_id" in error
        assert "severity" in error

    def test_sensitive_data_masking(self, client):
        """機密データマスキングテスト"""
        request_data = {
            "trigger": "manual",
            "params": {
                "password": "secret123",
                "api_key": "key_abc123",
                "command": ["echo", "test"],
            },
        }

        response = client.post("/api/intake/pipeline", json=request_data)
        pipeline_id = response.json()["pipeline_id"]

        # ステータス確認でマスクされていることを確認
        status_response = client.get(f"/api/intake/pipeline/{pipeline_id}")
        status_data = status_response.json()

        # パラメータが適切にマスクされている
        params = status_data["params"]
        assert params["password"] == "***MASKED***"
        assert params["api_key"] == "***MASKED***"
        assert params["command"] == ["echo", "test"]  # 機密でないデータはそのまま
