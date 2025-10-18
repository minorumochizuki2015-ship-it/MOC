#!/usr/bin/env python3
"""
SSE (Server-Sent Events) 統合テスト
リアルタイム通信機能の独立性と動作を検証
"""

import json
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orch_dashboard_refactored import OrchDashboardRefactored

from src.blueprints.sse_routes import SSEManager, sse_bp


class TestSSEIntegration:
    """SSE統合テストクラス"""

    @pytest.fixture
    def dashboard(self):
        """テスト用ダッシュボードインスタンス"""
        dashboard = OrchDashboardRefactored()
        dashboard.app.config["TESTING"] = True
        return dashboard

    @pytest.fixture
    def client(self, dashboard):
        """テスト用Flaskクライアント"""
        return dashboard.app.test_client()

    @pytest.fixture
    def sse_manager(self):
        """テスト用SSEマネージャー"""
        return SSEManager()

    def test_sse_manager_initialization(self, sse_manager):
        """SSEマネージャーの初期化テスト"""
        assert sse_manager.clients == {}
        assert sse_manager.client_counter == 0

    def test_sse_client_registration(self, sse_manager):
        """SSEクライアント登録テスト"""
        # モッククライアントを作成
        mock_client = MagicMock()

        # クライアント登録
        client_id = sse_manager.add_client(mock_client)

        assert client_id in sse_manager.clients
        assert sse_manager.clients[client_id] == mock_client
        assert sse_manager.client_counter == 1

    def test_sse_client_removal(self, sse_manager):
        """SSEクライアント削除テスト"""
        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        # クライアント削除
        sse_manager.remove_client(client_id)

        assert client_id not in sse_manager.clients

    def test_sse_broadcast_message(self, sse_manager):
        """SSEブロードキャストテスト"""
        # 複数のモッククライアントを登録
        mock_clients = []
        client_ids = []

        for i in range(3):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            mock_clients.append(mock_client)
            client_ids.append(client_id)

        # メッセージをブロードキャスト
        test_message = {"type": "test", "data": "hello"}
        sse_manager.broadcast(test_message)

        # 全クライアントにメッセージが送信されたことを確認
        for mock_client in mock_clients:
            mock_client.put.assert_called_once()

    def test_sse_health_endpoint(self, client):
        """SSEヘルスエンドポイントテスト"""
        response = client.get("/events/health")
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["status"] == "healthy"
        assert "clients" in data
        assert "uptime" in data

    def test_sse_broadcast_endpoint(self, client):
        """SSEブロードキャストエンドポイントテスト"""
        test_data = {
            "type": "test_broadcast",
            "message": "テストメッセージ",
            "timestamp": time.time(),
        }

        response = client.post(
            "/events/broadcast", data=json.dumps(test_data), content_type="application/json"
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["success"] is True

    def test_sse_events_endpoint_structure(self, client):
        """SSEイベントエンドポイント構造テスト"""
        # SSEエンドポイントへのGETリクエスト
        response = client.get("/events")

        # SSEレスポンスの基本構造を確認
        assert response.status_code == 200
        assert response.content_type.startswith("text/event-stream")
        assert "Cache-Control" in response.headers
        assert response.headers["Cache-Control"] == "no-cache"

    @pytest.mark.integration
    def test_sse_real_connection(self, dashboard):
        """実際のSSE接続テスト（統合テスト）"""
        # テスト用サーバーを別スレッドで起動
        server_thread = threading.Thread(
            target=lambda: dashboard.app.run(port=5002, debug=False, use_reloader=False),
            daemon=True,
        )
        server_thread.start()
        time.sleep(2)  # サーバー起動待機

        try:
            # SSEエンドポイントに接続
            response = requests.get("http://localhost:5002/events", stream=True, timeout=5)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")

            # ブロードキャストテスト
            broadcast_data = {"type": "integration_test", "message": "統合テスト"}
            broadcast_response = requests.post(
                "http://localhost:5002/events/broadcast", json=broadcast_data, timeout=5
            )
            assert broadcast_response.status_code == 200

        except requests.exceptions.RequestException as e:
            pytest.skip(f"統合テストスキップ: サーバー接続エラー {e}")

    def test_sse_error_handling(self, sse_manager):
        """SSEエラーハンドリングテスト"""
        # 無効なクライアントIDでの削除
        sse_manager.remove_client("invalid_id")  # エラーが発生しないことを確認

        # ブロードキャスト時のクライアントエラー
        mock_client = MagicMock()
        mock_client.put.side_effect = Exception("クライアントエラー")

        client_id = sse_manager.add_client(mock_client)
        sse_manager.broadcast({"type": "error_test"})

        # エラーが発生してもクライアントが削除されることを確認
        assert client_id not in sse_manager.clients

    def test_sse_concurrent_clients(self, sse_manager):
        """SSE同時接続クライアントテスト"""
        # 複数クライアントの同時登録
        clients = []
        for i in range(10):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            clients.append((client_id, mock_client))

        assert len(sse_manager.clients) == 10

        # 同時ブロードキャスト
        test_message = {"type": "concurrent_test", "data": f"message_{time.time()}"}
        sse_manager.broadcast(test_message)

        # 全クライアントが呼び出されたことを確認
        for client_id, mock_client in clients:
            mock_client.put.assert_called_once()

    def test_sse_message_formatting(self, sse_manager):
        """SSEメッセージフォーマットテスト"""
        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        # 様々な形式のメッセージをテスト
        test_messages = [
            {"type": "string", "data": "simple string"},
            {"type": "object", "data": {"key": "value", "number": 123}},
            {"type": "array", "data": [1, 2, 3, "test"]},
            {"type": "unicode", "data": "日本語メッセージ🚀"},
        ]

        for message in test_messages:
            sse_manager.broadcast(message)
            mock_client.put.assert_called()
            mock_client.reset_mock()


if __name__ == "__main__":
    # テスト実行
    pytest.main([__file__, "-v", "--tb=short"])
