#!/usr/bin/env python3
"""
SSE (Server-Sent Events) 長時間接続テスト
リアルタイム通信の安定性と耐久性を検証
"""

import json
import os
import queue
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orch_dashboard_refactored import OrchDashboardRefactored

from src.blueprints.sse_routes import SSEManager


class TestSSELongevity:
    """SSE長時間接続テストクラス"""

    @pytest.fixture
    def dashboard(self):
        """テスト用ダッシュボードインスタンス"""
        dashboard = OrchDashboardRefactored()
        dashboard.app.config["TESTING"] = True
        return dashboard

    @pytest.fixture
    def sse_manager(self):
        """テスト用SSEマネージャー"""
        return SSEManager()

    def test_sse_manager_memory_leak(self, sse_manager):
        """SSEマネージャーのメモリリークテスト"""
        initial_clients = len(sse_manager.clients)

        # 大量のクライアントを追加・削除
        client_ids = []
        for i in range(100):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            client_ids.append(client_id)

        assert len(sse_manager.clients) == initial_clients + 100

        # 全クライアントを削除
        for client_id in client_ids:
            sse_manager.remove_client(client_id)

        assert len(sse_manager.clients) == initial_clients

    def test_sse_concurrent_broadcast_stress(self, sse_manager):
        """SSE同時ブロードキャストストレステスト"""
        # 複数クライアントを登録
        clients = []
        for i in range(50):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            clients.append((client_id, mock_client))

        # 複数スレッドから同時ブロードキャスト
        def broadcast_worker(worker_id):
            for i in range(10):
                message = {
                    "type": "stress_test",
                    "worker_id": worker_id,
                    "message_id": i,
                    "data": f"message_{worker_id}_{i}",
                }
                sse_manager.broadcast(message)
                time.sleep(0.01)  # 短い間隔

        # 5つのワーカースレッドを起動
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=broadcast_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()

        # 全スレッドの完了を待機
        for thread in threads:
            thread.join()

        # 全クライアントが適切に呼び出されたことを確認
        for client_id, mock_client in clients:
            assert mock_client.put.call_count >= 10  # 最低10回は呼び出される

    def test_sse_client_error_recovery(self, sse_manager):
        """SSEクライアントエラー回復テスト"""
        # 正常なクライアントと異常なクライアントを混在
        normal_clients = []
        error_clients = []

        # 正常なクライアント
        for i in range(5):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            normal_clients.append((client_id, mock_client))

        # エラーを発生させるクライアント
        for i in range(3):
            mock_client = MagicMock()
            mock_client.put.side_effect = Exception("Client error")
            client_id = sse_manager.add_client(mock_client)
            error_clients.append((client_id, mock_client))

        initial_client_count = len(sse_manager.clients)

        # ブロードキャスト実行
        sse_manager.broadcast({"type": "error_test", "data": "test"})

        # エラークライアントが削除され、正常クライアントは残ることを確認
        assert len(sse_manager.clients) == len(normal_clients)

        # 正常クライアントは呼び出されている
        for client_id, mock_client in normal_clients:
            mock_client.put.assert_called_once()

    def test_sse_high_frequency_messages(self, sse_manager):
        """SSE高頻度メッセージテスト"""
        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        # 高頻度でメッセージを送信
        message_count = 1000
        start_time = time.time()

        for i in range(message_count):
            message = {"type": "high_frequency", "sequence": i, "timestamp": time.time()}
            sse_manager.broadcast(message)

        end_time = time.time()
        duration = end_time - start_time

        # パフォーマンス確認
        assert duration < 5.0  # 5秒以内に完了
        assert mock_client.put.call_count == message_count

        print(f"高頻度メッセージテスト: {message_count}メッセージを{duration:.2f}秒で処理")

    def test_sse_large_message_handling(self, sse_manager):
        """SSE大容量メッセージハンドリングテスト"""
        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        # 大容量メッセージを作成
        large_data = {
            "type": "large_message",
            "data": {
                "large_array": list(range(10000)),
                "large_string": "x" * 50000,
                "nested_data": {"level1": {"level2": {"level3": ["data"] * 1000}}},
            },
        }

        # 大容量メッセージのブロードキャスト
        start_time = time.time()
        sse_manager.broadcast(large_data)
        end_time = time.time()

        # パフォーマンスと正常性を確認
        assert end_time - start_time < 1.0  # 1秒以内に完了
        mock_client.put.assert_called_once()

        # 呼び出されたメッセージの内容を確認
        called_message = mock_client.put.call_args[0][0]
        assert called_message["type"] == "large_message"
        assert len(called_message["data"]["large_array"]) == 10000

    def test_sse_unicode_message_handling(self, sse_manager):
        """SSE Unicode メッセージハンドリングテスト"""
        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        # 様々なUnicodeメッセージをテスト
        unicode_messages = [
            {"type": "japanese", "data": "こんにちは世界 🌍"},
            {"type": "chinese", "data": "你好世界 🇨🇳"},
            {"type": "arabic", "data": "مرحبا بالعالم 🌙"},
            {"type": "emoji", "data": "🚀🎉🔥💯⭐🌟✨🎯"},
            {"type": "mixed", "data": "Hello 世界 🌍 مرحبا 你好"},
        ]

        for message in unicode_messages:
            sse_manager.broadcast(message)
            mock_client.put.assert_called()

            # 呼び出されたメッセージの内容を確認
            called_message = mock_client.put.call_args[0][0]
            assert called_message["type"] == message["type"]
            assert called_message["data"] == message["data"]

            mock_client.reset_mock()

    @pytest.mark.slow
    def test_sse_extended_connection_simulation(self, sse_manager):
        """SSE拡張接続シミュレーションテスト"""
        # 長時間接続をシミュレート
        connection_duration = 30  # 30秒間のテスト
        message_interval = 1  # 1秒間隔

        mock_client = MagicMock()
        client_id = sse_manager.add_client(mock_client)

        start_time = time.time()
        message_count = 0

        while time.time() - start_time < connection_duration:
            message = {"type": "heartbeat", "timestamp": time.time(), "sequence": message_count}
            sse_manager.broadcast(message)
            message_count += 1
            time.sleep(message_interval)

        # 接続が維持され、メッセージが正常に送信されたことを確認
        assert mock_client.put.call_count == message_count
        assert message_count >= connection_duration / message_interval - 1

        print(f"拡張接続テスト: {connection_duration}秒間で{message_count}メッセージを送信")

    def test_sse_stats_accuracy(self, sse_manager):
        """SSE統計情報精度テスト"""
        initial_stats = sse_manager.get_stats()
        initial_time = time.time()

        # クライアントを追加
        clients = []
        for i in range(10):
            mock_client = MagicMock()
            client_id = sse_manager.add_client(mock_client)
            clients.append(client_id)

        # 統計情報を確認
        stats = sse_manager.get_stats()
        assert stats["connected_clients"] == 10
        assert stats["status"] == "healthy"
        assert stats["uptime"] >= 0

        # 時間経過を確実にするため少し待機
        time.sleep(0.1)

        # 一部クライアントを削除
        for i in range(5):
            sse_manager.remove_client(clients[i])

        # 統計情報の更新を確認
        updated_stats = sse_manager.get_stats()
        assert updated_stats["connected_clients"] == 5
        assert updated_stats["uptime"] >= stats["uptime"]  # 等しいか大きい


if __name__ == "__main__":
    # テスト実行（slowマークのテストは除外）
    pytest.main([__file__, "-v", "--tb=short", "-m", "not slow"])
