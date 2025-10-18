#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# テスト対象のインポート
from src.auto_retrain_scheduler import AutoRetrainScheduler


class TestAutoRetrainScheduler(unittest.TestCase):
    """自動再訓練スケジューラーのテストクラス"""

    def setUp(self):
        """テストセットアップ"""
        self.scheduler = AutoRetrainScheduler()

        # テスト用の一時ディレクトリ
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "monitoring.json"

        # テスト用設定ファイル作成
        test_config = {"ai_prediction": {"retrain_interval_hours": 1, "min_training_samples": 10}}
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(test_config, f)

    def tearDown(self):
        """テストクリーンアップ"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_config(self):
        """設定読み込みテスト"""
        # 正常な設定ファイル
        with patch("src.auto_retrain_scheduler.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = (
                json.dumps(
                    {"ai_prediction": {"retrain_interval_hours": 2, "min_training_samples": 20}}
                )
            )

            config = self.scheduler.load_config()
            self.assertEqual(config["retrain_interval_hours"], 6)
            self.assertEqual(config["min_training_samples"], 100)

    def test_get_status(self):
        """状態取得テスト"""
        status = self.scheduler.get_status()

        self.assertIn("is_running", status)
        self.assertIn("config", status)
        self.assertIn("next_run_estimate", status)
        self.assertIsInstance(status["is_running"], bool)

    @patch("src.auto_retrain_scheduler.QualityPredictor")
    @patch("src.auto_retrain_scheduler.ResourceDemandPredictor")
    def test_retrain_models(self, mock_resource_predictor, mock_quality_predictor):
        """モデル再訓練テスト"""
        # モックの設定
        mock_quality_instance = MagicMock()
        mock_quality_instance.train_model.return_value = {"accuracy": 0.85}
        mock_quality_predictor.return_value = mock_quality_instance

        mock_resource_instance = MagicMock()
        mock_resource_instance.train_model.return_value = {"mse": 0.15}
        mock_resource_predictor.return_value = mock_resource_instance

        # 再訓練実行（同期的にテスト）
        import asyncio

        results = asyncio.run(self.scheduler.retrain_models())

        # 結果検証
        self.assertIn("quality_model", results)
        self.assertIn("resource_model", results)
        self.assertEqual(results["quality_model"]["success"], True)
        self.assertEqual(results["resource_model"]["success"], True)

    @patch("src.auto_retrain_scheduler.QualityPredictor")
    def test_retrain_models_with_error(self, mock_quality_predictor):
        """エラー時の再訓練テスト"""
        # エラーを発生させるモック
        mock_quality_predictor.side_effect = Exception("Training failed")

        import asyncio

        results = asyncio.run(self.scheduler.retrain_models())

        # エラー結果検証
        self.assertIn("quality_model", results)
        self.assertIn("errors", results)
        self.assertTrue(len(results["errors"]) > 0)

    def test_save_retrain_log(self):
        """再訓練ログ保存テスト"""
        test_results = {
            "quality_model": {"status": "success", "accuracy": 0.85},
            "resource_model": {"status": "success", "mse": 0.15},
        }

        with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
            with patch("src.auto_retrain_scheduler.Path") as mock_path:
                mock_path.return_value.parent.mkdir = MagicMock()

                self.scheduler.save_retrain_log(test_results)

                # ファイル書き込み確認
                mock_file.assert_called_once()
                handle = mock_file.return_value.__enter__.return_value
                written_content = "".join(call.args[0] for call in handle.write.call_args_list)
                self.assertIn("quality_model", written_content)
                self.assertIn("resource_model", written_content)

    def test_start_stop_scheduler(self):
        """スケジューラー開始・停止テスト"""
        import asyncio

        async def run_test():
            # 短時間でテストを終了するため
            self.scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒

            # 開始
            start_task = asyncio.create_task(self.scheduler.start())

            # 少し待ってから停止
            await asyncio.sleep(0.1)
            await self.scheduler.stop()

            # タスクの完了を待つ
            try:
                await asyncio.wait_for(start_task, timeout=1.0)
            except asyncio.TimeoutError:
                start_task.cancel()

            # 停止状態確認
            self.assertFalse(self.scheduler.is_running)

        asyncio.run(run_test())


class TestAutoRetrainIntegration(unittest.TestCase):
    """自動再訓練統合テスト"""

    def test_full_integration(self):
        """完全統合テスト"""
        import asyncio

        async def run_integration_test():
            scheduler = AutoRetrainScheduler()

            # 状態確認
            status = scheduler.get_status()
            assert "is_running" in status
            assert status["is_running"] is False

            # 短時間実行テスト
            scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒

            # 開始・停止テスト
            start_task = asyncio.create_task(scheduler.start())
            await asyncio.sleep(0.1)
            await scheduler.stop()

            try:
                await asyncio.wait_for(start_task, timeout=1.0)
            except asyncio.TimeoutError:
                start_task.cancel()

        asyncio.run(run_integration_test())


def test_scheduler_integration():
    """pytest用統合テスト"""
    import asyncio

    async def run_test():
        scheduler = AutoRetrainScheduler()

        # 状態確認
        status = scheduler.get_status()
        assert "is_running" in status
        assert status["is_running"] is False

        # 短時間実行テスト
        scheduler.config["retrain_interval_hours"] = 0.001  # 3.6秒

        # 開始・停止テスト
        start_task = asyncio.create_task(scheduler.start())
        await asyncio.sleep(0.1)
        await scheduler.stop()

        try:
            await asyncio.wait_for(start_task, timeout=1.0)
        except asyncio.TimeoutError:
            start_task.cancel()

    asyncio.run(run_test())


if __name__ == "__main__":
    # 同期テスト実行
    unittest.main(argv=[""], exit=False, verbosity=2)

    # 非同期テスト実行
    print("\n=== 非同期テスト実行 ===")
    asyncio.run(test_scheduler_integration())
