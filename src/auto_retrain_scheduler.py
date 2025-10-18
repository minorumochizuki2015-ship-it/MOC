"""
自動再訓練スケジューラー
ML最適化タスク008の一部として、定期的なモデル再訓練を自動化
"""

import asyncio
import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

from src.ai_prediction import QualityPredictor, ResourceDemandPredictor


class AutoRetrainScheduler:
    """自動再訓練スケジューラー"""

    def __init__(self, config_path: str = "config/monitoring.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.task: Optional[asyncio.Task] = None

        # デフォルト設定
        self.default_config = {
            "retrain_interval_hours": 6,
            "min_training_samples": 100,
            "feature_importance_threshold": 0.1,
            "performance_threshold": 0.8,
            "max_retries": 3,
            "retry_delay_minutes": 30,
        }

        self.load_config()

    def load_config(self) -> dict:
        """設定ファイル読み込み"""
        try:
            if self.config_path.exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self.config = config.get("ai_prediction", self.default_config)
            else:
                self.config = self.default_config
                self.logger.warning(f"Config file not found: {self.config_path}, using defaults")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self.config = self.default_config

        return self.config

    def check_training_data_availability(self) -> Dict[str, bool]:
        """学習データの可用性チェック"""
        results = {
            "quality_data_available": False,
            "resource_data_available": False,
            "quality_sample_count": 0,
            "resource_sample_count": 0,
        }

        try:
            # 品質データチェック
            db_path = Path("data/quality_metrics.db")
            if db_path.exists():
                with closing(sqlite3.connect(db_path, timeout=30, check_same_thread=False)) as conn:
                    with conn:
                        cursor = conn.execute("SELECT COUNT(*) FROM quality_metrics")
                        count = cursor.fetchone()[0]
                        results["quality_sample_count"] = count
                        results["quality_data_available"] = (
                            count >= self.config["min_training_samples"]
                        )

            # リソースデータチェック（仮想的なチェック）
            # 実際の実装では適切なデータソースを確認
            results["resource_sample_count"] = 150  # ダミー値
            results["resource_data_available"] = True

        except Exception as e:
            self.logger.error(f"Failed to check training data: {e}")

        return results

    async def retrain_models(self) -> Dict[str, any]:
        """モデル再訓練実行"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "quality_model": {"success": False, "metrics": {}},
            "resource_model": {"success": False, "metrics": {}},
            "errors": [],
        }

        try:
            # 品質予測モデル再訓練
            self.logger.info("Starting quality model retraining...")
            quality_predictor = QualityPredictor()

            try:
                quality_metrics = quality_predictor.train_model()
                results["quality_model"]["success"] = True
                results["quality_model"]["metrics"] = quality_metrics
                self.logger.info(
                    f"Quality model retrained successfully: accuracy={quality_metrics.get('accuracy', 'N/A')}"
                )
            except Exception as e:
                error_msg = f"Quality model retraining failed: {e}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)

            # リソース需要予測モデル再訓練
            self.logger.info("Starting resource model retraining...")
            resource_predictor = ResourceDemandPredictor()

            try:
                resource_metrics = resource_predictor.train_model()
                results["resource_model"]["success"] = True
                results["resource_model"]["metrics"] = resource_metrics
                self.logger.info(
                    f"Resource model retrained successfully: R²={resource_metrics.get('r2_score', 'N/A')}"
                )
            except Exception as e:
                error_msg = f"Resource model retraining failed: {e}"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)

        except Exception as e:
            error_msg = f"Unexpected error during retraining: {e}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def save_retrain_log(self, results: Dict[str, any]) -> None:
        """再訓練ログ保存"""
        try:
            log_dir = Path("data/logs/retrain")
            log_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = log_dir / f"retrain_log_{timestamp}.json"

            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Retrain log saved: {log_file}")

        except Exception as e:
            self.logger.error(f"Failed to save retrain log: {e}")

    async def schedule_loop(self) -> None:
        """スケジュール実行ループ"""
        self.logger.info("Auto retrain scheduler started")

        while self.is_running:
            try:
                # データ可用性チェック
                data_status = self.check_training_data_availability()
                self.logger.info(f"Training data status: {data_status}")

                if data_status["quality_data_available"] or data_status["resource_data_available"]:
                    # 再訓練実行
                    results = await self.retrain_models()

                    # ログ保存
                    self.save_retrain_log(results)

                    # 成功/失敗の判定
                    success_count = sum(
                        [results["quality_model"]["success"], results["resource_model"]["success"]]
                    )

                    if success_count > 0:
                        self.logger.info(
                            f"Retraining completed: {success_count}/2 models successful"
                        )
                    else:
                        self.logger.warning("All model retraining failed")
                else:
                    self.logger.info("Insufficient training data, skipping retraining")

                # 次回実行まで待機
                interval_hours = self.config["retrain_interval_hours"]
                wait_seconds = interval_hours * 3600
                self.logger.info(f"Next retraining in {interval_hours} hours")

                await asyncio.sleep(wait_seconds)

            except asyncio.CancelledError:
                self.logger.info("Retrain scheduler cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in schedule loop: {e}")
                # エラー時は短い間隔で再試行
                await asyncio.sleep(self.config.get("retry_delay_minutes", 30) * 60)

    async def start(self) -> None:
        """スケジューラー開始"""
        if self.is_running:
            self.logger.warning("Scheduler is already running")
            return

        self.is_running = True
        self.task = asyncio.create_task(self.schedule_loop())
        self.logger.info("Auto retrain scheduler started")

    async def stop(self) -> None:
        """スケジューラー停止"""
        if not self.is_running:
            return

        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        self.logger.info("Auto retrain scheduler stopped")

    def get_status(self) -> Dict[str, any]:
        """スケジューラー状態取得"""
        return {
            "is_running": self.is_running,
            "config": self.config,
            "next_run_estimate": (
                (
                    datetime.now() + timedelta(hours=self.config["retrain_interval_hours"])
                ).isoformat()
                if self.is_running
                else None
            ),
        }


# グローバルインスタンス
scheduler = AutoRetrainScheduler()


async def main():
    """テスト実行"""
    import logging

    logging.basicConfig(level=logging.INFO)

    try:
        await scheduler.start()
        # テスト用に短時間実行
        await asyncio.sleep(10)
    finally:
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(main())
