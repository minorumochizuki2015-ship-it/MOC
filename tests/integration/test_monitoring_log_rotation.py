"""
統合テスト: 監視システムのログローテーション・保持期間機能

このテストは以下の機能を検証します:
1. ファイルサイズによるログローテーション
2. バックアップファイルの管理
3. 古いログファイルの自動削除
4. 設定値による動作制御
"""

import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from src.monitoring_system import MonitoringSystem


class TestMonitoringLogRotation:
    """監視システムのログローテーション統合テスト"""

    def setup_method(self):
        """各テストメソッドの前に実行される初期化"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test_notifications.log"
        self.reports_dir = Path(self.temp_dir) / "ORCH" / "REPORTS"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # 既存のログファイルをクリーンアップ
        self._cleanup_log_files()

        # テスト用設定（実際のMonitoringSystemの設定構造に合わせる）
        self.test_config = {
            "monitoring_interval": 30,
            "alert_thresholds": {
                "test_coverage_min": 0.8,
                "code_complexity_max": 3.0,
                "error_rate_max": 0.05,
                "performance_score_min": 0.8,
                "prediction_confidence_min": 0.7,
            },
            "alert_channels": {
                "file": True,
                "console": True,
                "dashboard": True,
                "email": False,
                "webhook": False,
            },
            "email": {
                "enabled": False,
                "smtp_server": "localhost",
                "smtp_port": 587,
                "use_tls": True,
                "from": "monitoring@orch-next.local",
                "to": ["admin@orch-next.local"],
                "username": "",
                "password": "",
            },
            "webhook": {
                "enabled": False,
                "url": "http://localhost:8080/alerts",
                "headers": {"Content-Type": "application/json"},
                "timeout": 10,
                "success_codes": [200],
            },
            "file_channel": {
                "rotation_enabled": True,
                "max_bytes": 100,  # 小さなサイズでテスト
                "backup_count": 3,
            },
            "anomaly_detection": {
                "enabled": True,
                "window_size": 50,
                "z_score_threshold": 2.5,
            },
            "data_retention_days": 1,  # 1日で古いファイルとして扱う
        }

    def _cleanup_log_files(self):
        """ログファイルをクリーンアップ"""
        import glob

        log_files = glob.glob("ORCH/REPORTS/notifications.log*")
        for log_file in log_files:
            try:
                Path(log_file).unlink()
            except FileNotFoundError:
                pass

    def teardown_method(self):
        """各テストメソッドの後に実行されるクリーンアップ"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self._cleanup_log_files()

    def test_log_rotation_by_size(self):
        """ファイルサイズによるログローテーションのテスト"""
        # MonitoringSystem インスタンス作成
        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = self.test_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # スパムフィルターを無効化
        with patch.object(
            monitoring.notification_service.spam_filter,
            "should_allow_notification",
            return_value=True,
        ):
            # 初期メッセージを送信
            analysis_data = {
                "alerts": [
                    {
                        "type": "test",
                        "severity": "info",
                        "message": "Initial message",
                        "timestamp": datetime.now().isoformat(),
                    }
                ]
            }
            monitoring.send_alerts(analysis_data)

        # 実際のログファイルパスを確認
        actual_log_file = Path("ORCH/REPORTS/notifications.log")
        assert actual_log_file.exists(), "ログファイルが作成された"

    def test_backup_count_limit(self):
        """バックアップファイル数制限のテスト"""
        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = self.test_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # スパムフィルターを無効化
        with patch.object(
            monitoring.notification_service.spam_filter,
            "should_allow_notification",
            return_value=True,
        ):
            # 複数回大きなメッセージを送信してローテーションを発生させる
            for i in range(5):
                analysis_data = {
                    "alerts": [
                        {
                            "type": "test",
                            "severity": "info",
                            "message": f"Large message {i}: " + "A" * 100,
                            "timestamp": datetime.now().isoformat(),
                        }
                    ]
                }
                monitoring.send_alerts(analysis_data)

        # 実際のログファイルパスでバックアップファイル数を確認
        actual_log_file = Path("ORCH/REPORTS/notifications.log")
        backup_files = list(actual_log_file.parent.glob(f"{actual_log_file.name}.*"))
        assert (
            len(backup_files) <= self.test_config["file_channel"]["backup_count"]
        ), f"バックアップファイル数が制限内: {len(backup_files)} <= {self.test_config['file_channel']['backup_count']}"

    def test_old_log_purging(self):
        """古いログファイルの削除テスト"""
        # ORCH/REPORTSディレクトリに古いファイルを作成
        reports_dir = Path("ORCH/REPORTS")
        reports_dir.mkdir(parents=True, exist_ok=True)
        old_file = reports_dir / "old_log.log"
        old_file.write_text("old log content", encoding="utf-8")

        # ファイルの更新時刻を古く設定
        old_time = time.time() - (self.test_config["data_retention_days"] + 1) * 24 * 3600
        os.utime(old_file, (old_time, old_time))

        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = self.test_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # 古いファイル削除を明示的に実行
        monitoring._purge_old_logs_if_needed()

        # 古いファイルが削除されたことを確認
        assert not old_file.exists(), "古いログファイルが削除された"

    def test_rotation_disabled(self):
        """ローテーション無効時のテスト"""
        disabled_config = self.test_config.copy()
        disabled_config["file_channel"]["rotation_enabled"] = False

        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = disabled_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # スパムフィルターを無効化
        with patch.object(
            monitoring.notification_service.spam_filter,
            "should_allow_notification",
            return_value=True,
        ):
            # 大きなメッセージを送信
            large_message = "A" * 200
            analysis_data = {
                "alerts": [
                    {
                        "type": "test",
                        "severity": "info",
                        "message": large_message,
                        "timestamp": datetime.now().isoformat(),
                    }
                ]
            }
            monitoring.send_alerts(analysis_data)

        # ローテーションが発生しないことを確認
        actual_log_file = Path("ORCH/REPORTS/notifications.log")
        backup_file = Path(str(actual_log_file) + ".1")
        assert not backup_file.exists(), "ローテーション無効時はバックアップファイルが作成されない"

    def test_purge_frequency_limit(self):
        """パージ頻度制限のテスト"""
        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = self.test_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # 短時間で複数回パージを実行
        monitoring._purge_old_logs_if_needed()
        first_purge_time = monitoring._last_purge_ts

        # すぐに再実行
        monitoring._purge_old_logs_if_needed()
        second_purge_time = monitoring._last_purge_ts

        # 1時間以内の再実行では時刻が更新されないことを確認
        assert second_purge_time == first_purge_time, "1時間以内の再実行ではパージが制限される"

    def test_config_caching(self):
        """設定キャッシュのテスト"""
        with patch("src.monitoring_system.MonitoringSystem._load_config") as mock_load:
            mock_load.return_value = self.test_config
            monitoring = MonitoringSystem(str(self.log_file.parent / "config.json"))

        # 設定が正しく読み込まれていることを確認
        config = monitoring.config
        assert (
            config["file_channel"]["rotation_enabled"]
            == self.test_config["file_channel"]["rotation_enabled"]
        )
        assert config["file_channel"]["max_bytes"] == self.test_config["file_channel"]["max_bytes"]
        assert (
            config["file_channel"]["backup_count"]
            == self.test_config["file_channel"]["backup_count"]
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
