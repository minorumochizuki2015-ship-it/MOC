"""
リアルタイム監視システム
品質メトリクスの自動収集とアラート機能
"""

import json
import logging
import smtplib
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

from src.ai_prediction import QualityPredictor


class AnomalyDetector:
    """異常検知エンジン"""

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.metric_history = {
            "test_coverage": deque(maxlen=window_size),
            "code_complexity": deque(maxlen=window_size),
            "error_rate": deque(maxlen=window_size),
            "performance_score": deque(maxlen=window_size),
        }
        self.baseline_stats = {}

    def update_history(self, metrics: Dict) -> None:
        """メトリクス履歴更新"""
        for key in self.metric_history:
            if key in metrics:
                self.metric_history[key].append(metrics[key])

    def calculate_baseline(self) -> None:
        """ベースライン統計計算"""
        for metric, history in self.metric_history.items():
            if len(history) >= 10:  # 最低10データポイント必要
                values = np.array(history)
                self.baseline_stats[metric] = {
                    "mean": np.mean(values),
                    "std": np.std(values),
                    "min": np.min(values),
                    "max": np.max(values),
                    "q25": np.percentile(values, 25),
                    "q75": np.percentile(values, 75),
                }

    def detect_anomalies(self, current_metrics: Dict) -> List[Dict]:
        """異常検知"""
        anomalies = []

        if not self.baseline_stats:
            return anomalies

        for metric, value in current_metrics.items():
            if metric not in self.baseline_stats:
                continue

            stats = self.baseline_stats[metric]

            # Z-score異常検知
            z_score = abs(value - stats["mean"]) / (stats["std"] + 1e-8)
            if z_score > 2.5:  # 2.5σを超える場合
                anomalies.append(
                    {
                        "type": "statistical_anomaly",
                        "metric": metric,
                        "value": value,
                        "z_score": z_score,
                        "severity": "high" if z_score > 3.0 else "medium",
                        "message": f"{metric}が統計的異常値: {value:.3f} (Z-score: {z_score:.2f})",
                    }
                )

            # IQR異常検知
            iqr = stats["q75"] - stats["q25"]
            lower_bound = stats["q25"] - 1.5 * iqr
            upper_bound = stats["q75"] + 1.5 * iqr

            if value < lower_bound or value > upper_bound:
                anomalies.append(
                    {
                        "type": "iqr_anomaly",
                        "metric": metric,
                        "value": value,
                        "bounds": [lower_bound, upper_bound],
                        "severity": "medium",
                        "message": f"{metric}がIQR範囲外: {value:.3f} (範囲: {lower_bound:.3f}-{upper_bound:.3f})",
                    }
                )

            # トレンド異常検知
            if len(self.metric_history[metric]) >= 5:
                recent_values = list(self.metric_history[metric])[-5:]
                trend = np.polyfit(range(len(recent_values)), recent_values, 1)[0]

                # 急激な変化を検知
                if abs(trend) > stats["std"] * 0.5:
                    anomalies.append(
                        {
                            "type": "trend_anomaly",
                            "metric": metric,
                            "trend": trend,
                            "severity": "medium",
                            "message": f"{metric}に急激な変化: トレンド {trend:.4f}",
                        }
                    )

        return anomalies


class AlertManager:
    """アラート管理システム"""

    def __init__(self, config: Dict):
        self.config = config
        self.alert_history = deque(maxlen=1000)
        self.suppression_rules = {}
        self.escalation_rules = config.get("escalation_rules", {})

    def should_suppress_alert(self, alert: Dict) -> bool:
        """アラート抑制判定"""
        alert_key = f"{alert['type']}_{alert.get('metric', 'general')}"

        # 同じアラートの重複抑制（5分間）
        now = datetime.now()
        for hist_alert in reversed(self.alert_history):
            if hist_alert.get("key") == alert_key and (now - hist_alert["timestamp"]).seconds < 300:
                return True

        return False

    def escalate_alert(self, alert: Dict) -> Dict:
        """アラートエスカレーション"""
        escalated = alert.copy()

        # 重要度に基づくエスカレーション
        if alert["severity"] == "critical":
            escalated["escalated"] = True
            escalated["notification_channels"] = ["email", "sms", "dashboard"]
        elif alert["severity"] == "high":
            escalated["notification_channels"] = ["email", "dashboard"]
        else:
            escalated["notification_channels"] = ["dashboard"]

        return escalated

    def process_alert(self, alert: Dict) -> Optional[Dict]:
        """アラート処理"""
        if self.should_suppress_alert(alert):
            return None

        # アラート履歴に追加
        alert_record = {
            "alert": alert,
            "timestamp": datetime.now(),
            "key": f"{alert['type']}_{alert.get('metric', 'general')}",
        }
        self.alert_history.append(alert_record)

        # エスカレーション処理
        return self.escalate_alert(alert)


class NotificationService:
    """通知サービス"""

    def __init__(self, config: Dict):
        self.config = config
        self.email_config = config.get("email", {})
        self.webhook_config = config.get("webhook", {})

    def send_email_alert(self, alert: Dict) -> bool:
        """メールアラート送信"""
        try:
            if not self.email_config.get("enabled", False):
                return False

            msg = MIMEMultipart()
            msg["From"] = self.email_config["from"]
            msg["To"] = ", ".join(self.email_config["to"])
            msg["Subject"] = f"[ORCH-Next Alert] {alert['severity'].upper()}: {alert['type']}"

            body = f"""
アラート詳細:
- 種類: {alert['type']}
- 重要度: {alert['severity']}
- メッセージ: {alert['message']}
- 時刻: {datetime.now().isoformat()}

システム: ORCH-Next 監視システム
            """

            msg.attach(MIMEText(body, "plain", "utf-8"))

            server = smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"])
            if self.email_config.get("use_tls", True):
                server.starttls()
            if self.email_config.get("username"):
                server.login(self.email_config["username"], self.email_config["password"])

            server.send_message(msg)
            server.quit()

            return True

        except Exception as e:
            logging.error(f"Email alert failed: {e}")
            return False

    def send_webhook_alert(self, alert: Dict) -> bool:
        """Webhook通知送信"""
        try:
            if not self.webhook_config.get("enabled", False):
                return False

            import requests

            payload = {
                "alert_type": alert["type"],
                "severity": alert["severity"],
                "message": alert["message"],
                "timestamp": datetime.now().isoformat(),
                "system": "ORCH-Next",
            }

            response = requests.post(
                self.webhook_config["url"],
                json=payload,
                headers=self.webhook_config.get("headers", {}),
                timeout=10,
            )

            return response.status_code == 200

        except Exception as e:
            logging.error(f"Webhook alert failed: {e}")
            return False


class MonitoringSystem:
    """品質監視システム"""

    def __init__(self, config_path: str = "config/monitoring.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.predictor = QualityPredictor()
        self.anomaly_detector = AnomalyDetector()
        self.alert_manager = AlertManager(self.config)
        self.notification_service = NotificationService(self.config)
        self.is_running = False
        self.monitor_thread = None

        # ログ設定
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("data/logs/current/monitoring.log"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)

    def _load_config(self) -> Dict:
        """設定読み込み"""
        default_config = {
            "monitoring_interval": 30,  # 秒
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
            },
            "anomaly_detection": {
                "enabled": True,
                "window_size": 50,
                "z_score_threshold": 2.5,
            },
            "data_retention_days": 30,
        }

        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # デフォルト設定とマージ
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                self.logger.warning(f"Config load failed, using defaults: {e}")

        # デフォルト設定を保存
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)

        return default_config

    def collect_current_metrics(self) -> Dict:
        """現在のメトリクス収集"""
        try:
            # 実際のプロジェクトメトリクス収集
            # ここでは模擬データを生成（実際の実装では pytest, coverage, etc. を使用）
            import random

            metrics = {
                "timestamp": datetime.now().isoformat(),
                "test_coverage": random.uniform(0.7, 0.95),
                "code_complexity": random.uniform(1.5, 4.0),
                "error_rate": random.uniform(0.01, 0.12),
                "performance_score": random.uniform(0.75, 0.95),
                "source": "real_time_collection",
            }

            return metrics

        except Exception as e:
            self.logger.error(f"Metrics collection failed: {e}")
            return {}

    def analyze_metrics(self, metrics: Dict) -> Dict:
        """メトリクス分析"""
        try:
            # AI予測実行
            if not self.predictor.is_trained:
                self.predictor.train_model()

            prediction = self.predictor.predict_quality_issue(
                {
                    "test_coverage": metrics["test_coverage"],
                    "code_complexity": metrics["code_complexity"],
                    "error_rate": metrics["error_rate"],
                    "performance_score": metrics["performance_score"],
                }
            )

            # 異常検知実行
            self.anomaly_detector.update_history(metrics)
            self.anomaly_detector.calculate_baseline()
            anomalies = self.anomaly_detector.detect_anomalies(metrics)

            # 閾値チェック
            alerts = []
            thresholds = self.config["alert_thresholds"]

            if metrics["test_coverage"] < thresholds["test_coverage_min"]:
                alerts.append(
                    {
                        "type": "coverage_low",
                        "severity": "warning",
                        "message": f"テストカバレッジが低下: {metrics['test_coverage']:.1%}",
                        "metric": "test_coverage",
                        "value": metrics["test_coverage"],
                    }
                )

            if metrics["code_complexity"] > thresholds["code_complexity_max"]:
                alerts.append(
                    {
                        "type": "complexity_high",
                        "severity": "warning",
                        "message": f"コード複雑度が高い: {metrics['code_complexity']:.2f}",
                        "metric": "code_complexity",
                        "value": metrics["code_complexity"],
                    }
                )

            if metrics["error_rate"] > thresholds["error_rate_max"]:
                alerts.append(
                    {
                        "type": "error_rate_high",
                        "severity": "critical",
                        "message": f"エラー率が高い: {metrics['error_rate']:.1%}",
                        "metric": "error_rate",
                        "value": metrics["error_rate"],
                    }
                )

            if metrics["performance_score"] < thresholds["performance_score_min"]:
                alerts.append(
                    {
                        "type": "performance_low",
                        "severity": "warning",
                        "message": f"パフォーマンスが低下: {metrics['performance_score']:.1%}",
                        "metric": "performance_score",
                        "value": metrics["performance_score"],
                    }
                )

            if prediction["confidence"] < thresholds["prediction_confidence_min"]:
                alerts.append(
                    {
                        "type": "prediction_uncertain",
                        "severity": "info",
                        "message": f"予測信頼度が低い: {prediction['confidence']:.1%}",
                        "metric": "prediction_confidence",
                        "value": prediction["confidence"],
                    }
                )

            # 異常検知アラートを追加
            for anomaly in anomalies:
                alerts.append(anomaly)

            return {
                "metrics": metrics,
                "prediction": prediction,
                "alerts": alerts,
                "anomalies": anomalies,
                "analysis_time": datetime.now().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Metrics analysis failed: {e}")
            return {"error": str(e)}

    def send_alerts(self, analysis: Dict) -> None:
        """アラート送信"""
        alerts = analysis.get("alerts", [])
        if not alerts:
            return

        channels = self.config["alert_channels"]

        for alert in alerts:
            # アラート管理システムで処理
            processed_alert = self.alert_manager.process_alert(alert)
            if not processed_alert:
                continue  # 抑制されたアラート

            message = f"[{processed_alert['severity'].upper()}] {processed_alert['message']}"

            # ファイル出力
            if channels.get("file", False):
                alert_file = Path("data/logs/current/alerts.log")
                alert_file.parent.mkdir(parents=True, exist_ok=True)
                with open(alert_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()} - {message}\n")

            # コンソール出力
            if channels.get("console", False):
                if processed_alert["severity"] == "critical":
                    self.logger.error(message)
                elif processed_alert["severity"] == "warning":
                    self.logger.warning(message)
                else:
                    self.logger.info(message)

            # メール通知
            if channels.get("email", False) and "email" in processed_alert.get(
                "notification_channels", []
            ):
                self.notification_service.send_email_alert(processed_alert)

            # Webhook通知
            if channels.get("webhook", False) and "webhook" in processed_alert.get(
                "notification_channels", []
            ):
                self.notification_service.send_webhook_alert(processed_alert)

            # ダッシュボード通知
            if channels.get("dashboard", False):
                self._notify_dashboard(processed_alert)

    def _notify_dashboard(self, alert: Dict) -> None:
        """ダッシュボード通知"""
        # WebSocket or REST API経由でダッシュボードに通知
        # 現在は模擬実装
        self.logger.info(f"Dashboard notification: {alert['message']}")

    def store_metrics(self, analysis: Dict) -> None:
        """メトリクス保存"""
        try:
            metrics = analysis["metrics"]
            prediction = analysis["prediction"]

            # データベースに保存
            db_path = Path("data/quality_metrics.db")
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO quality_metrics 
                    (timestamp, test_coverage, code_complexity, error_rate, 
                     performance_score, quality_issue, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        metrics["timestamp"],
                        metrics["test_coverage"],
                        metrics["code_complexity"],
                        metrics["error_rate"],
                        metrics["performance_score"],
                        prediction["prediction"],
                        f"Confidence: {prediction['confidence']:.3f}, Source: {metrics.get('source', 'unknown')}",
                    ),
                )
                conn.commit()

            self.logger.debug(f"Metrics stored: {metrics['timestamp']}")

        except Exception as e:
            self.logger.error(f"Metrics storage failed: {e}")

    def cleanup_old_data(self) -> None:
        """古いデータクリーンアップ"""
        try:
            retention_days = self.config["data_retention_days"]
            cutoff_date = datetime.now() - timedelta(days=retention_days)

            db_path = Path("data/quality_metrics.db")
            with sqlite3.connect(db_path) as conn:
                result = conn.execute(
                    """
                    DELETE FROM quality_metrics 
                    WHERE datetime(timestamp) < datetime(?)
                """,
                    (cutoff_date.isoformat(),),
                )

                deleted_count = result.rowcount
                conn.commit()

            if deleted_count > 0:
                self.logger.info(f"Cleaned up {deleted_count} old records")

        except Exception as e:
            self.logger.error(f"Data cleanup failed: {e}")

    def monitoring_loop(self) -> None:
        """監視ループ"""
        self.logger.info("Monitoring loop started")

        while self.is_running:
            try:
                # メトリクス収集
                metrics = self.collect_current_metrics()
                if not metrics:
                    time.sleep(self.config["monitoring_interval"])
                    continue

                # 分析実行
                analysis = self.analyze_metrics(metrics)
                if "error" in analysis:
                    time.sleep(self.config["monitoring_interval"])
                    continue

                # アラート送信
                self.send_alerts(analysis)

                # データ保存
                self.store_metrics(analysis)

                # 定期クリーンアップ（1時間に1回）
                if datetime.now().minute == 0:
                    self.cleanup_old_data()

                # 次回実行まで待機
                time.sleep(self.config["monitoring_interval"])

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.config["monitoring_interval"])

        self.logger.info("Monitoring loop stopped")

    def start(self) -> None:
        """監視開始"""
        if self.is_running:
            self.logger.warning("Monitoring already running")
            return

        self.is_running = True
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.logger.info("Monitoring system started")

    def stop(self) -> None:
        """監視停止"""
        if not self.is_running:
            self.logger.warning("Monitoring not running")
            return

        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)

        self.logger.info("Monitoring system stopped")

    def get_status(self) -> Dict:
        """監視状況取得"""
        return {
            "is_running": self.is_running,
            "config": self.config,
            "thread_alive": self.monitor_thread.is_alive() if self.monitor_thread else False,
            "last_check": datetime.now().isoformat(),
        }


def main():
    """メイン実行関数"""
    monitor = MonitoringSystem()

    try:
        print("Starting monitoring system...")
        monitor.start()

        # 監視実行（Ctrl+Cで停止）
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping monitoring system...")
        monitor.stop()
        print("Monitoring system stopped")


if __name__ == "__main__":
    main()
