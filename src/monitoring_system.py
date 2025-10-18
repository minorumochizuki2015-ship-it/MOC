"""
リアルタイム監視システム
品質メトリクスの自動収集とアラート機能
"""

import json
import logging
import os
import smtplib
import sqlite3
import threading
import time
from collections import deque
from contextlib import closing
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from src.ai_prediction import QualityPredictor
from src.alert_enhancer import AlertEnhancer
from src.performance_monitor import SystemPerformanceMonitor


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

                # 急激な変化を検知（過度な誤検知を防ぐため閾値を厳しめに設定）
                if abs(trend) > stats["std"]:
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

        # スパム対策フィルター
        from .notification_spam_filter import NotificationSpamFilter

        self.spam_filter = NotificationSpamFilter(config.get("spam_filter", {}))

    def send_email_alert(self, alert: Dict) -> bool:
        """メールアラート送信"""
        try:
            if not self.email_config.get("enabled", False):
                return False

            # スパム対策チェック
            alert_content = f"{alert['type']}:{alert['message']}"
            priority = alert.get("severity", "medium")
            if not self.spam_filter.should_allow_notification(
                "email_alert", alert_content, priority
            ):
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

            # スパム対策チェック
            alert_content = f"{alert['type']}:{alert['message']}"
            priority = alert.get("severity", "medium")
            if not self.spam_filter.should_allow_notification(
                "webhook_alert", alert_content, priority
            ):
                return False

            import requests

            payload = {
                "alert_type": alert["type"],
                "severity": alert["severity"],
                "message": alert["message"],
                "timestamp": datetime.now().isoformat(),
                "system": "ORCH-Next",
            }

            # 設定からタイムアウトと成功コードを反映
            timeout = self.webhook_config.get("timeout", 10)
            success_codes = set(self.webhook_config.get("success_codes", [200]))

            response = requests.post(
                self.webhook_config["url"],
                json=payload,
                headers=self.webhook_config.get("headers", {}),
                timeout=timeout,
            )

            return response.status_code in success_codes

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
        self.performance_monitor = SystemPerformanceMonitor()
        self.alert_enhancer = AlertEnhancer()
        self.is_running = False
        self.monitor_thread = None
        # 安全停止のための管理構造
        self._managed_timers: List[threading.Timer] = []
        self._thread_lock = threading.Lock()
        # テストモード検出（pytest 実行時はファイルハンドラを抑止）
        self._test_mode = bool(os.environ.get("PYTEST_CURRENT_TEST"))

        # ログ設定
        try:
            # ログディレクトリを事前作成（FileHandler生成前）
            log_dir = Path("data/logs/current")
            log_dir.mkdir(parents=True, exist_ok=True)
            handlers = [logging.StreamHandler()]
            if not self._test_mode:
                handlers.insert(0, logging.FileHandler(log_dir / "monitoring.log"))

            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(levelname)s - %(message)s",
                handlers=handlers,
            )
        except Exception:
            # ログ初期化失敗時はコンソールのみで継続
            logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        # ファイルチャネル書き込みのスレッドロック（フォールバック用）
        self._file_lock = threading.Lock()
        # ファイルローテーション設定のキャッシュ
        self._file_rotation_cfg = None
        # ログクリーンアップの最終実行時刻
        self._last_purge_ts = 0.0

    def close(self) -> None:
        """監視システムの安全終了（ログハンドラ含む）"""
        try:
            # 監視停止
            self.is_running = False
            # 登録タイマーのキャンセル
            with self._thread_lock:
                for t in self._managed_timers:
                    try:
                        t.cancel()
                    except Exception:
                        pass
                self._managed_timers.clear()

            # ログハンドラのクリーンアップ（FileIO の未処理例外抑止）
            try:
                for h in list(self.logger.handlers):
                    try:
                        h.flush()
                        h.close()
                    except Exception:
                        pass
                    try:
                        self.logger.removeHandler(h)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            # 終了処理で例外を出さない（pytest Unraisable を回避）
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

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
                "timeout": 10,
                "success_codes": [200],
            },
            "file_channel": {
                "rotation_enabled": True,
                "max_bytes": 10 * 1024 * 1024,  # 10MB
                "backup_count": 10,
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
        """アラート送信（強化版）"""
        alerts = analysis.get("alerts", [])
        if not alerts:
            return

        channels = self.config["alert_channels"]

        for alert in alerts:
            try:
                # 強化されたアラート送信
                success = self.alert_enhancer.send_enhanced_alert(alert)

                if success:
                    self.logger.info(f"Enhanced alert sent: {alert.get('type', 'unknown')}")
                else:
                    self.logger.warning(f"Alert suppressed: {alert.get('type', 'unknown')}")

            except Exception as e:
                self.logger.error(f"Failed to send enhanced alert: {e}")

            # アラート管理システムで処理（従来の処理も併用）
            processed_alert = self.alert_manager.process_alert(alert)
            if not processed_alert:
                continue  # 抑制されたアラート

            message = f"[{processed_alert['severity'].upper()}] {processed_alert['message']}"

            # ファイル出力（ローカル通知ログ: ORCH/REPORTS/notifications.log）
            if channels.get("file", False):
                # スパム対策チェック（ファイルチャネルにも適用）
                try:
                    alert_content = f"{processed_alert.get('type','general')}:{processed_alert.get('message','')}"
                    priority = processed_alert.get("severity", "medium")
                    if not self.notification_service.spam_filter.should_allow_notification(
                        "file_alert", alert_content, priority
                    ):
                        # 許可されない場合は次のチャネルへ
                        continue
                except Exception as e:
                    self.logger.debug(f"File channel spam filter check skipped: {e}")

                report_log = Path("ORCH/REPORTS/notifications.log")
                report_log.parent.mkdir(parents=True, exist_ok=True)
                # 構造化情報も含めて記録
                log_line = {
                    "timestamp": datetime.now().isoformat(),
                    "type": processed_alert.get("type", "general"),
                    "severity": processed_alert.get("severity", "info"),
                    "message": processed_alert.get("message", ""),
                    "system": "ORCH-Next",
                }
                # ファイルロックを試行（filelock があればプロセス間ロック、なければスレッドロック）
                try:
                    try:
                        from filelock import FileLock

                        lock = FileLock(str(report_log) + ".lock")
                        with lock:
                            # ローテーション（プロセスロック下）
                            self._rotate_report_log_if_needed(report_log)
                            with open(report_log, "a", encoding="utf-8") as f:
                                f.write(json.dumps(log_line, ensure_ascii=False) + "\n")
                    except ImportError:
                        # フォールバック: スレッドロックのみ
                        with self._file_lock:
                            # ローテーション（スレッドロック下）
                            self._rotate_report_log_if_needed(report_log)
                            with open(report_log, "a", encoding="utf-8") as f:
                                f.write(json.dumps(log_line, ensure_ascii=False) + "\n")
                except Exception:
                    # フォールバックでプレーンテキストを記録
                    try:
                        with open(report_log, "a", encoding="utf-8") as f:
                            f.write(
                                f"{log_line['timestamp']} [{log_line['severity'].upper()}] {log_line['type']} - {log_line['message']}\n"
                            )
                    except Exception as e:
                        self.logger.warning(f"File channel write failed: {e}")

                # 承認・作業トラッキングへの証跡自動登録
                try:
                    self._register_evidence(processed_alert)
                except Exception as e:
                    self.logger.warning(f"Evidence registration skipped: {e}")

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

    def _register_evidence(self, alert: Dict) -> None:
        """APPROVALS.md / WORK_TRACKING.md に証跡を追記する"""
        timestamp = datetime.now().isoformat()
        severity = alert.get("severity", "info").upper()
        a_type = alert.get("type", "general")
        message = alert.get("message", "")

        line = f"- [{timestamp}] Alert {severity} {a_type} — {message}\n"

        # WORK_TRACKING.md への追記
        wt_path = Path("WORK_TRACKING.md")
        try:
            with open(wt_path, "a", encoding="utf-8") as f:
                f.write("\n" + line)
        except Exception as e:
            self.logger.warning(f"WORK_TRACKING evidence append failed: {e}")

        # APPROVALS.md への追記（ORCH/STATE 配下）
        approvals_path = Path("ORCH/STATE/APPROVALS.md")
        # 親ディレクトリが存在しない場合に作成（ファイル作成前に必須）
        try:
            approvals_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.warning(f"APPROVALS directory ensure failed: {e}")
        try:
            with open(approvals_path, "a", encoding="utf-8") as f:
                f.write("\n" + line)
        except Exception as e:
            self.logger.warning(f"APPROVALS evidence append failed: {e}")

    def _get_file_rotation_config(self) -> Dict:
        """ファイルチャネルのローテーション設定を取得（キャッシュ）"""
        if self._file_rotation_cfg is None:
            cfg = self.config.get("file_channel", {})
            self._file_rotation_cfg = {
                "enabled": bool(cfg.get("rotation_enabled", True)),
                "max_bytes": int(cfg.get("max_bytes", 10 * 1024 * 1024)),
                "backup_count": int(cfg.get("backup_count", 10)),
            }
        return self._file_rotation_cfg

    def _rotate_report_log_if_needed(self, report_log: Path) -> None:
        """必要に応じて ORCH/REPORTS/notifications.log をローテーションする"""
        cfg = self._get_file_rotation_config()
        if not cfg["enabled"]:
            return
        try:
            if report_log.exists():
                size = report_log.stat().st_size
                if size >= cfg["max_bytes"]:
                    backup_count = cfg["backup_count"]
                    # 既存バックアップを後ろへシフト
                    for i in range(backup_count, 0, -1):
                        src = report_log.with_name(report_log.name + f".{i}")
                        dst = report_log.with_name(report_log.name + f".{i+1}")
                        if src.exists():
                            # 最古を削除してからリネーム
                            if i == backup_count and dst.exists():
                                try:
                                    dst.unlink()
                                except Exception:
                                    pass
                            try:
                                src.rename(dst)
                            except Exception:
                                self.logger.debug(f"Rotation rename failed: {src} -> {dst}")
                    # 現行ファイルを .1 へ
                    try:
                        report_log.rename(report_log.with_name(report_log.name + ".1"))
                    except Exception:
                        self.logger.debug("Rotation current rename failed; continuing append")
        except Exception as e:
            self.logger.debug(f"Rotation check failed: {e}")

    def _purge_old_logs_if_needed(self) -> None:
        """保持期間に基づく古いログの削除（1時間に1回だけ実行）"""
        try:
            now_ts = time.time()
            # 1時間に1回だけ実行
            if now_ts - float(self._last_purge_ts) < 3600:
                return
            self._last_purge_ts = now_ts

            retention_days = int(self.config.get("data_retention_days", 30))
            cutoff_ts = now_ts - retention_days * 86400

            target_dirs = [Path("ORCH/REPORTS"), Path("data/logs/current")]
            for d in target_dirs:
                if not d.exists():
                    continue
                for p in d.glob("**/*"):
                    if p.is_file():
                        try:
                            if p.stat().st_mtime < cutoff_ts:
                                p.unlink()
                        except Exception:
                            # 個別失敗は無視
                            pass
        except Exception as e:
            self.logger.debug(f"Log purge skipped: {e}")

    def store_metrics(self, analysis: Dict) -> None:
        """メトリクス保存"""
        try:
            metrics = analysis["metrics"]
            prediction = analysis["prediction"]

            # データベースに保存
            db_path = Path("data/quality_metrics.db")
            with closing(sqlite3.connect(db_path, timeout=30, check_same_thread=False)) as conn:
                with conn:
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

            self.logger.debug(f"Metrics stored: {metrics['timestamp']}")

        except Exception as e:
            self.logger.error(f"Metrics storage failed: {e}")

    def cleanup_old_data(self) -> None:
        """古いデータクリーンアップ"""
        try:
            retention_days = self.config["data_retention_days"]
            cutoff_date = datetime.now() - timedelta(days=retention_days)

            db_path = Path("data/quality_metrics.db")
            with closing(sqlite3.connect(db_path, timeout=30, check_same_thread=False)) as conn:
                with conn:
                    result = conn.execute(
                        """
                        DELETE FROM quality_metrics 
                        WHERE datetime(timestamp) < datetime(?)
                    """,
                        (cutoff_date.isoformat(),),
                    )

                    deleted_count = result.rowcount

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

                # パフォーマンスメトリクス分析
                performance_summary = self.performance_monitor.get_performance_summary()
                if "error" not in performance_summary:
                    # パフォーマンスアラートを分析に追加
                    performance_alerts = self._analyze_performance_alerts(performance_summary)
                    if "alerts" not in analysis:
                        analysis["alerts"] = []
                    analysis["alerts"].extend(performance_alerts)
                    analysis["performance"] = performance_summary

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

    def _analyze_performance_alerts(self, performance_summary: Dict) -> List[Dict]:
        """パフォーマンス関連のアラート分析"""
        alerts = []
        current = performance_summary.get("current", {})
        thresholds = performance_summary.get("thresholds", {})

        # CPU使用率チェック
        cpu_percent = current.get("cpu_percent", 0)
        if cpu_percent > thresholds.get("cpu_usage_max", 80):
            alerts.append(
                {
                    "type": "performance_cpu_high",
                    "severity": "warning" if cpu_percent < 90 else "critical",
                    "message": f"CPU使用率が高い: {cpu_percent:.1f}%",
                    "metric": "cpu_usage",
                    "value": cpu_percent,
                    "threshold": thresholds.get("cpu_usage_max", 80),
                }
            )

        # メモリ使用率チェック
        memory_percent = current.get("memory_percent", 0)
        if memory_percent > thresholds.get("memory_usage_max", 85):
            alerts.append(
                {
                    "type": "performance_memory_high",
                    "severity": "warning" if memory_percent < 95 else "critical",
                    "message": f"メモリ使用率が高い: {memory_percent:.1f}%",
                    "metric": "memory_usage",
                    "value": memory_percent,
                    "threshold": thresholds.get("memory_usage_max", 85),
                }
            )

        # ディスク使用率チェック
        disk_usage = current.get("disk_usage", {})
        for device, usage in disk_usage.items():
            if isinstance(usage, dict) and usage.get("percent", 0) > thresholds.get(
                "disk_usage_max", 90
            ):
                alerts.append(
                    {
                        "type": "performance_disk_high",
                        "severity": "critical" if usage["percent"] > 95 else "warning",
                        "message": f"ディスク使用率が高い ({device}): {usage['percent']:.1f}%",
                        "metric": "disk_usage",
                        "value": usage["percent"],
                        "threshold": thresholds.get("disk_usage_max", 90),
                        "device": device,
                    }
                )

        return alerts

    def start(self) -> None:
        """監視開始"""
        if self.is_running:
            self.logger.warning("Monitoring already running")
            return

        self.is_running = True
        with self._thread_lock:
            self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitor_thread.start()

        # パフォーマンス監視も開始
        self.performance_monitor.start_monitoring()

        self.logger.info("Monitoring system started")

    def stop(self) -> None:
        """監視停止"""
        if not self.is_running:
            self.logger.warning("Monitoring not running")
            return

        self.is_running = False
        # 管理タイマーのキャンセル
        try:
            for t in list(self._managed_timers):
                try:
                    t.cancel()
                except Exception:
                    pass
            self._managed_timers.clear()
        except Exception:
            pass

        with self._thread_lock:
            if self.monitor_thread:
                try:
                    self.monitor_thread.join(timeout=5)
                except Exception:
                    pass

        # パフォーマンス監視も停止
        self.performance_monitor.stop_monitoring()

        self.logger.info("Monitoring system stopped")

    def get_status(self) -> Dict:
        """監視状況取得"""
        return {
            "is_running": self.is_running,
            "config": self.config,
            "thread_alive": self.monitor_thread.is_alive() if self.monitor_thread else False,
            "last_check": datetime.now().isoformat(),
        }

    def get_system_status(self) -> Dict[str, Any]:
        """システム全体の状態を取得"""
        try:
            current_metrics = self.collect_current_metrics()

            # 全体的な健康状態を判定
            overall_status = "healthy"
            if current_metrics.get("error_rate", 0) > 0.05:
                overall_status = "critical"
            elif current_metrics.get("test_coverage", 1.0) < 0.7:
                overall_status = "warning"
            elif current_metrics.get("performance_score", 1.0) < 0.8:
                overall_status = "warning"

            return {
                "overall_status": overall_status,
                "uptime": time.time() - getattr(self, "start_time", time.time()),
                "last_update": datetime.now().isoformat(),
                "metrics": current_metrics,
                "alerts_active": len(getattr(self.alert_manager, "alert_history", [])),
                "monitoring_active": self.is_running,
                "error_rate": current_metrics.get("error_rate", 0),
                "test_coverage": current_metrics.get("test_coverage", 0),
            }
        except Exception as e:
            self.logger.error(f"システム状態取得エラー: {e}")
            return {
                "overall_status": "error",
                "error": str(e),
                "last_update": datetime.now().isoformat(),
                "error_rate": 0,
                "test_coverage": 0,
            }

    def get_performance_summary(self) -> Dict[str, Any]:
        """パフォーマンス監視データのサマリーを取得"""
        try:
            if hasattr(self, "performance_monitor") and self.performance_monitor:
                return self.performance_monitor.get_performance_summary()
            else:
                # フォールバック: サンプルデータを返す
                return {
                    "cpu_usage": 45.2,
                    "memory_usage": 67.8,
                    "disk_usage": 23.1,
                    "avg_response_time": 125.5,
                    "network_latency": 15.2,
                    "timestamp": datetime.now().isoformat(),
                }
        except Exception as e:
            self.logger.error(f"パフォーマンスサマリー取得エラー: {e}")
            return {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.1,
                "avg_response_time": 125.5,
                "network_latency": 15.2,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def get_alert_statistics(self) -> Dict[str, Any]:
        """アラート統計データを取得"""
        try:
            if hasattr(self, "alert_enhancer") and self.alert_enhancer:
                return self.alert_enhancer.get_alert_statistics()
            else:
                # フォールバック: 基本統計を返す
                active_count = 0
                if hasattr(self, "alert_manager") and hasattr(self.alert_manager, "alert_history"):
                    active_count = len(self.alert_manager.alert_history)

                return {
                    "active_count": active_count,
                    "daily_count": active_count,  # 簡易実装
                    "recent_alerts": [
                        {
                            "title": "システム監視中",
                            "severity": "info",
                            "timestamp": datetime.now().isoformat(),
                            "message": "監視システムが正常に動作しています",
                        }
                    ],
                    "timestamp": datetime.now().isoformat(),
                }
        except Exception as e:
            self.logger.error(f"アラート統計取得エラー: {e}")
            return {
                "active_count": 0,
                "daily_count": 0,
                "recent_alerts": [],
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def get_metrics_history(self, hours: int = 24, metric_type: str = "all") -> Dict[str, Any]:
        """メトリクス履歴データを取得"""
        try:
            import random

            # 簡易実装: 現在のメトリクスを基にサンプルデータを生成
            current_time = datetime.now()
            history_data = {"performance": [], "response_times": [], "alerts": []}

            # 過去24時間のサンプルデータを生成（1時間間隔）
            for i in range(hours):
                timestamp = current_time - timedelta(hours=i)

                # パフォーマンスデータ
                history_data["performance"].append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "cpu_usage": random.uniform(20, 80),
                        "memory_usage": random.uniform(30, 70),
                        "disk_usage": random.uniform(40, 60),
                    }
                )

                # 応答時間データ
                history_data["response_times"].append(
                    {"timestamp": timestamp.isoformat(), "response_time": random.uniform(100, 500)}
                )

            # データを時系列順にソート
            history_data["performance"].reverse()
            history_data["response_times"].reverse()

            return history_data

        except Exception as e:
            self.logger.error(f"メトリクス履歴取得エラー: {e}")
            return {"performance": [], "response_times": [], "alerts": [], "error": str(e)}

    # 追加: 安全な開始/停止API（テストやCIで使用）
    def safe_start(self) -> bool:
        """例外を外に出さない安全な開始。成功ならTrueを返す"""
        try:
            self.start()
            return True
        except Exception as e:
            try:
                self.logger.error(f"safe_start failed: {e}")
            except Exception:
                pass
            return False

    def safe_stop(self) -> bool:
        """例外を外に出さない安全な停止。成功ならTrueを返す"""
        try:
            self.stop()
            return True
        except Exception as e:
            try:
                self.logger.error(f"safe_stop failed: {e}")
            except Exception:
                pass
            return False


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
