"""
アラート機能強化モジュール
高度なアラート分類、重要度判定、通知チャンネル管理を提供
"""

import json
import logging
import smtplib
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


class AlertSeverity(Enum):
    """アラート重要度"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCategory(Enum):
    """アラートカテゴリ"""

    PERFORMANCE = "performance"
    QUALITY = "quality"
    SECURITY = "security"
    SYSTEM = "system"
    BUSINESS = "business"


class NotificationChannel(Enum):
    """通知チャンネル"""

    EMAIL = "email"
    WEBHOOK = "webhook"
    DASHBOARD = "dashboard"
    SLACK = "slack"
    TEAMS = "teams"


class AlertEnhancer:
    """強化されたアラート管理システム"""

    def __init__(self, config_path: str = "config/alert_config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self.alert_history = []
        self.suppressed_alerts = {}

    def _load_config(self) -> Dict:
        """設定ファイル読み込み"""
        default_config = {
            "severity_thresholds": {
                "cpu_usage": {"medium": 70, "high": 85, "critical": 95},
                "memory_usage": {"medium": 75, "high": 90, "critical": 98},
                "disk_usage": {"medium": 80, "high": 90, "critical": 95},
                "error_rate": {"medium": 0.05, "high": 0.1, "critical": 0.2},
                "response_time": {"medium": 1.0, "high": 3.0, "critical": 5.0},
            },
            "notification_channels": {
                "email": {
                    "enabled": True,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "alerts@example.com",
                    "password": "CHANGEME",
                    "recipients": ["admin@example.com"],
                },
                "webhook": {
                    "enabled": True,
                    "url": "https://hooks.slack.com/services/CHANGEME",
                    "timeout": 10,
                },
                "dashboard": {"enabled": True, "endpoint": "http://localhost:5001/api/alerts"},
            },
            "alert_rules": {
                "suppression_window": 300,  # 5分
                "escalation_delay": 900,  # 15分
                "max_alerts_per_hour": 50,
                "cooldown_period": 60,  # 1分
            },
            "business_hours": {
                "start": "09:00",
                "end": "18:00",
                "timezone": "Asia/Tokyo",
                "weekdays_only": True,
            },
        }

        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded_config = json.load(f)
                    # デフォルト設定とマージ
                    default_config.update(loaded_config)
            except Exception as e:
                logging.warning(f"設定ファイル読み込みエラー: {e}")

        return default_config

    def _setup_logging(self) -> logging.Logger:
        """ログ設定"""
        logger = logging.getLogger("AlertEnhancer")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def classify_alert(self, alert: Dict) -> Dict:
        """アラート分類と重要度判定"""
        alert_type = alert.get("type", "unknown")
        metric = alert.get("metric", "")
        value = alert.get("value", 0)

        # カテゴリ判定
        category = self._determine_category(alert_type, metric)

        # 重要度判定
        severity = self._determine_severity(metric, value, alert.get("severity"))

        # 拡張情報追加
        enhanced_alert = alert.copy()
        enhanced_alert.update(
            {
                "category": category.value,
                "severity": severity.value,
                "timestamp": datetime.now().isoformat(),
                "alert_id": f"{alert_type}_{int(time.time())}",
                "business_impact": self._assess_business_impact(category, severity),
                "recommended_action": self._get_recommended_action(alert_type, severity),
            }
        )

        return enhanced_alert

    def _determine_category(self, alert_type: str, metric: str) -> AlertCategory:
        """アラートカテゴリ判定"""
        if any(
            keyword in alert_type.lower()
            for keyword in ["cpu", "memory", "disk", "network", "performance"]
        ):
            return AlertCategory.PERFORMANCE
        elif any(
            keyword in alert_type.lower() for keyword in ["coverage", "complexity", "quality"]
        ):
            return AlertCategory.QUALITY
        elif any(keyword in alert_type.lower() for keyword in ["security", "auth", "permission"]):
            return AlertCategory.SECURITY
        elif any(keyword in alert_type.lower() for keyword in ["system", "service", "daemon"]):
            return AlertCategory.SYSTEM
        else:
            return AlertCategory.BUSINESS

    def _determine_severity(
        self, metric: str, value: float, current_severity: str = None
    ) -> AlertSeverity:
        """重要度判定"""
        if current_severity:
            try:
                return AlertSeverity(current_severity.lower())
            except ValueError:
                pass

        thresholds = self.config["severity_thresholds"].get(metric, {})

        if value >= thresholds.get("critical", float("inf")):
            return AlertSeverity.CRITICAL
        elif value >= thresholds.get("high", float("inf")):
            return AlertSeverity.HIGH
        elif value >= thresholds.get("medium", float("inf")):
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def _assess_business_impact(self, category: AlertCategory, severity: AlertSeverity) -> str:
        """ビジネス影響度評価"""
        impact_matrix = {
            (AlertCategory.PERFORMANCE, AlertSeverity.CRITICAL): "サービス停止の可能性",
            (AlertCategory.PERFORMANCE, AlertSeverity.HIGH): "ユーザー体験の大幅な劣化",
            (AlertCategory.QUALITY, AlertSeverity.CRITICAL): "品質基準の重大な違反",
            (AlertCategory.SECURITY, AlertSeverity.CRITICAL): "セキュリティ侵害の可能性",
            (AlertCategory.SYSTEM, AlertSeverity.CRITICAL): "システム障害の可能性",
        }

        return impact_matrix.get((category, severity), "軽微な影響")

    def _get_recommended_action(self, alert_type: str, severity: AlertSeverity) -> str:
        """推奨アクション"""
        actions = {
            "performance_cpu_high": "CPU使用率の高いプロセスを特定し、最適化を検討",
            "performance_memory_high": "メモリリークの確認とガベージコレクションの実行",
            "performance_disk_high": "不要ファイルの削除とディスク容量の拡張",
            "quality_coverage_low": "テストカバレッジの向上とテストケースの追加",
            "security_auth_failed": "認証ログの確認と不正アクセスの調査",
        }

        base_action = actions.get(alert_type, "詳細な調査と適切な対応")

        if severity == AlertSeverity.CRITICAL:
            return f"緊急対応: {base_action}"
        elif severity == AlertSeverity.HIGH:
            return f"優先対応: {base_action}"
        else:
            return base_action

    def should_suppress_alert(self, alert: Dict) -> bool:
        """アラート抑制判定"""
        alert_key = f"{alert.get('type')}_{alert.get('metric')}"
        current_time = time.time()

        # 抑制ウィンドウ内の同じアラートをチェック
        if alert_key in self.suppressed_alerts:
            last_sent = self.suppressed_alerts[alert_key]
            suppression_window = self.config["alert_rules"]["suppression_window"]

            if current_time - last_sent < suppression_window:
                return True

        # 時間あたりのアラート数制限
        recent_alerts = [
            a for a in self.alert_history if current_time - a.get("timestamp_unix", 0) < 3600
        ]

        max_alerts = self.config["alert_rules"]["max_alerts_per_hour"]
        if len(recent_alerts) >= max_alerts:
            return True

        return False

    def send_enhanced_alert(self, alert: Dict) -> bool:
        """強化されたアラート送信"""
        # アラート分類
        enhanced_alert = self.classify_alert(alert)

        # 抑制チェック
        if self.should_suppress_alert(enhanced_alert):
            self.logger.info(f"アラート抑制: {enhanced_alert.get('alert_id')}")
            return False

        # 通知チャンネル決定
        channels = self._select_notification_channels(enhanced_alert)

        success = True
        for channel in channels:
            try:
                if channel == NotificationChannel.EMAIL:
                    self._send_email_alert(enhanced_alert)
                elif channel == NotificationChannel.WEBHOOK:
                    self._send_webhook_alert(enhanced_alert)
                elif channel == NotificationChannel.DASHBOARD:
                    self._send_dashboard_alert(enhanced_alert)

                self.logger.info(f"アラート送信成功: {channel.value}")
            except Exception as e:
                self.logger.error(f"アラート送信失敗 ({channel.value}): {e}")
                success = False

        # 履歴記録
        enhanced_alert["timestamp_unix"] = time.time()
        self.alert_history.append(enhanced_alert)

        # 抑制記録更新
        alert_key = f"{enhanced_alert.get('type')}_{enhanced_alert.get('metric')}"
        self.suppressed_alerts[alert_key] = time.time()

        return success

    def _select_notification_channels(self, alert: Dict) -> List[NotificationChannel]:
        """通知チャンネル選択"""
        severity = AlertSeverity(alert.get("severity", "low"))
        channels = []

        # 重要度に応じたチャンネル選択
        if severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            channels.extend([NotificationChannel.EMAIL, NotificationChannel.WEBHOOK])

        if severity != AlertSeverity.LOW:
            channels.append(NotificationChannel.DASHBOARD)

        # 設定で有効なチャンネルのみ
        enabled_channels = []
        for channel in channels:
            if self.config["notification_channels"].get(channel.value, {}).get("enabled", False):
                enabled_channels.append(channel)

        return enabled_channels

    def _send_email_alert(self, alert: Dict) -> None:
        """メールアラート送信"""
        email_config = self.config["notification_channels"]["email"]

        msg = MIMEMultipart()
        msg["From"] = email_config["username"]
        msg["To"] = ", ".join(email_config["recipients"])
        msg["Subject"] = f"[{alert['severity'].upper()}] {alert['message']}"

        body = f"""
アラート詳細:
- ID: {alert['alert_id']}
- カテゴリ: {alert['category']}
- 重要度: {alert['severity']}
- メッセージ: {alert['message']}
- ビジネス影響: {alert['business_impact']}
- 推奨アクション: {alert['recommended_action']}
- 発生時刻: {alert['timestamp']}

詳細な調査を行ってください。
        """

        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"]) as server:
            server.starttls()
            server.login(email_config["username"], email_config["password"])
            server.send_message(msg)

    def _send_webhook_alert(self, alert: Dict) -> None:
        """Webhookアラート送信"""
        webhook_config = self.config["notification_channels"]["webhook"]

        payload = {
            "text": f"[{alert['severity'].upper()}] {alert['message']}",
            "attachments": [
                {
                    "color": self._get_alert_color(alert["severity"]),
                    "fields": [
                        {"title": "カテゴリ", "value": alert["category"], "short": True},
                        {"title": "重要度", "value": alert["severity"], "short": True},
                        {
                            "title": "ビジネス影響",
                            "value": alert["business_impact"],
                            "short": False,
                        },
                        {
                            "title": "推奨アクション",
                            "value": alert["recommended_action"],
                            "short": False,
                        },
                    ],
                    "timestamp": alert["timestamp"],
                }
            ],
        }

        response = requests.post(
            webhook_config["url"], json=payload, timeout=webhook_config.get("timeout", 10)
        )
        response.raise_for_status()

    def _send_dashboard_alert(self, alert: Dict) -> None:
        """ダッシュボードアラート送信"""
        dashboard_config = self.config["notification_channels"]["dashboard"]

        response = requests.post(dashboard_config["endpoint"], json=alert, timeout=10)
        response.raise_for_status()

    def _get_alert_color(self, severity: str) -> str:
        """アラート色取得"""
        colors = {
            "low": "#36a64f",  # 緑
            "medium": "#ff9500",  # オレンジ
            "high": "#ff0000",  # 赤
            "critical": "#8b0000",  # 暗赤
        }
        return colors.get(severity, "#808080")

    def get_alert_statistics(self) -> Dict[str, Any]:
        """アラート統計情報を取得"""
        try:
            now = datetime.now()
            last_24h = now - timedelta(hours=24)

            # 過去24時間のアラートを集計
            recent_alerts = [
                alert
                for alert in self.alert_history
                if datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")) > last_24h
            ]

            # 重要度別集計
            by_severity = {}
            for alert in recent_alerts:
                severity = alert.get("severity", "unknown")
                by_severity[severity] = by_severity.get(severity, 0) + 1

            # カテゴリ別集計
            by_category = {}
            for alert in recent_alerts:
                category = alert.get("category", "unknown")
                by_category[category] = by_category.get(category, 0) + 1

            # 抑制されたアラート数
            suppressed_count = len(
                [alert for alert in recent_alerts if alert.get("suppressed", False)]
            )

            return {
                "total_alerts_24h": len(recent_alerts),
                "by_severity": by_severity,
                "by_category": by_category,
                "suppressed_count": suppressed_count,
                "average_per_hour": len(recent_alerts) / 24.0,
                "timestamp": now.isoformat(),
            }

        except Exception as e:
            self.logger.error(f"アラート統計取得エラー: {e}")
            return {
                "total_alerts_24h": 0,
                "by_severity": {},
                "by_category": {},
                "suppressed_count": 0,
                "average_per_hour": 0.0,
                "timestamp": datetime.now().isoformat(),
            }
