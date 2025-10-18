import json
from datetime import datetime

import pytest

pytest.importorskip("pandas")

from src.realtime_dashboard import AlertMessage, RealtimeDashboard, RealtimeMetrics


@pytest.fixture()
def dashboard_client(tmp_path):
    """RealtimeDashboard のテストクライアントを生成"""
    db_path = tmp_path / "quality_metrics.db"
    dash = RealtimeDashboard(db_path=str(db_path))
    client = dash.app.test_client()
    return dash, client


def make_metric(ts: str = None) -> RealtimeMetrics:
    """テスト用メトリクス生成"""
    return RealtimeMetrics(
        timestamp=ts or datetime.now().isoformat(),
        cpu_usage=12.3,
        memory_usage=45.6,
        disk_usage=78.9,
        active_tasks=3,
        pending_approvals=1,
        system_health="ok",
        ai_prediction_accuracy=0.91,
        automation_rate=0.73,
        alert_count=0,
    )


def make_alert(alert_id: str = "a1", acknowledged: bool = False) -> AlertMessage:
    """テスト用アラート生成"""
    return AlertMessage(
        id=alert_id,
        timestamp=datetime.now().isoformat(),
        level="warning",
        category="system",
        title="Test Alert",
        message="This is a test alert",
        source="unit_test",
        acknowledged=acknowledged,
        auto_resolved=False,
    )


class TestRealtimeDashboardAPI:
    def test_api_realtime_metrics_empty(self, dashboard_client):
        dash, client = dashboard_client
        resp = client.get("/api/realtime/metrics")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "metrics" in body
        assert isinstance(body["metrics"], list)
        assert body["count"] == len(body["metrics"]) == 0

    def test_api_realtime_metrics_with_data(self, dashboard_client):
        dash, client = dashboard_client
        # 2件投入
        dash.metrics_buffer.append(make_metric())
        dash.metrics_buffer.append(make_metric())
        resp = client.get("/api/realtime/metrics")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == len(body["metrics"]) > 0
        # メトリクスのキー確認
        m = body["metrics"][0]
        for k in [
            "timestamp",
            "cpu_usage",
            "memory_usage",
            "disk_usage",
            "active_tasks",
            "pending_approvals",
            "system_health",
            "ai_prediction_accuracy",
            "automation_rate",
            "alert_count",
        ]:
            assert k in m

    def test_api_realtime_alerts(self, dashboard_client):
        dash, client = dashboard_client
        # active 1 / acknowledged 1
        dash.alerts_buffer.append(make_alert("a1", acknowledged=False))
        dash.alerts_buffer.append(make_alert("a2", acknowledged=True))
        resp = client.get("/api/realtime/alerts")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["total_count"] == 2
        assert body["active_count"] == 1
        assert len(body["alerts"]) == 1
        a = body["alerts"][0]
        for k in [
            "id",
            "timestamp",
            "level",
            "category",
            "title",
            "message",
            "source",
            "acknowledged",
            "auto_resolved",
        ]:
            assert k in a

    def test_api_system_status(self, dashboard_client):
        dash, client = dashboard_client
        resp = client.get("/api/realtime/system-status")
        assert resp.status_code == 200
        body = resp.get_json()
        for k in [
            "monitoring_active",
            "active_connections",
            "predictor_ready",
            "automation_enabled",
            "uptime",
            "timestamp",
        ]:
            assert k in body

    def test_acknowledge_alert_success(self, dashboard_client):
        dash, client = dashboard_client
        dash.alerts_buffer.append(make_alert("a1", acknowledged=False))
        resp = client.post("/api/alerts/a1/acknowledge")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "acknowledged"
        assert body["alert_id"] == "a1"
        # バッファの状態が更新されていること
        found = [a for a in dash.alerts_buffer if a.id == "a1"][0]
        assert found.acknowledged is True

    def test_acknowledge_alert_not_found(self, dashboard_client):
        dash, client = dashboard_client
        resp = client.post("/api/alerts/unknown/acknowledge")
        assert resp.status_code == 404
        body = resp.get_json()
        assert "error" in body

    def test_health(self, dashboard_client):
        dash, client = dashboard_client
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body.get("status") == "ok"

    def test_sse_events_stream_headers(self, dashboard_client):
        dash, client = dashboard_client
        resp = client.get("/events")
        # ストリーミング内容は読み切らない。ヘッダのみ確認。
        assert resp.status_code == 200
        assert resp.headers.get("Content-Type") == "text/event-stream"
