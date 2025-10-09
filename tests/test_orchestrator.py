#!/usr/bin/env python3
"""
Integration tests for ORCH-Next Orchestrator API
"""

import hashlib
import hmac
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.dispatcher import TaskDispatcher, TaskPriority, TaskStatus
from src.orchestrator import app, get_dispatcher


@pytest.fixture
def temp_db():
    """Create temporary database for testing"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def test_dispatcher(temp_db):
    """Create test dispatcher instance"""
    return TaskDispatcher(temp_db)


@pytest.fixture
def client(test_dispatcher):
    """Create test client with mocked dispatcher"""
    app.dependency_overrides[get_dispatcher] = lambda: test_dispatcher
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_task(test_dispatcher):
    """Create a sample task for testing"""
    import sqlite3
    from datetime import datetime

    task_id = "test_task_001"
    now = datetime.utcnow()

    with sqlite3.connect(test_dispatcher.db_path) as conn:
        conn.execute(
            """
            INSERT INTO tasks (id, title, status, priority, owner, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                task_id,
                "Test Task",
                TaskStatus.READY.value,
                TaskPriority.MEDIUM.value,
                "test_owner",
                now.isoformat(),
                now.isoformat(),
            ),
        )
        conn.commit()

    return task_id


class TestHealthEndpoint:

    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestMetricsEndpoint:

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint returns Prometheus format"""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"

        content = response.text
        assert "orch_http_requests_total" in content
        assert "orch_sse_connections_active" in content
        assert "orch_webhook_signatures_verified_total" in content

    def test_metrics_after_requests(self, client):
        """Test metrics are updated after HTTP requests"""
        # Make some requests to generate metrics
        client.get("/health")
        client.get("/health")

        response = client.get("/metrics")
        content = response.text

        # Should have metrics for GET /health requests
        assert 'orch_http_requests_total{method="GET",endpoint="/health",status="200"}' in content


class TestDispatchEndpoint:

    def test_dispatch_success(self, client, sample_task):
        """Test successful task dispatch"""
        payload = {"core_id": "test_worker", "stay": False, "priority": "medium", "timeout": 1800}

        response = client.post("/dispatch", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["task_id"] == sample_task

    def test_dispatch_no_tasks(self, client):
        """Test dispatch when no tasks available"""
        payload = {"core_id": "test_worker", "priority": "high"}

        response = client.post("/dispatch", json=payload)

        assert response.status_code == 404
        data = response.json()
        assert "No tasks available" in data["detail"]

    def test_dispatch_invalid_priority(self, client):
        """Test dispatch with invalid priority"""
        payload = {"core_id": "test_worker", "priority": "invalid_priority"}

        response = client.post("/dispatch", json=payload)

        # Should default to medium priority and work
        assert response.status_code in [200, 404]  # 404 if no tasks

    def test_dispatch_validation_error(self, client):
        """Test dispatch with missing required fields"""
        payload = {
            "priority": "high"
            # Missing core_id
        }

        response = client.post("/dispatch", json=payload)

        assert response.status_code == 422  # Validation error


class TestWebhookEndpoint:

    def create_webhook_signature(self, payload: bytes, secret: str) -> str:
        """Create HMAC signature for webhook"""
        signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return f"sha256={signature}"

    def test_webhook_valid_signature(self, client):
        """Test webhook with valid HMAC signature"""
        payload = {"event": "test_event", "data": {"key": "value"}}

        payload_bytes = json.dumps(payload).encode("utf-8")
        secret = "your-webhook-secret"  # Should match orchestrator.py
        signature = self.create_webhook_signature(payload_bytes, secret)

        headers = {"X-Hub-Signature-256": signature}

        response = client.post("/webhook", json=payload, headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"

    def test_webhook_invalid_signature(self, client):
        """Test webhook with invalid signature"""
        payload = {"event": "test_event", "data": {"key": "value"}}

        headers = {"X-Hub-Signature-256": "sha256=invalid_signature"}

        response = client.post("/webhook", json=payload, headers=headers)

        assert response.status_code == 401
        data = response.json()
        assert "Invalid signature" in data["detail"]

    def test_webhook_missing_signature(self, client):
        """Test webhook without signature header"""
        payload = {"event": "test_event", "data": {"key": "value"}}

        response = client.post("/webhook", json=payload)

        assert response.status_code == 401

    @patch("src.orchestrator.process_webhook")
    def test_webhook_background_processing(self, mock_process, client):
        """Test webhook triggers background processing"""
        payload = {"event": "task_completed", "data": {"task_id": "test_001"}}

        payload_bytes = json.dumps(payload).encode("utf-8")
        secret = "your-webhook-secret"
        signature = self.create_webhook_signature(payload_bytes, secret)

        headers = {"X-Hub-Signature-256": signature}

        response = client.post("/webhook", json=payload, headers=headers)

        assert response.status_code == 200
        # Background task should be scheduled (can't easily test execution)


class TestJobEndpoints:

    def test_get_job_events(self, client):
        """Test getting job events"""
        job_id = "test_job_001"

        response = client.get(f"/jobs/{job_id}/events")

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert "events" in data

    def test_update_job_status(self, client, sample_task):
        """Test updating job status"""
        payload = {"status": "doing", "notes": "Task in progress"}

        response = client.put(f"/jobs/{sample_task}", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == sample_task
        assert data["status"] == "doing"

    def test_update_job_invalid_status(self, client, sample_task):
        """Test updating job with invalid status"""
        payload = {"status": "invalid_status"}

        response = client.put(f"/jobs/{sample_task}", json=payload)

        assert response.status_code == 400
        data = response.json()
        assert "Invalid status" in data["detail"]

    def test_update_nonexistent_job(self, client):
        """Test updating non-existent job"""
        payload = {"status": "done"}

        response = client.put("/jobs/nonexistent", json=payload)

        assert response.status_code == 404


class TestMiddleware:

    def test_metrics_middleware_records_requests(self, client):
        """Test that middleware records HTTP metrics"""
        # Clear any existing metrics
        from src.orchestrator import metrics_data

        metrics_data["http_requests_total"].clear()

        # Make a request
        response = client.get("/health")
        assert response.status_code == 200

        # Check metrics were recorded
        assert len(metrics_data["http_requests_total"]) > 0

        # Should have entry for GET /health 200
        key = "GET_/health_200"
        assert key in metrics_data["http_requests_total"]
        assert metrics_data["http_requests_total"][key] >= 1

    def test_cors_headers(self, client):
        """Test CORS headers are present"""
        response = client.options("/health")

        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers


class TestErrorHandling:

    @patch("src.orchestrator.get_dispatcher")
    def test_dispatch_database_error(self, mock_get_dispatcher, client):
        """Test dispatch handles database errors gracefully"""
        # Mock dispatcher to raise exception
        mock_dispatcher = MagicMock()
        mock_dispatcher.dispatch_task.side_effect = Exception("Database error")
        mock_get_dispatcher.return_value = mock_dispatcher

        payload = {"core_id": "test_worker", "priority": "medium"}

        response = client.post("/dispatch", json=payload)

        assert response.status_code == 500
        data = response.json()
        assert "Database error" in data["detail"]

    def test_webhook_processing_error(self, client):
        """Test webhook handles processing errors gracefully"""
        # This test verifies the endpoint accepts the webhook even if processing fails
        payload = {"event": "error_event", "data": {"will": "cause_error"}}

        payload_bytes = json.dumps(payload).encode("utf-8")
        secret = "your-webhook-secret"
        signature = self.create_webhook_signature(payload_bytes, secret)

        headers = {"X-Hub-Signature-256": signature}

        response = client.post("/webhook", json=payload, headers=headers)

        # Should still accept the webhook
        assert response.status_code == 200


class TestIntegration:

    def test_full_dispatch_workflow(self, client, sample_task):
        """Test complete dispatch workflow"""
        # 1. Check initial metrics
        metrics_response = client.get("/metrics")
        initial_metrics = metrics_response.text

        # 2. Dispatch task
        dispatch_payload = {"core_id": "integration_worker", "priority": "high"}

        dispatch_response = client.post("/dispatch", json=dispatch_payload)
        assert dispatch_response.status_code == 200

        dispatch_data = dispatch_response.json()
        task_id = dispatch_data["task_id"]

        # 3. Update task status
        update_payload = {
            "status": "done",
            "artifact": "test_artifact.md",
            "notes": "Integration test completed",
        }

        update_response = client.put(f"/jobs/{task_id}", json=update_payload)
        assert update_response.status_code == 200

        # 4. Check updated metrics
        final_metrics_response = client.get("/metrics")
        final_metrics = final_metrics_response.text

        # Metrics should have changed
        assert final_metrics != initial_metrics

        # 5. Check job events
        events_response = client.get(f"/jobs/{task_id}/events")
        assert events_response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
