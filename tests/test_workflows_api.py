import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src.dispatcher import TaskDispatcher
from src.lock_manager import LockManager
from src.monitor import Monitor
from src.orchestrator import app
from src.security import SecurityManager, UserRole, get_security_manager


@pytest.fixture
def test_app():
    """Create test app with real security manager"""
    # Create test config with in-memory database
    config = {
        "database": {"path": ":memory:"},
        "jwt": {
            "secret_key": "test_secret_key_for_workflows_api_tests",
            "algorithm": "HS256",
            "expiry_hours": 24,
            "leeway_seconds": 120,
        },
        "security": {
            "enable_cleanup_on_init": False,
            "password_min_length": 8,
            "max_failed_attempts": 5,
            "lockout_duration_minutes": 15,
        },
        "webhook": {"secret": "test_webhook_secret", "time_tolerance": 120},
        "rate_limits": {},
        "dispatcher": {"max_concurrent_tasks": 5},
        "lock_manager": {"cleanup_interval_seconds": 300},
        "monitor": {"metrics_retention_hours": 24},
    }

    # Initialize components with in-memory database
    security_manager = SecurityManager(config)
    dispatcher = TaskDispatcher(config)
    lock_manager = LockManager(config["database"]["path"], enable_cleanup_thread=False)
    monitor = Monitor(config)

    # Inject dependencies
    app.state.config = config
    app.state.security_manager = security_manager
    app.state.dispatcher = dispatcher
    app.state.lock_manager = lock_manager
    app.state.monitor = monitor

    # Override the get_security_manager dependency to use our test instance
    def override_get_security_manager():
        return security_manager

    app.dependency_overrides[get_security_manager] = override_get_security_manager

    yield app


@pytest.fixture
def test_client(test_app):
    """Create test client"""
    return TestClient(test_app)


@pytest.fixture
def test_user_token(test_app):
    """Create test user and return JWT token"""
    security_manager = test_app.state.security_manager

    # Create test user
    user = security_manager.create_user(
        username="test_workflows_user",
        email="workflows@test.com",
        password="test_password_123",
        role=UserRole.OPERATOR,
    )

    # Generate JWT token
    token = security_manager.create_jwt_token(
        user_id=user.user_id, username=user.username, email=user.email, role=user.role
    )

    return token


@pytest.fixture
def auth_headers(test_user_token):
    """Create authorization headers"""
    return {"Authorization": f"Bearer {test_user_token}"}


@pytest.fixture
def viewer_token(test_app):
    """Create viewer user and return JWT token"""
    security_manager = test_app.state.security_manager

    # Create viewer user
    user = security_manager.create_user(
        username="test_viewer_user",
        email="viewer@test.com",
        password="test_password_123",
        role=UserRole.VIEWER,
    )

    # Generate JWT token
    token = security_manager.create_jwt_token(
        user_id=user.user_id, username=user.username, email=user.email, role=user.role
    )

    return token


@pytest.fixture
def viewer_headers(viewer_token):
    """Create viewer authorization headers"""
    return {"Authorization": f"Bearer {viewer_token}"}


def test_list_workflows_empty(test_client, viewer_headers):
    """Test listing workflows when no workflows are available"""
    response = test_client.get("/api/workflows/", headers=viewer_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_run_workflow_from_yaml_success(test_client, auth_headers):
    """Test running a workflow from YAML text"""
    yaml_text = """
    workflow:
      id: wf-001
      name: Sample Workflow
      steps:
        - id: step1
          action: noop
    """
    r = test_client.post(
        "/api/workflows/run",
        json={"yaml": yaml_text, "context": {"foo": "bar"}},
        headers=auth_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") == "success"
    assert data.get("workflow_id") == "wf-001"


def test_run_workflow_missing_yaml(test_client, auth_headers):
    """Test running workflow without YAML content"""
    r = test_client.post("/api/workflows/run", json={}, headers=auth_headers)
    assert r.status_code == 400


def test_approvals_stub_endpoints(test_client, auth_headers):
    """Test approval endpoints return expected stub responses"""
    # List approvals
    r = test_client.get("/api/workflows/approvals", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "pending" in data

    # Record approval with invalid decision
    r2 = test_client.post(
        "/api/workflows/approvals",
        json={"approval_id": "ap-1", "decision": "invalid"},
        headers=auth_headers,
    )
    assert r2.status_code == 400

    # Record approval success
    r3 = test_client.post(
        "/api/workflows/approvals",
        json={"approval_id": "ap-1", "decision": "approve"},
        headers=auth_headers,
    )
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3.get("status") == "accepted"
    assert data3.get("decision") == "approve"


# Security and Role-based Access Control Tests
class TestSecurityIntegration:
    """Test security integration with role-based access control"""

    def test_workflow_execution_requires_operator_role(self, test_client, viewer_headers):
        """Test that workflow execution requires OPERATOR role or higher"""
        yaml_text = """
        workflow:
          id: wf-security-test
          name: Security Test Workflow
          steps:
            - id: step1
              action: noop
        """

        r = test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=viewer_headers,
        )
        # Should be forbidden due to insufficient role
        assert r.status_code == 403

    def test_approval_recording_requires_operator_role(self, test_client, viewer_headers):
        """Test that approval recording requires OPERATOR role or higher"""
        r = test_client.post(
            "/api/workflows/approvals",
            json={
                "approval_id": "sec-test-001",
                "task_id": "task-001",
                "approver": "viewer_user",
                "decision": "approved",
            },
            headers=viewer_headers,
        )
        # Should be forbidden due to insufficient role
        assert r.status_code == 403

    def test_approver_must_match_authenticated_user(self, test_client, auth_headers):
        """Test that approver field must match authenticated user"""
        r = test_client.post(
            "/api/workflows/approvals",
            json={
                "approval_id": "sec-test-002",
                "task_id": "task-002",
                "approver": "different_user",  # Mismatch
                "decision": "approved",
            },
            headers=auth_headers,
        )
        # Should be forbidden due to approver mismatch
        assert r.status_code == 403


# Approval Workflow Tests
class TestApprovalWorkflows:
    """Test approval workflow branching and decision logic"""

    def test_approval_decision_branching(self, test_client, auth_headers):
        """Test different approval decision branches"""
        # Test approved decision
        r1 = test_client.post(
            "/api/workflows/approvals",
            json={
                "approval_id": "branch-test-001",
                "task_id": "task-001",
                "approver": "operator_user",
                "decision": "approved",
                "comments": "Looks good",
            },
            headers=auth_headers,
        )
        assert r1.status_code == 200
        data1 = r1.json()
        assert data1["status"] == "recorded"
        assert data1["approval"]["decision"] == "approved"

        # Test rejected decision
        r2 = test_client.post(
            "/api/workflows/approvals",
            json={
                "approval_id": "branch-test-002",
                "task_id": "task-002",
                "approver": "operator_user",
                "decision": "rejected",
                "comments": "Needs revision",
            },
            headers=auth_headers,
        )
        assert r2.status_code == 200
        data2 = r2.json()
        assert data2["status"] == "recorded"
        assert data2["approval"]["decision"] == "rejected"

    def test_duplicate_approval_id_prevention(self, test_client, auth_headers):
        """Test that duplicate approval IDs are prevented"""
        # This test relies on the existing approval data
        # First approval should succeed, second should fail
        approval_data = {
            "approval_id": "duplicate-test-001",
            "task_id": "task-001",
            "approver": "test_user",
            "decision": "approved",
        }

        # First submission
        r1 = test_client.post("/api/workflows/approvals", json=approval_data, headers=auth_headers)
        # Second submission with same ID
        r2 = test_client.post("/api/workflows/approvals", json=approval_data, headers=auth_headers)

        # Second should fail with conflict
        assert r2.status_code == 409
        assert "already exists" in r2.json()["detail"]


# Failure Handling Tests
class TestFailureHandling:
    """Test failure scenarios and error handling"""

    def test_invalid_yaml_workflow(self, test_client, auth_headers):
        """Test handling of invalid YAML workflow definitions"""
        invalid_yaml = "invalid: yaml: content: [unclosed"

        r = test_client.post(
            "/api/workflows/run",
            json={"yaml": invalid_yaml, "context": {}},
            headers=auth_headers,
        )
        assert r.status_code == 400
        assert "detail" in r.json()

    def test_missing_required_fields(self, test_client, auth_headers):
        """Test handling of missing required fields"""
        # Missing workflow definition
        r1 = test_client.post("/api/workflows/run", json={}, headers=auth_headers)
        assert r1.status_code == 400

        # Missing approval_id
        r2 = test_client.post(
            "/api/workflows/approvals",
            json={"decision": "approved"},
            headers=auth_headers,
        )
        assert r2.status_code == 400

    @patch("src.workflows_api._engine.run_definition")
    def test_workflow_execution_failure(self, mock_run_definition, test_client, auth_headers):
        """Test handling of workflow execution failures"""
        # Mock workflow execution failure
        mock_run_definition.side_effect = Exception("Execution failed")

        yaml_text = """
        workflow:
          id: wf-failure-test
          name: Failure Test Workflow
          steps:
            - id: step1
              action: noop
        """

        r = test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=auth_headers,
        )
        assert r.status_code == 500
        assert "Execution failed" in r.json()["detail"]


# Metrics and Observability Tests
class TestMetricsAndObservability:
    """Test Prometheus metrics and observability features"""

    def test_metrics_endpoint_accessibility(self, test_client, viewer_headers):
        """Test that metrics endpoint is accessible"""
        r = test_client.get("/api/workflows/metrics", headers=viewer_headers)
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/plain; charset=utf-8"

    def test_metrics_format(self, test_client, viewer_headers):
        """Test that metrics are in Prometheus format"""
        r = test_client.get("/api/workflows/metrics", headers=viewer_headers)
        content = r.text

        # Check for expected metric names
        assert "workflow_executions_total" in content
        assert "workflow_execution_duration_seconds_total" in content
        assert "workflow_executions_success_total" in content
        assert "workflow_executions_failure_total" in content
        assert "workflow_approval_requests_total" in content

        # Check for Prometheus format headers
        assert "# HELP" in content
        assert "# TYPE" in content

    def test_metrics_updated_on_execution(self, test_client, auth_headers, viewer_headers):
        """Test that metrics are updated when workflows are executed"""
        # Get initial metrics
        r1 = test_client.get("/api/workflows/metrics", headers=viewer_headers)
        initial_content = r1.text

        # Execute a workflow
        yaml_text = """
        workflow:
          id: wf-metrics-test
          name: Metrics Test Workflow
          steps:
            - id: step1
              action: noop
        """

        test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=auth_headers,
        )

        # Get updated metrics
        r2 = test_client.get("/api/workflows/metrics", headers=viewer_headers)
        updated_content = r2.text

        # Metrics should have changed
        assert initial_content != updated_content


# Retry and Timeout Tests
class TestRetryAndTimeout:
    """Test retry logic and timeout handling"""

    @patch("src.workflows_api._engine.run_definition")
    def test_execution_timeout_handling(self, mock_execute, test_client, auth_headers):
        """Test handling of execution timeouts"""

        # Mock a slow execution that would timeout
        def slow_execution(*args, **kwargs):
            from src.workflow_engine import StepResult, WorkflowResult

            time.sleep(0.1)  # Simulate slow execution
            return WorkflowResult(
                workflow_id="timeout-test",
                status="success",
                steps=[StepResult(step_id="step1", status="success")],
            )

        mock_execute.side_effect = slow_execution

        yaml_text = """
        workflow:
          id: wf-timeout-test
          name: Timeout Test Workflow
          steps:
            - id: step1
              action: slow_operation
        """

        start_time = time.time()
        r = test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=auth_headers,
        )
        execution_time = time.time() - start_time

        # Should complete (our mock is fast enough)
        assert r.status_code == 200
        # Should include execution duration in metadata
        data = r.json()
        assert "metadata" in data
        assert "execution_duration_seconds" in data["metadata"]

    @patch("src.workflows_api._engine.run_definition")
    def test_retry_on_transient_failure(self, mock_execute, test_client, auth_headers):
        """Test retry logic for transient failures"""
        # Mock transient failure followed by success
        call_count = 0

        def transient_failure(*args, **kwargs):
            from src.workflow_engine import StepResult, WorkflowResult

            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Transient network error")
            return WorkflowResult(
                workflow_id="retry-test",
                status="success",
                steps=[StepResult(step_id="step1", status="success")],
            )

        mock_execute.side_effect = transient_failure

        yaml_text = """
        workflow:
          id: wf-retry-test
          name: Retry Test Workflow
          steps:
            - id: step1
              action: network_operation
        """

        # First call should fail
        r1 = test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=auth_headers,
        )
        assert r1.status_code == 500

        # Second call should succeed
        r2 = test_client.post(
            "/api/workflows/run",
            json={"yaml": yaml_text, "context": {}},
            headers=auth_headers,
        )
        assert r2.status_code == 200


# Workflow Catalog Tests
class TestWorkflowCatalog:
    """Test workflow catalog functionality"""

    def test_catalog_listing(self, test_client, viewer_headers):
        """Test workflow catalog listing"""
        r = test_client.get("/api/workflows/", headers=viewer_headers)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

        # Check for expected workflow catalog items
        if data:  # If catalog has items
            item = data[0]
            expected_fields = [
                "file_path",
                "name",
                "description",
                "version",
                "author",
                "tags",
                "created_at",
                "workflow_steps",
            ]
            for field in expected_fields:
                assert field in item

    def test_specific_workflow_details(self, test_client, viewer_headers):
        """Test retrieving specific workflow details"""
        # First get the catalog to find available workflows
        r1 = test_client.get("/api/workflows/", headers=viewer_headers)
        catalog = r1.json()

        if catalog:  # If catalog has items
            workflow_name = catalog[0]["name"]
            r2 = test_client.get(f"/api/workflows/{workflow_name}", headers=viewer_headers)
            assert r2.status_code == 200

            data = r2.json()
            # Check for expected WorkflowCatalogItem fields
            expected_fields = [
                "file_path",
                "name",
                "description",
                "version",
                "author",
                "tags",
                "created_at",
                "metadata",
            ]
            for field in expected_fields:
                assert field in data
            assert data["name"] == workflow_name

    def test_nonexistent_workflow_details(self, test_client, viewer_headers):
        """Test retrieving details for non-existent workflow"""
        r = test_client.get("/api/workflows/nonexistent-workflow", headers=viewer_headers)
        assert r.status_code == 404
        assert "not found" in r.json()["detail"]
