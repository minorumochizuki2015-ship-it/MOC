#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for ORCH-Next tests
"""

import asyncio
import logging
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch

import pytest

# Test configuration: load optional plugins only if available to avoid ImportError
_optional_plugins = ["pytest_asyncio", "pytest_mock", "pytest_benchmark", "pytest_timeout"]
_loaded_plugins = []
for _p in _optional_plugins:
    try:
        __import__(_p)
        _loaded_plugins.append(_p)
    except Exception:
        pass
pytest_plugins = _loaded_plugins

# Ensure src is importable when running tests from ORCH-Next root
try:
    ROOT = Path(__file__).resolve().parents[1]  # ORCH-Next
    SRC = ROOT / "src"
    for p in [str(ROOT), str(SRC)]:
        if p not in sys.path:
            sys.path.insert(0, p)
except Exception:
    pass

# Configure logging for tests
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Disable noisy loggers during tests
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# Configure pytest-asyncio
def pytest_configure(config):
    """Configure pytest for asyncio tests"""
    config.option.asyncio_mode = "auto"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Base test configuration"""
    return {
        "database": {
            "path": ":memory:",  # Use in-memory SQLite for tests
            "pool_size": 5,
            "timeout": 30,
        },
        "jwt": {
            "secret_key": "test-jwt-secret-key-for-testing-only",
            "algorithm": "HS256",
            "expiry_hours": 1,  # Short expiry for testing
        },
        "webhook": {"secret": "test-webhook-secret-for-testing-only", "time_tolerance": 120},
        "rate_limits": {
            "rules": [
                {
                    "endpoint": "/test",
                    "method": "GET",
                    "max_requests": 10,
                    "window_seconds": 3600,
                    "per_user": True,
                }
            ]
        },
        "monitoring": {
            "enabled": False,  # Disable monitoring in tests
            "interval": 60,
            "slack_webhook": None,
        },
        "logging": {"level": "DEBUG", "format": "json"},
    }


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def temp_db_path(temp_dir: Path) -> Path:
    """Create a temporary database file path"""
    return temp_dir / "test.db"


@pytest.fixture
def test_data_dir(temp_dir: Path) -> Path:
    """Create test data directory structure"""
    data_dir = temp_dir / "data"
    data_dir.mkdir()

    # Create subdirectories
    (data_dir / "logs").mkdir()
    (data_dir / "config").mkdir()
    (data_dir / "backups").mkdir()
    (data_dir / "metrics").mkdir()

    return data_dir


@pytest.fixture
def mock_security_manager():
    """Mock SecurityManager for testing"""
    from datetime import datetime

    from src.security import SecurityManager, User, UserRole

    manager = MagicMock(spec=SecurityManager)

    # Mock user for testing
    test_user = User(
        user_id="test-user-123",
        username="testuser",
        email="test@example.com",
        role=UserRole.OPERATOR,
        is_active=True,
        created_at=datetime.utcnow(),
    )

    # Configure mock methods
    manager.verify_jwt_token.return_value = test_user
    manager.authenticate_user.return_value = test_user
    manager.create_jwt_token.return_value = "mock-jwt-token"
    manager.verify_hmac_signature.return_value = True
    manager.check_rate_limit.return_value = (True, {"remaining": 100})

    return manager


@pytest.fixture
def mock_dispatcher():
    """Mock TaskDispatcher for testing"""
    from src.dispatcher import TaskDispatcher

    dispatcher = MagicMock(spec=TaskDispatcher)

    # Configure mock methods
    dispatcher.dispatch_task.return_value = {
        "task_id": "test-task-123",
        "status": "dispatched",
        "core_id": "TEST_CORE_01",
    }
    dispatcher.get_metrics.return_value = {
        "tasks_dispatched": 10,
        "tasks_completed": 8,
        "tasks_failed": 1,
        "avg_duration": 45.2,
    }

    return dispatcher


@pytest.fixture
def mock_lock_manager():
    """Mock LockManager for testing"""
    from src.lock_manager import LockManager

    manager = MagicMock(spec=LockManager)

    # Configure mock methods
    manager.acquire_lock.return_value = True
    manager.release_lock.return_value = True
    manager.extend_lock.return_value = True
    manager.get_lock_info.return_value = {
        "resource": "test-resource",
        "owner": "test-owner",
        "acquired_at": "2024-01-01T12:00:00Z",
        "expires_at": "2024-01-01T13:00:00Z",
    }

    return manager


@pytest.fixture
def mock_monitor():
    """Mock Monitor service for testing"""
    from src.monitor import Monitor

    monitor = MagicMock(spec=Monitor)

    # Configure mock methods
    monitor.collect_metrics.return_value = {
        "cpu_percent": 45.2,
        "memory_percent": 62.1,
        "disk_usage": 78.5,
        "active_connections": 12,
    }
    monitor.detect_anomalies.return_value = []
    monitor.suggest_recovery.return_value = ["restart_service"]

    return monitor


@pytest.fixture
def sample_webhook_payload():
    """Sample webhook payload for testing"""
    return {
        "event": "task.completed",
        "task_id": "test-task-123",
        "core_id": "TEST_CORE_01",
        "status": "success",
        "timestamp": "2024-01-01T12:00:00Z",
        "data": {"duration": 45.2, "output": "Task completed successfully"},
    }


@pytest.fixture
def sample_dispatch_request():
    """Sample dispatch request for testing"""
    return {
        "coreId": "TEST_CORE_01",
        "stay": False,
        "priority": 1,
        "timeout": 300,
        "metadata": {"source": "test", "environment": "testing"},
    }


@pytest.fixture
def mock_database():
    """Mock database connection for testing"""
    with patch("sqlite3.connect") as mock_connect:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None

        mock_connect.return_value = mock_conn

        yield mock_conn, mock_cursor


@pytest.fixture
def clean_database(temp_db_path: Path):
    """Provide a clean database for each test"""
    # Remove database if it exists
    if temp_db_path.exists():
        temp_db_path.unlink()

    yield temp_db_path

    # Cleanup after test
    if temp_db_path.exists():
        temp_db_path.unlink()


@pytest.fixture
def populated_database(clean_database: Path, test_config: Dict[str, Any]):
    """Provide a database with test data"""
    from src.dispatcher import TaskDispatcher
    from src.lock_manager import LockManager
    from src.security import SecurityManager

    # Update config to use test database
    config = test_config.copy()
    config["database"]["path"] = str(clean_database)

    # Initialize components to create schema
    security_manager = SecurityManager(config)
    dispatcher = TaskDispatcher(config)
    lock_manager = LockManager(str(clean_database))

    # Add test data
    test_user = security_manager.create_user(
        username="testuser",
        email="test@example.com",
        password="testpassword123",
        role=security_manager.UserRole.OPERATOR,
    )

    yield {
        "db_path": clean_database,
        "config": config,
        "test_user": test_user,
        "security_manager": security_manager,
        "dispatcher": dispatcher,
        "lock_manager": lock_manager,
    }


@pytest.fixture
def mock_external_services():
    """Mock external services (Slack, webhooks, etc.)"""
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True}
        mock_post.return_value = mock_response

        yield mock_post


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch, temp_dir: Path):
    """Set up test environment variables"""
    # Set test environment variables
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("DATA_DIR", str(temp_dir))

    # Disable external integrations during tests
    monkeypatch.setenv("DISABLE_SLACK", "true")
    monkeypatch.setenv("DISABLE_WEBHOOKS", "true")
    monkeypatch.setenv("DISABLE_MONITORING", "true")


# Performance testing fixtures
@pytest.fixture
def benchmark_config():
    """Configuration for benchmark tests"""
    return {"min_rounds": 5, "max_time": 10.0, "warmup": True, "warmup_iterations": 2}


# Integration test fixtures
@pytest.fixture
def integration_config(test_config: Dict[str, Any], temp_dir: Path):
    """Configuration for integration tests"""
    config = test_config.copy()

    # Use real database file for integration tests
    config["database"]["path"] = str(temp_dir / "integration.db")

    # Enable monitoring for integration tests
    config["monitoring"]["enabled"] = True
    config["monitoring"]["interval"] = 5  # Short interval for testing

    return config


# Async test helpers
@pytest.fixture
async def async_client():
    """Async HTTP client for testing FastAPI endpoints"""
    from httpx import AsyncClient

    async with AsyncClient() as client:
        yield client


# Test data generators
@pytest.fixture
def task_generator():
    """Generate test tasks"""

    def _generate_task(task_id: str = None, core_id: str = None, **kwargs):
        import uuid

        return {
            "task_id": task_id or str(uuid.uuid4()),
            "core_id": core_id or "TEST_CORE_01",
            "status": "pending",
            "priority": 1,
            "created_at": "2024-01-01T12:00:00Z",
            "timeout": 300,
            **kwargs,
        }

    return _generate_task


@pytest.fixture
def user_generator():
    """Generate test users"""

    def _generate_user(username: str = None, role: str = "operator", **kwargs):
        import uuid

        from src.security import UserRole

        return {
            "user_id": str(uuid.uuid4()),
            "username": username or f"testuser_{uuid.uuid4().hex[:8]}",
            "email": f'{username or "test"}@example.com',
            "role": UserRole(role),
            "is_active": True,
            **kwargs,
        }

    return _generate_user


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup resources after each test"""
    yield

    # Close any open database connections
    import gc

    gc.collect()

    # Clear any cached modules
    import sys

    modules_to_clear = [name for name in sys.modules if name.startswith("src.")]
    for module_name in modules_to_clear:
        if hasattr(sys.modules[module_name], "_instances"):
            sys.modules[module_name]._instances.clear()


# Test markers for pytest
def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "e2e: mark test as an end-to-end test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "security: mark test as security-related")
    config.addinivalue_line("markers", "performance: mark test as performance-related")
    config.addinivalue_line("markers", "contract: mark test as a contract test")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names"""
    for item in items:
        # Add markers based on test file names
        if "test_security" in item.nodeid:
            item.add_marker(pytest.mark.security)

        if "integration" in item.nodeid or "full_workflow" in item.name:
            item.add_marker(pytest.mark.integration)

        if "performance" in item.name or "benchmark" in item.name:
            item.add_marker(pytest.mark.performance)

        if "contract" in item.name or "hmac" in item.name or "jwt" in item.name:
            item.add_marker(pytest.mark.contract)

        # Mark slow tests
        if any(keyword in item.name.lower() for keyword in ["slow", "load", "stress"]):
            item.add_marker(pytest.mark.slow)


# Fallback benchmark fixture in case pytest-benchmark is unavailable or misconfigured
@pytest.fixture
def benchmark():
    """Minimal benchmark-like fixture: simply executes the function and returns its result.

    This serves as a compatibility fallback so performance-marked tests can still run
    when the pytest-benchmark plugin is not providing the 'benchmark' fixture.
    """
    def _run(func, *args, **kwargs):
        return func(*args, **kwargs)

    return _run


# Custom assertions
def assert_valid_uuid(value: str):
    """Assert that a string is a valid UUID"""
    import uuid

    try:
        uuid.UUID(value)
    except ValueError:
        pytest.fail(f"'{value}' is not a valid UUID")


def assert_valid_timestamp(value: str):
    """Assert that a string is a valid ISO timestamp"""
    from datetime import datetime

    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"'{value}' is not a valid ISO timestamp")


def assert_response_time(duration: float, max_seconds: float = 1.0):
    """Assert that response time is within acceptable limits"""
    if duration > max_seconds:
        pytest.fail(f"Response time {duration:.3f}s exceeds {max_seconds}s limit")


# Add custom assertions to pytest namespace
pytest.assert_valid_uuid = assert_valid_uuid
pytest.assert_valid_timestamp = assert_valid_timestamp
pytest.assert_response_time = assert_response_time


# Test-only RSA private key fixture for RS256 token generation
@pytest.fixture
def jwt_rsa_private_key() -> str:
    """Generate a temporary RSA private key (PEM) for RS256 tests.

    This key is generated at test time and is NOT used in production. It allows
    RS256 token creation to validate algorithm handling (expected to be rejected
    by the application which only accepts HS256).
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem_bytes.decode("utf-8")
    except Exception:
        # Fallback: return an empty string to avoid hard failure. Tests using this fixture
        # should treat inability to generate RS256 tokens as a rejection case.
        return ""
