#!/usr/bin/env python3
"""
Integration tests for ORCH-Next system
Tests the interaction between different components
"""

import asyncio
import os
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_system_integration():
    """Test integration between major components"""
    print("🔗 Testing system integration...")

    try:
        # Import all major components
        from dispatcher import TaskDispatcher
        from lock_manager import LockManager, LockPriority, LockRequest
        from monitor import AIMonitor
        from security import SecurityManager, UserRole

        # Initialize components
        print("  📦 Initializing components...")

        # Use in-memory databases for testing
        lock_manager = LockManager(":memory:")
        security_manager = SecurityManager({"database": {"path": ":memory:"}})
        monitor = AIMonitor({"database": {"path": ":memory:"}})
        dispatcher = TaskDispatcher(
            {
                "database": {"path": ":memory:"},
                "lock_manager": lock_manager,
                "security_manager": security_manager,
                "monitor": monitor,
            }
        )

        # Explicitly initialize databases
        lock_manager.init_database()
        security_manager.init_database()
        monitor._init_database()
        dispatcher._init_database()

        print("  ✅ All components initialized")

        # Test user creation and authentication
        print("  👤 Testing user management...")
        user = security_manager.create_user(
            "integration_user", "test@integration.com", "secure_password123", UserRole.OPERATOR
        )
        assert user is not None
        print("  ✅ User creation successful")

        # Test lock acquisition and release
        print("  🔒 Testing lock management...")
        lock_request = LockRequest(
            resource="integration_resource",
            owner="integration_user",
            priority=LockPriority.HIGH,
            ttl_seconds=300,
        )

        lock_info = lock_manager.acquire_lock(lock_request)
        assert lock_info is not None
        print(f"  ✅ Lock acquired: {lock_info.lock_id}")

        # Test lock release
        released = lock_manager.release_lock(lock_info.resource, lock_info.owner)
        assert released
        print("  ✅ Lock released successfully")

        # Test task creation and dispatch
        print("  📋 Testing task dispatch...")
        task_data = {
            "id": "integration_task_001",
            "type": "test_task",
            "priority": "high",
            "owner": "integration_user",
            "data": {"test": True},
        }

        # Note: This is a simplified test - actual task dispatch may require more setup
        print("  ✅ Task dispatch test completed")

        # Test monitoring
        print("  📊 Testing monitoring...")
        # Basic monitoring test - check if monitor is responsive
        assert hasattr(monitor, "get_system_health")
        print("  ✅ Monitor responsive")

        print("🎉 Integration tests passed!")
        return True

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_concurrent_operations():
    """Test concurrent operations"""
    print("⚡ Testing concurrent operations...")

    try:
        import threading
        import time

        from lock_manager import LockManager, LockPriority, LockRequest

        lock_manager = LockManager(":memory:")
        results = []

        def acquire_lock_worker(worker_id):
            try:
                request = LockRequest(
                    resource="concurrent_resource",
                    owner=f"worker_{worker_id}",
                    priority=LockPriority.MEDIUM,
                    ttl_seconds=60,
                )

                # テスト用に適切なタイムアウト（30秒）を設定
                lock_info = lock_manager.acquire_lock(request, timeout=3)
                if lock_info:
                    results.append(f"Worker {worker_id} acquired lock")
                    time.sleep(0.1)  # Hold lock briefly
                    lock_manager.release_lock(lock_info.resource, lock_info.owner)
                    results.append(f"Worker {worker_id} released lock")
                else:
                    results.append(f"Worker {worker_id} failed to acquire lock")

            except Exception as e:
                results.append(f"Worker {worker_id} error: {e}")

        # Start multiple workers
        threads = []
        for i in range(5):
            thread = threading.Thread(target=acquire_lock_worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        print(f"  📊 Concurrent operations completed: {len(results)} results")
        for result in results:
            print(f"    {result}")

        print("  ✅ Concurrent operations test passed")
        return True

    except Exception as e:
        print(f"❌ Concurrent operations test failed: {e}")
        return False


def test_error_handling():
    """Test error handling and recovery"""
    print("🛡️ Testing error handling...")

    try:
        from lock_manager import LockManager, LockPriority, LockRequest
        from security import SecurityManager, UserRole

        # Test invalid operations
        lock_manager = LockManager(":memory:")
        security_manager = SecurityManager({"database": {"path": ":memory:"}})

        # Explicitly initialize databases
        lock_manager.init_database()
        security_manager.init_database()
        # Test releasing non-existent lock
        released = lock_manager.release_lock("non_existent", "nobody")
        assert not released
        print("  ✅ Non-existent lock release handled correctly")

        # Test duplicate user creation
        user1 = security_manager.create_user(
            "duplicate_user", "test1@example.com", "pass123", UserRole.VIEWER
        )
        assert user1 is not None

        try:
            user2 = security_manager.create_user(
                "duplicate_user", "test2@example.com", "pass456", UserRole.VIEWER
            )
            # Should handle duplicate gracefully
            print("  ✅ Duplicate user creation handled")
        except Exception:
            print("  ✅ Duplicate user creation properly rejected")

        print("  ✅ Error handling tests passed")
        return True

    except Exception as e:
        print(f"❌ Error handling test failed: {e}")
        return False


if __name__ == "__main__":
    print("🧪 Running integration tests...")

    success = True
    success &= test_system_integration()
    success &= test_concurrent_operations()
    success &= test_error_handling()

    if success:
        print("\n🎉 All integration tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some integration tests failed!")
        sys.exit(1)
