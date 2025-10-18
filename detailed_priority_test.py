#!/usr/bin/env python3
"""Detailed priority queue test with extensive logging"""

import logging
import os
import tempfile
import time

from src.lock_manager import LockManager, LockPriority, LockRequest

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("src.lock_manager")
logger.setLevel(logging.DEBUG)


def detailed_priority_test():
    """Test priority queue with detailed step-by-step logging"""
    try:
        # Create temporary database
        temp_db = tempfile.mktemp(suffix=".db")
        lock_manager = LockManager(db_path=temp_db, enable_cleanup_thread=False)

        print("=== Detailed Priority Test ===")

        # Step 1: Create initial lock
        print("\n--- Step 1: Create initial lock ---")
        initial_request = LockRequest(
            resource="test_resource",
            owner="initial_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=3,  # Short TTL for quick test
        )
        initial_lock = lock_manager.acquire_lock(initial_request)
        print(f"Initial lock: {initial_lock}")

        # Step 2: Add all requests to queue immediately
        print("\n--- Step 2: Add requests to queue ---")

        low_request = LockRequest(
            resource="test_resource",
            owner="low_owner",
            priority=LockPriority.LOW,
            ttl_seconds=60,
        )

        medium_request = LockRequest(
            resource="test_resource",
            owner="medium_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=60,
        )

        high_request = LockRequest(
            resource="test_resource",
            owner="high_owner",
            priority=LockPriority.HIGH,
            ttl_seconds=60,
        )

        # Add to queue manually
        print("Adding low priority request...")
        low_queue_id = lock_manager._add_to_queue(low_request)
        print(f"Low queue ID: {low_queue_id}")

        print("Adding medium priority request...")
        medium_queue_id = lock_manager._add_to_queue(medium_request)
        print(f"Medium queue ID: {medium_queue_id}")

        print("Adding high priority request...")
        high_queue_id = lock_manager._add_to_queue(high_request)
        print(f"High queue ID: {high_queue_id}")

        # Check queue status
        print("\n--- Step 3: Check queue status ---")
        queue_status = lock_manager.get_queue_status("test_resource")
        print(f"Queue entries: {len(queue_status)}")
        for entry in queue_status:
            print(
                f"  {entry['owner']}: priority={entry['priority']}, requested_at={entry['requested_at']}"
            )

        # Step 3: Wait for initial lock to expire
        print("\n--- Step 4: Wait for initial lock to expire ---")
        print("Waiting 4 seconds for initial lock to expire...")
        time.sleep(4)

        # Check if initial lock is still active
        current_lock = lock_manager.get_lock_info("test_resource")
        print(f"Current lock after wait: {current_lock}")

        # Clean up expired locks
        print("Cleaning up expired locks...")
        cleaned = lock_manager.cleanup_expired_locks()
        print(f"Cleaned up {cleaned} expired locks")

        # Check lock status again
        current_lock = lock_manager.get_lock_info("test_resource")
        print(f"Current lock after cleanup: {current_lock}")

        # Step 4: Check who can acquire
        print("\n--- Step 5: Check acquisition eligibility ---")
        for queue_id, owner, priority in [
            (high_queue_id, "high_owner", "HIGH"),
            (medium_queue_id, "medium_owner", "MEDIUM"),
            (low_queue_id, "low_owner", "LOW"),
        ]:
            can_acquire = lock_manager._can_acquire_from_queue(queue_id)
            print(f"{owner} ({priority}): can_acquire = {can_acquire}")

        # Step 5: Try acquisition in priority order
        print("\n--- Step 6: Attempt acquisition in priority order ---")
        acquired_lock = None

        for queue_id, owner, priority in [
            (high_queue_id, "high_owner", "HIGH"),
            (medium_queue_id, "medium_owner", "MEDIUM"),
            (low_queue_id, "low_owner", "LOW"),
        ]:
            print(f"\nTrying {owner} ({priority})...")
            if lock_manager._can_acquire_from_queue(queue_id):
                lock_info = lock_manager._acquire_from_queue(queue_id)
                if lock_info:
                    print(f"✅ {owner} acquired lock: {lock_info}")
                    acquired_lock = (owner, priority, lock_info)
                    break
                else:
                    print(f"❌ {owner} failed to acquire lock")
            else:
                print(f"⏳ {owner} cannot acquire yet")

        # Final results
        print("\n--- Final Results ---")
        if acquired_lock:
            owner, priority, lock_info = acquired_lock
            print(f"Winner: {owner} with priority {priority}")
            if priority == "HIGH":
                print("✅ HIGH priority won (correct)")
            else:
                print(f"❌ {priority} priority won (incorrect - should be HIGH)")
        else:
            print("❌ No one acquired the lock")

        # Final queue status
        queue_status = lock_manager.get_queue_status("test_resource")
        print(f"Remaining queue entries: {len(queue_status)}")

    finally:
        try:
            if "temp_db" in locals():
                os.unlink(temp_db)
        except:
            pass


if __name__ == "__main__":
    detailed_priority_test()
