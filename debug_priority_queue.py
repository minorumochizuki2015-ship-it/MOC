#!/usr/bin/env python3
"""Debug script for priority queue behavior"""

import logging
import os
import tempfile
import threading
import time

from src.lock_manager import LockManager, LockPriority, LockRequest

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("src.lock_manager")
logger.setLevel(logging.DEBUG)


def debug_priority_queue():
    """Debug priority queue behavior step by step"""

    # Create temporary database file
    temp_db = tempfile.mktemp(suffix=".db")
    try:
        lock_manager = LockManager(temp_db, enable_cleanup_thread=False)

        print("=== Step 1: Acquire initial lock ===")
        initial_request = LockRequest(
            resource="test_resource",
            owner="initial_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=8,  # Longer TTL to ensure all threads queue up
        )

        initial_lock = lock_manager.acquire_lock(initial_request)
        print(f"Initial lock: {initial_lock}")

        print("\n=== Step 2: Queue requests in order ===")

        # Queue low priority first
        low_request = LockRequest(
            resource="test_resource",
            owner="low_owner",
            priority=LockPriority.LOW,
            ttl_seconds=60,
        )

        # Queue medium priority second
        medium_request = LockRequest(
            resource="test_resource",
            owner="medium_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=60,
        )

        # Queue high priority third
        high_request = LockRequest(
            resource="test_resource",
            owner="high_owner",
            priority=LockPriority.HIGH,
            ttl_seconds=60,
        )

        results = {}
        thread_ready = threading.Event()
        threads_started = 0

        def try_acquire(request, name):
            nonlocal threads_started
            print(f"Thread {name} starting...")
            print(f"Thread {name} requesting lock with priority {request.priority}")

            # Signal that this thread is ready
            threads_started += 1
            if threads_started == 3:
                thread_ready.set()

            result = lock_manager.acquire_lock(request, timeout=20)  # Longer timeout
            results[name] = result
            print(f"Thread {name} result: {result}")
            if result is None:
                print(f"Thread {name} failed to acquire lock")

        # Start all threads simultaneously
        threads = []
        for request, name in [
            (low_request, "low"),
            (medium_request, "medium"),
            (high_request, "high"),
        ]:
            thread = threading.Thread(target=try_acquire, args=(request, name))
            threads.append(thread)
            thread.start()

        # Wait for all threads to be ready
        thread_ready.wait(timeout=5)
        time.sleep(2)  # Give time for all to be added to queue

        print("\n=== Step 3: Check queue status ===")
        queue_status = lock_manager.get_queue_status("test_resource")
        print(f"Queue status after all threads started: {len(queue_status)} entries")
        for entry in queue_status:
            print(f"  {entry['owner']}: priority={entry['priority']}")

        print("\n=== Step 4: Wait for initial lock to expire ===")
        time.sleep(6)

        print("Cleaning up expired locks...")
        cleaned = lock_manager.cleanup_expired_locks()
        print(f"Cleaned up {cleaned} expired locks")

        print("\n=== Step 5: Wait for results ===")
        for thread in threads:
            thread.join()

        print(f"\nFinal results: {results}")

        # Check which one succeeded
        successful = [name for name, result in results.items() if result is not None]
        failed = [name for name, result in results.items() if result is None]

        print(f"Successful: {successful}")
        print(f"Failed: {failed}")

        if successful:
            winner = successful[0]
            winner_priority = results[winner].priority
            print(f"Winner: {winner} with priority {winner_priority}")

            if winner == "high":
                print("✅ HIGH priority won (correct)")
            else:
                print(f"❌ {winner.upper()} priority won (incorrect - should be HIGH)")
        else:
            print("❌ No one won (all timed out)")

    finally:
        # Clean up temporary database
        if os.path.exists(temp_db):
            os.unlink(temp_db)


if __name__ == "__main__":
    debug_priority_queue()
