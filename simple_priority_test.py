#!/usr/bin/env python3
"""Simple priority queue test"""

import logging
import os
import tempfile
import time

from src.lock_manager import LockManager, LockPriority, LockRequest

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('src.lock_manager')
logger.setLevel(logging.DEBUG)

def simple_priority_test():
    """Test priority queue with sequential requests"""
    try:
        # Create temporary database
        temp_db = tempfile.mktemp(suffix='.db')
        lock_manager = LockManager(db_path=temp_db, enable_cleanup_thread=False)
        
        print("=== Simple Priority Test ===")
        
        # Step 1: Create initial lock
        initial_request = LockRequest(
            resource="test_resource",
            owner="initial_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=10
        )
        initial_lock = lock_manager.acquire_lock(initial_request)
        print(f"Initial lock: {initial_lock}")
        
        # Step 2: Add requests to queue in order: low, medium, high
        low_request = LockRequest(
            resource="test_resource",
            owner="low_owner",
            priority=LockPriority.LOW,
            ttl_seconds=60
        )
        
        medium_request = LockRequest(
            resource="test_resource",
            owner="medium_owner",
            priority=LockPriority.MEDIUM,
            ttl_seconds=60
        )
        
        high_request = LockRequest(
            resource="test_resource",
            owner="high_owner",
            priority=LockPriority.HIGH,
            ttl_seconds=60
        )
        
        print("\n=== Adding requests to queue ===")
        
        # Add low priority first
        print("Adding low priority request...")
        low_queue_id = lock_manager._add_to_queue(low_request)
        print(f"Low queue ID: {low_queue_id}")
        
        # Add medium priority
        print("Adding medium priority request...")
        medium_queue_id = lock_manager._add_to_queue(medium_request)
        print(f"Medium queue ID: {medium_queue_id}")
        
        # Add high priority
        print("Adding high priority request...")
        high_queue_id = lock_manager._add_to_queue(high_request)
        print(f"High queue ID: {high_queue_id}")
        
        # Check queue status
        print("\n=== Queue Status ===")
        queue_status = lock_manager.get_queue_status("test_resource")
        print(f"Queue entries: {len(queue_status)}")
        for entry in queue_status:
            print(f"  {entry['owner']}: priority={entry['priority']}, requested_at={entry['requested_at']}")
        
        # Wait for initial lock to expire
        print("\n=== Waiting for initial lock to expire ===")
        time.sleep(11)
        
        # Clean up expired locks
        print("Cleaning up expired locks...")
        cleaned = lock_manager.cleanup_expired_locks()
        print(f"Cleaned up {cleaned} expired locks")
        
        # Check who can acquire now
        print("\n=== Checking acquisition order ===")
        for queue_id, owner in [(low_queue_id, "low_owner"), (medium_queue_id, "medium_owner"), (high_queue_id, "high_owner")]:
            can_acquire = lock_manager._can_acquire_from_queue(queue_id)
            print(f"{owner}: can_acquire = {can_acquire}")
        
        # Try to acquire in order
        print("\n=== Attempting acquisition ===")
        for queue_id, owner in [(high_queue_id, "high_owner"), (medium_queue_id, "medium_owner"), (low_queue_id, "low_owner")]:
            if lock_manager._can_acquire_from_queue(queue_id):
                lock_info = lock_manager._acquire_from_queue(queue_id)
                if lock_info:
                    print(f"✅ {owner} acquired lock: {lock_info}")
                    break
                else:
                    print(f"❌ {owner} failed to acquire lock")
            else:
                print(f"⏳ {owner} cannot acquire yet")
        
        # Final queue status
        print("\n=== Final Queue Status ===")
        queue_status = lock_manager.get_queue_status("test_resource")
        print(f"Remaining queue entries: {len(queue_status)}")
        
    finally:
        try:
            if 'temp_db' in locals():
                os.unlink(temp_db)
        except:
            pass

if __name__ == "__main__":
    simple_priority_test()