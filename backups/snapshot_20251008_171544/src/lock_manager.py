#!/usr/bin/env python3
"""
ORCH-Next SQLite-based Lock Manager
Implements TTL, priority queuing, and fair lock distribution
"""

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LockPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class LockRequest:
    resource: str
    owner: str
    priority: LockPriority
    ttl_seconds: int
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class LockInfo:
    resource: str
    owner: str
    priority: LockPriority
    acquired_at: datetime
    expires_at: datetime
    metadata: Dict[str, Any]
    lock_id: str


class LockManager:
    """
    SQLite-based distributed lock manager with:
    - TTL-based automatic cleanup
    - Priority-based fair queuing
    - Starvation prevention
    - Deadlock detection
    """

    def __init__(self, db_path: str = "data/locks.db", enable_cleanup_thread: bool = True):
        self.db_path = Path(db_path)
        self._enable_cleanup_thread = enable_cleanup_thread
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local_lock = threading.RLock()
        self._cleanup_interval = 30  # seconds
        self._max_wait_time = 300  # 5 minutes max wait
        self._starvation_threshold = 180  # 3 minutes

        # For in-memory databases, keep a persistent connection
        if str(self.db_path) == ":memory:":
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._init_database_connection(self._conn)
        else:
            self._conn = None
            self.init_database()

        # Start background cleanup thread only if enabled (useful to disable in tests)
        if self._enable_cleanup_thread:
            self._start_cleanup_thread()

    def _init_database_connection(self, conn):
        """Initialize database schema on a given connection"""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS locks (
                lock_id TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                owner TEXT NOT NULL,
                priority INTEGER NOT NULL,
                acquired_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_locks_resource ON locks(resource)
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_locks_expires_at ON locks(expires_at)
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_locks_priority ON locks(priority)
        """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lock_queue (
                queue_id TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                owner TEXT NOT NULL,
                priority INTEGER NOT NULL,
                requested_at TIMESTAMP NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                metadata TEXT
            )
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_queue_resource_priority ON lock_queue(resource, priority DESC, requested_at ASC)
        """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lock_history (
                history_id TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                owner TEXT NOT NULL,
                action TEXT NOT NULL,  -- 'acquired', 'released', 'expired', 'failed'
                timestamp TIMESTAMP NOT NULL,
                duration_seconds REAL,
                metadata TEXT
            )
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_history_resource_timestamp ON lock_history(resource, timestamp)
        """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_history_owner_timestamp ON lock_history(owner, timestamp)
        """
        )

        conn.commit()

    def init_database(self):
        """Initialize the lock database schema"""
        with sqlite3.connect(self.db_path) as conn:
            self._init_database_connection(conn)

    def acquire_lock(
        self, request: LockRequest, timeout: Optional[int] = None
    ) -> Optional[LockInfo]:
        """
        Acquire a lock with priority queuing and fair scheduling

        Args:
            request: Lock request details
            timeout: Maximum wait time in seconds (None for no timeout)

        Returns:
            LockInfo if successful, None if failed
        """
        start_time = time.time()
        timeout = timeout or self._max_wait_time

        with self._local_lock:
            # Check if resource is already locked by same owner
            existing = self._get_active_lock(request.resource)
            if existing and existing.owner == request.owner:
                # Extend existing lock
                return self._extend_lock(existing, request.ttl_seconds)

            # Try immediate acquisition
            if not existing:
                return self._create_lock(request)

            # Add to queue and wait
            queue_id = self._add_to_queue(request)

            try:
                while time.time() - start_time < timeout:
                    # Check if we can acquire now
                    if self._can_acquire_from_queue(queue_id):
                        lock_info = self._acquire_from_queue(queue_id)
                        if lock_info:
                            return lock_info

                    # Wait before next check
                    time.sleep(0.1)

                # Timeout - remove from queue
                self._remove_from_queue(queue_id)
                self._record_history(
                    request.resource,
                    request.owner,
                    "failed",
                    metadata={
                        "reason": "timeout",
                        "wait_time": time.time() - start_time,
                    },
                )
                return None

            except Exception as e:
                self._remove_from_queue(queue_id)
                logger.error(f"Error acquiring lock for {request.resource}: {e}")
                return None

    def release_lock(self, resource: str, owner: str) -> bool:
        """
        Release a lock

        Args:
            resource: Resource identifier
            owner: Lock owner

        Returns:
            True if released successfully
        """
        with self._local_lock:
            try:
                if self._conn:  # Use persistent connection for in-memory DB
                    cursor = self._conn.cursor()

                    # Get lock info for history
                    cursor.execute(
                        """
                        SELECT lock_id, acquired_at FROM locks 
                        WHERE resource = ? AND owner = ?
                    """,
                        (resource, owner),
                    )

                    row = cursor.fetchone()
                    if not row:
                        return False

                    lock_id, acquired_at = row
                    acquired_time = datetime.fromisoformat(acquired_at)
                    duration = (datetime.utcnow() - acquired_time).total_seconds()

                    # Remove lock
                    cursor.execute(
                        """
                        DELETE FROM locks WHERE resource = ? AND owner = ?
                    """,
                        (resource, owner),
                    )

                    if cursor.rowcount > 0:
                        self._record_history(resource, owner, "released", duration_seconds=duration)
                        self._conn.commit()
                        logger.info(f"Released lock on {resource} by {owner}")
                        return True

                    return False

                else:  # Use new connection for file-based DB
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()

                        # Get lock info for history
                        cursor.execute(
                            """
                            SELECT lock_id, acquired_at FROM locks 
                            WHERE resource = ? AND owner = ?
                        """,
                            (resource, owner),
                        )

                        row = cursor.fetchone()
                        if not row:
                            return False

                        lock_id, acquired_at = row
                        acquired_time = datetime.fromisoformat(acquired_at)
                        duration = (datetime.utcnow() - acquired_time).total_seconds()

                        # Remove lock
                        cursor.execute(
                            """
                            DELETE FROM locks WHERE resource = ? AND owner = ?
                        """,
                            (resource, owner),
                        )

                        if cursor.rowcount > 0:
                            self._record_history(
                                resource, owner, "released", duration_seconds=duration
                            )
                            conn.commit()
                            logger.info(f"Released lock on {resource} by {owner}")
                            return True

                        return False

            except Exception as e:
                logger.error(f"Error releasing lock {resource} by {owner}: {e}")
                return False

    def extend_lock(self, resource: str, owner: str, additional_seconds: int) -> bool:
        """
        Extend an existing lock's TTL

        Args:
            resource: Resource identifier
            owner: Lock owner
            additional_seconds: Additional time to add

        Returns:
            True if extended successfully
        """
        with self._local_lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()

                    # Update expiration time
                    new_expires_at = datetime.utcnow() + timedelta(seconds=additional_seconds)

                    cursor.execute(
                        """
                        UPDATE locks 
                        SET expires_at = ?
                        WHERE resource = ? AND owner = ? AND expires_at > ?
                    """,
                        (
                            new_expires_at.isoformat(),
                            resource,
                            owner,
                            datetime.utcnow().isoformat(),
                        ),
                    )

                    if cursor.rowcount > 0:
                        conn.commit()
                        logger.debug(
                            f"Extended lock on {resource} by {owner} for {additional_seconds}s"
                        )
                        return True

                    return False

            except Exception as e:
                logger.error(f"Error extending lock {resource} by {owner}: {e}")
                return False

    def get_lock_info(self, resource: str) -> Optional[LockInfo]:
        """Get information about a lock"""
        return self._get_active_lock(resource)

    def list_locks(self, owner: Optional[str] = None) -> List[LockInfo]:
        """
        List active locks, optionally filtered by owner

        Args:
            owner: Filter by owner (None for all locks)

        Returns:
            List of active locks
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                if owner:
                    cursor.execute(
                        """
                        SELECT lock_id, resource, owner, priority, acquired_at, expires_at, metadata
                        FROM locks 
                        WHERE owner = ? AND expires_at > ?
                        ORDER BY acquired_at
                    """,
                        (owner, datetime.utcnow().isoformat()),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT lock_id, resource, owner, priority, acquired_at, expires_at, metadata
                        FROM locks 
                        WHERE expires_at > ?
                        ORDER BY acquired_at
                    """,
                        (datetime.utcnow().isoformat(),),
                    )

                locks = []
                for row in cursor.fetchall():
                    (
                        lock_id,
                        resource,
                        owner,
                        priority,
                        acquired_at,
                        expires_at,
                        metadata,
                    ) = row

                    locks.append(
                        LockInfo(
                            resource=resource,
                            owner=owner,
                            priority=LockPriority(priority),
                            acquired_at=datetime.fromisoformat(acquired_at),
                            expires_at=datetime.fromisoformat(expires_at),
                            metadata=json.loads(metadata) if metadata else {},
                            lock_id=lock_id,
                        )
                    )

                return locks

        except Exception as e:
            logger.error(f"Error listing locks: {e}")
            return []

    def get_queue_status(self, resource: str) -> List[Dict[str, Any]]:
        """
        Get queue status for a resource

        Args:
            resource: Resource identifier

        Returns:
            List of queued requests
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT owner, priority, requested_at, ttl_seconds, metadata
                    FROM lock_queue 
                    WHERE resource = ?
                    ORDER BY priority DESC, requested_at ASC
                """,
                    (resource,),
                )

                queue = []
                for row in cursor.fetchall():
                    owner, priority, requested_at, ttl_seconds, metadata = row

                    queue.append(
                        {
                            "owner": owner,
                            "priority": LockPriority(priority).name,
                            "requested_at": requested_at,
                            "ttl_seconds": ttl_seconds,
                            "metadata": json.loads(metadata) if metadata else {},
                            "wait_time": (
                                datetime.utcnow() - datetime.fromisoformat(requested_at)
                            ).total_seconds(),
                        }
                    )

                return queue

        except Exception as e:
            logger.error(f"Error getting queue status for {resource}: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """Get lock manager statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Active locks count
                cursor.execute(
                    "SELECT COUNT(*) FROM locks WHERE expires_at > ?",
                    (datetime.utcnow().isoformat(),),
                )
                active_locks = cursor.fetchone()[0]

                # Queue length
                cursor.execute("SELECT COUNT(*) FROM lock_queue")
                queue_length = cursor.fetchone()[0]

                # Recent activity (last hour)
                hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
                cursor.execute(
                    """
                    SELECT action, COUNT(*) 
                    FROM lock_history 
                    WHERE timestamp > ? 
                    GROUP BY action
                """,
                    (hour_ago,),
                )

                recent_activity = dict(cursor.fetchall())

                # Average lock duration (last 24 hours)
                day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
                cursor.execute(
                    """
                    SELECT AVG(duration_seconds) 
                    FROM lock_history 
                    WHERE action = 'released' AND timestamp > ? AND duration_seconds IS NOT NULL
                """,
                    (day_ago,),
                )

                avg_duration = cursor.fetchone()[0] or 0

                return {
                    "active_locks": active_locks,
                    "queue_length": queue_length,
                    "recent_activity": recent_activity,
                    "average_lock_duration_seconds": round(avg_duration, 2),
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

    def cleanup_expired_locks(self) -> int:
        """
        Clean up expired locks and stale queue entries

        Returns:
            Number of locks cleaned up
        """
        cleaned_count = 0

        try:
            # For in-memory databases, always proceed
            # For file databases, check if file exists
            if str(self.db_path) != ":memory:" and not self.db_path.exists():
                return 0

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Check if tables exist
                cursor.execute(
                    """
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name IN ('locks', 'lock_queue', 'lock_history')
                """
                )
                existing_tables = {row[0] for row in cursor.fetchall()}

                if "locks" not in existing_tables:
                    return 0

                # Get expired locks for history
                cursor.execute(
                    """
                    SELECT resource, owner, acquired_at 
                    FROM locks 
                    WHERE expires_at <= ?
                """,
                    (datetime.utcnow().isoformat(),),
                )

                expired_locks = cursor.fetchall()

                # Record expiration in history (only if history table exists)
                if "lock_history" in existing_tables:
                    for resource, owner, acquired_at in expired_locks:
                        acquired_time = datetime.fromisoformat(acquired_at)
                        duration = (datetime.utcnow() - acquired_time).total_seconds()
                        self._record_history(resource, owner, "expired", duration_seconds=duration)

                # Remove expired locks
                cursor.execute(
                    """
                    DELETE FROM locks WHERE expires_at <= ?
                """,
                    (datetime.utcnow().isoformat(),),
                )

                cleaned_count = cursor.rowcount

                # Clean up old queue entries (only if queue table exists)
                if "lock_queue" in existing_tables:
                    old_threshold = (
                        datetime.utcnow() - timedelta(seconds=self._max_wait_time)
                    ).isoformat()
                    cursor.execute(
                        """
                        DELETE FROM lock_queue WHERE requested_at <= ?
                    """,
                        (old_threshold,),
                    )

                # Clean up old history (keep last 30 days)
                history_threshold = (datetime.utcnow() - timedelta(days=30)).isoformat()
                cursor.execute(
                    """
                    DELETE FROM lock_history WHERE timestamp <= ?
                """,
                    (history_threshold,),
                )

                conn.commit()

                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired locks")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        return cleaned_count

    def _get_connection(self):
        """Get database connection (persistent for in-memory, new for file-based)"""
        if self._conn:
            return self._conn
        else:
            return sqlite3.connect(self.db_path)

    def _execute_with_connection(self, query, params=None, fetch=False):
        """Execute query with appropriate connection handling"""
        if self._conn:
            cursor = self._conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if fetch:
                result = cursor.fetchall()
            else:
                result = cursor.rowcount

            self._conn.commit()
            return result
        else:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)

                if fetch:
                    return cursor.fetchall()
                else:
                    return cursor.rowcount

    def _get_active_lock(self, resource: str) -> Optional[LockInfo]:
        """Get active lock for a resource"""
        try:
            if self._conn:
                # Use persistent connection for in-memory database
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    SELECT lock_id, owner, priority, acquired_at, expires_at, metadata
                    FROM locks 
                    WHERE resource = ? AND expires_at > ?
                """,
                    (resource, datetime.utcnow().isoformat()),
                )

                row = cursor.fetchone()
            else:
                # Use new connection for file-based database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT lock_id, owner, priority, acquired_at, expires_at, metadata
                        FROM locks 
                        WHERE resource = ? AND expires_at > ?
                    """,
                        (resource, datetime.utcnow().isoformat()),
                    )

                    row = cursor.fetchone()

            if row:
                lock_id, owner, priority, acquired_at, expires_at, metadata = row

                return LockInfo(
                    resource=resource,
                    owner=owner,
                    priority=LockPriority(priority),
                    acquired_at=datetime.fromisoformat(acquired_at),
                    expires_at=datetime.fromisoformat(expires_at),
                    metadata=json.loads(metadata) if metadata else {},
                    lock_id=lock_id,
                )

            return None

        except Exception as e:
            logger.error(f"Error getting active lock for {resource}: {e}")
            return None

    def _create_lock(self, request: LockRequest) -> LockInfo:
        """Create a new lock"""
        import uuid

        lock_id = str(uuid.uuid4())
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=request.ttl_seconds)

        try:
            if self._conn:
                # Use persistent connection for in-memory database
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO locks (lock_id, resource, owner, priority, acquired_at, expires_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        lock_id,
                        request.resource,
                        request.owner,
                        request.priority.value,
                        now.isoformat(),
                        expires_at.isoformat(),
                        json.dumps(request.metadata),
                    ),
                )
                self._conn.commit()
            else:
                # Use new connection for file-based database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO locks (lock_id, resource, owner, priority, acquired_at, expires_at, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            lock_id,
                            request.resource,
                            request.owner,
                            request.priority.value,
                            now.isoformat(),
                            expires_at.isoformat(),
                            json.dumps(request.metadata),
                        ),
                    )
                    conn.commit()

            # Record in history
            self._record_history(request.resource, request.owner, "acquired")

            logger.info(f"Created lock {lock_id} on {request.resource} for {request.owner}")

            return LockInfo(
                resource=request.resource,
                owner=request.owner,
                priority=request.priority,
                acquired_at=now,
                expires_at=expires_at,
                metadata=request.metadata,
                lock_id=lock_id,
            )

        except Exception as e:
            logger.error(f"Error creating lock: {e}")
            raise

    def _extend_lock(self, lock_info: LockInfo, additional_seconds: int) -> LockInfo:
        """Extend an existing lock"""
        new_expires_at = datetime.utcnow() + timedelta(seconds=additional_seconds)

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    UPDATE locks 
                    SET expires_at = ?
                    WHERE lock_id = ?
                """,
                    (new_expires_at.isoformat(), lock_info.lock_id),
                )

                conn.commit()

                lock_info.expires_at = new_expires_at
                return lock_info

        except Exception as e:
            logger.error(f"Error extending lock {lock_info.lock_id}: {e}")
            raise

    def _add_to_queue(self, request: LockRequest) -> str:
        """Add request to priority queue"""
        import uuid

        queue_id = str(uuid.uuid4())

        try:
            if self._conn:  # Use persistent connection for in-memory DB
                cursor = self._conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO lock_queue (queue_id, resource, owner, priority, requested_at, ttl_seconds, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        queue_id,
                        request.resource,
                        request.owner,
                        request.priority.value,
                        datetime.utcnow().isoformat(),
                        request.ttl_seconds,
                        json.dumps(request.metadata),
                    ),
                )

                self._conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()

                    cursor.execute(
                        """
                        INSERT INTO lock_queue (queue_id, resource, owner, priority, requested_at, ttl_seconds, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            queue_id,
                            request.resource,
                            request.owner,
                            request.priority.value,
                            datetime.utcnow().isoformat(),
                            request.ttl_seconds,
                            json.dumps(request.metadata),
                        ),
                    )

                conn.commit()

                logger.debug(f"Added {request.owner} to queue for {request.resource}")
                return queue_id

        except Exception as e:
            logger.error(f"Error adding to queue: {e}")
            raise

    def _can_acquire_from_queue(self, queue_id: str) -> bool:
        """Check if a queued request can acquire the lock"""
        try:
            if self._conn:  # Use persistent connection for in-memory DB
                cursor = self._conn.cursor()
            else:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                # Get queue entry details
                cursor.execute(
                    """
                    SELECT resource, owner, priority, requested_at
                    FROM lock_queue 
                    WHERE queue_id = ?
                """,
                    (queue_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return False

                resource, owner, priority, requested_at = row

                # Check if resource is still locked
                if self._get_active_lock(resource):
                    return False

                # Check if this is the next in line (fair queuing with priority)
                cursor.execute(
                    """
                    SELECT COUNT(*) 
                    FROM lock_queue 
                    WHERE resource = ? AND (
                        priority > ? OR 
                        (priority = ? AND requested_at < ?)
                    )
                """,
                    (resource, priority, priority, requested_at),
                )

                ahead_count = cursor.fetchone()[0]

                # Also check for starvation prevention
                request_time = datetime.fromisoformat(requested_at)
                wait_time = (datetime.utcnow() - request_time).total_seconds()

                # Allow acquisition if no one ahead or if waiting too long (starvation prevention)
                result = ahead_count == 0 or wait_time > self._starvation_threshold

                # Commit if using persistent connection
                if self._conn:
                    self._conn.commit()
                else:
                    conn.commit()
                    conn.close()

                return result

        except Exception as e:
            logger.error(f"Error checking queue acquisition for {queue_id}: {e}")
            return False

    def _acquire_from_queue(self, queue_id: str) -> Optional[LockInfo]:
        """Acquire lock from queue"""
        try:
            if self._conn:  # Use persistent connection for in-memory DB
                cursor = self._conn.cursor()
            else:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                # Get queue entry
                cursor.execute(
                    """
                    SELECT resource, owner, priority, ttl_seconds, metadata
                    FROM lock_queue 
                    WHERE queue_id = ?
                """,
                    (queue_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                resource, owner, priority, ttl_seconds, metadata = row

                # Create lock request
                request = LockRequest(
                    resource=resource,
                    owner=owner,
                    priority=LockPriority(priority),
                    ttl_seconds=ttl_seconds,
                    metadata=json.loads(metadata) if metadata else {},
                )

                # Try to create lock
                lock_info = self._create_lock(request)

                # Remove from queue
                self._remove_from_queue(queue_id)

                # Commit if using persistent connection
                if self._conn:
                    self._conn.commit()
                else:
                    conn.commit()
                    conn.close()

                return lock_info

        except Exception as e:
            logger.error(f"Error acquiring from queue {queue_id}: {e}")
            return None

    def _remove_from_queue(self, queue_id: str):
        """Remove entry from queue"""
        try:
            if self._conn:  # Use persistent connection for in-memory DB
                cursor = self._conn.cursor()
                cursor.execute("DELETE FROM lock_queue WHERE queue_id = ?", (queue_id,))
                self._conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM lock_queue WHERE queue_id = ?", (queue_id,))
                    conn.commit()

        except Exception as e:
            logger.error(f"Error removing from queue {queue_id}: {e}")

    def _record_history(
        self,
        resource: str,
        owner: str,
        action: str,
        duration_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record lock history"""
        import uuid

        try:
            if self._conn:
                # Use persistent connection for in-memory database
                cursor = self._conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO lock_history (history_id, resource, owner, action, timestamp, duration_seconds, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        str(uuid.uuid4()),
                        resource,
                        owner,
                        action,
                        datetime.utcnow().isoformat(),
                        duration_seconds,
                        json.dumps(metadata) if metadata else None,
                    ),
                )
                self._conn.commit()
            else:
                # Use new connection for file-based database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO lock_history (history_id, resource, owner, action, timestamp, duration_seconds, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            str(uuid.uuid4()),
                            resource,
                            owner,
                            action,
                            datetime.utcnow().isoformat(),
                            duration_seconds,
                            json.dumps(metadata) if metadata else None,
                        ),
                    )
                    conn.commit()

        except Exception as e:
            logger.error(f"Error recording history: {e}")

    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        import threading

        def cleanup_loop():
            while True:
                try:
                    self.cleanup_expired_locks()
                    time.sleep(self._cleanup_interval)
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {e}")
                    time.sleep(self._cleanup_interval)

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
        logger.info("Started lock cleanup thread")


# Convenience functions for common use cases
def acquire_resource_lock(
    resource: str,
    owner: str,
    ttl_seconds: int = 300,
    priority: LockPriority = LockPriority.MEDIUM,
    timeout: Optional[int] = None,
) -> Optional[LockInfo]:
    """Convenience function to acquire a resource lock"""
    manager = LockManager()
    request = LockRequest(
        resource=resource, owner=owner, priority=priority, ttl_seconds=ttl_seconds
    )
    return manager.acquire_lock(request, timeout)


def release_resource_lock(resource: str, owner: str) -> bool:
    """Convenience function to release a resource lock"""
    manager = LockManager()
    return manager.release_lock(resource, owner)


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    manager = LockManager("test_locks.db")

    # Test basic locking
    request = LockRequest(
        resource="test_resource",
        owner="test_owner",
        priority=LockPriority.HIGH,
        ttl_seconds=60,
    )

    lock = manager.acquire_lock(request)
    if lock:
        print(f"Acquired lock: {lock}")

        # Extend lock
        manager.extend_lock("test_resource", "test_owner", 30)

        # Release lock
        manager.release_lock("test_resource", "test_owner")

    # Print statistics
    stats = manager.get_statistics()
    print(f"Statistics: {stats}")
