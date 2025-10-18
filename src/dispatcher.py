#!/usr/bin/env python3
"""
ORCH-Next Task Dispatcher
Replaces PowerShell Task-Dispatcher.ps1 with Python-first approach
"""

import asyncio
import atexit
import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from fastapi import FastAPI, Response
from prometheus_client import Counter, Gauge, generate_latest

app = FastAPI()

try:
    from sse_starlette import EventSourceResponse  # type: ignore
except ModuleNotFoundError:
    # Fallback stub when sse_starlette is not installed (e.g., CI or unit tests)
    from fastapi import Response as _FastAPIResponse  # type: ignore

    EventSourceResponse = _FastAPIResponse  # type: ignore


async def sse_events():
    """Generate SSE events for task updates

    Note: increments active SSE connections gauge on subscribe and decrements
    on disconnect to help track stability and success rate.
    """
    # Increment active connections when a client subscribes
    try:
        sse_connections_active.inc()
        while True:
            payload = {
                "message": "Task status changed",
                "timestamp": datetime.now().isoformat(),
            }
            yield f"event: task_update\ndata: {json.dumps(payload)}\n\n"
            await asyncio.sleep(5)  # Heartbeat every 5 seconds
    finally:
        # Ensure we decrement even if the client disconnects or errors occur
        sse_connections_active.dec()


@app.get("/events")
async def events():
    """SSE endpoint for real-time updates (legacy path)"""
    return EventSourceResponse(sse_events())


@app.get("/sse/events")
async def sse_events_path():
    """SSE endpoint for real-time updates (documented path)"""
    return EventSourceResponse(sse_events())


from fastapi import Request


@app.post("/webhook")
async def webhook(request: Request):
    """Webhook endpoint for external integrations"""
    payload = await request.json()
    logger.info(f"Received webhook: {payload}")
    return {"status": "received"}


from app.shared.logging_config import get_logger, is_pytest_running

# Configure logging via shared logging_config
logger = get_logger(__name__, in_pytest=is_pytest_running())
atexit.register(logging.shutdown)


class TaskStatus(Enum):
    PENDING = "pending"
    READY = "ready"
    DOING = "doing"
    REVIEW = "review"
    DONE = "done"
    HOLD = "hold"
    DROP = "drop"


class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    id: str
    title: str
    status: TaskStatus
    priority: TaskPriority
    owner: str
    created_at: datetime
    updated_at: datetime
    due_date: Optional[datetime] = None
    lock_owner: Optional[str] = None
    lock_expires_at: Optional[datetime] = None
    artifact: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class DispatchRequest:
    core_id: str
    stay: bool = False
    priority: TaskPriority = TaskPriority.MEDIUM
    timeout: int = 1800  # 30 minutes default


class TaskDispatcher:
    def __init__(self, config: Union[str, Dict[str, Any]] = "data/orch.db"):
        if isinstance(config, str):
            self.db_path = Path(config)
        else:
            db_path = config.get("database", {}).get("path", "data/orch.db")
            self.db_path = Path(db_path)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database with required tables"""
        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                # Improve SQLite concurrency and stability on Windows
                # Busy timeout to mitigate transient file locks
                try:
                    conn.execute("PRAGMA busy_timeout=5000;")
                except Exception:
                    pass
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("PRAGMA foreign_keys=ON;")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tasks (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL,
                        priority INTEGER NOT NULL,
                        owner TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        due_date TEXT,
                        lock_owner TEXT,
                        lock_expires_at TEXT,
                        artifact TEXT,
                        notes TEXT
                )
                """
                )

                conn.execute(
                    """
                CREATE TABLE IF NOT EXISTS locks (
                    lock_id TEXT PRIMARY KEY,
                    resource TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    metadata TEXT
                )
            """
                )

            # Events persistence for job lifecycle and auditing
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    data TEXT,
                    FOREIGN KEY (task_id) REFERENCES tasks (id)
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_task_id ON events(task_id);
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    labels TEXT,
                    timestamp TEXT NOT NULL
                )
            """
            )

            # Minimal users table to satisfy persistence tests
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    email TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """
            )

            # Security events table required by integration tests
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    endpoint TEXT,
                    details TEXT,
                    timestamp TEXT NOT NULL
                )
            """
            )

            # Indexes for security_events to support queries under load
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_type_timestamp ON security_events(event_type, timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_user_timestamp ON security_events(user_id, timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_security_events_ip_timestamp ON security_events(ip_address, timestamp)"
            )

            logger.info("Database initialized successfully")

    def _log_event(
        self, task_id: str, event_type: str, data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record an event in the events table for auditing and job history"""
        event_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO events (event_id, task_id, event_type, timestamp, data)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (event_id, task_id, event_type, now, json.dumps(data or {})),
                )

    def acquire_lock(
        self, resource: str, owner: str, priority: TaskPriority, ttl: int = 1800
    ) -> bool:
        """Acquire a lock with priority and TTL (schema unified with LockManager)"""
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=ttl)

        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                # Clean expired locks first
                conn.execute("DELETE FROM locks WHERE datetime(expires_at) <= datetime('now')")

                # Check existing active lock for the resource
                cursor = conn.execute(
                    """
                    SELECT lock_id, owner, priority FROM locks 
                    WHERE resource = ? AND datetime(expires_at) > datetime('now')
                    """,
                    (resource,),
                )
                existing = cursor.fetchone()

                if existing is None:
                    # Create new lock entry
                    lock_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO locks (lock_id, resource, owner, priority, acquired_at, expires_at, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            lock_id,
                            resource,
                            owner,
                            priority.value,
                            now.isoformat(),
                            expires_at.isoformat(),
                            json.dumps({}),
                        ),
                    )
                    logger.info(f"Lock acquired: {resource} by {owner}")
                    lock_acquisitions_total.labels(resource=resource).inc()
                    return True
                else:
                    # Existing lock present; evaluate priority for takeover
                    existing_lock_id, existing_owner, existing_priority = existing
                    if priority.value > existing_priority:
                        conn.execute(
                            """
                            UPDATE locks SET owner = ?, priority = ?, acquired_at = ?, expires_at = ?
                            WHERE lock_id = ?
                        """,
                            (
                                owner,
                                priority.value,
                                now.isoformat(),
                                expires_at.isoformat(),
                                existing_lock_id,
                            ),
                        )
                        # Connection context will commit automatically
                        logger.info(
                            f"Lock taken over: {resource} by {owner} (priority {priority.value})"
                        )
                        lock_acquisitions_total.labels(resource=resource).inc()
                        return True
                    else:
                        logger.warning(
                            f"Lock acquisition failed: {resource} held by {existing_owner}"
                        )
                        return False

    def release_lock(self, resource: str, owner: str) -> bool:
        """Release a lock"""
        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                cursor = conn.execute(
                    "DELETE FROM locks WHERE resource = ? AND owner = ?", (resource, owner)
                )
                if cursor.rowcount > 0:
                    logger.info(f"Lock released: {resource} by {owner}")
                    return True
                else:
                    logger.warning(f"Lock release failed: {resource} not held by {owner}")
                    return False

    def get_next_task(
        self, owner: str, priority_filter: Optional[TaskPriority] = None
    ) -> Optional[Task]:
        """Get next available task with priority ordering"""
        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                query = """
                    SELECT * FROM tasks 
                    WHERE status = 'ready' 
                    AND (lock_expires_at IS NULL OR datetime(lock_expires_at) < datetime('now'))
                """
                params = []

                if priority_filter:
                    query += " AND priority >= ?"
                    params.append(priority_filter.value)

                query += " ORDER BY priority DESC, created_at ASC LIMIT 1"

                cursor = conn.execute(query, params)
                row = cursor.fetchone()

                if row:
                    return self._row_to_task(row)
                return None

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        owner: str,
        lock_owner: Optional[str] = None,
        lock_expires_at: Optional[datetime] = None,
        artifact: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """Update task status and metadata"""
        now = datetime.utcnow()

        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                params = [
                    status.value,
                    now.isoformat(),
                    lock_owner,
                    lock_expires_at.isoformat() if lock_expires_at else None,
                    artifact,
                    notes,
                    task_id,
                    owner,
                ]

                cursor = conn.execute(
                    """
                    UPDATE tasks SET 
                        status = ?, 
                        updated_at = ?,
                        lock_owner = ?,
                        lock_expires_at = ?,
                        artifact = ?,
                        notes = ?
                    WHERE id = ? AND owner = ?
                """,
                    params,
                )

                if cursor.rowcount > 0:
                    logger.info(f"Task {task_id} updated to {status.value} by {owner}")
                    self._record_metric(
                        "task_status_changes",
                        1,
                        {"task_id": task_id, "status": status.value},
                    )
                    # Record status change as an event for persistence tests and auditing
                    self._log_event(
                        task_id,
                        f"status_{status.value}",
                        {
                            "owner": owner,
                            "lock_owner": lock_owner,
                            "lock_expires_at": (
                                lock_expires_at.isoformat() if lock_expires_at else None
                            ),
                            "artifact": artifact,
                            "notes": notes,
                        },
                    )
                    return True
                else:
                    logger.warning(
                        f"Task update failed: {task_id} not found or not owned by {owner}"
                    )
                    return False

    def dispatch_task(self, request: DispatchRequest = None, **kwargs) -> Dict[str, Any]:
        """Main dispatch logic - replaces PowerShell dispatcher

        Backward compatibility:
        - Supports legacy call style with keyword arguments: core_id, stay, priority, timeout
        """
        start_time = time.time()
        result = {
            "success": False,
            "task_id": None,
            "message": "",
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            # Build request from legacy kwargs if needed
            if request is None:
                core_id = kwargs.get("core_id")
                stay = bool(kwargs.get("stay", False))
                priority_kw = kwargs.get("priority", TaskPriority.MEDIUM)
                timeout = int(kwargs.get("timeout", 1800))

                try:
                    priority = (
                        priority_kw
                        if isinstance(priority_kw, TaskPriority)
                        else TaskPriority(int(getattr(priority_kw, "value", priority_kw)))
                    )
                except Exception:
                    priority = TaskPriority.MEDIUM

                request = DispatchRequest(
                    core_id=core_id,
                    stay=stay,
                    priority=priority,
                    timeout=timeout,
                )

            # Acquire dispatcher lock
            lock_resource = f"dispatcher_{request.core_id}"
            if not self.acquire_lock(
                lock_resource, request.core_id, request.priority, request.timeout
            ):
                result["message"] = f"Failed to acquire dispatcher lock for {request.core_id}"
                return result

            # Get next task
            task = self.get_next_task(request.core_id, request.priority)
            if not task:
                result["message"] = "No tasks available"
                if not request.stay:
                    self.release_lock(lock_resource, request.core_id)
                return result

            # Transition task to DOING
            lock_expires = datetime.utcnow() + timedelta(seconds=request.timeout)
            if self.update_task_status(
                task.id,
                TaskStatus.DOING,
                request.core_id,
                lock_owner=request.core_id,
                lock_expires_at=lock_expires,
            ):
                result["success"] = True
                result["task_id"] = task.id
                result["message"] = f"Task {task.id} dispatched to {request.core_id}"

                # Persist dispatch event
                self._log_event(
                    task.id,
                    "dispatched",
                    {
                        "core_id": request.core_id,
                        "priority": request.priority.name,
                        "timeout": request.timeout,
                    },
                )

                # Record metrics
                duration = time.time() - start_time
                self._record_metric(
                    "dispatch_duration_seconds", duration, {"core_id": request.core_id}
                )
                self._record_metric(
                    "tasks_dispatched_total",
                    1,
                    {"core_id": request.core_id, "priority": request.priority.name},
                )

            else:
                result["message"] = f"Failed to update task {task.id} status"
                self.release_lock(lock_resource, request.core_id)

        except Exception as e:
            logger.error(f"Dispatch error: {e}")
            result["message"] = f"Dispatch error: {str(e)}"
            self.release_lock(lock_resource, request.core_id)

        return result

    def _row_to_task(self, row) -> Task:
        """Convert database row to Task object"""
        return Task(
            id=row[0],
            title=row[1],
            status=TaskStatus(row[2]),
            priority=TaskPriority(row[3]),
            owner=row[4],
            created_at=datetime.fromisoformat(row[5]),
            updated_at=datetime.fromisoformat(row[6]),
            due_date=datetime.fromisoformat(row[7]) if row[7] else None,
            lock_owner=row[8],
            lock_expires_at=datetime.fromisoformat(row[9]) if row[9] else None,
            artifact=row[10],
            notes=row[11],
        )

    def _record_metric(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record metric for monitoring"""
        metric_id = str(uuid.uuid4())
        now = datetime.utcnow()

        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO metrics (id, metric_name, value, labels, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (metric_id, name, value, json.dumps(labels or {}), now.isoformat()),
                )

    def cleanup_expired_locks(self):
        """Clean up expired locks and tasks"""
        with closing(sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)) as conn:
            with conn:
                # Clean expired locks
                cursor = conn.execute(
                    "DELETE FROM locks WHERE datetime(expires_at) <= datetime('now')"
                )
                expired_locks = cursor.rowcount

                # Reset tasks with expired locks
                cursor = conn.execute(
                    """
                    UPDATE tasks SET 
                        status = 'ready',
                        lock_owner = NULL,
                        lock_expires_at = NULL,
                        updated_at = datetime('now')
                    WHERE status = 'doing' 
                    AND lock_expires_at IS NOT NULL 
                    AND datetime(lock_expires_at) < datetime('now')
                """
                )
                reset_tasks = cursor.rowcount

                if expired_locks > 0 or reset_tasks > 0:
                    logger.info(
                        f"Cleanup: {expired_locks} expired locks, {reset_tasks} reset tasks"
                    )

    def close(self):
        """Release resources and cleanup"""
        try:
            # TaskDispatcher doesn't maintain persistent connections,
            # but we can perform final cleanup if needed
            self.cleanup_expired_locks()
        except Exception:
            pass

    def __del__(self):
        # Ensure resources are released on GC
        self.close()


# Prometheus metrics
http_requests_total = Counter(
    "orch_http_requests_total", "Total HTTP requests", ["method", "status"]
)
sse_connections_active = Gauge("orch_sse_connections_active", "Active SSE connections")
task_duration_seconds = Gauge("orch_task_duration_seconds", "Task execution duration")
lock_acquisitions_total = Counter("orch_lock_acquisitions_total", "Lock acquisitions", ["resource"])


@app.get("/metrics")
async def metrics_endpoint():
    http_requests_total.labels(method="GET", status="200").inc()
    return Response(content=generate_latest(), media_type="text/plain")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="ORCH-Next Task Dispatcher")
    parser.add_argument("--action", choices=["dispatch", "cleanup"], default="dispatch")
    parser.add_argument("--core-id", required=True, help="Core ID for task assignment")
    parser.add_argument("--stay", action="store_true", help="Keep dispatcher lock after dispatch")
    parser.add_argument(
        "--priority", choices=["low", "medium", "high", "critical"], default="medium"
    )
    parser.add_argument("--timeout", type=int, default=1800, help="Lock timeout in seconds")

    args = parser.parse_args()

    dispatcher = TaskDispatcher()

    if args.action == "cleanup":
        dispatcher.cleanup_expired_locks()
        print("Cleanup completed")
    else:
        priority_map = {
            "low": TaskPriority.LOW,
            "medium": TaskPriority.MEDIUM,
            "high": TaskPriority.HIGH,
            "critical": TaskPriority.CRITICAL,
        }

        request = DispatchRequest(
            core_id=args.core_id,
            stay=args.stay,
            priority=priority_map[args.priority],
            timeout=args.timeout,
        )

        result = dispatcher.dispatch_task(request)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
