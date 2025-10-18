from datetime import datetime

import pytest

from src.dispatcher import Task, TaskDispatcher, TaskPriority, TaskStatus


@pytest.fixture
def dispatcher(tmp_path):
    db_path = tmp_path / "test.db"
    return TaskDispatcher(str(db_path))


def test_acquire_lock(dispatcher):
    assert dispatcher.acquire_lock("test_resource", "test_owner", TaskPriority.HIGH)
    assert not dispatcher.acquire_lock("test_resource", "other_owner", TaskPriority.LOW)


def test_release_lock(dispatcher):
    dispatcher.acquire_lock("test_resource", "test_owner", TaskPriority.HIGH)
    assert dispatcher.release_lock("test_resource", "test_owner")
    assert not dispatcher.release_lock("test_resource", "wrong_owner")


def test_update_task_status(dispatcher):
    # First, insert a task directly into the database
    import sqlite3

    task = Task(
        "1",
        "Test Task",
        TaskStatus.PENDING,
        TaskPriority.MEDIUM,
        "owner",
        datetime.now(),
        datetime.now(),
    )

    # Insert task into database
    with sqlite3.connect(dispatcher.db_path) as conn:
        conn.execute(
            """
            INSERT INTO tasks (id, title, status, priority, owner, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.id,
                task.title,
                task.status.value,
                task.priority.value,
                task.owner,
                task.created_at.isoformat(),
                task.updated_at.isoformat(),
            ),
        )
        conn.commit()

    # Now test update_task_status
    assert dispatcher.update_task_status("1", TaskStatus.DOING, "owner")
