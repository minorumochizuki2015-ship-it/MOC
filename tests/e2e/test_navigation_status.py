"""
Basic navigation reachability tests.
Verifies that key UI pages are served successfully.
"""

from src.dashboard import app


def test_dashboard_status():
    client = app.test_client()
    resp = client.get("/dashboard")
    assert resp.status_code == 200


def test_style_manager_status():
    client = app.test_client()
    resp = client.get("/style-manager")
    assert resp.status_code == 200


def test_tasks_status():
    client = app.test_client()
    resp = client.get("/tasks")
    assert resp.status_code == 200
