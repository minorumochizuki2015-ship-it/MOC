import os

import pytest
import requests

BASE = os.getenv("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")


@pytest.mark.integration
@pytest.mark.timeout(5)
def test_models_endpoint():
    try:
        r = requests.get(f"{BASE}/models", timeout=5)
    except Exception:
        pytest.skip("server unavailable")
    if r.status_code != 200:
        pytest.skip(f"server unhealthy: {r.status_code}")
    data = r.json()
    assert (
        isinstance(data, dict) and "data" in data and data["data"]
    ), "no models listed"


@pytest.mark.integration
@pytest.mark.timeout(10)
def test_chat_completion_minimal():
    try:
        r = requests.get(f"{BASE}/models", timeout=5)
        model = r.json()["data"][0]["id"]
    except Exception:
        pytest.skip("server unavailable or no model")
    payload = {"model": model, "messages": [{"role": "user", "content": "OK"}]}
    resp = requests.post(f"{BASE}/chat/completions", json=payload, timeout=10)
    if resp.status_code != 200:
        pytest.skip(f"chat endpoint unhealthy: {resp.status_code}")
    out = resp.json()
    assert out.get("choices"), "no completion returned"
