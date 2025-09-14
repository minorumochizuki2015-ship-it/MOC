import os
from importlib import reload

import src.core.kernel as K


def test_router_code_tasks_env_override(monkeypatch):
    monkeypatch.setenv("CODE_TASKS", "generate,format")
    reload(K)
    assert K.get_model_id("generate") == K.MODEL_ID_CODER
    assert K.get_model_id("debug") == K.DEFAULT_MODEL_ID
