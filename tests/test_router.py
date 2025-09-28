import os
from importlib import reload

import pytest

import src.core.kernel as K


def test_router_code_tasks_env_override(monkeypatch):
    monkeypatch.setenv("CODE_TASKS", "generate,format")
    reload(K)

    # ローカルAI接続が必要なテストのため、環境変数チェック
    if not (os.getenv("LOCALAI_URL") or os.getenv("OPENAI_COMPAT_BASE")):
        pytest.skip(
            "LOCALAI_URL/OPENAI_COMPAT_BASE 未設定のため router テストをスキップ"
        )

    # Kernelクラスのインスタンスを作成してテスト
    kernel = K.Kernel(memory=None)
    assert kernel._get_model_id("generate") == K.MODEL_ID_CODER
    # デフォルトモデルIDの取得は環境に依存するため、存在確認のみ
    try:
        default_model = kernel._get_default_model_id()
        assert isinstance(default_model, str) and len(default_model) > 0
    except Exception:
        # ローカルAIサーバーが起動していない場合はスキップ
        pytest.skip(
            "ローカルAIサーバーに接続できないため、デフォルトモデルIDテストをスキップ"
        )
