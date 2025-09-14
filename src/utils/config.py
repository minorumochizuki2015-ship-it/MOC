# config.py (Final, Multi-Provider Ready + Hardening)
# 8080統一 / Ollama(Gemma3) / Google AI（Gemini）に対応
# - PROVIDER: openai_compat | ollama | google_ai
# - /v1 自動付与、Ollamaタイムアウト環境変数、ログ保存先の存在保証 などを実装

import os

# =====================================
# Provider selection
# =====================================
PROVIDER = os.getenv("PROVIDER", "openai_compat")  # openai_compat | ollama | google_ai

# =====================================
# OpenAI-compatible (llama_cpp.server) on 8080
# =====================================
# 入力ゆらぎ対策：/v1 の自動付与
OPENAI_COMPAT_BASE = os.getenv("OPENAI_COMPAT_BASE", "http://localhost:8080")
_base = OPENAI_COMPAT_BASE.rstrip("/")
if not _base.endswith("/v1"):
    OPENAI_COMPAT_BASE = _base + "/v1"
else:
    OPENAI_COMPAT_BASE = _base
# OpenAI互換クライアントで使う論理名（llama_cpp.serverでは "local" が通例）
LOCAL_MODEL_NAME = os.getenv("LOCAL_MODEL_NAME", "local")

# =====================================
# Ollama (Gemma3 先行)
# =====================================
# /api/chat を既定とする（messages 形式）
OLLAMA_CHAT_URL = os.getenv("OLLAMA_CHAT_URL", "http://localhost:11434/api/chat")
GEMMA_OLLAMA_NAME = os.getenv("GEMMA_OLLAMA_NAME", "gemma3:4b")
# 通信タイムアウト（秒）
try:
    OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))
except ValueError:
    OLLAMA_TIMEOUT = 600

# =====================================
# Google Generative AI (Gemini)
# =====================================
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
# 安定名を既定に。必要なら環境変数で上書き（例: gemini-1.5-pro-latest）
GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "gemini-1.5-pro")

# =====================================
# Paths & Files
# =====================================
try:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
except NameError:
    PROJECT_ROOT = os.getcwd()

LOG_FILE_PATH = os.path.join(
    PROJECT_ROOT, "data", "logs", "current", "interaction_log.json"
)
PERSONA_FILE_PATH = os.path.join(PROJECT_ROOT, "data", "persona_context.json")
CONCEPTUAL_DICTIONARY_PATH = os.path.join(
    PROJECT_ROOT, "data", "conceptual_dictionary.json"
)
EVOLVED_THEMES_PATH = os.path.join(PROJECT_ROOT, "data", "evolved_themes.json")

# ログ保存先の存在保証（初回起動対策）
_log_dir = os.path.dirname(LOG_FILE_PATH)
if _log_dir and not os.path.exists(_log_dir):
    os.makedirs(_log_dir, exist_ok=True)

# =====================================
# 設定の一元化（envとJSONの併用）
# =====================================
import json
import pathlib


def load_settings():
    """ユーザー設定ファイルを読み込み（存在しない場合は空辞書）"""
    p = pathlib.Path.home() / "LocalAI" / "config" / "settings.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


SET = load_settings()

# 設定値の統合（環境変数 > JSON設定 > デフォルト）
OPENAI_BASE = os.getenv(
    "OPENAI_COMPAT_BASE", SET.get("openai_base", "http://127.0.0.1:8080/v1")
)
API_KEY = os.getenv("OPENAI_API_KEY", SET.get("api_key", "sk-local"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", SET.get("max_tokens", 1024)))
TIMEOUT_S = int(os.getenv("TIMEOUT_S", SET.get("timeout_s", 300)))
