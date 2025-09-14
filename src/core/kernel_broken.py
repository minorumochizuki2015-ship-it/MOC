from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple

# 設定値の直接定義
OPENAI_BASE = os.environ.get("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")
MAX_TOKENS = 2000
TIMEOUT_S = 180.0


def _http(url: str, data: dict = None, timeout: float = TIMEOUT_S) -> dict:
    """HTTPリクエストを送信"""
    try:
        if data:
            req_data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {API_KEY}",
                    "User-Agent": "GoverningCore-v5/1.0",
                },
            )
        else:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "User-Agent": "GoverningCore-v5/1.0",
                },
            )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else "No error body"
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Error body: {error_body}")
        raise Exception(f"HTTP Error {e.code}: {e.reason}")
    except Exception as e:
        print(f"Request error: {e}")
        raise Exception(f"Request error: {e}")


def generate_chat(
    history: list, prompt: str, max_tokens: int = 2000, system: str = None
) -> str:
    """会話履歴を保持した推論（簡素化版）"""
    try:
        print(
            f"DEBUG: generate_chat開始 - 履歴数: {len(history)}, プロンプト: {prompt[:50]}..."
        )

        # メッセージを構築
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})

        # 履歴を追加（最新2件のみ）
        for msg in history[-2:]:
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                msgs.append(msg)
            elif isinstance(msg, str):
                msgs.append({"role": "user", "content": msg})

        msgs.append({"role": "user", "content": prompt})

        # モデルIDを取得
        print("DEBUG: モデル一覧取得中...")
        models_resp = _http(f"{OPENAI_BASE}/models", timeout=10)
        if "data" not in models_resp or not models_resp["data"]:
            raise Exception("利用可能なモデルが見つかりません")

        mid = models_resp["data"][0]["id"]
        print(f"DEBUG: 使用モデル: {mid}")

        # トークン数を制限
        max_tokens = min(max_tokens, 2000)

        # リクエストボディ
        body = {
            "model": mid,
            "messages": msgs,
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "stream": False,
        }

        print(f"DEBUG: リクエスト送信中...")
        res = _http(f"{OPENAI_BASE}/chat/completions", body, timeout=180)

        if "choices" not in res or not res["choices"]:
            raise Exception(f"API応答にchoicesがありません: {res}")

        ch = res["choices"][0]
        msg = ch.get("message") or {}
        content = msg.get("content") or ch.get("text") or ""

        if not content.strip():
            raise Exception("空の応答が返されました")

        print(f"DEBUG: 生成完了 - 結果長: {len(content)}")
        return content.strip()

    except Exception as e:
        print(f"DEBUG: generate_chat エラー: {e}")
        raise Exception(f"チャット生成エラー: {e}")


# 互換性のためのエイリアス
def generate(prompt: str) -> str:
    return generate_chat([], prompt)


def chat(prompt: str) -> str:
    return generate_chat([], prompt)


def run(prompt: str) -> str:
    return generate_chat([], prompt)
