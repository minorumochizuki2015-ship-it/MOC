#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
動作するkernel.pyの実装
"""

import json
import os
import time
import urllib.request
from typing import Any, Dict

# 設定値
OPENAI_BASE = os.environ.get("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")
MAX_TOKENS = 1000
TIMEOUT_S = 60.0


def _http_request(
    url: str, data: Dict[str, Any] = None, timeout: float = TIMEOUT_S
) -> Dict[str, Any]:
    """HTTPリクエストを送信"""
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
            "User-Agent": "GoverningCore-v5/1.0",
        }

        if data:
            json_data = json.dumps(data, ensure_ascii=False)
            data_bytes = json_data.encode("utf-8")
        else:
            data_bytes = None

        req = urllib.request.Request(url, data=data_bytes, headers=headers)

        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_text = response.read().decode("utf-8")
            return json.loads(response_text)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else "No error body"
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Error body: {error_body}")
        raise Exception(f"HTTP Error {e.code}: {e.reason}")
    except Exception as e:
        print(f"Request error: {e}")
        raise Exception(f"Request error: {e}")


def generate_chat(
    history: list, prompt: str, max_tokens: int = 1000, system: str = None
) -> str:
    """会話履歴を保持した推論"""
    try:
        print(f"DEBUG: generate_chat開始 - 履歴数: {len(history)}")

        # メッセージを構築
        messages = []

        # システムメッセージ
        if system:
            messages.append({"role": "system", "content": system})

        # 履歴を追加（最新2件のみ）
        for msg in history[-2:]:
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                messages.append(msg)
            elif isinstance(msg, str):
                messages.append({"role": "user", "content": msg})

        # 現在のプロンプトを追加
        messages.append({"role": "user", "content": prompt})

        # モデルIDを取得
        print("DEBUG: モデル一覧取得中...")
        models_response = _http_request(f"{OPENAI_BASE}/models", timeout=10)

        if "data" not in models_response or not models_response["data"]:
            raise Exception("利用可能なモデルが見つかりません")

        model_id = models_response["data"][0]["id"]
        print(f"DEBUG: 使用モデル: {model_id}")

        # トークン数を制限
        max_tokens = min(max_tokens, MAX_TOKENS)

        # リクエストボディ
        request_body = {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "stream": False,
        }

        print(f"DEBUG: リクエスト送信中...")
        response = _http_request(
            f"{OPENAI_BASE}/chat/completions", request_body, timeout=60
        )

        if "choices" not in response or not response["choices"]:
            raise Exception(f"API応答にchoicesがありません: {response}")

        choice = response["choices"][0]
        message = choice.get("message", {})
        content = message.get("content", "")

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


def healthcheck() -> bool:
    """サーバーのヘルスチェック"""
    try:
        response = _http_request(f"{OPENAI_BASE}/models", timeout=5)
        return "data" in response and len(response.get("data", [])) > 0
    except:
        return False
