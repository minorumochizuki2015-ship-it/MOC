from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple

from src.core.governance import Governance

# 設定値の直接定義
OPENAI_BASE = os.environ.get("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")
MAX_TOKENS = 15000
TIMEOUT_S = 180.0  # 3分に延長


class Kernel:
    def __init__(self, memory) -> None:
        self.memory = memory
        self.v1 = OPENAI_BASE
        self.api_key = API_KEY
        self.model = None  # 遅延初期化
        self._initialized = False

        # 性能最適化のためのキャッシュとメトリクス
        self._response_cache = {}
        self._cache_lock = threading.Lock()
        self._performance_metrics = {
            "total_requests": 0,
            "cache_hits": 0,
            "avg_response_time": 0.0,
            "error_count": 0,
        }
        self._metrics_lock = threading.Lock()

    def _req(
        self,
        url: str,
        data: Dict[str, Any] | None = None,
        timeout: float = TIMEOUT_S,
        retries: int = 2,
    ) -> Dict[str, Any]:
        """HTTPリクエストを再試行付きで実行"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = None if data is None else json.dumps(data).encode("utf-8")

        for i in range(retries + 1):
            try:
                req = urllib.request.Request(url, data=body, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.loads(r.read().decode("utf-8"))
            except Exception as e:
                if i == retries:
                    raise
                time.sleep(0.6 * (i + 1))  # 指数バックオフ

    def _ensure_initialized(self):
        """サーバー接続を確認し、必要に応じて初期化"""
        if not self._initialized:
            try:
                self.model = self._get_model_id()
                self._initialized = True
            except Exception as e:
                raise ConnectionError(f"サーバーに接続できません: {e}")

    def _get_model_id(self) -> str:
        lst = self._req(self.v1 + "/models")
        return lst["data"][0]["id"]

    def _generate_cache_key(self, prompt: str) -> str:
        """プロンプトからキャッシュキーを生成"""
        return hashlib.md5(prompt.encode("utf-8")).hexdigest()[:16]

    def _update_metrics(
        self, response_time: float, cache_hit: bool = False, error: bool = False
    ):
        """性能メトリクスを更新"""
        with self._metrics_lock:
            self._performance_metrics["total_requests"] += 1
            if cache_hit:
                self._performance_metrics["cache_hits"] += 1
            if error:
                self._performance_metrics["error_count"] += 1

            # 平均応答時間の更新（指数移動平均）
            alpha = 0.1
            current_avg = self._performance_metrics["avg_response_time"]
            self._performance_metrics["avg_response_time"] = (
                alpha * response_time + (1 - alpha) * current_avg
            )

    def get_performance_metrics(self) -> Dict[str, Any]:
        """性能メトリクスを取得"""
        with self._metrics_lock:
            metrics = self._performance_metrics.copy()
            if metrics["total_requests"] > 0:
                metrics["cache_hit_rate"] = (
                    metrics["cache_hits"] / metrics["total_requests"]
                )
                metrics["error_rate"] = (
                    metrics["error_count"] / metrics["total_requests"]
                )
            else:
                metrics["cache_hit_rate"] = 0.0
                metrics["error_rate"] = 0.0
            return metrics

    def query_local_api(self, prompt: str, use_cache: bool = True) -> Dict[str, Any]:
        """高性能なAPIクエリ（キャッシュ機能付き）"""
        # サーバー接続を確認
        self._ensure_initialized()

        start_time = time.time()

        # キャッシュチェック
        if use_cache:
            cache_key = self._generate_cache_key(prompt)
            with self._cache_lock:
                if cache_key in self._response_cache:
                    cached_response = self._response_cache[cache_key]
                    self._update_metrics(time.time() - start_time, cache_hit=True)
                    return cached_response

        try:
            # システムメッセージを簡潔に
            sysmsg = "あなたは統治核AIです。簡潔で正確な回答を提供してください。"
            body = {
                "model": self.model or "auto",
                "messages": [
                    {"role": "system", "content": sysmsg},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": MAX_TOKENS,
                "temperature": 0.7,
                "top_p": 0.95,
                "stream": False,
            }
            resp = self._req(self.v1 + "/chat/completions", body)
            text = (
                (resp.get("choices") or [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )
            gov = Governance().summarize_governance_analysis(text, None)

            result = {"response_text": text, "governance_analysis": gov}

            # キャッシュに保存
            if use_cache:
                with self._cache_lock:
                    self._response_cache[cache_key] = result
                    # キャッシュサイズ制限（最大100エントリ）
                    if len(self._response_cache) > 100:
                        # 古いエントリを削除（FIFO）
                        oldest_key = next(iter(self._response_cache))
                        del self._response_cache[oldest_key]

            self._update_metrics(time.time() - start_time)
            return result

        except Exception as e:
            self._update_metrics(time.time() - start_time, error=True)
            raise e


def http_req(url, data=None, timeout=TIMEOUT_S, retries=2):
    import json
    import time
    import urllib.request

    hdr = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    body = None if data is None else json.dumps(data).encode("utf-8")
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=body, headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            if i == retries:
                raise
            time.sleep(0.6 * (i + 1))


import json

# ---- minimal OpenAI-compatible wrapper (appended) ----
import os
import urllib.request

OPENAI_BASE = os.environ.get("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")


def _http(url, data=None, timeout=60):
    try:
        hdr = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "GoverningCore-AI/1.0",
        }

        if data is not None:
            # データを適切にシリアライズ
            json_data = json.dumps(data, ensure_ascii=False)
            data_bytes = json_data.encode("utf-8")
        else:
            data_bytes = None

        req = urllib.request.Request(url, data=data_bytes, headers=hdr)

        with urllib.request.urlopen(req, timeout=timeout) as r:
            response_text = r.read().decode("utf-8")
            return json.loads(response_text)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else "No error body"
        print(f"HTTP Error {e.code}: {error_body}")
        raise Exception(f"HTTP Error {e.code}: {error_body}")
    except Exception as e:
        print(f"HTTP Request Error: {e}")
        raise Exception(f"HTTP Request Error: {e}")


def generate(prompt: str, max_tokens: int = 128) -> str:
    mid = _http(f"{OPENAI_BASE}/models")["data"][0]["id"]
    body = {
        "model": mid,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream": False,
    }
    res = _http(f"{OPENAI_BASE}/chat/completions", body, timeout=120)
    ch = (res.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    return (msg.get("content") or ch.get("text") or "").strip()


# aliases
def chat(x):
    return generate(x)


def run(x):
    return generate(x)


# --- session-aware chat & file context ---
def generate_chat(
    history: list, prompt: str, max_tokens: int = 15000, system: str = None
) -> str:
    """会話履歴を保持した推論"""
    try:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})

        # 履歴を適切にフォーマット（最新3件のみ）
        recent_history = history[-3:] if len(history) > 3 else history
        for msg in recent_history:
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                msgs.append(msg)
            elif isinstance(msg, str):
                msgs.append({"role": "user", "content": msg})

        msgs.append({"role": "user", "content": prompt})

        # モデルIDを取得
        models_resp = _http(f"{OPENAI_BASE}/models", timeout=10)
        if "data" not in models_resp or not models_resp["data"]:
            raise Exception("利用可能なモデルが見つかりません")

        mid = models_resp["data"][0]["id"]

        # シンプルなトークン制限
        max_tokens = min(max_tokens, 2000)  # 最大2000トークンに制限

        # リクエストボディを適切にフォーマット
        body = {
            "model": mid,
            "messages": msgs,
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "stream": False,
        }

        print(
            f"DEBUG: リクエスト送信 - モデル: {mid}, メッセージ数: {len(msgs)}, max_tokens: {max_tokens}"
        )

        res = _http(f"{OPENAI_BASE}/chat/completions", body, timeout=180)

        if "choices" not in res or not res["choices"]:
            raise Exception(f"API応答にchoicesがありません: {res}")

        ch = res["choices"][0]
        msg = ch.get("message") or {}
        content = msg.get("content") or ch.get("text") or ""

        if not content.strip():
            raise Exception("空の応答が返されました")

        return content.strip()

    except Exception as e:
        print(f"DEBUG: generate_chat エラー: {e}")
        raise Exception(f"チャット生成エラー: {e}")


def _truncate_messages(msgs, max_length):
    """メッセージを適切に短縮"""
    truncated_msgs = []
    current_length = 0

    for msg in msgs:
        content = str(msg.get("content", ""))
        if current_length + len(content) <= max_length:
            truncated_msgs.append(msg)
            current_length += len(content)
        else:
            # 最後のメッセージを短縮
            remaining = max_length - current_length
            if remaining > 100:  # 最低100文字は確保
                truncated_content = content[: remaining - 50] + "..."
                truncated_msg = msg.copy()
                truncated_msg["content"] = truncated_content
                truncated_msgs.append(truncated_msg)
            break

    return truncated_msgs


from pathlib import Path


def read_paths(paths: list[str], max_kb: int = 64) -> str:
    """ローカルファイルを読み込んでコンテキストに変換"""
    chunks = []
    for p in paths:
        try:
            b = Path(p).read_bytes()[: max_kb * 1024]
            try:
                t = b.decode("utf-8")
            except UnicodeDecodeError:
                t = b.decode("cp932", "ignore")
            chunks.append(f"### {Path(p).name}\n```\n{t}\n```")
        except Exception as e:
            chunks.append(f"### {Path(p).name}\n<read error: {e}>")
    return "\n\n".join(chunks)


def healthcheck() -> bool:
    """ローカルLLMサーバーのヘルスチェック"""
    try:
        response = _http(f"{OPENAI_BASE}/models", timeout=5)
        return "data" in response and len(response.get("data", [])) > 0
    except:
        return False


_model_id_cache = None


def _model_id():
    """モデルID取得（キャッシュ付き）"""
    global _model_id_cache
    if _model_id_cache is None:
        _model_id_cache = _http(f"{OPENAI_BASE}/models")["data"][0]["id"]
    return _model_id_cache


DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", "120"))
FALLBACK_MODEL = os.environ.get("FALLBACK_MODEL", "qwen2-7b-instruct-q4_k_m")
# ---- end wrapper ----
