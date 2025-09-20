from __future__ import annotations

import hashlib
import json
import math
import os
import random
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.governance import Governance

# === context guard ===
DEFAULT_CTX = int(os.environ.get("LLM_CTX_SIZE", "4096"))  # サーバ未取得時の既定
OUTPUT_MAX_TOKENS = int(os.environ.get("LLM_OUT_TOKENS", "600"))
HISTORY_KEEP_PAIRS = int(os.environ.get("LLM_HISTORY_PAIRS", "2"))
_RAG_LIMIT_DEFAULT = int(os.environ.get("LLM_RAG_CHARS", "500"))
_USER_LIMIT_DEFAULT = int(os.environ.get("LLM_USER_CHARS", "2000"))

# === 安定化v2設定 ===
READ_TIMEOUT = int(os.environ.get("LLM_READ_TIMEOUT", "600"))
RETRY_MAX = int(os.environ.get("LLM_RETRY_MAX", "3"))
STREAM_IDLE_SECS = int(os.environ.get("LLM_STREAM_IDLE", "45"))
_TOK_BY_TASK = {
    k: int(v)
    for k, v in (
        t.split(":")
        for t in os.environ.get(
            "TOKENS_BY_TASK", "generate:600,refactor:400,run:200"
        ).split(",")
    )
}


def _exp_backoff(i: int) -> float:
    return min(30, (2**i) + random.uniform(0, 0.5))


def _dedup_clip(text: str, max_lines: int = 30) -> str:
    """RAG去重＋30行クリップ"""
    seen, out = set(), []
    for ln in text.splitlines():
        k = ln.strip()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(ln)
        if len(out) >= max_lines:
            break
    return "\n".join(out)


def _max_tokens_for(task: Optional[str], fallback: int) -> int:
    """タスク別max_tokens取得"""
    if task is None:
        return fallback
    return _TOK_BY_TASK.get(task, fallback)


def _nonstream_continue(url, body, headers, prefix=""):
    """SSE失敗時に非ストリームで続きを1回分取得。"""
    follow = body.copy()
    follow["stream"] = False
    # 自動継続プロンプト
    if prefix:
        follow_msgs = follow["messages"] + [
            {"role": "assistant", "content": prefix},
            {"role": "user", "content": "続きから出力して"},
        ]
    else:
        follow_msgs = follow["messages"]
    follow["messages"] = follow_msgs

    r = _sess.post(url, json=follow, headers=headers, timeout=(5, READ_TIMEOUT))
    r.raise_for_status()
    jr = r.json()
    return jr.get("choices", [{}])[0].get("message", {}).get("content", "") or jr.get(
        "choices", [{}]
    )[0].get("text", "")


def _stream_generate_chat(url, body, headers):
    """
    可能な限りSSEで受信。無通信が STREAM_IDLE_SECS を超えたら
    例外を投げずに 非ストリーム へ自動フォールバックして続き取得。
    """
    chunks, finish_reason = [], None
    last_rx = time.time()

    try:
        with _sess.post(
            url,
            json={**body, "stream": True},
            headers=headers,
            timeout=(5, READ_TIMEOUT),
            stream=True,
        ) as resp:
            resp.raise_for_status()
            # 文字化け対策: ストリーミングレスポンスのエンコーディングを明示的に設定
            resp.encoding = 'utf-8'
            
            for line in resp.iter_lines(decode_unicode=True):
                # 無通信監視
                now = time.time()
                if now - last_rx > STREAM_IDLE_SECS:
                    raise TimeoutError("stream idle timeout")

                if not line:
                    continue
                last_rx = now

                # llama.cpp は "data: {json}" と "[DONE]" を返す
                if line.startswith("data: "):
                    line = line[6:]
                if line.strip() == "[DONE]":
                    break

                try:
                    j = json.loads(line)
                except Exception:
                    continue

                # 取りうる位置の順で抽出
                delta = j.get("choices", [{}])[0].get("delta", {}) or j.get(
                    "choices", [{}]
                )[0].get("message", {})
                if "content" in delta:
                    content = delta["content"]
                    # 文字化け対策: ストリーミングコンテンツの文字エンコーディング修正
                    if isinstance(content, str):
                        import unicodedata
                        content = unicodedata.normalize('NFC', content)
                        content = ''.join(char for char in content if unicodedata.category(char)[0] != 'C' or char in '\n\t')
                    chunks.append(content)

                fr = j.get("choices", [{}])[0].get("finish_reason")
                if fr:
                    finish_reason = fr
    except (requests.ReadTimeout, requests.ConnectionError, TimeoutError) as e:
        # ★ ここでフォールバック（例外は上げない）
        print(f"LOG_SUM: STREAM_FALLBACK: {e}")
        text_so_far = "".join(chunks)
        more = _nonstream_continue(url, body, headers, prefix=text_so_far)
        return text_so_far + more, "fallback"
    except Exception as e:
        # 予期せぬ例外のみ従来通り
        raise

    return "".join(chunks), finish_reason or "stop"


def _approx_tokens_from_text(s: str) -> int:
    # 安全側: 1 token ≒ 3.5〜4 chars を想定
    return max(1, math.ceil(len(s) / 4))


# 設定値の直接定義
OPENAI_BASE = os.environ.get("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080")
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")
MAX_TOKENS = 15000
TIMEOUT_S = 180.0

# コード特化モデル（GPT提案）
DEFAULT_MODEL_ID = os.getenv("MODEL_ID", "qwen2-7b-instruct")
MODEL_ID_CODER = os.getenv("MODEL_ID_CODER", "qwen2.5-coder-7b-instruct")


def _env_code_tasks() -> set[str]:
    v = os.getenv("CODE_TASKS", "")
    return set(s.strip() for s in v.split(",") if s.strip()) or {
        "generate",
        "complete",
        "refactor",
        "run",
        "format",
    }


# パフォーマンス最適化用キャッシュ
_response_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()  # 3分に延長

# keep-alive + 再試行セッション
_sess = requests.Session()
_retry = Retry(total=3, backoff_factor=1.5, status_forcelist=[408, 502, 503, 504])
_sess.mount("http://", HTTPAdapter(max_retries=_retry, pool_maxsize=8))
_sess.headers.update({"Connection": "keep-alive"})


class Kernel:
    def __init__(self, memory) -> None:
        self.memory = memory
        self.v1 = OPENAI_BASE + "/v1"
        self.api_key = API_KEY
        self.model = None  # 遅延初期化
        self._initialized = False

        # 性能最適化のためのキャッシュとメトリクス
        self._response_cache: Dict[str, Any] = {}
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
                    # 文字化け対策: 複数のエンコーディングを試行
                    raw_data = r.read()
                    try:
                        # UTF-8を試行
                        decoded_data = raw_data.decode("utf-8")
                    except UnicodeDecodeError:
                        try:
                            # Shift_JISを試行
                            decoded_data = raw_data.decode("shift_jis")
                        except UnicodeDecodeError:
                            try:
                                # CP932を試行
                                decoded_data = raw_data.decode("cp932")
                            except UnicodeDecodeError:
                                # 最後の手段: エラーを置換
                                decoded_data = raw_data.decode("utf-8", errors="replace")
                    return json.loads(decoded_data)
            except Exception as e:
                if i == retries:
                    raise
                time.sleep(0.6 * (i + 1))  # 指数バックオフ

        # この行は到達しないが、mypyのため
        raise RuntimeError("Unexpected end of retry loop")

    def _ensure_initialized(self):
        """サーバー接続を確認し、必要に応じて初期化"""
        if not self._initialized:
            try:
                self.model = self._get_model_id()
                self._initialized = True
            except Exception as e:
                raise ConnectionError(f"サーバーに接続できません: {e}")

    def _get_model_id(self, task: str = None) -> str:
        """タスク別モデルルーティング（GPT提案）"""
        code_tasks = _env_code_tasks()
        mid = MODEL_ID_CODER if (task in code_tasks) else self._get_default_model_id()
        try:
            print(f"LOG_SUM: route model={mid} task={task}")
        except Exception:
            pass
        return mid

    def _get_default_model_id(self) -> str:
        """デフォルトモデル取得"""
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
            raw_text = (
                (resp.get("choices") or [{}])[0]
                .get("message", {})
                .get("content", "")
            )
            
            # 文字化け対策: 応答テキストのエンコーディング修正
            if isinstance(raw_text, str):
                try:
                    # Unicode正規化
                    import unicodedata
                    text = unicodedata.normalize('NFC', raw_text)
                    # 制御文字を除去
                    text = ''.join(char for char in text if unicodedata.category(char)[0] != 'C' or char in '\n\t')
                except Exception:
                    text = raw_text
            else:
                text = str(raw_text) if raw_text else ""
            
            text = text.strip()
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

# OPENAI_BASE is already defined above, no need to redefine
API_KEY = os.environ.get("OPENAI_API_KEY", "sk-local")


def _http(url, data=None, timeout=READ_TIMEOUT, stream=False):
    """
    再試行つきHTTP。stream=TrueはSSE/行分割を想定、失敗時は非ストリームに自動フォールバック。
    """
    hdr = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "User-Agent": "GoverningCore-AI/1.0",
    }

    for attempt in range(RETRY_MAX + 1):
        try:
            if stream and data is not None:
                with _sess.post(
                    url, json=data, headers=hdr, timeout=(5, timeout), stream=True
                ) as resp:
                    resp.raise_for_status()
                    full = []
                    for line in resp.iter_lines(decode_unicode=True):
                        if not line:
                            continue
                        if line.startswith("data: "):
                            line = line[6:]
                        ch = json.loads(line) if line.strip() else None
                        if not ch:
                            continue
                        piece = (
                            ch.get("delta", {}).get("content")
                            or ch.get("message", {}).get("content")
                            or ch.get("text")
                        )
                        if piece:
                            full.append(piece)
                    out = "".join(full)
                    if out:
                        return {"ok": True, "text": out}
                    # フォールバック（本文空）
            # 非ストリーム（初回orフォールバック）
            r = _sess.post(url, json=data, headers=hdr, timeout=(5, timeout))
            r.raise_for_status()
            js = r.json()
            txt = js.get("choices", [{}])[0].get("message", {}).get(
                "content"
            ) or js.get("choices", [{}])[0].get("text")
            return {"ok": True, "text": txt or ""}
        except Exception as e:
            if attempt >= RETRY_MAX:
                return {"ok": False, "err": str(e)}
            time.sleep(_exp_backoff(attempt))


def generate(prompt: str, max_tokens: int = 128) -> str:
    # ベンチマーク開始
    from ..utils.benchmark_logger import benchmark_logger

    benchmark_id = benchmark_logger.start_benchmark(prompt, "auto", "generate")

    try:
        # モデルID取得（エラーハンドリング強化）
        # 直接モデルIDを使用（サーバーがv1/modelsをサポートしていない場合）
        mid = "/models/qwen2-7b-instruct-q4_k_m.gguf"
        body = {
            "model": mid,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "stream": False,
        }
        res = _http(f"{OPENAI_BASE}/v1/chat/completions", body, timeout=120)

        if not res.get("ok"):
            raise Exception(f"推論実行失敗: {res.get('err', 'Unknown error')}")

        response_text = res.get("text", "").strip()

        # トークン数推定
        tokens_generated = max(1, len(response_text) // 4)

        # ベンチマーク終了
        benchmark_logger.end_benchmark(
            benchmark_id, response_text, tokens_generated, "stop"
        )

        return response_text

    except Exception as e:
        # エラー時のベンチマーク終了
        benchmark_logger.end_benchmark(benchmark_id, "", 0, "error", str(e))
        raise


# aliases
def chat(x):
    return generate(x)


def run(x):
    return generate(x)


# --- session-aware chat & file context ---
def generate_chat(
    history: list,
    prompt: str,
    max_tokens: int = 15000,
    system: str = None,
    task_type: str = None,
) -> str:
    """会話履歴を保持した推論（GPT提案に従ってタスク別モデルルーティング）"""
    # ベンチマーク開始
    from ..utils.benchmark_logger import benchmark_logger

    benchmark_id = benchmark_logger.start_benchmark(prompt, "auto", task_type)

    try:
        # キャッシュキーを生成（パフォーマンス最適化）
        cache_key = f"{task_type}:{hash(prompt)}:{hash(str(history))}"

        with _cache_lock:
            if cache_key in _response_cache:
                print("✓ キャッシュヒット")
                cached_response = _response_cache[cache_key]
                # キャッシュヒット時もベンチマーク記録
                tokens_generated = max(1, len(cached_response) // 4)
                benchmark_logger.end_benchmark(
                    benchmark_id, cached_response, tokens_generated, "cached"
                )
                return cached_response

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

        # タスク別モデルルーティング（GPT提案）
        code_tasks = _env_code_tasks()
        if task_type in code_tasks:
            # コード生成専用モデル
            model_id = MODEL_ID_CODER
            print(f"DEBUG: コード生成タスク用モデル使用: {model_id}")
        else:
            # デフォルトモデル（GET使用）
            try:
                r = _sess.get(f"{OPENAI_BASE}/v1/models", timeout=10)
                r.raise_for_status()
                models_resp = r.json()
                if "data" not in models_resp or not models_resp["data"]:
                    raise Exception("利用可能なモデルが見つかりません")
                model_id = models_resp["data"][0]["id"]
                print(f"DEBUG: デフォルトモデル使用: {model_id}")
            except Exception as e:
                print(f"DEBUG: モデル取得エラー: {e}")
                model_id = DEFAULT_MODEL_ID

        mid = model_id

        # タスク別max_tokens適用
        out_tokens = _max_tokens_for(task_type, OUTPUT_MAX_TOKENS)

        # 安全圧縮（GPT提案に従って完全実装）
        safe_messages = _truncate_messages_smart(
            msgs, ctx_limit=DEFAULT_CTX, out_tokens=out_tokens
        )
        max_tokens = min(out_tokens, max_tokens)

        # CTX_DBGログ（圧縮適用の可視化）
        in_tokens = sum(_approx_tokens_from_text(m.get("content", "")) for m in msgs)
        trimmed = len(msgs) != len(safe_messages)
        hist_pairs = (
            len([m for m in safe_messages if m.get("role") in ("user", "assistant")])
            // 2
        )
        rag_len = sum(
            len(m.get("content", ""))
            for m in safe_messages
            if "Context:" in m.get("content", "")
        )
        print(
            f"CTX_DBG: limit={DEFAULT_CTX} in_tok={in_tokens} out_tok={out_tokens} trimmed={trimmed} hist_pairs={hist_pairs} rag_len={rag_len}"
        )

        # ログ1行要約（回帰監視）
        model_id = mid
        task_type_str = task_type or "unknown"
        print(
            f"LOG_SUM: model={model_id} in_tok={in_tokens} out_tok={out_tokens} trimmed={trimmed} task={task_type_str}"
        )

        # リクエストボディを適切にフォーマット（パフォーマンス最適化）
        STREAM_PAYLOAD = os.getenv("LLM_STREAM", "1") != "0"
        body = {
            "model": mid,
            "messages": safe_messages,  # 安全圧縮されたメッセージを使用
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "top_p": 0.95,  # パフォーマンス向上
            "repeat_penalty": 1.1,  # パフォーマンス向上
            "stream": STREAM_PAYLOAD,
        }

        # 自動継続設定
        AUTO_CONT = os.getenv("LLM_AUTO_CONTINUE", "1") != "0"
        CONT_MAX = int(os.getenv("LLM_CONT_MAX", "2"))
        SAVE_LAST = os.getenv("LLM_SAVE_LAST", "1") != "0"
        SAVE_PATH = os.getenv("LLM_SAVE_LAST_PATH", "data/outputs/last_reply.txt")

        print(
            f"DEBUG: リクエスト送信 - モデル: {mid}, メッセージ数: {len(msgs)}, max_tokens: {max_tokens}"
        )

        url = f"{OPENAI_BASE}/v1/chat/completions"
        hdr = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "GoverningCore-AI/1.0",
        }

        full_text = ""
        finish_reason = None

        if STREAM_PAYLOAD:
            # 新しい堅牢SSE処理を使用
            full_text, finish_reason = _stream_generate_chat(url, body, hdr)
        else:
            # 非ストリーミング
            r = _sess.post(url, json=body, headers=hdr, timeout=(5, READ_TIMEOUT))
            r.raise_for_status()
            
            # 文字化け対策: レスポンスの文字エンコーディングを明示的に処理
            r.encoding = 'utf-8'
            
            # 生のレスポンスデータを取得
            raw_response = r.content
            print(f"DEBUG: 生レスポンス長: {len(raw_response)} bytes")
            
            # 複数のエンコーディングを試行
            decoded_text = None
            for encoding in ['utf-8', 'utf-8-sig', 'cp932', 'shift_jis', 'euc-jp']:
                try:
                    decoded_text = raw_response.decode(encoding)
                    print(f"DEBUG: エンコーディング成功: {encoding}")
                    break
                except UnicodeDecodeError:
                    continue
            
            if decoded_text is None:
                # 最後の手段: エラーを置換
                decoded_text = raw_response.decode('utf-8', errors='replace')
                print("DEBUG: エラー置換でデコード")
            
            try:
                data = json.loads(decoded_text)
            except Exception as e:
                print(f"DEBUG: JSON解析失敗: {e}")
                # JSON解析に失敗した場合、テキストとして処理
                import unicodedata
                normalized_text = unicodedata.normalize('NFC', decoded_text)
                # 制御文字を除去
                clean_text = ''.join(char for char in normalized_text if unicodedata.category(char)[0] != 'C' or char in '\n\t')
                data = {"choices": [{"message": {"content": clean_text}, "finish_reason": "stop"}]}
            
            choice = (data.get("choices") or [{}])[0]
            raw_content = choice.get("message", {}).get("content", "") or choice.get("text", "")
            
            # 文字化け対策: コンテンツの文字エンコーディング修正（強化版）
            if isinstance(raw_content, str):
                import unicodedata
                # Unicode正規化
                full_text = unicodedata.normalize('NFC', raw_content)
                # 制御文字を除去
                full_text = ''.join(char for char in full_text if unicodedata.category(char)[0] != 'C' or char in '\n\t')
                # 追加の文字化け修正
                full_text = full_text.encode('utf-8', errors='ignore').decode('utf-8')
                print(f"DEBUG: 最終テキスト長: {len(full_text)} 文字")
            else:
                full_text = str(raw_content) if raw_content else ""
            
            finish_reason = choice.get("finish_reason")

        # --- 自動継続（lengthで切れたら追い取得） ---
        rounds = 0
        while AUTO_CONT and finish_reason == "length" and rounds < CONT_MAX:
            rounds += 1
            # 直前までの出力をアシスタント発話として追加し、ユーザーに「続き」を投げる
            cont_msgs = list(safe_messages)
            cont_msgs.append({"role": "assistant", "content": full_text})
            cont_msgs.append({"role": "user", "content": "続き"})
            body2 = {
                "model": mid,
                "messages": cont_msgs,
                "max_tokens": max_tokens,
                "stream": False,
            }
            try:
                r2 = _sess.post(url, json=body2, headers=hdr, timeout=(5, READ_TIMEOUT))
                r2.raise_for_status()
                d2 = r2.json()
                c2 = (d2.get("choices") or [{}])[0]
                add = c2.get("message", {}).get("content", "") or c2.get("text", "")
                full_text += add
                finish_reason = c2.get("finish_reason")
                print(f"LOG_SUM: auto-continue round={rounds} finish={finish_reason}")
            except Exception as e:
                print(f"LOG_SUM: auto-continue failed: {e}")
                break

        # 生成物の保存（UI表示が切れてもファイルで全量確認可能）
        if SAVE_LAST:
            try:
                os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
                # 文字化け対策: 保存前にテキストを正規化
                import unicodedata
                normalized_text = unicodedata.normalize('NFC', full_text)
                # 制御文字を除去
                clean_text = ''.join(char for char in normalized_text if unicodedata.category(char)[0] != 'C' or char in '\n\t')
                with open(SAVE_PATH, "w", encoding="utf-8") as f:
                    f.write(clean_text)
                print(f"LOG_SUM: saved result -> {SAVE_PATH}")
            except Exception as e:
                print(f"LOG_SUM: save failed: {e}")

        if not full_text:
            raise Exception("空の応答（サーバ応答は受信したが本文なし）")

        result_text = full_text

        # トークン数推定
        tokens_generated = max(1, len(result_text) // 4)

        # ベンチマーク終了
        benchmark_logger.end_benchmark(
            benchmark_id, result_text, tokens_generated, finish_reason
        )

        # キャッシュに保存（パフォーマンス最適化）
        with _cache_lock:
            _response_cache[cache_key] = result_text.strip()
            # キャッシュサイズ制限（最大100エントリ）
            if len(_response_cache) > 100:
                # 古いエントリを削除（FIFO）
                oldest_key = next(iter(_response_cache))
                del _response_cache[oldest_key]

        return result_text.strip()

    except Exception as e:
        print(f"DEBUG: generate_chat エラー: {e}")
        # エラー時のベンチマーク終了
        benchmark_logger.end_benchmark(benchmark_id, "", 0, "error", str(e))
        raise Exception(f"チャット生成エラー: {e}")


def _truncate_messages_smart(
    messages,
    ctx_limit=DEFAULT_CTX,
    out_tokens=OUTPUT_MAX_TOKENS,
    rag_limit=_RAG_LIMIT_DEFAULT,
    user_limit=_USER_LIMIT_DEFAULT,
):
    """
    優先: system 全保持 → 直近 HISTORY_KEEP_PAIRS の user/assistant → 現在の user を文字数制限。
    RAGは先に500文字へ切詰め（LLM_RAG_CHARS）。
    """
    if not isinstance(messages, list):
        return messages

    # 1) 文字数制限（RAGとuser本文）
    trimmed = []
    sys_msgs = [m for m in messages if m.get("role") == "system"]
    others = [m for m in messages if m.get("role") != "system"]

    def _cap_text(role, content):
        if not isinstance(content, str):
            return content
        if role == "user":
            # RAGブロックの簡易検出（"Context:"以降など）を先に短縮
            parts = content.split("Context:", 1)
            if len(parts) == 2:
                head, ctx = parts[0], parts[1]
                ctx = ctx[:rag_limit]
                content = head + "Context:" + ctx
            # 最終的なユーザ本文を文字数制限
            return content[:user_limit]
        return content

    for m in messages:
        c = m.get("content", "")
        m2 = dict(m)
        m2["content"] = _cap_text(m2.get("role"), c)
        trimmed.append(m2)

    # 2) 履歴の間引き（system全部＋直近Nペア＋末尾user）
    kept = []
    kept.extend(sys_msgs)
    # user/assistantのペア抽出（末尾から）
    ua = [m for m in trimmed if m.get("role") in ("user", "assistant")]
    # 末尾userを確実に残すため保持しつつ、直近ペアを収集
    last_user = ua[-1] if ua and ua[-1].get("role") == "user" else None
    # 直近から遡って user/assistant をペア単位で拾う
    pairs = []
    buf = []
    for m in reversed(ua[:-1] if last_user else ua):
        buf.append(m)
        if len(buf) == 2:
            pairs.append(buf[:])
            buf.clear()
        if len(pairs) >= HISTORY_KEEP_PAIRS:
            break
    # 復元（古い順）
    for p in reversed(pairs):
        for m in reversed(p):
            kept.append(m)
    if last_user:
        kept.append(last_user)

    # 3) トークン予算で再調整（system優先）
    # 予算: ctx_limit - out_tokens（出力分を確保）
    budget = max(512, ctx_limit - out_tokens)

    def toks(ms):
        return sum(_approx_tokens_from_text(m.get("content", "")) for m in ms)

    base = toks(sys_msgs)
    pool = [m for m in kept if m.get("role") != "system"]
    out = sys_msgs[:]
    for m in pool:
        if (toks(out) + _approx_tokens_from_text(m.get("content", ""))) <= budget:
            out.append(m)
        else:
            break
    return out


def _truncate_messages(msgs, max_length):
    """メッセージを適切に短縮（後方互換性のため保持）"""
    return _truncate_messages_smart(msgs, max_length)


from pathlib import Path


def _looks_binary(b: bytes) -> bool:
    """簡易バイナリ判定: NUL含有 or 非可視文字の多さ"""
    head = b[:1024]
    if b"\x00" in head:
        return True
    # 非可視(制御)比率が高ければバイナリとみなす
    ctrl = sum(1 for x in head if x < 9 or (13 < x < 32))
    return ctrl > max(4, len(head) // 16)


def _hexdump(b: bytes, width: int = 16, max_lines: int = 256) -> str:
    """上限付きヘックスダンプ（幅=16、既定で最大256行）"""
    out = []
    limit = min(len(b), width * max_lines)
    for i in range(0, limit, width):
        chunk = b[i : i + width]
        hx = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"{i:08x}  {hx:<{width*3-1}}  |{asc}|")
    if len(b) > limit:
        out.append(f"... ({len(b)-limit} bytes truncated)")
    return "\n".join(out)


def read_paths(paths: list[str], max_kb: int = 64) -> str:
    """ローカルファイルを読み込んでコンテキストに変換（バイナリ安全化）"""
    chunks = []
    for p in paths:
        try:
            b = Path(p).read_bytes()[: max_kb * 1024]
            if _looks_binary(b):
                # バイナリは編集不可のため短縮ヘックスでプレビュー
                dump = _hexdump(b, width=16, max_lines=256)
                chunks.append(
                    f"### {Path(p).name} (binary preview, {len(b)} bytes shown)\n```\n{dump}\n```"
                )
            else:
                try:
                    t = b.decode("utf-8")
                except UnicodeDecodeError:
                    t = b.decode("cp932", "replace")
                chunks.append(f"### {Path(p).name}\n```\n{t}\n```")
        except Exception as e:
            chunks.append(f"### {Path(p).name}\n<read error: {e}>")
    return "\n\n".join(chunks)


def healthcheck() -> bool:
    """ローカルLLMサーバーのヘルスチェック（GET使用）"""
    try:
        # health check (GETが正。古いビルド互換のフォールバックも用意)
        def _probe(urls):
            for p in urls:
                try:
                    r = _sess.get(f"{OPENAI_BASE}{p}", timeout=5)
                    if r.status_code == 200:
                        return True, p
                except Exception:
                    pass
            return False, None

        ok, hit = _probe(("/v1/models", "/healthz"))
        if ok:
            print(f"LOG_SUM: health ok via {hit}")
            return True
        return False
    except:
        return False


_model_id_cache = None


def _model_id():
    """モデルID取得（キャッシュ付き、GET使用）"""
    global _model_id_cache
    if _model_id_cache is None:
        try:
            r = _sess.get(f"{OPENAI_BASE}/v1/models", timeout=10)
            r.raise_for_status()
            data = r.json()
            _model_id_cache = data["data"][0]["id"]
        except Exception as e:
            print(f"DEBUG: モデルID取得エラー: {e}")
            _model_id_cache = "qwen2-7b-instruct"  # フォールバック
    return _model_id_cache


DEFAULT_TIMEOUT = int(os.environ.get("DEFAULT_TIMEOUT", "120"))
FALLBACK_MODEL = os.environ.get("FALLBACK_MODEL", "qwen2-7b-instruct-q4_k_m")
# ---- end wrapper ----
