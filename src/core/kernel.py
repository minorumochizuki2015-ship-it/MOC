"""Minimal core kernel implementation.

Functions:
- generate: single-turn text generation
- generate_chat: multi-message chat generation
- read_paths: load directory paths from config/paths.json with safe defaults
- healthcheck: runtime health info
- _model_id: current model identifier

Design goals:
- No external network calls by default (safe for CI/tests).
- Validates inputs and returns predictable outputs.
- Timezone-aware UTC timestamps.
- Logging avoids FileHandler to prevent pytest unraisable FileIO warnings.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from app.shared.logging_config import get_logger, is_pytest_running

# --- Logging (pytest 時は FileHandler 抑止) ---
logger = get_logger("src.core.kernel", in_pytest=is_pytest_running())


# --- Public API ---
def _model_id() -> str:
    """Return current model identifier.

    Priority: env KERNEL_MODEL_ID, else default.
    """
    return os.getenv("KERNEL_MODEL_ID", "orch-core-default")


def read_paths() -> Dict[str, str]:
    """Load baseline/milestones/tasks/metrics paths from config/paths.json.

    Falls back to safe defaults if file missing or invalid.
    """
    defaults: Dict[str, str] = {
        "baseline_dir": "data/baseline",
        "milestones_dir": "data/baseline/milestones",
        "tasks_dir": "data/baseline/tasks",
        "metrics_dir": "data/baseline/metrics",
    }
    cfg_path = Path("config/paths.json")
    try:
        if cfg_path.exists():
            with cfg_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            # ensure defaults exist
            for k, v in defaults.items():
                data.setdefault(k, v)
            return data
    except Exception as e:
        logger.warning(f"Failed to load paths config, using defaults: {e}")
    return defaults


def healthcheck() -> Dict[str, Any]:
    """Return a minimal health status payload."""
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "status": "ok",
        "timestamp": ts,
        "version": _model_id(),
    }
    # Could add provider/config checks here; keep minimal for now.
    return payload


@dataclass
class _GenOptions:
    temperature: float = 0.7
    max_tokens: int = 1024
    top_p: float = 1.0
    stop: Optional[List[str]] = None
    model: Optional[str] = None
    stream: bool = False


def _normalize_options(options: Optional[Dict[str, Any]]) -> _GenOptions:
    if options is None:
        return _GenOptions()
    # basic validation
    temperature = float(options.get("temperature", 0.7))
    if not (0.0 <= temperature <= 2.0):
        raise ValueError("temperature must be in [0.0, 2.0]")

    max_tokens = int(options.get("max_tokens", 1024))
    if max_tokens <= 0:
        raise ValueError("max_tokens must be > 0")

    top_p = float(options.get("top_p", 1.0))
    if not (0.0 <= top_p <= 1.0):
        raise ValueError("top_p must be in [0.0, 1.0]")

    stop = options.get("stop")
    if stop is not None and not isinstance(stop, list):
        raise ValueError("stop must be a list of strings")

    model = options.get("model")
    stream = bool(options.get("stream", False))
    return _GenOptions(
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=top_p,
        stop=stop,
        model=model,
        stream=stream,
    )


def _start_timer() -> float:
    return time.perf_counter()


def _end_timer(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def generate(
    prompt: str, options: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Single-turn text generation (minimal local implementation).

    This implementation returns a deterministic echo-style output and does not
    call any external provider. It validates inputs and shapes the response
    according to the agreed minimal API.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")

    opts = _normalize_options(options)
    start = _start_timer()

    # simple local generation: echo with minor formatting and stop handling
    text = prompt.strip()
    if opts.stop:
        for s in opts.stop:
            if s and isinstance(s, str):
                idx = text.find(s)
                if idx != -1:
                    text = text[:idx]
                    break

    # honor max_tokens roughly by character length (safe, non-strict)
    if len(text) > opts.max_tokens:
        text = text[: opts.max_tokens]
        finish_reason = "length"
    else:
        finish_reason = "stop"

    usage_ms = _end_timer(start)
    model_id = opts.model or _model_id()

    return {
        "text": text,
        "model_id": model_id,
        "tokens": {"input": 0, "output": 0, "total": 0},
        "finish_reason": finish_reason,
        "usage_ms": usage_ms,
        # raw: provider response passthrough (none in local minimal impl)
    }


def generate_chat(
    messages: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Multi-message chat generation (minimal local implementation)."""
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty list")

    for m in messages:
        if not isinstance(m, dict):
            raise ValueError("each message must be a dict")
        role = m.get("role")
        content = m.get("content")
        if role not in {"system", "user", "assistant"}:
            raise ValueError("message.role must be one of system|user|assistant")
        if not isinstance(content, str):
            raise ValueError("message.content must be a string")

    opts = _normalize_options(options)
    start = _start_timer()

    # respond to the last user message; if none, respond to last message
    last_user = next((m for m in reversed(messages) if m.get("role") == "user"), messages[-1])
    content = last_user.get("content", "")
    reply = f"Acknowledged: {content.strip()}"

    # approximate stop/max_tokens handling
    if opts.stop:
        for s in opts.stop:
            if s and isinstance(s, str):
                idx = reply.find(s)
                if idx != -1:
                    reply = reply[:idx]
                    break

    finish_reason = "stop"
    if len(reply) > opts.max_tokens:
        reply = reply[: opts.max_tokens]
        finish_reason = "length"

    usage_ms = _end_timer(start)
    model_id = opts.model or _model_id()

    return {
        "role": "assistant",
        "content": reply,
        "model_id": model_id,
        "tokens": {"input": 0, "output": 0, "total": 0},
        "finish_reason": finish_reason,
        # tool_calls: omitted in minimal implementation
    }
