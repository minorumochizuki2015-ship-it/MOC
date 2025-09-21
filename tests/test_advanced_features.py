# -*- coding: utf-8 -*-
"""
Advanced Feature Smoke Test
- kernel.generate_chat / kernel.read_paths の存在と動作
- 64KB/ファイル上限, UTF-8/CP932 読み分け
- モデル接続と応答時間
実行:  python tests/test_advanced_features.py
"""
import os
import sys
import time
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.core import kernel

fail = 0

@pytest.mark.integration


def check(name, cond, info=""):
    global fail
    if cond:
        print(f"[PASS] {name}")
    else:
        fail += 1
        print(f"[FAIL] {name}" + (f" -> {info}" if info else ""))


print("=== Advanced Feature Smoke Test ===")

# 0) healthcheck / model id
hc = False
mid = "N/A"
t0 = time.monotonic()
try:
    hc = kernel.healthcheck()
    mid = kernel._model_id() if hc else "N/A"
except Exception as e:
    print("[WARN] healthcheck error:", e)
dt = time.monotonic() - t0
check("healthcheck()", hc, "http://127.0.0.1:8080/v1 を確認")
print(f"model: {mid}  ({dt:.2f}s)")

# 1) 関数の存在
check("has generate_chat()", hasattr(kernel, "generate_chat"))
check("has read_paths()", hasattr(kernel, "read_paths"))

# 2) read_paths 検証
datadir = ROOT / "data" / "test_inputs"
datadir.mkdir(parents=True, exist_ok=True)

utf8_p = datadir / "utf8.txt"
cp932_p = datadir / "cp932.txt"
big_p = datadir / "big.txt"

utf8_p.write_text("これはUTF-8テスト。🍣🍺\n行2\n", encoding="utf-8")
cp932_p.write_bytes("これはCP932テスト。\n行2\n".encode("cp932", "strict"))
big_p.write_bytes(b"A" * (120 * 1024))  # 120KB

ctx = ""
t1 = time.monotonic()
try:
    ctx = kernel.read_paths([str(utf8_p), str(cp932_p), str(big_p)])
    ok = ("### utf8.txt" in ctx) and ("### cp932.txt" in ctx) and ("### big.txt" in ctx)
    check("read_paths() returns all headers", ok)
    check("read_paths() size limit (~64KB/each)", len(ctx) <= 70 * 1024)
except Exception as e:
    check("read_paths() no exception", False, str(e))
t_ctx = time.monotonic() - t1
print(f"read_paths time: {t_ctx:.2f}s, length: {len(ctx)}")

# 3) 単発推論
reply_simple = ""
t2 = time.monotonic()
try:
    reply_simple = kernel.generate("5文字で挨拶")
    check("generate() non-empty reply", bool(reply_simple.strip()))
except Exception as e:
    check("generate() no exception", False, str(e))
t_gen = time.monotonic() - t2
print(f"generate reply: {reply_simple!r}  ({t_gen:.2f}s)")

# 4) 会話継続推論
reply_chat = ""
history = [{"role": "user", "content": "一言で自己紹介して"}]
system_ctx = ("以下はローカル抜粋:\n" + ctx) if ctx else None

t3 = time.monotonic()
try:
    reply_chat = kernel.generate_chat(
        history, "今度は5文字で挨拶", max_tokens=64, system=system_ctx
    )
    check("generate_chat() non-empty reply", bool(reply_chat.strip()))
except Exception as e:
    check("generate_chat() no exception", False, str(e))
t_chat = time.monotonic() - t3
print(f"generate_chat reply: {reply_chat!r}  ({t_chat:.2f}s)")

print("=== Result ===")
if fail:
    print(f"FAILED: {fail} case(s)")
    sys.exit(1)
print("ALL PASS")

def test_advanced_features():
    """pytest wrapper for advanced features test"""
    # The actual test logic is executed at module level above
    # This function serves as a pytest entry point
    assert fail == 0, f"Advanced features test failed with {fail} case(s)"
