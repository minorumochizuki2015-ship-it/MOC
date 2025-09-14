import csv
import os
import time

from openai import OpenAI

BASE = os.getenv("OPENAI_COMPAT_BASE", "http://127.0.0.1:8080")
MODEL = os.getenv("LOCAL_MODEL_NAME", "auto")
client = OpenAI(base_url=BASE, api_key="sk-local")

PROMPT = "日本語で1段落の自己紹介を書いてください。"


def run_once():
    t0 = time.time()
    # /v1/completions を使用（llama_cpp.server の chat バグ回避）
    r = client.completions.create(model=MODEL, prompt=PROMPT)
    dt = time.time() - t0
    usage = getattr(r, "usage", None)
    comp = int(getattr(usage, "completion_tokens", 0) or 0)
    tps = comp / dt if dt > 0 else 0.0
    return dt, comp, tps


def main():
    rows = []
    for _ in range(3):
        dt, comp, tps = run_once()
        rows.append(
            {"dt": f"{dt:.2f}", "completion_tokens": comp, "tok_per_s": f"{tps:.2f}"}
        )
    with open("bench_result.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["dt", "completion_tokens", "tok_per_s"])
        w.writeheader()
        w.writerows(rows)
    print("bench_result.csv written")


if __name__ == "__main__":
    main()
