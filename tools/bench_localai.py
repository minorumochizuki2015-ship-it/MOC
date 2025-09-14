import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def get_model_id(base):
    r = requests.get(f"{base}/models", timeout=10)
    r.raise_for_status()
    d = r.json()
    if isinstance(d, dict) and "data" in d and d["data"]:
        return d["data"][0]["id"]
    raise RuntimeError("no model id")


def one_call(
    base, model, prompt, max_tokens, stream=False, temperature=0.2, timeout=600
):
    url = f"{base}/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": stream,
    }
    t0 = time.perf_counter()
    comp_toks = 0
    finish = "unknown"
    text = ""
    try:
        if stream:
            with requests.post(
                url, json=body, timeout=(5, timeout), stream=True
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    if line.startswith("data: "):
                        line = line[6:]
                    if line.strip() == "[DONE]":
                        break
                    try:
                        ch = json.loads(line)
                        delta = (
                            ch.get("choices", [{}])[0]
                            .get("delta", {})
                            .get("content", "")
                        )
                        text += delta or ""
                        finish = (
                            ch.get("choices", [{}])[0].get("finish_reason", finish)
                            or finish
                        )
                    except Exception:
                        pass
        else:
            resp = requests.post(url, json=body, timeout=(5, timeout))
            resp.raise_for_status()
            d = resp.json()
            text = d.get("choices", [{}])[0].get("message", {}).get("content", "")
            finish = d.get("choices", [{}])[0].get("finish_reason", finish) or finish
            usage = d.get("usage") or {}
            comp_toks = usage.get("completion_tokens") or 0
    except Exception as e:
        return {
            "ok": False,
            "err": str(e),
            "sec": 0,
            "tps": 0,
            "finish": "error",
            "tok": 0,
        }

    sec = time.perf_counter() - t0
    # usage が無い場合は概算（かなり荒いが一応）
    if comp_toks == 0:
        comp_toks = max(1, int(len(text) / 4))
    tps = comp_toks / sec if sec > 0 else 0
    return {
        "ok": True,
        "err": "",
        "sec": sec,
        "tps": tps,
        "finish": finish,
        "tok": comp_toks,
    }


def run_suite(base, model, max_tokens, stream, rounds, conc, prompt_short, prompt_long):
    results = []

    def submit(p):
        return one_call(base, model, p, max_tokens=max_tokens, stream=stream)

    # 1) ショート応答 x rounds
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(submit, prompt_short) for _ in range(rounds)]
        for f in as_completed(futs):
            results.append(("short", f.result()))

    # 2) ロング応答 x rounds
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(submit, prompt_long) for _ in range(rounds)]
        for f in as_completed(futs):
            results.append(("long", f.result()))

    # 集計
    out = {
        "n": len(results),
        "ok": 0,
        "err": 0,
        "avg_tps": 0.0,
        "p50": 0.0,
        "p95": 0.0,
        "trim_len": 0,
    }
    tps = []
    for kind, r in results:
        if r["ok"]:
            out["ok"] += 1
            tps.append(r["tps"])
        else:
            out["err"] += 1
    if tps:
        tps.sort()

        def pctile(arr, p):
            i = max(0, min(len(arr) - 1, int(round((p / 100.0) * (len(arr) - 1)))))
            return arr[i]

        out["avg_tps"] = sum(tps) / len(tps)
        out["p50"] = pctile(tps, 50)
        out["p95"] = pctile(tps, 95)
    return results, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base", default=os.environ.get("OPENAI_BASE", "http://127.0.0.1:8080/v1")
    )
    ap.add_argument("--model", default="")
    ap.add_argument(
        "--max_tokens", type=int, default=int(os.environ.get("LLM_OUT_TOKENS", "600"))
    )
    ap.add_argument("--stream", action="store_true")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--conc", type=int, default=1)
    ap.add_argument("--out", default="bench_result.json")
    args = ap.parse_args()

    model = args.model or get_model_id(args.base)

    prompt_short = "PythonでFizzBuzz関数を書いて。コードのみ。"
    prompt_long = "以下の仕様で中規模な関数を書いて。丁寧な docstring とテスト例も含める。\n- 入力: JSON文字列\n- 処理: バリデーション→正規化→集計\n- 出力: 辞書\n- 制約: 例外はValueErrorで統一\n- 型ヒント必須"

    results, summary = run_suite(
        base=args.base,
        model=model,
        max_tokens=args.max_tokens,
        stream=args.stream,
        rounds=args.rounds,
        conc=args.conc,
        prompt_short=prompt_short,
        prompt_long=prompt_long,
    )
    data = {
        "base": args.base,
        "model": model,
        "max_tokens": args.max_tokens,
        "stream": args.stream,
        "rounds": args.rounds,
        "conc": args.conc,
        "summary": summary,
        "results": results,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
