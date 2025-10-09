import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_RESULTS_DIR = ROOT / "data" / "test_results"
OUT_PATH = ROOT / "data" / "results" / "quality_score_latest.json"


def _find_jsons() -> list[Path]:
    paths = []
    # Primary location
    if TEST_RESULTS_DIR.exists():
        paths.extend(TEST_RESULTS_DIR.glob("*.json"))
    # Artifacts fallback: search recursively for test_results-like dirs
    for p in ROOT.glob("**/*test_results*/**/*.json"):
        paths.append(p)
    # De-duplicate
    uniq = []
    seen = set()
    for p in paths:
        if p.as_posix() not in seen:
            uniq.append(p)
            seen.add(p.as_posix())
    return uniq


def _load_metrics() -> dict:
    metrics = {
        "http": {},
        "sse": {},
        "canary": {},
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sources": [],
    }
    for jf in _find_jsons():
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        metrics["sources"].append(jf.as_posix())
        # Heuristics: detect type by keys
        if {"success_rate", "avg_latency_ms", "p95_latency_ms"}.issubset(data.keys()):
            metrics["http"] = data
        elif {"drop_rate", "reconnection_ms", "message_delay_p95_ms"}.issubset(data.keys()):
            metrics["sse"] = data
        elif "canary" in data or "success_count" in data or "fail_count" in data:
            metrics["canary"] = data
    return metrics


def _score_common(m: dict) -> float:
    # 0-5 scale
    http_sr = m.get("http", {}).get("success_rate")
    sse_sr = 1.0 - m.get("sse", {}).get("drop_rate", 0.0) if m.get("sse") else None
    avg = m.get("http", {}).get("avg_latency_ms")
    p95 = m.get("http", {}).get("p95_latency_ms")

    # 機能性
    func = 0.0
    if isinstance(http_sr, (int, float)):
        if http_sr >= 0.99:
            func = 5
        elif http_sr >= 0.98:
            func = 4
        elif http_sr >= 0.95:
            func = 3
        elif http_sr >= 0.90:
            func = 2
        else:
            func = 1

    # 信頼性/安定性（Canary/SSE）
    rel = 0.0
    if isinstance(sse_sr, (int, float)):
        if sse_sr >= 0.97:
            rel = 5
        elif sse_sr >= 0.95:
            rel = 4
        elif sse_sr >= 0.90:
            rel = 3
        elif sse_sr >= 0.80:
            rel = 2
        else:
            rel = 1

    # ユーザー中心性（応答性）
    uxs = 0.0
    if isinstance(avg, (int, float)) and isinstance(p95, (int, float)):
        if avg < 2000 and p95 < 2000:
            uxs = 5
        elif avg < 2500 and p95 < 2500:
            uxs = 4
        elif avg < 3000 and p95 < 3000:
            uxs = 3
        elif avg < 4000 and p95 < 4000:
            uxs = 2
        else:
            uxs = 1

    # 平均（0-5）
    vals = [v for v in [func, rel, uxs] if v > 0]
    return sum(vals) / len(vals) if vals else 0.0


def _score_special(m: dict) -> float:
    # 性能/統合性（HTTP 指標中心）。0-5スケール
    http_sr = m.get("http", {}).get("success_rate")
    avg = m.get("http", {}).get("avg_latency_ms")
    p95 = m.get("http", {}).get("p95_latency_ms")

    perf = 0.0
    if all(isinstance(x, (int, float)) for x in [http_sr, avg, p95]):
        if (http_sr >= 0.95) and (avg < 500) and (p95 < 1500):
            perf = 5
        elif (http_sr >= 0.93) and (avg < 700) and (p95 < 2000):
            perf = 4
        elif (http_sr >= 0.90) and (avg < 1000) and (p95 < 3000):
            perf = 3
        elif (http_sr >= 0.85) and (avg < 1500) and (p95 < 5000):
            perf = 2
        else:
            perf = 1

    # 視覚/応答性はダッシュボード計測が必要だが、未計測時は perf のみで代替
    vals = [perf] if perf > 0 else []
    return sum(vals) / len(vals) if vals else 0.0


def _score_novelty(m: dict) -> float:
    # 斬新さは簡易指標：AUTO_DECIDE/Canary 継続の存在で加点（将来拡張）
    flags_path = ROOT / "ORCH" / "STATE" / "flags.md"
    score = 3.0
    try:
        if flags_path.exists():
            txt = flags_path.read_text(encoding="utf-8").lower()
            if "auto_decide=on" in txt:
                score += 1
    except Exception:
        pass
    return min(5.0, score)


def main():
    metrics = _load_metrics()
    common = _score_common(metrics)
    special = _score_special(metrics)
    novelty = _score_novelty(metrics)

    total = (common * 8) + (special * 8) + (novelty * 4)
    gate = {
        "staging": total >= 70,
        "preprod": total >= 85,
        "autodecide": total >= 95,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(
            {
                "timestamp": metrics.get("timestamp"),
                "sources": metrics.get("sources"),
                "scores": {
                    "common": common,
                    "special": special,
                    "novelty": novelty,
                    "total": total,
                },
                "gate": gate,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"[aggregate_quality_score] common={common:.2f} special={special:.2f} novelty={novelty:.2f} total={total:.1f}"
    )
    print(
        f"[aggregate_quality_score] gate: staging={gate['staging']} preprod={gate['preprod']} autodecide={gate['autodecide']}"
    )
    # 集計は情報提供のみ。Fail は quality-gate の総合判定で制御。
    return 0


if __name__ == "__main__":
    sys.exit(main())
