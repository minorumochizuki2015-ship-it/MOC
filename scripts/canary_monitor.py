#!/usr/bin/env python3
"""
Canary監視スクリプト
重要APIのヘルスチェックを一定間隔で実行し、結果を data/test_results/ に保存する。
設定: config/monitoring.json（存在すれば使用）
対象（デフォルト）: /api/tasks, /api/milestones, /api/alerts, /api/predictions, /api/quality/metrics, /api/quality/health, /status, /events
"""

import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_INTERVAL_SEC = 10
DEFAULT_RUN_MINUTES = 30  # 30分継続

DEFAULT_ENDPOINTS = [
    "/api/tasks",
    "/api/milestones",
    "/api/alerts",
    "/api/predictions",
    "/api/quality/metrics",
    "/api/quality/health",
    "/status",
    "/events",
]


def load_config(config_path: str | None = None) -> dict:
    """Load monitoring config JSON if available."""
    cfg = {}
    paths_to_try = []
    if config_path:
        paths_to_try.append(Path(config_path))
    paths_to_try.append(Path("config/monitoring.json"))

    for p in paths_to_try:
        try:
            if p.exists():
                with p.open("r", encoding="utf-8") as f:
                    cfg = json.load(f)
                logger.info(f"Loaded config from {p}")
                break
        except Exception as e:
            logger.warning(f"Failed to load config from {p}: {e}")

    return cfg


def resolve_settings(cfg: dict, args: argparse.Namespace) -> tuple[str, int, int, list[str]]:
    """Resolve BASE_URL, INTERVAL_SEC, RUN_MINUTES, endpoints from config and args."""
    # Base URL
    base_url = DEFAULT_BASE_URL
    if args.base_url:
        base_url = args.base_url
    else:
        host = cfg.get("dashboard_config", {}).get("host", "127.0.0.1")
        port = cfg.get("dashboard_config", {}).get("port", 5000)
        base_url = f"http://{host}:{port}"

    # Interval
    interval_sec = DEFAULT_INTERVAL_SEC
    if args.interval_sec:
        interval_sec = args.interval_sec
    else:
        interval_sec = int(cfg.get("monitoring_interval", DEFAULT_INTERVAL_SEC))
        # Emergency mode overrides if requested
        if args.use_emergency and cfg.get("emergency_mode", {}).get("enabled", False):
            interval_sec = int(
                cfg.get("emergency_mode", {}).get("monitoring_interval", interval_sec)
            )

    # Duration (minutes)
    run_minutes = DEFAULT_RUN_MINUTES
    if args.run_minutes:
        run_minutes = args.run_minutes

    # Endpoints
    endpoints = DEFAULT_ENDPOINTS.copy()
    if isinstance(cfg.get("canary_endpoints"), list) and cfg.get("canary_endpoints"):
        endpoints = cfg["canary_endpoints"]
    # CLI can append extra endpoints
    if args.extra_endpoints:
        endpoints.extend(args.extra_endpoints)

    # De-duplicate while preserving order
    seen = set()
    unique_endpoints = []
    for ep in endpoints:
        if ep not in seen:
            unique_endpoints.append(ep)
            seen.add(ep)

    return base_url, interval_sec, run_minutes, unique_endpoints


def check_endpoint(base_url: str, path: str) -> dict:
    url = f"{base_url}{path}"
    start = time.time()
    try:
        # SSE endpoints use stream mode; regular endpoints use normal GET
        is_sse = path == "/events"
        resp = requests.get(
            url,
            timeout=5,
            stream=is_sse,
            headers={
                "Accept": "text/event-stream" if is_sse else "*/*",
                "Cache-Control": "no-cache",
            },
        )
        latency = time.time() - start
        ok = resp.status_code == 200
        # Optionally peek first SSE line to confirm stream is alive
        if ok and is_sse:
            try:
                # Read a tiny chunk without consuming too much
                chunk = next(resp.iter_lines(chunk_size=64))
                if chunk is None:
                    ok = False
            except StopIteration:
                ok = False
            except Exception:
                # Non-fatal; treat as ok based on status
                pass
        return {
            "path": path,
            "status_code": resp.status_code,
            "ok": ok,
            "latency_ms": int(latency * 1000),
        }
    except Exception as e:
        latency = time.time() - start
        return {"path": path, "error": str(e), "ok": False, "latency_ms": int(latency * 1000)}


def _evaluate_results(results: dict) -> dict:
    """Compute simple metrics for a run: error_rate, avg_latency_ms, sse_ok_rate."""
    checks = results.get("checks", [])
    total = 0
    errors = 0
    latencies = []
    sse_total = 0
    sse_ok = 0
    for it in checks:
        for r in it.get("results", []):
            total += 1
            if not r.get("ok"):
                errors += 1
            if isinstance(r.get("latency_ms"), int):
                latencies.append(r["latency_ms"])
            if r.get("path") == "/events":
                sse_total += 1
                if r.get("ok"):
                    sse_ok += 1
    error_rate = (errors / total) if total else 0.0
    avg_latency_ms = int(sum(latencies) / len(latencies)) if latencies else 0
    sse_ok_rate = (sse_ok / sse_total) if sse_total else None
    return {
        "samples": total,
        "error_rate": error_rate,
        "avg_latency_ms": avg_latency_ms,
        "sse_ok_rate": sse_ok_rate,
    }


def _run_single(
    base_url: str, interval_sec: int, run_minutes: int, endpoints: list[str], cfg: dict
) -> dict:
    out_dir = Path("data/test_results")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"canary_monitor_{ts}.json"

    results = {
        "started_at": datetime.now().isoformat(),
        "base_url": base_url,
        "interval_sec": interval_sec,
        "run_minutes": run_minutes,
        "checks": [],
    }

    total_iters = max(1, int((run_minutes * 60) / interval_sec))

    for _ in range(total_iters):
        iter_res = {"timestamp": datetime.now().isoformat(), "results": []}
        for ep in endpoints:
            iter_res["results"].append(check_endpoint(base_url, ep))
        results["checks"].append(iter_res)
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        time.sleep(interval_sec)

    results["finished_at"] = datetime.now().isoformat()
    with out_file.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    return results


def _run_sweep(cfg: dict, args: argparse.Namespace, base_url: str, endpoints: list[str]) -> dict:
    """Run interval sweep and choose optimal monitoring interval.
    Criteria: min error_rate, tie-breaker by avg_latency_ms and SSE ok rate.
    """
    # Parse sweep list
    sweep_list = []
    for tok in (args.sweep or "").split(","):
        tok = tok.strip()
        if tok.isdigit():
            sweep_list.append(int(tok))
    if not sweep_list:
        sweep_list = [3, 5, 10, 15]

    duration_sec = args.duration or 600  # default 10 minutes per interval

    summary = {
        "base_url": base_url,
        "endpoints": endpoints,
        "duration_sec_per_interval": duration_sec,
        "candidates": sweep_list,
        "results": {},
        "recommended_interval": None,
        "timestamp": datetime.now().isoformat(),
    }

    for interval in sweep_list:
        # Convert duration_sec to minutes for single-run helper
        run_minutes = max(1, int(duration_sec / 60))
        res = _run_single(base_url, interval, run_minutes, endpoints, cfg)
        metrics = _evaluate_results(res)
        summary["results"][str(interval)] = metrics

    # Select best
    def score_item(m: dict):
        # Lower error_rate better, lower avg_latency better; boost if sse_ok_rate is high
        er = m.get("error_rate", 1.0)
        lat = m.get("avg_latency_ms", 10_000)
        sse_boost = (1.0 - (m.get("sse_ok_rate") or 0.0)) * 0.1  # lower is better
        return (er, lat + sse_boost)

    best_interval = None
    best_score = None
    for k, m in summary["results"].items():
        sc = score_item(m)
        if best_score is None or sc < best_score:
            best_score = sc
            best_interval = int(k)
    summary["recommended_interval"] = best_interval

    # Persist sweep summary
    out_dir = Path("data/test_results")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"canary_sweep_{ts}.json"
    out_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # Optionally write back to config
    if args.output_config:
        try:
            cfg_path = Path(args.output_config)
            if not cfg_path.exists():
                # initialize minimal config structure if missing
                cfg_data = {
                    "monitoring_interval": best_interval,
                    "dashboard_config": cfg.get(
                        "dashboard_config", {"host": "127.0.0.1", "port": 5000}
                    ),
                }
            else:
                cfg_data = json.loads(cfg_path.read_text(encoding="utf-8"))
                cfg_data["monitoring_interval"] = best_interval
                if isinstance(cfg_data.get("emergency_mode"), dict):
                    # keep emergency mode slower or equal to normal interval
                    em = cfg_data["emergency_mode"]
                    em["monitoring_interval"] = max(
                        em.get("monitoring_interval", best_interval), best_interval
                    )
                    cfg_data["emergency_mode"] = em
            cfg_path.write_text(
                json.dumps(cfg_data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"[canary_sweep] wrote recommended interval={best_interval} to {cfg_path}")
        except Exception as e:
            print(f"[canary_sweep] failed to write config: {e}")

    print(
        f"[canary_sweep] candidates={sweep_list} results={summary['results']} recommended={best_interval}"
    )
    return summary


def main():
    parser = argparse.ArgumentParser(description="Canary monitor")
    parser.add_argument("--config", help="Path to monitoring config JSON", default=None)
    parser.add_argument("--base-url", help="Override base URL (e.g., http://127.0.0.1:5000)")
    parser.add_argument("--interval-sec", type=int, help="Monitoring interval in seconds")
    parser.add_argument("--run-minutes", type=int, help="Total monitoring duration in minutes")
    parser.add_argument(
        "--use-emergency",
        action="store_true",
        help="Use emergency monitoring settings if available",
    )
    parser.add_argument("--extra-endpoints", nargs="*", help="Append extra endpoints to monitor")
    # Sweep options
    parser.add_argument(
        "--sweep", help="Comma-separated list of intervals to evaluate (e.g., 3,5,10,15)"
    )
    parser.add_argument(
        "--duration", type=int, help="Per-interval duration in seconds for sweep mode"
    )
    parser.add_argument(
        "--output-config", help="Write recommended interval back to this config path"
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    base_url, interval_sec, run_minutes, endpoints = resolve_settings(cfg, args)

    # Sweep mode
    if args.sweep:
        _run_sweep(cfg, args, base_url, endpoints)
        return

    # Single run mode (default)
    _run_single(base_url, interval_sec, run_minutes, endpoints, cfg)


if __name__ == "__main__":
    main()
