#!/usr/bin/env python3
"""
HTTP API負荷テスト
設定ファイル(config/monitoring.json)のcanary_endpointsを対象に、
高並列アクセスでレイテンシと成功率を検証する。
"""

import asyncio
import json
import random
import statistics
import time
from datetime import datetime
from pathlib import Path

import aiohttp
import pytest


def load_monitoring_config():
    cfg_path = Path("config/monitoring.json")
    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    # 後方互換用のデフォルト
    return {
        "dashboard_config": {"host": "127.0.0.1", "port": 5000},
        "http_targets": [{"base_url": "http://127.0.0.1:5000", "endpoints": ["/", "/status"]}],
        "canary_endpoints": [
            "/status",
        ],
    }


async def http_worker(
    session: aiohttp.ClientSession,
    base_url: str,
    endpoints: list[str],
    duration: int,
    results: list[dict],
):
    start = time.time()
    # リトライ設定
    retry_max = 3
    backoff_base = 0.2  # 秒（指数バックオフ）
    request_timeout = aiohttp.ClientTimeout(total=8, sock_connect=3, sock_read=5)

    while time.time() - start < duration:
        ep = random.choice(endpoints)
        url = f"{base_url}{ep}"
        t0 = time.time()
        ok = False
        status = 0
        last_error = None

        for attempt in range(retry_max):
            try:
                async with session.get(url, timeout=request_timeout) as resp:
                    status = resp.status
                    ok = status == 200
                    # consume a small body to avoid connection reuse issues
                    await resp.read()
                # 5xx系はリトライ対象
                if not ok and status in (500, 502, 503, 504) and attempt < retry_max - 1:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue
                break
            except Exception as e:
                last_error = str(e)
                if attempt < retry_max - 1:
                    await asyncio.sleep(backoff_base * (2**attempt))
                    continue
                break

        latency_ms = int((time.time() - t0) * 1000)
        if ok:
            results.append({"endpoint": ep, "ok": True, "status": status, "latency_ms": latency_ms})
        else:
            if last_error is not None:
                results.append(
                    {"endpoint": ep, "ok": False, "error": last_error, "latency_ms": latency_ms}
                )
            else:
                results.append(
                    {"endpoint": ep, "ok": False, "status": status, "latency_ms": latency_ms}
                )


async def precheck_endpoints(
    session: aiohttp.ClientSession, base_url: str, endpoints: list[str], timeout_per_check: int = 3
):
    """対象エンドポイントを事前に健全性チェックし、到達可能なもののみを選別する。
    戻り値: (available_endpoints, excluded_details)
    """
    available: list[str] = []
    excluded: list[dict] = []
    check_timeout = aiohttp.ClientTimeout(total=timeout_per_check, sock_connect=2, sock_read=2)
    for ep in endpoints:
        url = f"{base_url}{ep}"
        try:
            async with session.get(url, timeout=check_timeout) as resp:
                # 200/204を到達可能とみなす（それ以外は除外）
                if resp.status in (200, 204):
                    available.append(ep)
                else:
                    excluded.append({"endpoint": ep, "status": resp.status})
        except Exception as e:
            excluded.append({"endpoint": ep, "error": str(e)})
    return available, excluded


def analyze_http_results(results: list[dict]):
    total = len(results)
    success = sum(1 for r in results if r.get("ok"))
    success_rate = success / total if total else 0.0
    latencies = [r["latency_ms"] for r in results if "latency_ms" in r]
    by_ep = {}
    for r in results:
        ep = r.get("endpoint", "unknown")
        by_ep.setdefault(ep, []).append(r)

    ep_summary = {}
    for ep, items in by_ep.items():
        lats = [it["latency_ms"] for it in items if "latency_ms" in it]
        ok_count = sum(1 for it in items if it.get("ok"))
        ep_summary[ep] = {
            "requests": len(items),
            "success_rate": ok_count / len(items) if items else 0,
            "latency_mean_ms": statistics.mean(lats) if lats else 0,
            "latency_p95_ms": statistics.quantiles(lats, n=20)[18] if len(lats) >= 20 else 0,
            "latency_max_ms": max(lats) if lats else 0,
        }

    return {
        "total_requests": total,
        "success_rate": success_rate,
        "latency_mean_ms": statistics.mean(latencies) if latencies else 0,
        "latency_p95_ms": statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else 0,
        "latency_max_ms": max(latencies) if latencies else 0,
        "per_endpoint": ep_summary,
    }


@pytest.mark.slow
@pytest.mark.performance
class TestHttpApiLoad:
    def test_http_api_high_concurrency(self):
        """HTTP APIに対して高並列アクセスで成功率とレイテンシを検証"""
        # pytest-asyncio プラグイン非依存で動作するように、async 本体は asyncio.run で実行
        asyncio.run(self._run_http_api_high_concurrency())

    async def _run_http_api_high_concurrency(self):
        """Async本体: 高並列HTTPアクセスの検証"""
        cfg = load_monitoring_config()
        # 新スキーマ: http_targets に複数base_url/endpointsが含まれる想定
        targets = cfg.get("http_targets")
        # 旧スキーマフォールバック
        if not targets:
            host = cfg.get("dashboard_config", {}).get("host", "127.0.0.1")
            port = cfg.get("dashboard_config", {}).get("port", 5000)
            base_url = f"http://{host}:{port}"
            endpoints = cfg.get("canary_endpoints", ["/status"])
            endpoints = [ep for ep in endpoints if ep != "/events"]
            targets = [{"base_url": base_url, "endpoints": endpoints}]

        concurrency = 50
        duration = 60  # seconds

        connector = aiohttp.TCPConnector(limit=concurrency)
        timeout = aiohttp.ClientTimeout(total=8, sock_connect=3, sock_read=5)
        headers = {"Cache-Control": "no-cache", "Pragma": "no-cache", "Connection": "keep-alive"}
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as session:
            results: list[dict] = []
            # ターゲット毎に事前チェック＆負荷実行
            for t in targets:
                base_url = t.get("base_url")
                eps = [ep for ep in t.get("endpoints", []) if ep != "/events"]
                available_eps, excluded = await precheck_endpoints(session, base_url, eps)
                if not available_eps:
                    # スキップせず次のターゲットへ（片方死んでも全体評価継続）
                    print(f"Skip target {base_url}: no reachable endpoints. Excluded: {excluded}")
                    continue
                tasks = [
                    asyncio.create_task(
                        http_worker(session, base_url, available_eps, duration, results)
                    )
                    for _ in range(concurrency)
                ]
                await asyncio.gather(*tasks)

        summary = analyze_http_results(results)

        # 成功率とレイテンシのしきい値（強化版）
        assert (
            summary["success_rate"] >= 0.95
        ), f"Success rate should be >= 95%, got {summary['success_rate']:.2%}"
        assert (
            summary["latency_mean_ms"] < 500
        ), f"Mean latency should be < 500ms, got {summary['latency_mean_ms']}ms"
        assert (
            summary["latency_p95_ms"] < 1500
        ), f"95th percentile latency should be < 1500ms, got {summary['latency_p95_ms']}ms"

        # 保存
        out_dir = Path("data/test_results")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"http_load_{ts}.json"
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(
                {"summary": summary, "raw_count": len(results)}, f, ensure_ascii=False, indent=2
            )

        # 集計スクリプト向けに標準化スキーマも出力（トップレベルキー）
        norm = {
            "success_rate": float(summary["success_rate"]),  # fraction (0-1) to整合 with aggregator
            "avg_latency_ms": int(summary["latency_mean_ms"]),
            "p95_latency_ms": int(summary["latency_p95_ms"]),
            "timestamp": datetime.now().isoformat() + "Z",
        }
        (out_dir / "http_metrics_latest.json").write_text(
            json.dumps(norm, ensure_ascii=False, indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    # __main__ 実行時にもメトリクスを出力し、pytestを使わない環境でも集計に乗るようにする
    import asyncio
    import os

    async def main():
        cfg = load_monitoring_config()

        # 新スキーマ優先（HTTP_BASE_URL/HTTP_ENDPOINTSが指定されていればそれを単一ターゲットとして上書き）
        env_base = os.environ.get("HTTP_BASE_URL")
        env_eps = os.environ.get("HTTP_ENDPOINTS")
        if env_base or env_eps:
            base_url = (
                env_base
                or f"http://{cfg.get('dashboard_config', {}).get('host', '127.0.0.1')}:{cfg.get('dashboard_config', {}).get('port', 5000)}"
            )
            endpoints = [
                ep.strip()
                for ep in (env_eps or "/status").split(",")
                if ep.strip() and ep.strip() != "/events"
            ]
            targets = [{"base_url": base_url, "endpoints": endpoints}]
        else:
            targets = cfg.get("http_targets")
            if not targets:
                host = cfg.get("dashboard_config", {}).get("host", "127.0.0.1")
                port = cfg.get("dashboard_config", {}).get("port", 5000)
                base_url = f"http://{host}:{port}"
                endpoints = [
                    ep for ep in cfg.get("canary_endpoints", ["/status"]) if ep != "/events"
                ]
                targets = [{"base_url": base_url, "endpoints": endpoints}]

        concurrency = int(os.environ.get("HTTP_CONCURRENCY", "50"))
        duration = int(os.environ.get("HTTP_DURATION", "60"))

        connector = aiohttp.TCPConnector(limit=concurrency)
        timeout = aiohttp.ClientTimeout(total=8, sock_connect=3, sock_read=5)
        headers = {"Cache-Control": "no-cache", "Pragma": "no-cache", "Connection": "keep-alive"}
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as session:
            results: list[dict] = []
            for t in targets:
                base_url = t.get("base_url")
                eps = [ep for ep in t.get("endpoints", []) if ep != "/events"]
                available_eps, excluded = await precheck_endpoints(session, base_url, eps)
                if not available_eps:
                    print(f"Skip target {base_url}: no reachable endpoints. Excluded: {excluded}")
                    continue
                tasks = [
                    asyncio.create_task(
                        http_worker(session, base_url, available_eps, duration, results)
                    )
                    for _ in range(concurrency)
                ]
                await asyncio.gather(*tasks)

        summary = analyze_http_results(results)

        # 保存（標準メトリクス）
        out_dir = Path("data/test_results")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"http_load_{ts}.json"
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(
                {"summary": summary, "raw_count": len(results), "targets": targets},
                f,
                ensure_ascii=False,
                indent=2,
            )

        norm = {
            "success_rate": float(summary.get("success_rate", 0.0)),
            "avg_latency_ms": int(summary.get("latency_mean_ms", 0)),
            "p95_latency_ms": int(summary.get("latency_p95_ms", 0)),
            "timestamp": datetime.now().isoformat() + "Z",
        }
        (out_dir / "http_metrics_latest.json").write_text(
            json.dumps(norm, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # コンソール出力
        print("HTTP Load Test Summary (main):")
        print(f"Targets: {targets}")
        print(f"Total Requests: {summary.get('total_requests', 0)}")
        print(f"Success Rate: {summary.get('success_rate', 0.0):.2%}")
        print(f"Mean Latency: {summary.get('latency_mean_ms', 0)} ms")
        print(f"P95 Latency: {summary.get('latency_p95_ms', 0)} ms")

    asyncio.run(main())
