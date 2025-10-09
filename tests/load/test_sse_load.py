#!/usr/bin/env python3
"""
Load tests for Server-Sent Events (SSE) connections
Tests 100+ concurrent connections and performance requirements
"""

import asyncio
import json
import logging
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import aiohttp
import pytest

logger = logging.getLogger(__name__)


@dataclass
class SSEMetrics:
    """Metrics for SSE connection testing"""

    connection_time: float
    first_message_time: float
    total_messages: int
    message_latencies: List[float]
    disconnection_time: float
    errors: List[str]
    reconnection_attempts: int
    reconnection_success_rate: float


class SSELoadTester:
    """Load tester for SSE connections"""

    def __init__(self, base_url: str = None, event_endpoint: str = None):
        # Allow environment override; default to dashboard SSE at 5000 if not provided
        env_base = os.environ.get("SSE_BASE_URL")
        env_event = os.environ.get("SSE_EVENT_ENDPOINT")
        self.base_url = base_url or env_base or "http://127.0.0.1:5000"
        self.event_endpoint = event_endpoint or env_event or "/events"
        self.metrics: List[SSEMetrics] = []

    async def create_sse_connection(self, client_id: str, duration: int = 60) -> SSEMetrics:
        """Create a single SSE connection and collect metrics"""
        metrics = SSEMetrics(
            connection_time=0,
            first_message_time=0,
            total_messages=0,
            message_latencies=[],
            disconnection_time=0,
            errors=[],
            reconnection_attempts=0,
            reconnection_success_rate=0,
        )

        start_time = time.time()
        first_message_received = False

        try:
            async with aiohttp.ClientSession() as session:
                # Measure connection time
                connect_start = time.time()

                async with session.get(
                    f"{self.base_url}{self.event_endpoint}",
                    headers={
                        "Accept": "text/event-stream",
                        "Cache-Control": "no-cache",
                        "X-Client-ID": client_id,
                    },
                ) as response:
                    metrics.connection_time = time.time() - connect_start

                    if response.status != 200:
                        metrics.errors.append(f"HTTP {response.status}")
                        return metrics

                    # Read SSE messages
                    async for line in response.content:
                        if time.time() - start_time > duration:
                            break

                        line = line.decode("utf-8").strip()
                        if not line:
                            continue

                        message_time = time.time()

                        if line.startswith("data:"):
                            if not first_message_received:
                                metrics.first_message_time = message_time - start_time
                                first_message_received = True

                            metrics.total_messages += 1

                            # Parse message to extract timestamp for latency calculation
                            try:
                                data = line[5:].strip()  # Remove 'data:' prefix
                                if data:
                                    message_data = json.loads(data)
                                    if "timestamp" in message_data:
                                        sent_time = float(message_data["timestamp"])
                                        latency = message_time - sent_time
                                        metrics.message_latencies.append(latency)
                            except (json.JSONDecodeError, ValueError, KeyError):
                                # Skip latency calculation for malformed messages
                                pass

                        elif line.startswith("event:"):
                            event_type = line[6:].strip()
                            if event_type == "error":
                                metrics.errors.append("Server sent error event")

        except aiohttp.ClientError as e:
            metrics.errors.append(f"Connection error: {str(e)}")
        except asyncio.TimeoutError:
            metrics.errors.append("Connection timeout")
        except Exception as e:
            metrics.errors.append(f"Unexpected error: {str(e)}")

        metrics.disconnection_time = time.time() - start_time
        return metrics

    async def test_concurrent_connections(
        self, num_connections: int, duration: int = 60
    ) -> List[SSEMetrics]:
        """Test multiple concurrent SSE connections"""
        logger.info(f"Starting {num_connections} concurrent SSE connections for {duration}s")

        tasks = []
        for i in range(num_connections):
            client_id = f"load-test-client-{i:03d}"
            task = asyncio.create_task(self.create_sse_connection(client_id, duration))
            tasks.append(task)

        # Wait for all connections to complete
        metrics_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and collect valid metrics
        valid_metrics = []
        for i, result in enumerate(metrics_list):
            if isinstance(result, Exception):
                logger.error(f"Connection {i} failed: {result}")
                # Create error metrics
                error_metrics = SSEMetrics(
                    connection_time=0,
                    first_message_time=0,
                    total_messages=0,
                    message_latencies=[],
                    disconnection_time=0,
                    errors=[str(result)],
                    reconnection_attempts=0,
                    reconnection_success_rate=0,
                )
                valid_metrics.append(error_metrics)
            else:
                valid_metrics.append(result)

        self.metrics = valid_metrics
        return valid_metrics

    def analyze_metrics(self) -> Dict[str, Any]:
        """Analyze collected metrics and return summary"""
        if not self.metrics:
            return {}

        # Connection metrics
        connection_times = [m.connection_time for m in self.metrics if m.connection_time > 0]
        first_message_times = [
            m.first_message_time for m in self.metrics if m.first_message_time > 0
        ]
        total_messages = [m.total_messages for m in self.metrics]

        # Latency metrics
        all_latencies = []
        for m in self.metrics:
            all_latencies.extend(m.message_latencies)

        # Error metrics
        total_errors = sum(len(m.errors) for m in self.metrics)
        connections_with_errors = sum(1 for m in self.metrics if m.errors)

        # Success rate
        successful_connections = len(
            [m for m in self.metrics if not m.errors and m.total_messages > 0]
        )
        success_rate = successful_connections / len(self.metrics) if self.metrics else 0

        analysis = {
            "total_connections": len(self.metrics),
            "successful_connections": successful_connections,
            "success_rate": success_rate,
            "connection_times": {
                "mean": statistics.mean(connection_times) if connection_times else 0,
                "median": statistics.median(connection_times) if connection_times else 0,
                "p95": (
                    statistics.quantiles(connection_times, n=20)[18]
                    if len(connection_times) >= 20
                    else 0
                ),
                "max": max(connection_times) if connection_times else 0,
            },
            "first_message_times": {
                "mean": statistics.mean(first_message_times) if first_message_times else 0,
                "median": statistics.median(first_message_times) if first_message_times else 0,
                "p95": (
                    statistics.quantiles(first_message_times, n=20)[18]
                    if len(first_message_times) >= 20
                    else 0
                ),
                "max": max(first_message_times) if first_message_times else 0,
            },
            "message_metrics": {
                "total_messages": sum(total_messages),
                "avg_messages_per_connection": (
                    statistics.mean(total_messages) if total_messages else 0
                ),
                "min_messages": min(total_messages) if total_messages else 0,
                "max_messages": max(total_messages) if total_messages else 0,
            },
            "latency_metrics": {
                "mean": statistics.mean(all_latencies) if all_latencies else 0,
                "median": statistics.median(all_latencies) if all_latencies else 0,
                "p95": (
                    statistics.quantiles(all_latencies, n=20)[18] if len(all_latencies) >= 20 else 0
                ),
                "p99": (
                    statistics.quantiles(all_latencies, n=100)[98]
                    if len(all_latencies) >= 100
                    else 0
                ),
                "max": max(all_latencies) if all_latencies else 0,
            },
            "error_metrics": {
                "total_errors": total_errors,
                "connections_with_errors": connections_with_errors,
                "error_rate": connections_with_errors / len(self.metrics) if self.metrics else 0,
            },
        }
        # Add top-level alias for error_rate to match test expectations
        analysis["error_rate"] = analysis["error_metrics"]["error_rate"]

        return analysis


def load_monitoring_config():
    cfg_path = Path("config/monitoring.json")
    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    # フォールバック（後方互換）
    return {"sse_targets": [{"base_url": "http://127.0.0.1:5000", "event_endpoint": "/events"}]}


async def precheck_sse(
    session: aiohttp.ClientSession, base_url: str, event_endpoint: str, timeout_sec: int = 3
):
    """SSEエンドポイントの事前到達チェック。200を返せばOK、それ以外は除外。"""
    try:
        async with session.get(
            f"{base_url}{event_endpoint}",
            headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
            timeout=aiohttp.ClientTimeout(total=timeout_sec, sock_connect=2, sock_read=2),
        ) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


@pytest.mark.slow
@pytest.mark.performance
class TestSSELoad:
    """Load tests for SSE connections"""

    @pytest.fixture
    def sse_tester(self):
        """Create SSE load tester instance"""
        return SSELoadTester()

    def test_10_concurrent_connections(self, sse_tester):
        """Test 10 concurrent SSE connections (warm-up test)"""
        # Arrange
        num_connections = 10
        duration = 30  # 30 seconds for warm-up

        # Act
        metrics = asyncio.run(sse_tester.test_concurrent_connections(num_connections, duration))
        analysis = sse_tester.analyze_metrics()

        # Assert
        assert len(metrics) == num_connections, f"Should have {num_connections} connection attempts"
        assert (
            analysis["success_rate"] >= 0.9
        ), f"Success rate should be >= 90%, got {analysis['success_rate']:.2%}"
        assert (
            analysis["connection_times"]["mean"] < 2.0
        ), f"Mean connection time should be < 2s, got {analysis['connection_times']['mean']:.3f}s"
        assert (
            analysis["first_message_times"]["mean"] < 1.0
        ), f"Mean first message time should be < 1s, got {analysis['first_message_times']['mean']:.3f}s"

        # Log results for debugging
        logger.info(f"10 connections test results: {json.dumps(analysis, indent=2)}")

    def test_50_concurrent_connections(self, sse_tester):
        """Test 50 concurrent SSE connections (medium load)"""
        # Arrange
        num_connections = 50
        duration = 45  # 45 seconds

        # Act
        metrics = asyncio.run(sse_tester.test_concurrent_connections(num_connections, duration))
        analysis = sse_tester.analyze_metrics()

        # Assert
        assert len(metrics) == num_connections, f"Should have {num_connections} connection attempts"
        assert (
            analysis["success_rate"] >= 0.85
        ), f"Success rate should be >= 85%, got {analysis['success_rate']:.2%}"
        assert (
            analysis["connection_times"]["p95"] < 5.0
        ), f"95th percentile connection time should be < 5s, got {analysis['connection_times']['p95']:.3f}s"
        assert (
            analysis["first_message_times"]["p95"] < 2.0
        ), f"95th percentile first message time should be < 2s, got {analysis['first_message_times']['p95']:.3f}s"

        # Log results for debugging
        logger.info(f"50 connections test results: {json.dumps(analysis, indent=2)}")

    def test_100_concurrent_connections(self, sse_tester):
        """Test 100 concurrent SSE connections (target load)"""
        # Arrange
        num_connections = 100
        duration = 60  # 60 seconds

        # Act
        metrics = asyncio.run(sse_tester.test_concurrent_connections(num_connections, duration))
        analysis = sse_tester.analyze_metrics()

        # Assert - Contract requirements
        assert len(metrics) == num_connections, f"Should have {num_connections} connection attempts"
        assert (
            analysis["success_rate"] >= 0.95
        ), f"Success rate should be >= 95%, got {analysis['success_rate']:.2%}"

        # Performance requirements
        assert (
            analysis["first_message_times"]["mean"] < 1.0
        ), f"Mean heartbeat latency should be < 1s, got {analysis['first_message_times']['mean']:.3f}s"
        assert (
            analysis["latency_metrics"]["p95"] < 2.0
        ), f"95th percentile message latency should be < 2s, got {analysis['latency_metrics']['p95']:.3f}s"
        assert (
            analysis["connection_times"]["p95"] < 3.0
        ), f"95th percentile connection time should be < 3s, got {analysis['connection_times']['p95']:.3f}s"

        # Reliability requirements
        assert (
            analysis["error_rate"] < 0.05
        ), f"Error rate should be < 5%, got {analysis['error_rate']:.2%}"
        assert (
            analysis["message_metrics"]["avg_messages_per_connection"] > 10
        ), f"Should receive > 10 messages per connection on average"

        # Log results for debugging
        logger.info(f"100 connections test results: {json.dumps(analysis, indent=2)}")
        # 標準化スキーマでSSEメトリクスを出力（集計用）
        out_dir = Path("data/test_results")
        out_dir.mkdir(parents=True, exist_ok=True)
        sse_norm = {
            "drop_rate": round(1.0 - analysis.get("success_rate", 0.0), 4),
            "reconnection_ms": int(1000 * analysis.get("first_message_times", {}).get("p95", 0)),
            "message_delay_p95_ms": int(1000 * analysis.get("latency_metrics", {}).get("p95", 0)),
            "timestamp": datetime.now().isoformat() + "Z",
        }
        (out_dir / "sse_metrics_latest.json").write_text(
            json.dumps(sse_norm, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def test_200_concurrent_connections_stress(self, sse_tester):
        """Test 200 concurrent SSE connections (stress test)"""
        # Arrange
        num_connections = 200
        duration = 30  # Shorter duration for stress test

        # Act
        metrics = asyncio.run(sse_tester.test_concurrent_connections(num_connections, duration))
        analysis = sse_tester.analyze_metrics()

        # Assert - Relaxed requirements for stress test
        assert len(metrics) == num_connections, f"Should have {num_connections} connection attempts"
        assert (
            analysis["success_rate"] >= 0.80
        ), f"Success rate should be >= 80% under stress, got {analysis['success_rate']:.2%}"

        # Performance under stress
        assert (
            analysis["connection_times"]["p95"] < 10.0
        ), f"95th percentile connection time should be < 10s under stress, got {analysis['connection_times']['p95']:.3f}s"
        assert (
            analysis["first_message_times"]["p95"] < 5.0
        ), f"95th percentile first message time should be < 5s under stress, got {analysis['first_message_times']['p95']:.3f}s"

        # Log results for debugging
        logger.info(f"200 connections stress test results: {json.dumps(analysis, indent=2)}")

    def test_connection_recovery_after_disconnect(self, sse_tester):
        """Test SSE connection recovery after network interruption"""
        # This test simulates network interruption and recovery
        # In a real scenario, this would involve network manipulation

        # Arrange
        num_connections = 20
        initial_duration = 15
        recovery_duration = 15

        # Act - Initial connections
        logger.info("Starting initial connections...")
        initial_metrics = asyncio.run(
            sse_tester.test_concurrent_connections(num_connections, initial_duration)
        )
        initial_analysis = sse_tester.analyze_metrics()

        # Simulate brief pause (network interruption)
        time.sleep(2)

        # Act - Recovery connections
        logger.info("Testing recovery connections...")
        recovery_tester = SSELoadTester()
        recovery_metrics = asyncio.run(
            recovery_tester.test_concurrent_connections(num_connections, recovery_duration)
        )
        recovery_analysis = recovery_tester.analyze_metrics()

        # Assert - Recovery should be successful
        assert (
            initial_analysis["success_rate"] >= 0.90
        ), f"Initial success rate should be >= 90%, got {initial_analysis['success_rate']:.2%}"
        assert (
            recovery_analysis["success_rate"] >= 0.95
        ), f"Recovery success rate should be >= 95%, got {recovery_analysis['success_rate']:.2%}"

        # Recovery should be fast
        assert (
            recovery_analysis["connection_times"]["mean"] < 2.0
        ), f"Recovery connection time should be < 2s, got {recovery_analysis['connection_times']['mean']:.3f}s"

        # Log results
        logger.info(f"Initial connections: {initial_analysis['success_rate']:.2%} success rate")
        logger.info(f"Recovery connections: {recovery_analysis['success_rate']:.2%} success rate")

    def test_gradual_connection_ramp_up(self, sse_tester):
        """Test gradual ramp-up of SSE connections"""
        # Arrange
        ramp_steps = [10, 25, 50, 75, 100]
        duration_per_step = 20

        results = {}

        for step_connections in ramp_steps:
            logger.info(f"Testing {step_connections} connections...")

            # Act
            step_tester = SSELoadTester()
            metrics = asyncio.run(
                step_tester.test_concurrent_connections(step_connections, duration_per_step)
            )
            analysis = step_tester.analyze_metrics()

            results[step_connections] = analysis

            # Assert - Performance should degrade gracefully
            assert (
                analysis["success_rate"] >= 0.85
            ), f"Success rate at {step_connections} connections should be >= 85%, got {analysis['success_rate']:.2%}"

            # Brief pause between steps
            time.sleep(1)

        # Assert - Performance degradation should be gradual
        success_rates = [results[step]["success_rate"] for step in ramp_steps]
        connection_times = [results[step]["connection_times"]["mean"] for step in ramp_steps]

        # Success rate should not drop dramatically
        min_success_rate = min(success_rates)
        max_success_rate = max(success_rates)
        assert (
            max_success_rate - min_success_rate < 0.15
        ), f"Success rate variation should be < 15%, got {max_success_rate - min_success_rate:.2%}"

        # Log ramp-up results
        for step in ramp_steps:
            analysis = results[step]
            logger.info(
                f"{step} connections: {analysis['success_rate']:.2%} success, {analysis['connection_times']['mean']:.3f}s avg connection time"
            )

    def test_long_running_connections(self, sse_tester):
        """Test long-running SSE connections for stability"""
        # Arrange
        num_connections = 25
        duration = 120  # 2 minutes

        # Act
        metrics = asyncio.run(sse_tester.test_concurrent_connections(num_connections, duration))
        analysis = sse_tester.analyze_metrics()

        # Assert - Long-running connections should be stable
        assert (
            analysis["success_rate"] >= 0.90
        ), f"Long-running success rate should be >= 90%, got {analysis['success_rate']:.2%}"
        assert (
            analysis["message_metrics"]["avg_messages_per_connection"] > 50
        ), f"Should receive > 50 messages per connection over 2 minutes"

        # Latency should remain stable over time
        assert (
            analysis["latency_metrics"]["p95"] < 3.0
        ), f"95th percentile latency should remain < 3s, got {analysis['latency_metrics']['p95']:.3f}s"

        # Log results
        logger.info(
            f"Long-running test: {analysis['message_metrics']['total_messages']} total messages over {duration}s"
        )
        logger.info(
            f"Average {analysis['message_metrics']['avg_messages_per_connection']:.1f} messages per connection"
        )
        # 追加で標準化メトリクスを出力（上書き更新）
        out_dir = Path("data/test_results")
        out_dir.mkdir(parents=True, exist_ok=True)
        sse_norm = {
            "drop_rate": round(1.0 - analysis.get("success_rate", 0.0), 4),
            "reconnection_ms": int(1000 * analysis.get("first_message_times", {}).get("p95", 0)),
            "message_delay_p95_ms": int(1000 * analysis.get("latency_metrics", {}).get("p95", 0)),
            "timestamp": datetime.now().isoformat() + "Z",
        }
        (out_dir / "sse_metrics_latest.json").write_text(
            json.dumps(sse_norm, ensure_ascii=False, indent=2), encoding="utf-8"
        )


@pytest.mark.slow
@pytest.mark.performance
class TestSSEPerformanceBenchmarks:
    """Performance benchmark tests for SSE"""

    def test_single_connection_throughput(self):
        """Benchmark single SSE connection throughput"""
        tester = SSELoadTester()

        # Test single connection for 30 seconds
        metrics = asyncio.run(tester.test_concurrent_connections(1, 30))
        analysis = tester.analyze_metrics()

        # Calculate throughput
        if analysis["message_metrics"]["total_messages"] > 0:
            throughput = analysis["message_metrics"]["total_messages"] / 30  # messages per second

            # Assert minimum throughput
            assert (
                throughput >= 1.0
            ), f"Single connection throughput should be >= 1 msg/s, got {throughput:.2f} msg/s"

            logger.info(f"Single connection throughput: {throughput:.2f} messages/second")

    def test_connection_establishment_speed(self):
        """Benchmark connection establishment speed"""
        tester = SSELoadTester()

        # Test rapid connection establishment
        start_time = time.time()
        metrics = asyncio.run(
            tester.test_concurrent_connections(50, 5)
        )  # Short duration, focus on connection time
        total_time = time.time() - start_time

        analysis = tester.analyze_metrics()

        # Assert connection speed
        assert (
            analysis["connection_times"]["mean"] < 1.0
        ), f"Mean connection time should be < 1s, got {analysis['connection_times']['mean']:.3f}s"
        assert (
            total_time < 10.0
        ), f"Total time to establish 50 connections should be < 10s, got {total_time:.3f}s"

        logger.info(
            f"Connection establishment: {analysis['connection_times']['mean']:.3f}s mean, {total_time:.3f}s total for 50 connections"
        )

    def test_memory_usage_under_load(self):
        """Test memory usage under SSE load (requires psutil)"""
        try:
            import os

            import psutil
        except ImportError:
            pytest.skip("psutil not available for memory testing")

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        tester = SSELoadTester()

        # Run load test
        asyncio.run(tester.test_concurrent_connections(100, 30))

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        # Assert reasonable memory usage
        assert (
            memory_increase < 100
        ), f"Memory increase should be < 100MB, got {memory_increase:.1f}MB"

        logger.info(
            f"Memory usage: {initial_memory:.1f}MB -> {final_memory:.1f}MB (+{memory_increase:.1f}MB)"
        )


if __name__ == "__main__":
    # Run load tests directly
    import asyncio

    async def main():
        cfg = load_monitoring_config()

        # 環境変数による単一ターゲット上書き
        env_base = os.environ.get("SSE_BASE_URL")
        env_ep = os.environ.get("SSE_EVENT_ENDPOINT")
        if env_base or env_ep:
            targets = [
                {
                    "base_url": env_base or "http://127.0.0.1:5000",
                    "event_endpoint": env_ep or "/events",
                }
            ]
        else:
            targets = cfg.get(
                "sse_targets", [{"base_url": "http://127.0.0.1:5000", "event_endpoint": "/events"}]
            )

        concurrency = int(os.environ.get("SSE_CONCURRENCY", "100"))
        duration = int(os.environ.get("SSE_DURATION", "60"))

        # セッション共通設定
        connector = aiohttp.TCPConnector(limit=concurrency)
        timeout = aiohttp.ClientTimeout(total=8, sock_connect=3, sock_read=5)
        headers = {"Cache-Control": "no-cache", "Pragma": "no-cache", "Connection": "keep-alive"}

        combined_metrics: List[SSEMetrics] = []
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as session:
            reachable_targets = []
            for t in targets:
                base = t.get("base_url")
                ep = t.get("event_endpoint", "/events")
                ok = await precheck_sse(session, base, ep)
                if not ok:
                    print(f"Skip target {base}{ep}: unreachable")
                    continue
                reachable_targets.append(t)
                tester = SSELoadTester(base_url=base, event_endpoint=ep)
                print(
                    f"Running SSE load: base={base}, endpoint={ep}, concurrency={concurrency}, duration={duration}s"
                )
                metrics = await tester.test_concurrent_connections(concurrency, duration)
                combined_metrics.extend(metrics)

        # 解析（複合メトリクス）
        aggregator = SSELoadTester(base_url="aggregate", event_endpoint="")
        aggregator.metrics = combined_metrics
        analysis = aggregator.analyze_metrics()

        # メトリクス保存（標準化スキーマと詳細）
        out_dir = Path("data/test_results")
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload = {
            "meta": {
                "source": "test_sse_load.py",
                "timestamp": timestamp,
                "targets": reachable_targets,
            },
            "analysis": analysis,
        }
        (out_dir / f"sse_load_{timestamp}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        sse_norm = {
            "drop_rate": round(1.0 - analysis.get("success_rate", 0.0), 4),
            "reconnection_ms": int(1000 * analysis.get("first_message_times", {}).get("p95", 0)),
            "message_delay_p95_ms": int(1000 * analysis.get("latency_metrics", {}).get("p95", 0)),
            "timestamp": datetime.now().isoformat() + "Z",
        }
        (out_dir / "sse_metrics_latest.json").write_text(
            json.dumps(sse_norm, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # コンソール出力
        print("\nSSE Load Test Summary (multi-target):")
        print(f"Targets: {reachable_targets}")
        print(f"Total Connections: {analysis.get('total_connections', 0)}")
        print(f"Success Rate: {analysis.get('success_rate', 0.0):.2%}")
        print(f"Mean First Message: {analysis.get('first_message_times', {}).get('mean', 0):.3f}s")
        print(f"P95 Latency: {analysis.get('latency_metrics', {}).get('p95', 0):.3f}s")
        print(f"Error Rate: {analysis.get('error_rate', 0.0):.2%}")

    asyncio.run(main())
