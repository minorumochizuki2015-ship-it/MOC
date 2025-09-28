#!/usr/bin/env python3
"""パフォーマンス最適化モジュール"""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Callable
import hashlib
import json
from collections import OrderedDict
from datetime import datetime, timedelta


class AdvancedCache:
    """高性能キャッシュシステム"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache = OrderedDict()
        self._timestamps = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """キャッシュから値を取得"""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            # TTL チェック
            if self._is_expired(key):
                del self._cache[key]
                del self._timestamps[key]
                self._misses += 1
                return None
            
            # LRU更新
            self._cache.move_to_end(key)
            self._hits += 1
            return self._cache[key]
    
    def set(self, key: str, value: Any) -> None:
        """キャッシュに値を設定"""
        with self._lock:
            # サイズ制限チェック
            if len(self._cache) >= self.max_size and key not in self._cache:
                # 最古のエントリを削除
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                del self._timestamps[oldest_key]
            
            self._cache[key] = value
            self._timestamps[key] = datetime.now()
            self._cache.move_to_end(key)
    
    def _is_expired(self, key: str) -> bool:
        """TTL期限切れチェック"""
        if key not in self._timestamps:
            return True
        
        age = datetime.now() - self._timestamps[key]
        return age.total_seconds() > self.ttl_seconds
    
    def get_stats(self) -> Dict[str, Any]:
        """キャッシュ統計を取得"""
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "ttl_seconds": self.ttl_seconds
            }


class AsyncProcessor:
    """非同期処理管理"""
    
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.loop = None
        self._running_tasks = {}
    
    async def process_async(self, func: Callable, *args, **kwargs) -> Any:
        """非同期でタスクを実行"""
        if self.loop is None:
            self.loop = asyncio.get_event_loop()
        
        future = self.loop.run_in_executor(self.executor, func, *args, **kwargs)
        return await future
    
    def submit_background_task(self, task_id: str, func: Callable, *args, **kwargs) -> None:
        """バックグラウンドタスクを投入"""
        future = self.executor.submit(func, *args, **kwargs)
        self._running_tasks[task_id] = future
    
    def get_task_result(self, task_id: str, timeout: float = 0.1) -> Optional[Any]:
        """バックグラウンドタスクの結果を取得"""
        if task_id not in self._running_tasks:
            return None
        
        future = self._running_tasks[task_id]
        try:
            result = future.result(timeout=timeout)
            del self._running_tasks[task_id]
            return result
        except Exception:
            return None


class PerformanceOptimizer:
    """統合パフォーマンス最適化"""
    
    def __init__(self):
        self.cache = AdvancedCache(max_size=2000, ttl_seconds=1800)  # 30分TTL
        self.async_processor = AsyncProcessor(max_workers=6)
        self.metrics = {
            "request_count": 0,
            "total_response_time": 0.0,
            "cache_saves": 0,
            "async_tasks": 0
        }
        self._metrics_lock = threading.Lock()
    
    def optimize_request(self, request_func: Callable, cache_key: str, *args, **kwargs) -> Any:
        """リクエストを最適化して実行"""
        start_time = time.time()
        
        # キャッシュチェック
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            self._update_metrics(time.time() - start_time, cache_hit=True)
            return cached_result
        
        # リクエスト実行
        result = request_func(*args, **kwargs)
        
        # キャッシュに保存
        self.cache.set(cache_key, result)
        
        self._update_metrics(time.time() - start_time, cache_hit=False)
        return result
    
    def _update_metrics(self, response_time: float, cache_hit: bool = False) -> None:
        """メトリクス更新"""
        with self._metrics_lock:
            self.metrics["request_count"] += 1
            self.metrics["total_response_time"] += response_time
            if cache_hit:
                self.metrics["cache_saves"] += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """パフォーマンスレポートを生成"""
        with self._metrics_lock:
            avg_response_time = (
                self.metrics["total_response_time"] / self.metrics["request_count"]
                if self.metrics["request_count"] > 0 else 0
            )
            
            cache_stats = self.cache.get_stats()
            
            return {
                "performance": {
                    "avg_response_time": f"{avg_response_time:.3f}s",
                    "total_requests": self.metrics["request_count"],
                    "cache_saves": self.metrics["cache_saves"],
                    "async_tasks": self.metrics["async_tasks"]
                },
                "cache": cache_stats,
                "recommendations": self._generate_recommendations(avg_response_time, cache_stats)
            }
    
    def _generate_recommendations(self, avg_response_time: float, cache_stats: Dict) -> List[str]:
        """パフォーマンス改善推奨事項"""
        recommendations = []
        
        if avg_response_time > 1.0:
            recommendations.append("応答時間が長いです。キャッシュ活用を増やしてください。")
        
        if cache_stats["hit_rate"] < 0.5:
            recommendations.append("キャッシュヒット率が低いです。TTL設定を見直してください。")
        
        if cache_stats["size"] > cache_stats["max_size"] * 0.9:
            recommendations.append("キャッシュサイズが上限に近づいています。")
        
        if not recommendations:
            recommendations.append("パフォーマンスは良好です。")
        
        return recommendations


# グローバルインスタンス
performance_optimizer = PerformanceOptimizer()