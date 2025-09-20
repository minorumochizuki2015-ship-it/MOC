#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M6: 観測・指標・進化器フック - 計測と将来の自動最適化の土台
latency.jsonl継続記録、auto_evolve.SimpleBOのsuggest()をUIで取得
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.simple_bo import SimpleBO, get_global_bo


class ObservationHooks:
    """観測・指標・進化器フック（M6）"""
    
    def __init__(self, log_dir: str = "data/logs/current"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.latency_file = self.log_dir / "latency.jsonl"
        self.bo_trials_file = self.log_dir / "bo_trials.jsonl"
        self.evolution_file = self.log_dir / "evolution_graph.jsonl"
        
        # SimpleBOインスタンス
        self.bo = get_global_bo()
        
    def record_latency(self, operation: str, latency_ms: float, metadata: Dict[str, Any] = None):
        """レイテンシーを記録（M6）"""
        try:
            entry = {
                "timestamp": time.time(),
                "operation": operation,
                "latency_ms": latency_ms,
                "metadata": metadata or {}
            }
            
            with open(self.latency_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                
        except Exception as e:
            print(f"レイテンシー記録エラー: {e}")
    
    def get_evolution_suggestions(self, n_suggestions: int = 1) -> List[Dict[str, float]]:
        """進化器からパラメータ提案を取得（M6）"""
        try:
            return self.bo.suggest(n_suggestions)
        except Exception as e:
            print(f"進化器提案取得エラー: {e}")
            return []
    
    def record_evolution_trial(self, params: Dict[str, float], result: float, metadata: Dict[str, Any] = None):
        """進化試行を記録（M6）"""
        try:
            self.bo.observe(params, result, metadata)
            
            # 追加の進化ログ
            entry = {
                "timestamp": time.time(),
                "params": params,
                "result": result,
                "metadata": metadata or {}
            }
            
            with open(self.bo_trials_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                
        except Exception as e:
            print(f"進化試行記録エラー: {e}")
    
    def get_latency_stats(self, limit: int = 100) -> Dict[str, Any]:
        """レイテンシー統計を取得（M6）"""
        try:
            if not self.latency_file.exists():
                return {"error": "レイテンシーファイルが存在しません"}
            
            latencies = []
            with open(self.latency_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        latencies.append(entry)
                    except json.JSONDecodeError:
                        continue
            
            if not latencies:
                return {"error": "レイテンシーデータがありません"}
            
            # 最新のlimit件に制限
            recent_latencies = latencies[-limit:]
            
            # 統計計算
            latency_values = [entry["latency_ms"] for entry in recent_latencies]
            avg_latency = sum(latency_values) / len(latency_values)
            min_latency = min(latency_values)
            max_latency = max(latency_values)
            
            return {
                "count": len(recent_latencies),
                "avg_latency_ms": avg_latency,
                "min_latency_ms": min_latency,
                "max_latency_ms": max_latency,
                "recent_operations": [entry["operation"] for entry in recent_latencies[-10:]]
            }
            
        except Exception as e:
            return {"error": f"レイテンシー統計取得エラー: {e}"}
    
    def get_evolution_stats(self) -> Dict[str, Any]:
        """進化統計を取得（M6）"""
        try:
            if not self.bo_trials_file.exists():
                return {"error": "進化試行ファイルが存在しません"}
            
            trials = []
            with open(self.bo_trials_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        trials.append(entry)
                    except json.JSONDecodeError:
                        continue
            
            if not trials:
                return {"error": "進化試行データがありません"}
            
            # 統計計算
            results = [trial["result"] for trial in trials]
            best_result = max(results)
            worst_result = min(results)
            avg_result = sum(results) / len(results)
            
            return {
                "total_trials": len(trials),
                "best_result": best_result,
                "worst_result": worst_result,
                "avg_result": avg_result,
                "improvement": best_result - worst_result if len(trials) > 1 else 0
            }
            
        except Exception as e:
            return {"error": f"進化統計取得エラー: {e}"}
    
    def generate_evolution_graph_data(self) -> Dict[str, Any]:
        """進化グラフ用データを生成（M6）"""
        try:
            latency_stats = self.get_latency_stats()
            evolution_stats = self.get_evolution_stats()
            
            graph_data = {
                "timestamp": time.time(),
                "latency_stats": latency_stats,
                "evolution_stats": evolution_stats,
                "suggestions": self.get_evolution_suggestions(3)
            }
            
            # 進化グラフファイルに記録
            with open(self.evolution_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(graph_data, ensure_ascii=False) + "\n")
            
            return graph_data
            
        except Exception as e:
            return {"error": f"進化グラフデータ生成エラー: {e}"}


# グローバルインスタンス
observation_hooks = ObservationHooks()
