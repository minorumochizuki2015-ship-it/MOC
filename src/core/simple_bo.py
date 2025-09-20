"""
SimpleBO (Simple Bayesian Optimization) - 簡易ベイジアン最適化器
M4実装: 統治核AIの進化最適化のためのフック機能
"""

import json
import math
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class SimpleBO:
    """簡易ベイジアン最適化器（フック機能のみ）"""

    def __init__(self, log_dir: str = "data/logs/current"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.trials_file = self.log_dir / "bo_trials.jsonl"
        self.results_file = self.log_dir / "bo_results.jsonl"

        # 最適化パラメータ
        self.param_bounds = {
            "learning_rate": (0.001, 0.1),
            "batch_size": (16, 128),
            "temperature": (0.1, 2.0),
            "max_tokens": (100, 1000),
        }

        # 履歴管理
        self.trial_history: List[Dict[str, Any]] = []
        self.best_result: Optional[Dict[str, Any]] = None

    def suggest(self, n_suggestions: int = 1) -> List[Dict[str, float]]:
        """
        次の試行パラメータを提案

        Args:
            n_suggestions: 提案するパラメータセット数

        Returns:
            提案されたパラメータのリスト
        """
        suggestions = []

        for _ in range(n_suggestions):
            # 簡易ランダムサンプリング（実際のBOではGPを使用）
            params = {}
            for param_name, (min_val, max_val) in self.param_bounds.items():
                if param_name in ["batch_size", "max_tokens"]:
                    # 整数パラメータ
                    params[param_name] = random.randint(int(min_val), int(max_val))
                else:
                    # 浮動小数点パラメータ
                    params[param_name] = random.uniform(min_val, max_val)

            suggestions.append(params)

        return suggestions

    def observe(
        self,
        params: Dict[str, float],
        result: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        試行結果を記録

        Args:
            params: 試行したパラメータ
            result: 結果（スコア）
            metadata: 追加メタデータ
        """
        trial_record = {
            "timestamp": time.time(),
            "params": params,
            "result": result,
            "metadata": metadata or {},
            "trial_id": len(self.trial_history) + 1,
        }

        # 履歴に追加
        self.trial_history.append(trial_record)

        # 最良結果を更新
        if self.best_result is None or result > self.best_result["result"]:
            self.best_result = trial_record

        # ファイルに保存
        self._save_trial(trial_record)
        self._save_results()

    def get_best_params(self) -> Optional[Dict[str, float]]:
        """最良のパラメータを取得"""
        if self.best_result:
            return self.best_result["params"]
        return None

    def get_best_result(self) -> Optional[float]:
        """最良の結果を取得"""
        if self.best_result:
            return self.best_result["result"]
        return None

    def get_trial_history(self) -> List[Dict[str, Any]]:
        """試行履歴を取得"""
        return self.trial_history.copy()

    def _save_trial(self, trial_record: Dict[str, Any]) -> None:
        """試行記録をファイルに保存"""
        try:
            with open(self.trials_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(trial_record) + "\n")
        except Exception as e:
            print(f"SimpleBO: 試行記録保存エラー: {e}")

    def _save_results(self) -> None:
        """結果サマリーをファイルに保存"""
        try:
            summary = {
                "timestamp": time.time(),
                "total_trials": len(self.trial_history),
                "best_result": self.best_result,
                "param_bounds": self.param_bounds,
            }

            with open(self.results_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(summary) + "\n")
        except Exception as e:
            print(f"SimpleBO: 結果保存エラー: {e}")

    def load_history(self) -> None:
        """保存された履歴を読み込み"""
        try:
            if self.trials_file.exists():
                with open(self.trials_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            trial = json.loads(line.strip())
                            self.trial_history.append(trial)

                # 最良結果を更新
                if self.trial_history:
                    self.best_result = max(
                        self.trial_history, key=lambda x: x["result"]
                    )
        except Exception as e:
            print(f"SimpleBO: 履歴読み込みエラー: {e}")

    def reset(self) -> None:
        """最適化器をリセット"""
        self.trial_history.clear()
        self.best_result = None

        # ファイルをクリア
        try:
            if self.trials_file.exists():
                self.trials_file.unlink()
            if self.results_file.exists():
                self.results_file.unlink()
        except Exception as e:
            print(f"SimpleBO: リセットエラー: {e}")


# グローバルインスタンス（フック用）
_global_bo: Optional[SimpleBO] = None


def get_global_bo() -> SimpleBO:
    """グローバルSimpleBOインスタンスを取得"""
    global _global_bo
    if _global_bo is None:
        _global_bo = SimpleBO()
        _global_bo.load_history()
    return _global_bo


def suggest_params(n_suggestions: int = 1) -> List[Dict[str, float]]:
    """パラメータ提案のフック関数"""
    bo = get_global_bo()
    return bo.suggest(n_suggestions)


def record_trial(
    params: Dict[str, float], result: float, metadata: Optional[Dict[str, Any]] = None
) -> None:
    """試行記録のフック関数"""
    bo = get_global_bo()
    bo.observe(params, result, metadata)


def get_best_params() -> Optional[Dict[str, float]]:
    """最良パラメータ取得のフック関数"""
    bo = get_global_bo()
    return bo.get_best_params()


def get_best_result() -> Optional[float]:
    """最良結果取得のフック関数"""
    bo = get_global_bo()
    return bo.get_best_result()
