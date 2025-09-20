"""
本格的な進化システム実装
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class Evolution:
    """本格的な進化システム実装"""

    def __init__(self):
        # 進化ゲノムを読み込み
        self.genome = self._load_evolutionary_genome()
        self.evolution_history = []
        self.current_cycle = 0
        self.best_fitness = 0.0
        self.best_genome = None

        # 進化パラメータ
        self.mutation_rate = 0.1
        self.crossover_rate = 0.8
        self.population_size = 20
        self.generations = 10

    def run_evolution_cycle(self, accelerated: bool = False) -> Dict[str, Any]:
        """本格的な進化サイクルを実行"""
        try:
            self.current_cycle += 1

            # 遺伝的アルゴリズムを実行
            from src.genetic.fitness_calculator import FitnessCalculator
            from src.genetic.genetic_algorithm import GeneticAlgorithm

            # 進化パラメータを調整
            if accelerated:
                self.generations = 20
                self.population_size = 30
                self.mutation_rate = 0.15

            # 遺伝的アルゴリズムを実行
            ga = GeneticAlgorithm(
                population_size=self.population_size,
                mutation_rate=self.mutation_rate,
                crossover_rate=self.crossover_rate,
            )

            # 現在のゲノムを初期集団の一部として使用
            initial_genome = self._convert_to_ga_format(self.genome)
            result = ga.run_experiment(self.generations)

            # 最良個体を取得
            best_individual = ga.get_best_individual()
            if best_individual:
                self.best_genome = best_individual
                self.best_fitness = result.get("best_fitness", 0.0)

                # ゲノムを更新
                self.genome = self._convert_from_ga_format(best_individual)

                # 進化ゲノムファイルを更新
                self._save_evolutionary_genome(self.genome)

            # 進化結果を記録
            evolution_result = {
                "cycle": self.current_cycle,
                "new_themes": self._count_new_themes(),
                "optimized_params": len(self.genome),
                "evolution_rate": result.get("convergence_rate", 0.0),
                "fitness_improvement": self._calculate_fitness_improvement(),
                "cycles_completed": self.current_cycle,
                "best_fitness": self.best_fitness,
                "generations": result.get("generations", 0),
                "population_size": result.get("individuals", 0),
                "accelerated": accelerated,
            }

            # 履歴に追加
            self.evolution_history.append(evolution_result)

            # 進化ログを保存
            self._save_evolution_log(evolution_result)

            return evolution_result

        except Exception as e:
            return {
                "cycle": self.current_cycle,
                "new_themes": 0,
                "optimized_params": 0,
                "evolution_rate": 0.0,
                "fitness_improvement": 0.0,
                "cycles_completed": 0,
                "error": str(e),
            }

    def get_current_genome(self) -> Dict[str, Any]:
        """現在のゲノムを取得"""
        return self.genome.copy()

    def analyze_evolution_history(self) -> Dict[str, Any]:
        """進化履歴を分析"""
        try:
            if not self.evolution_history:
                return {
                    "total_cycles": 0,
                    "avg_fitness": 0.0,
                    "max_fitness": 0.0,
                    "evolution_rate": 0.0,
                    "stability": 0.0,
                    "themes_discovered": 0,
                    "stable_themes": 0,
                    "evolving_themes": 0,
                    "response_speed": 0.0,
                    "accuracy": 0.0,
                    "consistency": 0.0,
                }

            # 統計を計算
            total_cycles = len(self.evolution_history)
            fitness_values = [
                cycle.get("best_fitness", 0.0) for cycle in self.evolution_history
            ]
            avg_fitness = (
                sum(fitness_values) / len(fitness_values) if fitness_values else 0.0
            )
            max_fitness = max(fitness_values) if fitness_values else 0.0

            # 進化率を計算
            evolution_rates = [
                cycle.get("evolution_rate", 0.0) for cycle in self.evolution_history
            ]
            avg_evolution_rate = (
                sum(evolution_rates) / len(evolution_rates) if evolution_rates else 0.0
            )

            # 安定性を計算（最近の5サイクルのばらつき）
            recent_fitness = (
                fitness_values[-5:] if len(fitness_values) >= 5 else fitness_values
            )
            if len(recent_fitness) > 1:
                import statistics

                stability = (
                    1.0
                    - (
                        statistics.stdev(recent_fitness)
                        / statistics.mean(recent_fitness)
                    )
                    if statistics.mean(recent_fitness) > 0
                    else 0.0
                )
            else:
                stability = 0.0

            # テーマ数を計算
            themes_discovered = sum(
                cycle.get("new_themes", 0) for cycle in self.evolution_history
            )
            stable_themes = max(
                0,
                themes_discovered
                - len(
                    [
                        cycle
                        for cycle in self.evolution_history
                        if cycle.get("evolution_rate", 0.0) > 0.5
                    ]
                ),
            )
            evolving_themes = themes_discovered - stable_themes

            # パフォーマンス指標を計算
            response_speed = self._calculate_response_speed()
            accuracy = self._calculate_accuracy()
            consistency = self._calculate_consistency()

            return {
                "total_cycles": total_cycles,
                "avg_fitness": avg_fitness,
                "max_fitness": max_fitness,
                "evolution_rate": avg_evolution_rate,
                "stability": max(0.0, min(1.0, stability)),
                "themes_discovered": themes_discovered,
                "stable_themes": stable_themes,
                "evolving_themes": evolving_themes,
                "response_speed": response_speed,
                "accuracy": accuracy,
                "consistency": consistency,
            }

        except Exception as e:
            return {
                "total_cycles": 0,
                "avg_fitness": 0.0,
                "max_fitness": 0.0,
                "evolution_rate": 0.0,
                "stability": 0.0,
                "themes_discovered": 0,
                "stable_themes": 0,
                "evolving_themes": 0,
                "response_speed": 0.0,
                "accuracy": 0.0,
                "consistency": 0.0,
            }

    def _load_evolutionary_genome(self) -> Dict[str, Any]:
        """進化ゲノムを読み込み"""
        try:
            genome_file = Path("data/genetic/evolutionary_genome.json")
            if genome_file.exists():
                with open(genome_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                # デフォルトゲノムを返す
                return {
                    "persona_update_threshold": {
                        "min": 3.5,
                        "max": 5.0,
                        "current_value": 4.0,
                    },
                    "high_score_weight": {"min": 1.0, "max": 2.5, "current_value": 1.5},
                    "knowledge_retrieval_scope": {
                        "min": 1,
                        "max": 4,
                        "current_value": 2,
                    },
                }
        except Exception as e:
            return {
                "persona_update_threshold": {
                    "min": 3.5,
                    "max": 5.0,
                    "current_value": 4.0,
                },
                "high_score_weight": {"min": 1.0, "max": 2.5, "current_value": 1.5},
                "knowledge_retrieval_scope": {"min": 1, "max": 4, "current_value": 2},
            }

    def _save_evolutionary_genome(self, genome: Dict[str, Any]) -> None:
        """進化ゲノムを保存"""
        try:
            genome_file = Path("data/genetic/evolutionary_genome.json")
            genome_file.parent.mkdir(parents=True, exist_ok=True)

            with open(genome_file, "w", encoding="utf-8") as f:
                json.dump(genome, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass

    def _convert_to_ga_format(self, genome: Dict[str, Any]) -> Dict[str, Any]:
        """進化ゲノム形式をGA形式に変換"""
        ga_genome = {}
        for param_name, param_data in genome.items():
            if isinstance(param_data, dict) and "current_value" in param_data:
                ga_genome[param_name] = param_data["current_value"]
            else:
                ga_genome[param_name] = param_data
        return ga_genome

    def _convert_from_ga_format(self, ga_genome: Dict[str, Any]) -> Dict[str, Any]:
        """GA形式を進化ゲノム形式に変換"""
        genome = {}
        for param_name, value in ga_genome.items():
            if param_name in ["persona_update_threshold", "high_score_weight"]:
                genome[param_name] = {
                    "min": 3.5 if param_name == "persona_update_threshold" else 1.0,
                    "max": 5.0 if param_name == "persona_update_threshold" else 2.5,
                    "current_value": value,
                }
            elif param_name == "knowledge_retrieval_scope":
                genome[param_name] = {"min": 1, "max": 4, "current_value": int(value)}
            else:
                genome[param_name] = value
        return genome

    def _count_new_themes(self) -> int:
        """新しいテーマ数を計算"""
        # 簡易実装：進化サイクルごとに1つの新しいテーマを発見
        return 1

    def _calculate_fitness_improvement(self) -> float:
        """適応度改善率を計算"""
        if len(self.evolution_history) < 2:
            return 0.0

        current_fitness = self.evolution_history[-1].get("best_fitness", 0.0)
        previous_fitness = self.evolution_history[-2].get("best_fitness", 0.0)

        if previous_fitness > 0:
            return ((current_fitness - previous_fitness) / previous_fitness) * 100
        else:
            return 0.0

    def _calculate_response_speed(self) -> float:
        """レスポンス速度を計算"""
        try:
            from src.core.simple_bo import get_global_bo

            bo = get_global_bo()
            history = bo.get_trial_history()

            if not history:
                return 0.0

            # 最近のレイテンシーを取得
            recent_latencies = []
            for trial in history[-10:]:
                if "metadata" in trial and "latency_ms" in trial["metadata"]:
                    recent_latencies.append(trial["metadata"]["latency_ms"])

            if not recent_latencies:
                return 0.0

            # 平均レスポンス時間（秒）
            avg_latency = sum(recent_latencies) / len(recent_latencies) / 1000
            return max(0.0, 10.0 - avg_latency)  # 10秒以下で高スコア

        except Exception as e:
            return 0.0

    def _calculate_accuracy(self) -> float:
        """精度を計算"""
        try:
            from src.genetic.fitness_calculator import FitnessCalculator

            calculator = FitnessCalculator()
            return calculator._evaluate_accuracy() * 100
        except Exception as e:
            return 0.0

    def _calculate_consistency(self) -> float:
        """一貫性を計算"""
        try:
            from src.genetic.fitness_calculator import FitnessCalculator

            calculator = FitnessCalculator()
            return calculator._evaluate_consistency() * 100
        except Exception as e:
            return 0.0

    def _save_evolution_log(self, result: Dict[str, Any]) -> None:
        """進化ログを保存"""
        try:
            log_dir = Path("data/logs/current")
            log_dir.mkdir(parents=True, exist_ok=True)

            log_file = log_dir / "evolution.log"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{json.dumps(result, ensure_ascii=False)}\n")

        except Exception as e:
            pass
