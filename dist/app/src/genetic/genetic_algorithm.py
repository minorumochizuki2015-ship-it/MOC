"""
本格的な遺伝的アルゴリズム実装
"""

import json
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class GeneticAlgorithm:
    """本格的な遺伝的アルゴリズム実装"""

    def __init__(
        self,
        population_size: int = 20,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.8,
    ):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.generation_count = 0
        self.best_individual = None
        self.best_fitness = -float("inf")
        self.fitness_history = []

        # パラメータの範囲定義
        self.param_bounds = {
            "learning_rate": (0.001, 0.1),
            "temperature": (0.1, 2.0),
            "max_tokens": (1000, 4000),
            "timeout": (60, 300),
            "persona_update_threshold": (3.5, 5.0),
            "high_score_weight": (1.0, 2.5),
            "knowledge_retrieval_scope": (1, 4),
        }

    def run_experiment(self, generations: int = 10) -> Dict[str, Any]:
        """遺伝的実験を実行"""
        try:
            # 初期集団を生成
            population = self._initialize_population()

            # 各世代で進化を実行
            for generation in range(generations):
                # 適応度を計算
                fitness_scores = self._evaluate_population(population)

                # 最良個体を更新
                best_idx = max(
                    range(len(fitness_scores)), key=lambda i: fitness_scores[i]
                )
                if fitness_scores[best_idx] > self.best_fitness:
                    self.best_fitness = fitness_scores[best_idx]
                    self.best_individual = population[best_idx].copy()

                # 履歴を記録
                self.fitness_history.append(
                    {
                        "generation": generation,
                        "best_fitness": self.best_fitness,
                        "avg_fitness": sum(fitness_scores) / len(fitness_scores),
                        "population_size": len(population),
                    }
                )

                # 次世代を生成
                population = self._evolve_population(population, fitness_scores)
                self.generation_count += 1

            # 最終結果を返す
            return {
                "generations": generations,
                "individuals": self.population_size,
                "best_fitness": self.best_fitness,
                "avg_fitness": (
                    sum(self.fitness_history[-1]["avg_fitness"] for _ in range(1))
                    if self.fitness_history
                    else 0.0
                ),
                "convergence_rate": self._calculate_convergence_rate(),
                "best_individual": self.best_individual,
                "fitness_history": self.fitness_history,
            }

        except Exception as e:
            return {
                "generations": 0,
                "individuals": 0,
                "best_fitness": 0.0,
                "avg_fitness": 0.0,
                "convergence_rate": 0.0,
                "error": str(e),
            }

    def run_ga_cycle(
        self,
        genome_definition: Dict[str, Any],
        population_size: int = 20,
        generations: int = 10,
    ) -> Tuple[Dict[str, Any], float]:
        """遺伝的アルゴリズムサイクルを実行（UI互換性）"""
        try:
            # パラメータを更新
            self.population_size = population_size

            # 進化実験を実行
            result = self.run_experiment(generations)

            # 最良個体を返す
            if self.best_individual:
                return self.best_individual, self.best_fitness
            else:
                # デフォルト個体を返す
                return genome_definition, 0.5

        except Exception as e:
            return genome_definition, 0.0

    def _initialize_population(self) -> List[Dict[str, Any]]:
        """初期集団を生成"""
        population = []
        for _ in range(self.population_size):
            individual = self._create_individual()
            population.append(individual)
        return population

    def _create_individual(self) -> Dict[str, Any]:
        """個体を作成"""
        individual = {}
        for param_name, (min_val, max_val) in self.param_bounds.items():
            if param_name in ["max_tokens", "knowledge_retrieval_scope"]:
                # 整数パラメータ
                individual[param_name] = random.randint(int(min_val), int(max_val))
            else:
                # 浮動小数点パラメータ
                individual[param_name] = random.uniform(min_val, max_val)
        return individual

    def _evaluate_population(self, population: List[Dict[str, Any]]) -> List[float]:
        """集団の適応度を評価"""
        fitness_scores = []
        for individual in population:
            try:
                from src.genetic.fitness_calculator import FitnessCalculator

                calculator = FitnessCalculator()
                fitness = calculator.calculate_fitness(individual)
                fitness_scores.append(fitness)
            except Exception as e:
                fitness_scores.append(0.0)
        return fitness_scores

    def _evolve_population(
        self, population: List[Dict[str, Any]], fitness_scores: List[float]
    ) -> List[Dict[str, Any]]:
        """集団を進化させる"""
        new_population = []

        # エリート選択（最良の10%を保持）
        elite_size = max(1, self.population_size // 10)
        elite_indices = sorted(
            range(len(fitness_scores)), key=lambda i: fitness_scores[i], reverse=True
        )[:elite_size]
        for idx in elite_indices:
            new_population.append(population[idx].copy())

        # 残りを交叉と突然変異で生成
        while len(new_population) < self.population_size:
            # 親を選択
            parent1 = self._tournament_selection(population, fitness_scores)
            parent2 = self._tournament_selection(population, fitness_scores)

            # 交叉
            if random.random() < self.crossover_rate:
                child = self._crossover(parent1, parent2)
            else:
                child = parent1.copy()

            # 突然変異
            if random.random() < self.mutation_rate:
                child = self._mutate(child)

            new_population.append(child)

        return new_population

    def _tournament_selection(
        self,
        population: List[Dict[str, Any]],
        fitness_scores: List[float],
        tournament_size: int = 3,
    ) -> Dict[str, Any]:
        """トーナメント選択"""
        tournament_indices = random.sample(
            range(len(population)), min(tournament_size, len(population))
        )
        tournament_fitness = [fitness_scores[i] for i in tournament_indices]
        winner_idx = tournament_indices[
            max(range(len(tournament_fitness)), key=lambda i: tournament_fitness[i])
        ]
        return population[winner_idx]

    def _crossover(
        self, parent1: Dict[str, Any], parent2: Dict[str, Any]
    ) -> Dict[str, Any]:
        """交叉操作"""
        child = {}
        for key in parent1:
            if key in parent2:
                if random.random() < 0.5:
                    child[key] = parent1[key]
                else:
                    child[key] = parent2[key]
            else:
                child[key] = parent1[key]
        return child

    def _mutate(self, individual: Dict[str, Any]) -> Dict[str, Any]:
        """突然変異操作"""
        mutated = individual.copy()
        for param_name, value in mutated.items():
            if param_name in self.param_bounds:
                min_val, max_val = self.param_bounds[param_name]
                if random.random() < 0.1:  # 10%の確率で突然変異
                    if param_name in ["max_tokens", "knowledge_retrieval_scope"]:
                        # 整数パラメータ
                        mutated[param_name] = random.randint(int(min_val), int(max_val))
                    else:
                        # 浮動小数点パラメータ
                        mutated[param_name] = random.uniform(min_val, max_val)
        return mutated

    def _calculate_convergence_rate(self) -> float:
        """収束率を計算"""
        if len(self.fitness_history) < 2:
            return 0.0

        # 最後の5世代の改善率を計算
        recent_generations = self.fitness_history[-5:]
        if len(recent_generations) < 2:
            return 0.0

        improvements = 0
        for i in range(1, len(recent_generations)):
            if (
                recent_generations[i]["best_fitness"]
                > recent_generations[i - 1]["best_fitness"]
            ):
                improvements += 1

        return improvements / (len(recent_generations) - 1)

    def get_best_individual(self) -> Optional[Dict[str, Any]]:
        """最良個体を取得"""
        return self.best_individual

    def get_fitness_history(self) -> List[Dict[str, Any]]:
        """適応度履歴を取得"""
        return self.fitness_history.copy()

    def save_results(self, filepath: str) -> None:
        """結果をファイルに保存"""
        try:
            results = {
                "best_individual": self.best_individual,
                "best_fitness": self.best_fitness,
                "generation_count": self.generation_count,
                "fitness_history": self.fitness_history,
                "timestamp": time.time(),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"結果保存エラー: {e}")


# 後方互換性のための関数
def run_ga_cycle(
    genome_definition: Dict[str, Any], population_size: int = 20, generations: int = 10
) -> Tuple[Dict[str, Any], float]:
    """遺伝的アルゴリズムサイクルを実行（関数版）"""
    ga = GeneticAlgorithm(population_size=population_size)
    return ga.run_ga_cycle(genome_definition, population_size, generations)
