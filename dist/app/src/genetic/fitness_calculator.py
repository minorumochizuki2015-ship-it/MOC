"""
本格的な適応度計算器
"""

import os
import statistics
from typing import Any, Dict


class FitnessCalculator:
    """本格的な適応度計算器"""

    def __init__(self):
        self.base_fitness = 0.5
        self.performance_history = []
        self.latency_weights = {
            "response_time": 0.3,
            "accuracy": 0.4,
            "consistency": 0.2,
            "efficiency": 0.1,
        }

    def calculate_fitness(self, genome: Dict[str, Any]) -> float:
        """実際のパフォーマンス指標に基づく適応度を計算"""
        try:
            # 基本適応度
            fitness = self.base_fitness

            # パフォーマンス履歴から実際の指標を取得
            performance_score = self._calculate_performance_score()

            # ゲノムパラメータの最適性を評価
            genome_score = self._evaluate_genome_parameters(genome)

            # 重み付きスコア計算
            fitness = (
                performance_score * 0.7  # 実際のパフォーマンス70%
                + genome_score * 0.3  # パラメータ最適性30%
            )

            # 0.0から1.0の範囲に制限
            fitness = max(0.0, min(1.0, fitness))

            return fitness

        except Exception as e:
            return 0.5

    def _calculate_performance_score(self) -> float:
        """実際のパフォーマンス指標を計算"""
        try:
            # レスポンス時間の評価
            response_time_score = self._evaluate_response_time()

            # 精度の評価
            accuracy_score = self._evaluate_accuracy()

            # 一貫性の評価
            consistency_score = self._evaluate_consistency()

            # 効率性の評価
            efficiency_score = self._evaluate_efficiency()

            # 重み付き平均
            total_score = (
                response_time_score * self.latency_weights["response_time"]
                + accuracy_score * self.latency_weights["accuracy"]
                + consistency_score * self.latency_weights["consistency"]
                + efficiency_score * self.latency_weights["efficiency"]
            )

            return total_score

        except Exception as e:
            return 0.5

    def _evaluate_response_time(self) -> float:
        """レスポンス時間を評価"""
        try:
            # 最近のレイテンシー履歴を取得
            from src.core.simple_bo import get_global_bo

            bo = get_global_bo()
            history = bo.get_trial_history()

            if not history:
                return 0.5

            # 最近10件のレイテンシーを取得
            recent_latencies = []
            for trial in history[-10:]:
                if "metadata" in trial and "latency_ms" in trial["metadata"]:
                    recent_latencies.append(trial["metadata"]["latency_ms"])

            if not recent_latencies:
                return 0.5

            # 平均レイテンシーを計算
            avg_latency = sum(recent_latencies) / len(recent_latencies)

            # レイテンシーが低いほど高スコア（逆数を使用）
            # 5秒以下で1.0、30秒以上で0.0
            if avg_latency <= 5000:
                return 1.0
            elif avg_latency >= 30000:
                return 0.0
            else:
                return 1.0 - (avg_latency - 5000) / 25000

        except Exception as e:
            return 0.5

    def _evaluate_accuracy(self) -> float:
        """精度を評価"""
        try:
            # 構文エラーの発生率を評価
            error_rate = self._calculate_error_rate()

            # エラー率が低いほど高スコア
            if error_rate <= 0.05:  # 5%以下
                return 1.0
            elif error_rate >= 0.5:  # 50%以上
                return 0.0
            else:
                return 1.0 - (error_rate - 0.05) / 0.45

        except Exception as e:
            return 0.5

    def _evaluate_consistency(self) -> float:
        """一貫性を評価"""
        try:
            # レスポンス時間のばらつきを評価
            from src.core.simple_bo import get_global_bo

            bo = get_global_bo()
            history = bo.get_trial_history()

            if len(history) < 3:
                return 0.5

            # 最近のレイテンシーを取得
            recent_latencies = []
            for trial in history[-10:]:
                if "metadata" in trial and "latency_ms" in trial["metadata"]:
                    recent_latencies.append(trial["metadata"]["latency_ms"])

            if len(recent_latencies) < 3:
                return 0.5

            # 標準偏差を計算
            std_dev = statistics.stdev(recent_latencies)
            mean_latency = statistics.mean(recent_latencies)

            # 変動係数（標準偏差/平均）が小さいほど高スコア
            cv = std_dev / mean_latency if mean_latency > 0 else 1.0

            if cv <= 0.1:  # 10%以下
                return 1.0
            elif cv >= 0.5:  # 50%以上
                return 0.0
            else:
                return 1.0 - (cv - 0.1) / 0.4

        except Exception as e:
            return 0.5

    def _evaluate_efficiency(self) -> float:
        """効率性を評価"""
        try:
            # トークン効率を評価
            from src.core.simple_bo import get_global_bo

            bo = get_global_bo()
            history = bo.get_trial_history()

            if not history:
                return 0.5

            # 最近の試行から効率性を計算
            recent_trials = history[-5:]
            efficiency_scores = []

            for trial in recent_trials:
                if "result" in trial and "metadata" in trial:
                    result = trial["result"]
                    metadata = trial["metadata"]

                    # 結果スコアが高く、レイテンシーが低いほど効率的
                    if "latency_ms" in metadata:
                        latency = metadata["latency_ms"]
                        # 結果スコア / レイテンシー（秒）
                        efficiency = result / (latency / 1000) if latency > 0 else 0
                        efficiency_scores.append(efficiency)

            if not efficiency_scores:
                return 0.5

            # 平均効率性を計算
            avg_efficiency = sum(efficiency_scores) / len(efficiency_scores)

            # 効率性が高いほど高スコア
            if avg_efficiency >= 0.1:
                return 1.0
            elif avg_efficiency <= 0.01:
                return 0.0
            else:
                return (avg_efficiency - 0.01) / 0.09

        except Exception as e:
            return 0.5

    def _calculate_error_rate(self) -> float:
        """エラー率を計算"""
        try:
            # ログファイルからエラー率を計算
            log_dir = "data/logs/current"
            error_count = 0
            total_count = 0

            if os.path.exists(log_dir):
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        with open(
                            os.path.join(log_dir, filename), "r", encoding="utf-8"
                        ) as f:
                            for line in f:
                                if "ERROR" in line or "エラー" in line:
                                    error_count += 1
                                total_count += 1

            if total_count == 0:
                return 0.0

            return error_count / total_count

        except Exception as e:
            return 0.1  # デフォルトエラー率

    def _evaluate_genome_parameters(self, genome: Dict[str, Any]) -> float:
        """ゲノムパラメータの最適性を評価"""
        try:
            score = 0.0
            total_params = 0

            # 各パラメータの最適性を評価
            for param_name, value in genome.items():
                if isinstance(value, dict) and "current_value" in value:
                    # 進化ゲノム形式の場合
                    current_val = value["current_value"]
                    min_val = value.get("min", 0)
                    max_val = value.get("max", 1)

                    # パラメータが範囲内の中央付近にあるほど高スコア
                    if min_val < max_val:
                        normalized = (current_val - min_val) / (max_val - min_val)
                        # 0.3-0.7の範囲で高スコア
                        if 0.3 <= normalized <= 0.7:
                            score += 1.0
                        else:
                            score += max(0.0, 1.0 - abs(normalized - 0.5) * 2)
                    else:
                        score += 0.5

                elif isinstance(value, (int, float)):
                    # 数値パラメータの場合
                    if param_name == "learning_rate":
                        if 0.001 <= value <= 0.1:
                            score += 1.0
                        else:
                            score += 0.5
                    elif param_name == "temperature":
                        if 0.1 <= value <= 1.0:
                            score += 1.0
                        else:
                            score += 0.5
                    elif param_name == "max_tokens":
                        if 1000 <= value <= 4000:
                            score += 1.0
                        else:
                            score += 0.5
                    else:
                        score += 0.5
                else:
                    score += 0.5

                total_params += 1

            return score / total_params if total_params > 0 else 0.5

        except Exception as e:
            return 0.5


# 後方互換性のための関数
def calculate_fitness(genome: Dict[str, Any]) -> float:
    """適応度計算の関数版（後方互換性）"""
    calculator = FitnessCalculator()
    return calculator.calculate_fitness(genome)
