"""
AI予測機能モジュール
品質問題の予測とテストデータ生成を行う
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingRegressor, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, mean_squared_error, r2_score
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler


class QualityPredictor:
    """品質問題予測クラス"""

    def __init__(self, db_path: str = "data/quality_metrics.db"):
        self.db_path = Path(db_path)
        # 精度向上のためのハイパーパラメータ調整
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=10, min_samples_split=5, min_samples_leaf=2, random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._init_database()

    def _init_database(self):
        """データベース初期化"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quality_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    test_coverage REAL,
                    code_complexity REAL,
                    error_rate REAL,
                    performance_score REAL,
                    quality_issue INTEGER,  -- 0: 正常, 1: 問題あり
                    notes TEXT
                )
            """
            )
            # リソース需要予測用テーブル追加
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resource_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    network_usage REAL,
                    active_tasks INTEGER,
                    predicted_load REAL,
                    notes TEXT
                )
            """
            )
            conn.commit()

    def generate_test_data(self, num_samples: int = 1000) -> None:
        """テストデータ生成（品質メトリクスとリソースメトリクス）"""
        np.random.seed(42)

        # 品質メトリクスデータ生成
        quality_data = []
        for i in range(num_samples):
            # 基本メトリクス生成（より現実的な分布）
            test_coverage = np.random.beta(8, 2)  # より高い値に偏った分布
            code_complexity = np.random.gamma(2, 1.5)  # ガンマ分布でより現実的
            error_rate = np.random.exponential(0.03)  # より低いエラー率
            performance_score = np.random.beta(9, 2)  # 高性能に偏った分布

            # 品質問題の判定ロジック（より厳密）
            quality_issue = 0
            if (
                test_coverage < 0.75
                or code_complexity > 4.0
                or error_rate > 0.08
                or performance_score < 0.75
            ):
                quality_issue = 1

            # ランダムノイズ削減（5%に変更）
            if np.random.random() < 0.05:
                quality_issue = 1 - quality_issue

            timestamp = (datetime.now() - timedelta(days=i)).isoformat()

            quality_data.append(
                {
                    "timestamp": timestamp,
                    "test_coverage": max(0, min(1, test_coverage)),
                    "code_complexity": max(0.1, code_complexity),
                    "error_rate": max(0, error_rate),
                    "performance_score": max(0, min(1, performance_score)),
                    "quality_issue": quality_issue,
                    "notes": f"Generated quality data {i+1}",
                }
            )

        # リソースメトリクスデータ生成
        resource_data = []
        for i in range(num_samples):
            # 時間帯による変動を考慮
            hour = (datetime.now() - timedelta(days=i)).hour
            base_load = 0.3 + 0.4 * np.sin(2 * np.pi * hour / 24)  # 日次サイクル

            cpu_usage = max(0, min(1, np.random.normal(base_load, 0.15)))
            memory_usage = max(0, min(1, np.random.normal(base_load + 0.1, 0.12)))
            disk_usage = max(0, min(1, np.random.normal(0.4, 0.1)))
            network_usage = max(0, min(1, np.random.exponential(0.2)))
            active_tasks = max(1, int(np.random.poisson(5 + base_load * 10)))

            # 予測負荷（現在の負荷 + トレンド）
            predicted_load = min(1, cpu_usage * 1.2 + np.random.normal(0, 0.05))

            timestamp = (datetime.now() - timedelta(days=i)).isoformat()

            resource_data.append(
                {
                    "timestamp": timestamp,
                    "cpu_usage": cpu_usage,
                    "memory_usage": memory_usage,
                    "disk_usage": disk_usage,
                    "network_usage": network_usage,
                    "active_tasks": active_tasks,
                    "predicted_load": predicted_load,
                    "notes": f"Generated resource data {i+1}",
                }
            )

        # データベースに保存
        with sqlite3.connect(self.db_path) as conn:
            # 品質メトリクス保存
            for record in quality_data:
                conn.execute(
                    """
                    INSERT INTO quality_metrics 
                    (timestamp, test_coverage, code_complexity, error_rate, 
                     performance_score, quality_issue, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record["timestamp"],
                        record["test_coverage"],
                        record["code_complexity"],
                        record["error_rate"],
                        record["performance_score"],
                        record["quality_issue"],
                        record["notes"],
                    ),
                )

            # リソースメトリクス保存
            for record in resource_data:
                conn.execute(
                    """
                    INSERT INTO resource_metrics 
                    (timestamp, cpu_usage, memory_usage, disk_usage, 
                     network_usage, active_tasks, predicted_load, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record["timestamp"],
                        record["cpu_usage"],
                        record["memory_usage"],
                        record["disk_usage"],
                        record["network_usage"],
                        record["active_tasks"],
                        record["predicted_load"],
                        record["notes"],
                    ),
                )
            conn.commit()

        print(f"Generated {num_samples} quality and resource data records")

    def load_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """学習データ読み込み"""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query(
                """
                SELECT test_coverage, code_complexity, error_rate, 
                       performance_score, quality_issue
                FROM quality_metrics
                ORDER BY timestamp DESC
            """,
                conn,
            )

        if df.empty:
            raise ValueError("No training data available")

        features = df[
            ["test_coverage", "code_complexity", "error_rate", "performance_score"]
        ].values
        labels = df["quality_issue"].values

        return features, labels

    def train_model(self) -> Dict[str, float]:
        """モデル学習（ハイパーパラメータ調整付き）"""
        X, y = self.load_training_data()

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # 特徴量スケーリング
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # ハイパーパラメータ調整
        param_grid = {
            "n_estimators": [150, 200, 250],
            "max_depth": [8, 10, 12],
            "min_samples_split": [3, 5, 7],
        }

        grid_search = GridSearchCV(
            RandomForestClassifier(random_state=42), param_grid, cv=5, scoring="accuracy", n_jobs=-1
        )

        grid_search.fit(X_train_scaled, y_train)
        self.model = grid_search.best_estimator_
        self.is_trained = True

        # 評価
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)

        return {
            "accuracy": accuracy,
            "best_params": grid_search.best_params_,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "cv_score": grid_search.best_score_,
        }

    def predict_quality_issue(self, metrics: Dict[str, float]) -> Dict[str, any]:
        """品質問題予測"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        features = np.array(
            [
                [
                    metrics["test_coverage"],
                    metrics["code_complexity"],
                    metrics["error_rate"],
                    metrics["performance_score"],
                ]
            ]
        )

        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0]

        return {
            "prediction": int(prediction),
            "probability_normal": float(probability[0]),
            "probability_issue": float(probability[1]),
            "confidence": float(max(probability)),
            "recommendation": self._get_recommendation(metrics, prediction),
        }

    def _get_recommendation(self, metrics: Dict[str, float], prediction: int) -> str:
        """推奨アクション生成"""
        if prediction == 0:
            return "品質状態は良好です。現在の開発プロセスを継続してください。"

        recommendations = []
        if metrics["test_coverage"] < 0.8:
            recommendations.append("テストカバレッジを80%以上に向上させてください")
        if metrics["code_complexity"] > 3.0:
            recommendations.append("コードの複雑度を下げるリファクタリングを検討してください")
        if metrics["error_rate"] > 0.05:
            recommendations.append("エラー率が高いため、品質チェックを強化してください")
        if metrics["performance_score"] < 0.8:
            recommendations.append("パフォーマンスの最適化が必要です")

        return "; ".join(recommendations) if recommendations else "品質改善が必要です"

    def get_feature_importance(self) -> Dict[str, float]:
        """特徴量重要度取得"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        feature_names = ["test_coverage", "code_complexity", "error_rate", "performance_score"]
        importance = self.model.feature_importances_

        return dict(zip(feature_names, importance))


class ResourceDemandPredictor:
    """リソース需要予測クラス"""

    def __init__(self, db_path: str = "data/quality_metrics.db"):
        self.db_path = Path(db_path)
        self.model = GradientBoostingRegressor(
            n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def load_resource_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """リソースデータ読み込み"""
        with sqlite3.connect(self.db_path) as conn:
            df = pd.read_sql_query(
                """
                SELECT cpu_usage, memory_usage, disk_usage, 
                       network_usage, active_tasks, predicted_load
                FROM resource_metrics
                ORDER BY timestamp DESC
            """,
                conn,
            )

        if df.empty:
            raise ValueError("No resource data available")

        features = df[
            ["cpu_usage", "memory_usage", "disk_usage", "network_usage", "active_tasks"]
        ].values
        targets = df["predicted_load"].values

        return features, targets

    def train_model(self) -> Dict[str, float]:
        """リソース需要予測モデル学習"""
        X, y = self.load_resource_data()

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # 特徴量スケーリング
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True

        # 評価
        y_pred = self.model.predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)

        return {
            "mse": mse,
            "rmse": np.sqrt(mse),
            "r2_score": r2,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        }

    def predict_resource_demand(self, current_metrics: Dict[str, float]) -> Dict[str, any]:
        """リソース需要予測"""
        if not self.is_trained:
            raise ValueError("Resource model not trained yet")

        features = np.array(
            [
                [
                    current_metrics["cpu_usage"],
                    current_metrics["memory_usage"],
                    current_metrics["disk_usage"],
                    current_metrics["network_usage"],
                    current_metrics["active_tasks"],
                ]
            ]
        )

        features_scaled = self.scaler.transform(features)
        predicted_load = self.model.predict(features_scaled)[0]

        # 予測結果の解釈
        load_level = "Low"
        if predicted_load > 0.7:
            load_level = "High"
        elif predicted_load > 0.4:
            load_level = "Medium"

        recommendation = self._get_resource_recommendation(predicted_load, current_metrics)

        return {
            "predicted_load": float(predicted_load),
            "load_level": load_level,
            "recommendation": recommendation,
            "confidence": min(
                1.0,
                1.0
                - abs(
                    predicted_load
                    - np.mean([current_metrics["cpu_usage"], current_metrics["memory_usage"]])
                ),
            ),
        }

    def _get_resource_recommendation(self, predicted_load: float, metrics: Dict[str, float]) -> str:
        """リソース推奨アクション生成"""
        recommendations = []

        if predicted_load > 0.8:
            recommendations.append("高負荷が予測されます。リソースの追加割り当てを検討してください")
        elif predicted_load > 0.6:
            recommendations.append("中程度の負荷が予測されます。監視を強化してください")

        if metrics["cpu_usage"] > 0.7:
            recommendations.append("CPU使用率が高いため、処理の最適化が必要です")
        if metrics["memory_usage"] > 0.8:
            recommendations.append("メモリ使用率が高いため、メモリリークの確認が必要です")
        if metrics["active_tasks"] > 10:
            recommendations.append(
                "アクティブタスクが多いため、タスクの優先度調整を検討してください"
            )

        return "; ".join(recommendations) if recommendations else "リソース状態は良好です"


def main():
    """メイン実行関数"""
    # 品質予測
    quality_predictor = QualityPredictor()

    print("Generating test data...")
    quality_predictor.generate_test_data(1000)

    print("Training quality prediction model...")
    quality_results = quality_predictor.train_model()
    print(f"Quality model trained with accuracy: {quality_results['accuracy']:.3f}")
    print(f"Best parameters: {quality_results['best_params']}")
    print(f"Cross-validation score: {quality_results['cv_score']:.3f}")

    # リソース需要予測
    resource_predictor = ResourceDemandPredictor()

    print("\nTraining resource demand prediction model...")
    resource_results = resource_predictor.train_model()
    print(f"Resource model trained with R² score: {resource_results['r2_score']:.3f}")
    print(f"RMSE: {resource_results['rmse']:.3f}")

    # サンプル予測
    sample_quality_metrics = {
        "test_coverage": 0.82,
        "code_complexity": 2.8,
        "error_rate": 0.04,
        "performance_score": 0.88,
    }

    sample_resource_metrics = {
        "cpu_usage": 0.65,
        "memory_usage": 0.72,
        "disk_usage": 0.45,
        "network_usage": 0.23,
        "active_tasks": 8,
    }

    quality_prediction = quality_predictor.predict_quality_issue(sample_quality_metrics)
    resource_prediction = resource_predictor.predict_resource_demand(sample_resource_metrics)

    print(f"\n=== Quality Prediction ===")
    print(f"Prediction: {'Issue' if quality_prediction['prediction'] else 'Normal'}")
    print(f"Confidence: {quality_prediction['confidence']:.3f}")
    print(f"Recommendation: {quality_prediction['recommendation']}")

    print(f"\n=== Resource Demand Prediction ===")
    print(f"Predicted Load: {resource_prediction['predicted_load']:.3f}")
    print(f"Load Level: {resource_prediction['load_level']}")
    print(f"Confidence: {resource_prediction['confidence']:.3f}")
    print(f"Recommendation: {resource_prediction['recommendation']}")


if __name__ == "__main__":
    main()
