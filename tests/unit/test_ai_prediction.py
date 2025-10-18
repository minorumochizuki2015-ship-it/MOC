import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest


def test_quality_predictor_predict(monkeypatch):
    from src import ai_prediction as aip

    class DummyModelRF:
        def predict(self, X):
            # Always predict issue=1
            return np.array([1])

        def predict_proba(self, X):
            # Normal=0.3, Issue=0.7
            return np.array([[0.3, 0.7]])

        # Importance for 4 features
        feature_importances_ = np.array([0.2, 0.3, 0.1, 0.4])

    class DummyScaler:
        def transform(self, X):
            # Identity transform
            return X

    def fake_try_load_model(self):
        # Inject dummy model/scaler and mark trained
        self.model = DummyModelRF()
        self.scaler = DummyScaler()
        self.is_trained = True

    # Patch before instantiation (constructor calls _try_load_model)
    monkeypatch.setattr(aip.QualityPredictor, "_try_load_model", fake_try_load_model)

    qp = aip.QualityPredictor(db_path=":memory:")

    metrics = {
        "test_coverage": 0.70,
        "code_complexity": 3.5,
        "error_rate": 0.06,
        "performance_score": 0.75,
    }

    result = qp.predict_quality_issue(metrics)

    assert result["prediction"] == 1
    assert 0.0 <= result["probability_issue"] <= 1.0
    assert "品質" in result["recommendation"] or "テストカバレッジ" in result["recommendation"]


def test_quality_predictor_feature_importance(monkeypatch):
    from src import ai_prediction as aip

    class DummyModelRF:
        feature_importances_ = np.array([0.25, 0.25, 0.25, 0.25])

    def fake_try_load_model(self):
        self.model = DummyModelRF()
        self.is_trained = True

    monkeypatch.setattr(aip.QualityPredictor, "_try_load_model", fake_try_load_model)

    qp = aip.QualityPredictor(db_path=":memory:")
    importance = qp.get_feature_importance()

    assert set(importance.keys()) == {
        "test_coverage",
        "code_complexity",
        "error_rate",
        "performance_score",
    }
    assert all(isinstance(v, (float, np.floating)) for v in importance.values())


@pytest.mark.parametrize(
    "metrics, expected_substrings",
    [
        (
            {
                "test_coverage": 0.70,
                "code_complexity": 2.0,
                "error_rate": 0.02,
                "performance_score": 0.85,
            },
            ["テストカバレッジ"],
        ),
        (
            {
                "test_coverage": 0.90,
                "code_complexity": 3.5,
                "error_rate": 0.02,
                "performance_score": 0.85,
            },
            ["複雑度"],
        ),
        (
            {
                "test_coverage": 0.90,
                "code_complexity": 2.0,
                "error_rate": 0.06,
                "performance_score": 0.85,
            },
            ["エラー率"],
        ),
        (
            {
                "test_coverage": 0.90,
                "code_complexity": 2.0,
                "error_rate": 0.02,
                "performance_score": 0.75,
            },
            ["パフォーマンス"],
        ),
    ],
)
def test_quality_predictor_recommendation_cases(monkeypatch, metrics, expected_substrings):
    from src import ai_prediction as aip

    class DummyModelRF:
        def predict(self, X):
            return np.array([1])

        def predict_proba(self, X):
            return np.array([[0.2, 0.8]])

        feature_importances_ = np.array([0.25, 0.25, 0.25, 0.25])

    class DummyScaler:
        def transform(self, X):
            return X

    def fake_try_load_model(self):
        self.model = DummyModelRF()
        self.scaler = DummyScaler()
        self.is_trained = True

    monkeypatch.setattr(aip.QualityPredictor, "_try_load_model", fake_try_load_model)

    qp = aip.QualityPredictor(db_path=":memory:")
    result = qp.predict_quality_issue(metrics)

    assert result["prediction"] == 1
    for substr in expected_substrings:
        assert substr in result["recommendation"]


@pytest.mark.parametrize(
    "predicted, expected_level",
    [
        (0.3, "Low"),
        (0.5, "Medium"),
        (0.85, "High"),
    ],
)
def test_resource_predictor_levels(monkeypatch, predicted, expected_level):
    from src import ai_prediction as aip

    class DummyGBR:
        def __init__(self, y):
            self._y = y

        def predict(self, X):
            return np.array([self._y])

    class DummyScaler:
        def transform(self, X):
            return X

    rp = aip.ResourceDemandPredictor(db_path=":memory:")
    monkeypatch.setattr(rp, "model", DummyGBR(predicted))
    monkeypatch.setattr(rp, "scaler", DummyScaler())
    monkeypatch.setattr(rp, "is_trained", True)

    metrics = {
        "cpu_usage": 0.5,
        "memory_usage": 0.5,
        "disk_usage": 0.5,
        "network_usage": 0.2,
        "active_tasks": 5,
    }

    result = rp.predict_resource_demand(metrics)
    assert result["load_level"] == expected_level


def test_quality_predictor_not_trained_raises(monkeypatch):
    from src import ai_prediction as aip

    def noop(self):
        # Do not load any model
        self.is_trained = False

    monkeypatch.setattr(aip.QualityPredictor, "_try_load_model", noop)

    qp = aip.QualityPredictor(db_path=":memory:")
    metrics = {
        "test_coverage": 0.8,
        "code_complexity": 2.0,
        "error_rate": 0.02,
        "performance_score": 0.9,
    }

    with pytest.raises(ValueError):
        qp.predict_quality_issue(metrics)


def test_resource_predictor_predict(monkeypatch):
    from src import ai_prediction as aip

    class DummyGBR:
        def predict(self, X):
            return np.array([0.6])

    class DummyScaler:
        def transform(self, X):
            return X

    rp = aip.ResourceDemandPredictor(db_path=":memory:")
    # Inject dummy trained model and scaler
    monkeypatch.setattr(rp, "model", DummyGBR())
    monkeypatch.setattr(rp, "scaler", DummyScaler())
    monkeypatch.setattr(rp, "is_trained", True)

    metrics = {
        "cpu_usage": 0.5,
        "memory_usage": 0.6,
        "disk_usage": 0.4,
        "network_usage": 0.3,
        "active_tasks": 5,
    }

    result = rp.predict_resource_demand(metrics)

    assert 0.0 <= result["predicted_load"] <= 1.0
    assert result["load_level"] in {"Low", "Medium", "High"}
    assert isinstance(result["recommendation"], str)


class TestQualityPredictorBasics(unittest.TestCase):
    """QualityPredictorの基本機能テスト"""

    def setUp(self):
        """テストセットアップ"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_quality.db"
        self.predictor = None

    def tearDown(self):
        """テストクリーンアップ"""
        # データベース接続を確実に閉じる
        if self.predictor is not None:
            del self.predictor

        # ファイル削除を試行
        try:
            if self.test_db_path.exists():
                self.test_db_path.unlink()
        except PermissionError:
            # Windowsでファイルが使用中の場合は無視
            pass

    def test_init_database(self):
        """データベース初期化テスト"""
        from src.ai_prediction import QualityPredictor

        self.predictor = QualityPredictor(db_path=str(self.test_db_path))

        # データベースファイルが作成されることを確認
        self.assertTrue(self.test_db_path.exists())

        # テーブルが作成されることを確認
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        self.assertIn("quality_metrics", tables)
        self.assertIn("resource_metrics", tables)

    def test_generate_test_data(self):
        """テストデータ生成テスト"""
        from src.ai_prediction import QualityPredictor

        self.predictor = QualityPredictor(db_path=str(self.test_db_path))
        num_samples = 10
        self.predictor.generate_test_data(num_samples)

        # データベースにデータが保存されることを確認
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()

            # 品質メトリクスデータの確認
            cursor.execute("SELECT COUNT(*) FROM quality_metrics")
            quality_count = cursor.fetchone()[0]
            self.assertEqual(quality_count, num_samples)

            # リソースメトリクスデータの確認
            cursor.execute("SELECT COUNT(*) FROM resource_metrics")
            resource_count = cursor.fetchone()[0]
            self.assertEqual(resource_count, num_samples)

    def test_load_training_data_empty(self):
        """学習データが空の場合のテスト"""
        from src.ai_prediction import QualityPredictor

        self.predictor = QualityPredictor(db_path=str(self.test_db_path))

        with self.assertRaises(ValueError) as cm:
            self.predictor.load_training_data()

        self.assertIn("No training data available", str(cm.exception))

    def test_load_training_data_with_data(self):
        """学習データが存在する場合のテスト"""
        from src.ai_prediction import QualityPredictor

        self.predictor = QualityPredictor(db_path=str(self.test_db_path))

        # テストデータを生成
        self.predictor.generate_test_data(50)

        # 学習データを読み込み
        features, labels = self.predictor.load_training_data()

        # データの形状確認
        self.assertEqual(features.shape[0], 50)  # サンプル数
        self.assertEqual(features.shape[1], 4)  # 特徴量数
        self.assertEqual(labels.shape[0], 50)  # ラベル数

        # データの値範囲確認
        self.assertTrue(np.all(features[:, 0] >= 0))  # test_coverage >= 0
        self.assertTrue(np.all(features[:, 0] <= 1))  # test_coverage <= 1
        self.assertTrue(np.all(features[:, 1] >= 0))  # code_complexity >= 0
        self.assertTrue(np.all(features[:, 2] >= 0))  # error_rate >= 0
        self.assertTrue(np.all(features[:, 3] >= 0))  # performance_score >= 0
        self.assertTrue(np.all(features[:, 3] <= 1))  # performance_score <= 1
        self.assertTrue(np.all(np.isin(labels, [0, 1])))  # labels in [0, 1]

    def test_train_model(self):
        """モデル学習テスト"""
        from src.ai_prediction import QualityPredictor

        self.predictor = QualityPredictor(db_path=str(self.test_db_path))

        # テストデータを生成
        self.predictor.generate_test_data(100)

        # モデル学習実行
        results = self.predictor.train_model()

        # 結果の確認
        self.assertIn("accuracy", results)
        self.assertIn("best_params", results)
        self.assertIn("train_samples", results)
        self.assertIn("test_samples", results)
        self.assertIn("cv_score", results)
        self.assertTrue(self.predictor.is_trained)

        # 結果の値が妥当な範囲内であることを確認
        self.assertGreaterEqual(results["accuracy"], 0)
        self.assertLessEqual(results["accuracy"], 1)
        self.assertGreater(results["train_samples"], 0)
        self.assertGreater(results["test_samples"], 0)
        self.assertIsInstance(results["best_params"], dict)


class TestResourceDemandPredictorBasics(unittest.TestCase):
    """ResourceDemandPredictorの基本機能テスト"""

    def setUp(self):
        """テストセットアップ"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_db_path = Path(self.temp_dir) / "test_resource.db"
        self.predictor = None

    def tearDown(self):
        """テストクリーンアップ"""
        # データベース接続を確実に閉じる
        if self.predictor is not None:
            del self.predictor

        # ファイル削除を試行
        try:
            if self.test_db_path.exists():
                self.test_db_path.unlink()
        except PermissionError:
            # Windowsでファイルが使用中の場合は無視
            pass

    def test_load_resource_data_empty(self):
        """リソースデータが空の場合のテスト"""
        from src.ai_prediction import QualityPredictor, ResourceDemandPredictor

        # データベースを初期化（テーブル作成のため）
        quality_predictor = QualityPredictor(db_path=str(self.test_db_path))

        self.predictor = ResourceDemandPredictor(db_path=str(self.test_db_path))

        with self.assertRaises(ValueError) as cm:
            self.predictor.load_resource_data()

        self.assertIn("No resource data available", str(cm.exception))

    def test_load_resource_data_with_data(self):
        """リソースデータが存在する場合のテスト"""
        from src.ai_prediction import QualityPredictor, ResourceDemandPredictor

        # データベースを初期化してテストデータを生成
        quality_predictor = QualityPredictor(db_path=str(self.test_db_path))
        quality_predictor.generate_test_data(30)

        self.predictor = ResourceDemandPredictor(db_path=str(self.test_db_path))

        # リソースデータを読み込み
        features, targets = self.predictor.load_resource_data()

        # データの形状確認
        self.assertEqual(features.shape[0], 30)  # サンプル数
        self.assertEqual(features.shape[1], 5)  # 特徴量数
        self.assertEqual(targets.shape[0], 30)  # ターゲット数

        # データの値範囲確認
        self.assertTrue(np.all(features[:, 0] >= 0))  # cpu_usage >= 0
        self.assertTrue(np.all(features[:, 0] <= 1))  # cpu_usage <= 1
        self.assertTrue(np.all(features[:, 1] >= 0))  # memory_usage >= 0
        self.assertTrue(np.all(features[:, 1] <= 1))  # memory_usage <= 1
        self.assertTrue(np.all(features[:, 4] >= 1))  # active_tasks >= 1

    def test_train_model_resource(self):
        """リソース需要予測モデル学習テスト"""
        from src.ai_prediction import QualityPredictor, ResourceDemandPredictor

        # データベースを初期化してテストデータを生成
        quality_predictor = QualityPredictor(db_path=str(self.test_db_path))
        quality_predictor.generate_test_data(100)

        self.predictor = ResourceDemandPredictor(db_path=str(self.test_db_path))

        # モデル学習実行
        results = self.predictor.train_model()

        # 結果の確認
        self.assertIn("mse", results)
        self.assertIn("rmse", results)
        self.assertIn("r2_score", results)
        self.assertIn("train_samples", results)
        self.assertIn("test_samples", results)
        self.assertTrue(self.predictor.is_trained)

        # 結果の値が妥当な範囲内であることを確認
        self.assertGreaterEqual(results["mse"], 0)
        self.assertGreaterEqual(results["rmse"], 0)
        self.assertLessEqual(results["r2_score"], 1)
        self.assertGreater(results["train_samples"], 0)
        self.assertGreater(results["test_samples"], 0)
