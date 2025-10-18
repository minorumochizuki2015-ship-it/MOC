#!/usr/bin/env python3
"""
ORCH-Next 簡易統合テスト - AI予測機能とダッシュボード
リリース前の最終品質チェック
"""

import sys
from datetime import datetime

import requests

sys.path.append(".")


def test_ai_prediction():
    """AI予測システムのテスト"""
    print("1. AI予測システム")
    try:
        from src.ai_prediction import QualityPredictor

        predictor = QualityPredictor()

        # モデルが学習済みでない場合は学習実行
        if not predictor.is_trained:
            print("   → モデル学習中...")
            results = predictor.train_model()
            print(f'   → 学習完了 (精度: {results["accuracy"]:.3f})')

        sample_metrics = {
            "test_coverage": 0.85,
            "error_rate": 0.03,
            "code_complexity": 2.5,
            "performance_score": 0.9,
        }
        prediction = predictor.predict_quality_issue(sample_metrics)
        status = "Issue" if prediction["prediction"] else "Normal"
        print(f"   ✓ 予測結果: {status}")
        print(f'   ✓ 信頼度: {prediction["confidence"]:.2f}')
        print(f'   ✓ 推奨: {prediction["recommendation"]}')
        return True
    except Exception as e:
        print(f"   ✗ エラー: {e}")
        return False


def test_monitoring_system():
    """監視システムのテスト"""
    print("2. 監視システム")
    try:
        from src.monitoring_system import MonitoringSystem

        monitor = MonitoringSystem()
        status = monitor.get_status()
        print("   ✓ 設定読み込み: OK")
        print(f'   ✓ 監視間隔: {status["config"]["monitoring_interval"]}秒')
        print(
            f'   ✓ 緊急モード: {"有効" if status["config"]["emergency_mode"]["enabled"] else "無効"}'
        )
        return True
    except Exception as e:
        print(f"   ✗ エラー: {e}")
        return False


def test_dashboard():
    """ダッシュボード接続テスト"""
    print("3. ダッシュボード")
    try:
        # IPv6/IPv4解決差異による接続拒否を避けるため、明示的にIPv4ループバックを使用
        response = requests.get("http://127.0.0.1:5000", timeout=5)
        print(f"   ✓ 接続: HTTP {response.status_code}")
        print("   ✓ URL: http://127.0.0.1:5000")
        return True
    except Exception as e:
        print(f"   ⚠ ダッシュボード未起動または接続エラー: {e}")
        return False


def test_data_generation():
    """テストデータ生成確認"""
    print("4. テストデータ")
    try:
        import sqlite3

        from src.ai_prediction import QualityPredictor

        predictor = QualityPredictor()

        # データベース接続確認
        conn = sqlite3.connect("data/quality_metrics.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM quality_metrics")
        count = cursor.fetchone()[0]
        conn.close()

        print("   ✓ データベース接続: OK")
        print(f"   ✓ 生成済みデータ: {count}件")

        if count >= 100:
            print("   ✓ 十分なデータ量: 学習可能")
            return True
        else:
            print("   ⚠ データ不足: 追加生成推奨")
            return False

    except Exception as e:
        print(f"   ✗ エラー: {e}")
        return False


def main():
    """メイン統合テスト実行"""
    print("=== ORCH-Next 簡易統合テスト ===")
    print(f'実行時刻: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print()

    results = []

    # 各テスト実行
    results.append(test_ai_prediction())
    print()

    results.append(test_monitoring_system())
    print()

    results.append(test_dashboard())
    print()

    results.append(test_data_generation())
    print()

    # 結果サマリー
    passed = sum(results)
    total = len(results)

    print("=== テスト結果サマリー ===")
    print(f"成功: {passed}/{total}")
    print(f"成功率: {passed/total*100:.1f}%")

    if passed >= 3:  # 4つ中3つ以上成功で合格
        print("✓ テスト合格 - リリース準備完了")
        return 0
    else:
        print("⚠ テスト不合格 - 修正が必要")
        return 1


if __name__ == "__main__":
    sys.exit(main())
