"""
ログ最適化実地テストスクリプト
新しいログ設定とパフォーマンス最適化の検証を行う
"""
import os
import sys
import time
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch
import logging

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config.logging_config import setup_logging, get_logger
from config.production_logging_config import (
    setup_production_logging, 
    get_performance_logger, 
    ConditionalLogger,
    get_environment_log_level
)

class LoggingTestSuite:
    """ログ最適化テストスイート"""
    
    def __init__(self):
        self.test_results = {}
        self.temp_dir = Path(tempfile.mkdtemp())
        print(f"テスト用一時ディレクトリ: {self.temp_dir}")
    
    def run_all_tests(self):
        """全テストを実行"""
        print("=" * 60)
        print("ログ最適化実地テスト開始")
        print("=" * 60)
        
        tests = [
            ("現在のログ設定テスト", self.test_current_logging),
            ("本番環境ログ設定テスト", self.test_production_config),
            ("パフォーマンステスト", self.test_performance_benchmark),
            ("ConditionalLoggerテスト", self.test_conditional_logger),
            ("環境変数制御テスト", self.test_environment_variables),
            ("ログローテーションテスト", self.test_log_rotation)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🧪 {test_name}を実行中...")
            try:
                result = test_func()
                self.test_results[test_name] = {"status": "PASS", "result": result}
                print(f"✅ {test_name}: PASS")
            except Exception as e:
                self.test_results[test_name] = {"status": "FAIL", "error": str(e)}
                print(f"❌ {test_name}: FAIL - {e}")
        
        self.print_summary()
    
    def test_current_logging(self):
        """現在のログ設定での動作テスト"""
        log_dir = self.temp_dir / "current_logs"
        logger = setup_logging(
            log_name="test_current",
            log_dir=log_dir,
            console_output=True,
            file_output=True
        )
        
        # 各ログレベルでテスト
        test_logger = get_logger("test_module")
        test_logger.debug("DEBUGレベルのテストメッセージ")
        test_logger.info("INFOレベルのテストメッセージ")
        test_logger.warning("WARNINGレベルのテストメッセージ")
        test_logger.error("ERRORレベルのテストメッセージ")
        
        # ログファイルの存在確認
        log_file = log_dir / "test_current.log"
        if not log_file.exists():
            raise Exception("ログファイルが作成されていません")
        
        # ログ内容の確認
        log_content = log_file.read_text(encoding='utf-8')
        expected_messages = ["INFOレベル", "WARNINGレベル", "ERRORレベル"]
        
        for msg in expected_messages:
            if msg not in log_content:
                raise Exception(f"期待されるメッセージが見つかりません: {msg}")
        
        return {
            "log_file_size": log_file.stat().st_size,
            "log_lines": len(log_content.splitlines()),
            "messages_found": len(expected_messages)
        }
    
    def test_production_config(self):
        """本番環境用ログ設定のテスト"""
        log_dir = self.temp_dir / "production_logs"
        
        # 本番環境設定でロガーを初期化
        logger = setup_production_logging(
            log_name="test_production",
            log_level=logging.INFO,
            log_dir=log_dir,
            console_output=False,  # 本番環境では無効
            file_output=True,
            max_file_size=1024,  # テスト用に小さく設定
            backup_count=3
        )
        
        # パフォーマンスロガーのテスト
        perf_logger = get_performance_logger("test_perf", enable_debug=False)
        
        # ログ出力テスト
        perf_logger.debug("このDEBUGメッセージは出力されないはず")
        perf_logger.info("本番環境INFOメッセージ")
        perf_logger.warning("本番環境WARNINGメッセージ")
        perf_logger.error("本番環境ERRORメッセージ")
        
        # ログファイルの確認
        log_file = log_dir / "test_production.log"
        if not log_file.exists():
            raise Exception("本番環境ログファイルが作成されていません")
        
        log_content = log_file.read_text(encoding='utf-8')
        
        # DEBUGメッセージが含まれていないことを確認
        if "このDEBUGメッセージ" in log_content:
            raise Exception("DEBUGメッセージが本番環境で出力されています")
        
        return {
            "log_file_size": log_file.stat().st_size,
            "debug_filtered": "このDEBUGメッセージ" not in log_content,
            "info_logged": "本番環境INFOメッセージ" in log_content
        }
    
    def test_performance_benchmark(self):
        """ログ出力のパフォーマンス測定"""
        log_dir = self.temp_dir / "performance_logs"
        
        # 通常のロガー
        normal_logger = setup_logging(
            log_name="perf_normal",
            log_dir=log_dir,
            console_output=False
        )
        test_logger = get_logger("perf_test")
        
        # 本番環境ロガー
        prod_logger = setup_production_logging(
            log_name="perf_production",
            log_level=logging.WARNING,  # より高いレベル
            log_dir=log_dir,
            console_output=False
        )
        perf_logger = get_performance_logger("perf_prod", enable_debug=False)
        
        # パフォーマンステスト
        iterations = 1000
        
        # 通常ログのベンチマーク
        start_time = time.time()
        for i in range(iterations):
            test_logger.info(f"通常ログメッセージ {i}")
        normal_time = time.time() - start_time
        
        # 本番環境ログのベンチマーク（高いレベルで出力されない）
        start_time = time.time()
        for i in range(iterations):
            perf_logger.info(f"本番ログメッセージ {i}")  # WARNINGレベル以下なので出力されない
        production_time = time.time() - start_time
        
        return {
            "iterations": iterations,
            "normal_logging_time": round(normal_time, 4),
            "production_logging_time": round(production_time, 4),
            "performance_improvement": round((normal_time - production_time) / normal_time * 100, 2)
        }
    
    def test_conditional_logger(self):
        """ConditionalLoggerのサンプリング機能テスト"""
        log_dir = self.temp_dir / "conditional_logs"
        
        # ベースロガーの設定
        setup_logging(
            log_name="conditional_test",
            log_dir=log_dir,
            console_output=False
        )
        base_logger = get_logger("conditional_test")
        
        # ConditionalLoggerの作成（10回に1回サンプリング）
        conditional_logger = ConditionalLogger(base_logger, sample_rate=10)
        
        # 100回ログ出力（10回出力されるはず）
        for i in range(100):
            conditional_logger.debug_sampled(f"サンプリングDEBUGメッセージ {i}")
            conditional_logger.info_sampled(f"サンプリングINFOメッセージ {i}")
        
        # ログファイルの確認
        log_file = log_dir / "conditional_test.log"
        if not log_file.exists():
            raise Exception("ConditionalLoggerのログファイルが作成されていません")
        
        log_content = log_file.read_text(encoding='utf-8')
        log_lines = [line for line in log_content.splitlines() if "サンプリング" in line]
        
        # 期待される行数（DEBUG + INFO で20行程度）
        expected_lines = 20  # 10回 × 2種類
        actual_lines = len(log_lines)
        
        if abs(actual_lines - expected_lines) > 2:  # 誤差を考慮
            raise Exception(f"サンプリング結果が期待値と異なります。期待: {expected_lines}, 実際: {actual_lines}")
        
        return {
            "total_calls": 200,  # DEBUG + INFO で200回
            "sampled_lines": actual_lines,
            "sampling_rate": round(actual_lines / 200 * 100, 2)
        }
    
    def test_environment_variables(self):
        """環境変数によるログレベル制御テスト"""
        test_cases = [
            ("development", logging.DEBUG),
            ("testing", logging.INFO),
            ("staging", logging.INFO),
            ("production", logging.WARNING)
        ]
        
        results = {}
        
        for env_name, expected_level in test_cases:
            with patch.dict(os.environ, {'ENVIRONMENT': env_name}):
                actual_level = get_environment_log_level()
                results[env_name] = {
                    "expected": expected_level,
                    "actual": actual_level,
                    "match": actual_level == expected_level
                }
        
        # 全ての環境でレベルが正しく設定されているか確認
        all_match = all(result["match"] for result in results.values())
        if not all_match:
            raise Exception("環境変数によるログレベル制御が正しく動作していません")
        
        return results
    
    def test_log_rotation(self):
        """ログローテーション機能の動作確認"""
        log_dir = self.temp_dir / "rotation_logs"
        
        # 小さなファイルサイズでローテーション設定
        logger = setup_production_logging(
            log_name="rotation_test",
            log_dir=log_dir,
            max_file_size=512,  # 512バイト
            backup_count=3,
            console_output=False
        )
        
        test_logger = get_performance_logger("rotation_test")
        
        # ファイルサイズを超えるまでログ出力
        for i in range(100):
            test_logger.warning(f"ローテーションテストメッセージ {i:03d} - これは長いメッセージです" * 2)
        
        # ローテーションファイルの確認
        log_files = list(log_dir.glob("rotation_test.log*"))
        
        if len(log_files) < 2:
            raise Exception("ログローテーションが実行されていません")
        
        return {
            "total_log_files": len(log_files),
            "main_log_exists": (log_dir / "rotation_test.log").exists(),
            "backup_files": len([f for f in log_files if f.name != "rotation_test.log"])
        }
    
    def print_summary(self):
        """テスト結果サマリーの表示"""
        print("\n" + "=" * 60)
        print("テスト結果サマリー")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results.values() if result["status"] == "PASS")
        total = len(self.test_results)
        
        print(f"総テスト数: {total}")
        print(f"成功: {passed}")
        print(f"失敗: {total - passed}")
        print(f"成功率: {passed / total * 100:.1f}%")
        
        print("\n詳細結果:")
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result["status"] == "PASS" else "❌"
            print(f"{status_icon} {test_name}: {result['status']}")
            
            if result["status"] == "PASS" and "result" in result:
                for key, value in result["result"].items():
                    print(f"    {key}: {value}")
            elif result["status"] == "FAIL":
                print(f"    エラー: {result['error']}")
        
        print(f"\nテスト用ファイル: {self.temp_dir}")
        print("テスト完了!")

def main():
    """メイン実行関数"""
    test_suite = LoggingTestSuite()
    test_suite.run_all_tests()

if __name__ == "__main__":
    main()