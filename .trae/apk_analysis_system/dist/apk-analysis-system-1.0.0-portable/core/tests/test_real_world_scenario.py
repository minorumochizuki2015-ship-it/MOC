"""
リアルワールドシナリオテスト
実際のMOCシステムでのログ最適化効果を検証
"""
import os
import sys
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config.logging_config import get_logger
from config.production_logging_config import (
    setup_production_logging, 
    get_performance_logger, 
    ConditionalLogger
)

class RealWorldLogTest:
    """実際のシステム使用パターンでのログテスト"""
    
    def __init__(self):
        self.results = {}
        self.test_dir = Path("data/logs/test_results")
        self.test_dir.mkdir(parents=True, exist_ok=True)
    
    def run_comprehensive_test(self):
        """包括的な実地テストを実行"""
        print("🚀 リアルワールドシナリオテスト開始")
        print("=" * 50)
        
        # テストシナリオ
        scenarios = [
            ("APK解析シミュレーション", self.simulate_apk_analysis),
            ("Unity解析シミュレーション", self.simulate_unity_analysis),
            ("並行処理ログテスト", self.simulate_concurrent_logging),
            ("高負荷ログテスト", self.simulate_high_load_logging),
            ("エラーハンドリングテスト", self.simulate_error_scenarios)
        ]
        
        for scenario_name, scenario_func in scenarios:
            print(f"\n📋 {scenario_name}を実行中...")
            start_time = time.time()
            
            try:
                result = scenario_func()
                execution_time = time.time() - start_time
                
                self.results[scenario_name] = {
                    "status": "SUCCESS",
                    "execution_time": round(execution_time, 3),
                    "details": result
                }
                print(f"✅ {scenario_name}: 成功 ({execution_time:.3f}秒)")
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.results[scenario_name] = {
                    "status": "FAILED",
                    "execution_time": round(execution_time, 3),
                    "error": str(e)
                }
                print(f"❌ {scenario_name}: 失敗 - {e}")
        
        self.generate_report()
    
    def simulate_apk_analysis(self):
        """APK解析プロセスのログ出力をシミュレート"""
        # 本番環境設定でロガーを初期化
        setup_production_logging(
            log_name="apk_analysis_test",
            log_dir=self.test_dir,
            console_output=False
        )
        
        logger = get_performance_logger("enhanced_apk_analyzer")
        conditional_logger = ConditionalLogger(logger, sample_rate=50)
        
        # APK解析の各フェーズをシミュレート
        phases = [
            ("Phase 1: 基本解析", 100),
            ("Phase 2: Unity深層解析", 150),
            ("Phase 3: IL2CPP詳細解析", 200),
            ("Phase 4: 動的解析", 300),
            ("Phase 5: 結果統合", 50)
        ]
        
        total_logs = 0
        for phase_name, iterations in phases:
            logger.info(f"{phase_name}開始")
            
            for i in range(iterations):
                # 高頻度ログをサンプリング
                conditional_logger.debug_sampled(f"{phase_name}: 処理中 {i}/{iterations}")
                
                # 重要なマイルストーンはそのままログ
                if i % 25 == 0:
                    logger.info(f"{phase_name}: 進捗 {i}/{iterations}")
                
                total_logs += 1
            
            logger.info(f"{phase_name}完了")
        
        return {
            "total_simulated_logs": total_logs,
            "phases_completed": len(phases),
            "log_file_size": (self.test_dir / "apk_analysis_test.log").stat().st_size
        }
    
    def simulate_unity_analysis(self):
        """Unity解析プロセスのログ出力をシミュレート"""
        logger = get_performance_logger("unity_dll_analyzer")
        
        # Unity関連ファイルの解析をシミュレート
        file_types = ["native_library", "il2cpp_metadata", "managed_assembly", "unity_assets"]
        
        total_files = 0
        for file_type in file_types:
            logger.info(f"{file_type}解析開始")
            
            # ファイル数をシミュレート
            file_count = {"native_library": 50, "il2cpp_metadata": 10, 
                         "managed_assembly": 30, "unity_assets": 100}[file_type]
            
            for i in range(file_count):
                logger.debug(f"{file_type}解析中: ファイル {i+1}/{file_count}")
                total_files += 1
            
            logger.info(f"{file_type}解析完了: {file_count}ファイル")
        
        return {
            "analyzed_file_types": len(file_types),
            "total_files_processed": total_files
        }
    
    def simulate_concurrent_logging(self):
        """並行処理でのログ出力をテスト"""
        logger = get_performance_logger("concurrent_test")
        
        def worker_task(worker_id, iterations):
            """ワーカータスク"""
            for i in range(iterations):
                logger.info(f"Worker {worker_id}: タスク {i} 実行中")
                logger.debug(f"Worker {worker_id}: 詳細情報 {i}")
                time.sleep(0.001)  # 短い処理時間をシミュレート
        
        # 5つのワーカーで並行実行
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for worker_id in range(5):
                future = executor.submit(worker_task, worker_id, 20)
                futures.append(future)
            
            # 全ワーカーの完了を待機
            for future in futures:
                future.result()
        
        return {
            "workers": 5,
            "tasks_per_worker": 20,
            "total_tasks": 100
        }
    
    def simulate_high_load_logging(self):
        """高負荷でのログ出力パフォーマンステスト"""
        # 通常のロガー
        normal_logger = get_logger("high_load_normal")
        
        # 最適化されたロガー
        optimized_logger = get_performance_logger("high_load_optimized", enable_debug=False)
        conditional_logger = ConditionalLogger(optimized_logger, sample_rate=100)
        
        iterations = 5000
        
        # 通常ログのパフォーマンス測定
        start_time = time.time()
        for i in range(iterations):
            normal_logger.debug(f"通常ログ: 高負荷テスト {i}")
            normal_logger.info(f"通常ログ: 情報メッセージ {i}")
        normal_time = time.time() - start_time
        
        # 最適化ログのパフォーマンス測定
        start_time = time.time()
        for i in range(iterations):
            conditional_logger.debug_sampled(f"最適化ログ: 高負荷テスト {i}")
            optimized_logger.info(f"最適化ログ: 情報メッセージ {i}")
        optimized_time = time.time() - start_time
        
        return {
            "iterations": iterations,
            "normal_logging_time": round(normal_time, 4),
            "optimized_logging_time": round(optimized_time, 4),
            "performance_improvement": round((normal_time - optimized_time) / normal_time * 100, 2)
        }
    
    def simulate_error_scenarios(self):
        """エラーシナリオでのログ出力をテスト"""
        logger = get_performance_logger("error_test")
        
        error_scenarios = [
            "ファイル読み込みエラー",
            "メモリ不足エラー",
            "ネットワーク接続エラー",
            "解析処理エラー",
            "データ変換エラー"
        ]
        
        for i, error_type in enumerate(error_scenarios):
            try:
                # エラーをシミュレート
                if i % 2 == 0:
                    raise Exception(f"{error_type}が発生しました")
                else:
                    logger.warning(f"{error_type}の警告: 処理を継続します")
            
            except Exception as e:
                logger.error(f"エラーハンドリング: {e}", exc_info=True)
        
        return {
            "error_scenarios_tested": len(error_scenarios),
            "exceptions_handled": len([s for i, s in enumerate(error_scenarios) if i % 2 == 0])
        }
    
    def generate_report(self):
        """テスト結果レポートを生成"""
        print("\n" + "=" * 60)
        print("リアルワールドテスト結果レポート")
        print("=" * 60)
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results.values() if r["status"] == "SUCCESS")
        total_time = sum(r["execution_time"] for r in self.results.values())
        
        print(f"📊 テスト概要:")
        print(f"   総テスト数: {total_tests}")
        print(f"   成功: {successful_tests}")
        print(f"   失敗: {total_tests - successful_tests}")
        print(f"   成功率: {successful_tests / total_tests * 100:.1f}%")
        print(f"   総実行時間: {total_time:.3f}秒")
        
        print(f"\n📋 詳細結果:")
        for test_name, result in self.results.items():
            status_icon = "✅" if result["status"] == "SUCCESS" else "❌"
            print(f"{status_icon} {test_name}")
            print(f"   実行時間: {result['execution_time']}秒")
            
            if result["status"] == "SUCCESS":
                for key, value in result["details"].items():
                    print(f"   {key}: {value}")
            else:
                print(f"   エラー: {result['error']}")
            print()
        
        # パフォーマンス改善の分析
        if "高負荷ログテスト" in self.results:
            perf_data = self.results["高負荷ログテスト"]["details"]
            print(f"🚀 パフォーマンス分析:")
            print(f"   通常ログ時間: {perf_data['normal_logging_time']}秒")
            print(f"   最適化ログ時間: {perf_data['optimized_logging_time']}秒")
            print(f"   改善率: {perf_data['performance_improvement']}%")
        
        print(f"\n📁 ログファイル保存先: {self.test_dir}")
        print("リアルワールドテスト完了!")

def main():
    """メイン実行関数"""
    test = RealWorldLogTest()
    test.run_comprehensive_test()

if __name__ == "__main__":
    main()