"""
実際のAPKファイルを使用したログ最適化実地テスト
HeyDooon_1.20_APKPure.apk での検証
"""
import os
import sys
import time
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.config.logging_config import get_logger, setup_logging
from config.production_logging_config import (
    setup_production_logging, 
    get_performance_logger, 
    ConditionalLogger
)

class RealAPKAnalysisTest:
    """実際のAPKファイルを使用したログ最適化テスト"""
    
    def __init__(self):
        self.apk_path = Path("C:/Users/User/Downloads/HeyDooon_1.20_APKPure.apk")
        self.test_dir = Path("data/logs/real_apk_test")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}
        
        # APKファイルの基本情報
        if self.apk_path.exists():
            self.apk_size = self.apk_path.stat().st_size
            print(f"📱 対象APK: {self.apk_path.name}")
            print(f"📊 ファイルサイズ: {self.apk_size:,} bytes ({self.apk_size/1024/1024:.1f} MB)")
        else:
            raise FileNotFoundError(f"APKファイルが見つかりません: {self.apk_path}")
    
    def run_comprehensive_apk_test(self):
        """包括的なAPK解析ログテストを実行"""
        print("\n🚀 実際のAPKファイルでのログ最適化テスト開始")
        print("=" * 60)
        
        test_scenarios = [
            ("通常ログでのAPK解析", self.test_normal_logging_apk_analysis),
            ("最適化ログでのAPK解析", self.test_optimized_logging_apk_analysis),
            ("並行処理でのAPK解析", self.test_concurrent_apk_analysis),
            ("高負荷シミュレーション", self.test_high_load_apk_processing),
            ("エラー処理テスト", self.test_error_handling_scenarios)
        ]
        
        for scenario_name, scenario_func in test_scenarios:
            print(f"\n🧪 {scenario_name}...")
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
        
        self.generate_comprehensive_report()
    
    def test_normal_logging_apk_analysis(self):
        """通常のログ設定でのAPK解析シミュレーション"""
        # 通常のログ設定
        setup_logging(
            log_name="normal_apk_analysis",
            log_dir=self.test_dir,
            console_output=False
        )
        
        logger = get_logger("enhanced_apk_analyzer")
        
        return self._simulate_apk_analysis_process(logger, "通常ログ")
    
    def test_optimized_logging_apk_analysis(self):
        """最適化されたログ設定でのAPK解析シミュレーション"""
        # 本番環境用ログ設定
        setup_production_logging(
            log_name="optimized_apk_analysis",
            log_dir=self.test_dir,
            console_output=False,
            max_file_size=20*1024*1024,  # 20MB
            backup_count=3
        )
        
        logger = get_performance_logger("enhanced_apk_analyzer", enable_debug=False)
        conditional_logger = ConditionalLogger(logger, sample_rate=100)
        
        return self._simulate_apk_analysis_process(conditional_logger, "最適化ログ")
    
    def _simulate_apk_analysis_process(self, logger, log_type):
        """APK解析プロセスをシミュレート"""
        # 実際のAPKサイズに基づいた処理量を計算
        processing_complexity = min(self.apk_size // (1024 * 1024), 500)  # 最大500回
        
        logger.info(f"APK解析開始: {self.apk_path.name} ({log_type})")
        logger.info(f"ファイルサイズ: {self.apk_size:,} bytes")
        
        # Phase 1: APK基本情報解析
        logger.info("Phase 1: APK基本情報解析開始")
        for i in range(min(50, processing_complexity // 10)):
            if hasattr(logger, 'debug_sampled'):
                logger.debug_sampled(f"マニフェスト解析: エントリ {i}")
            else:
                logger.debug(f"マニフェスト解析: エントリ {i}")
            
            if i % 10 == 0:
                logger.info(f"マニフェスト解析進捗: {i}/50")
        
        logger.info("Phase 1: APK基本情報解析完了")
        
        # Phase 2: DEXファイル解析
        logger.info("Phase 2: DEXファイル解析開始")
        dex_classes = min(200, processing_complexity // 5)
        
        for i in range(dex_classes):
            if hasattr(logger, 'debug_sampled'):
                logger.debug_sampled(f"DEXクラス解析: {i}/{dex_classes}")
            else:
                if i % 20 == 0:  # 通常ログでは頻度を下げる
                    logger.debug(f"DEXクラス解析: {i}/{dex_classes}")
            
            if i % 50 == 0:
                logger.info(f"DEXファイル解析進捗: {i}/{dex_classes}")
        
        logger.info("Phase 2: DEXファイル解析完了")
        
        # Phase 3: リソース解析
        logger.info("Phase 3: リソース解析開始")
        resource_count = min(150, processing_complexity // 7)
        
        for i in range(resource_count):
            if hasattr(logger, 'debug_sampled'):
                logger.debug_sampled(f"リソース解析: {i}/{resource_count}")
            else:
                if i % 15 == 0:
                    logger.debug(f"リソース解析: {i}/{resource_count}")
            
            if i % 30 == 0:
                logger.info(f"リソース解析進捗: {i}/{resource_count}")
        
        logger.info("Phase 3: リソース解析完了")
        
        # Phase 4: ネイティブライブラリ解析
        logger.info("Phase 4: ネイティブライブラリ解析開始")
        native_libs = min(25, processing_complexity // 20)
        
        for i in range(native_libs):
            logger.debug(f"ネイティブライブラリ解析: lib_{i}.so")
            
            if i % 5 == 0:
                logger.info(f"ネイティブライブラリ解析進捗: {i}/{native_libs}")
        
        logger.info("Phase 4: ネイティブライブラリ解析完了")
        
        # Phase 5: セキュリティ解析
        logger.info("Phase 5: セキュリティ解析開始")
        security_checks = 20
        
        for i in range(security_checks):
            logger.debug(f"セキュリティチェック: {i+1}/{security_checks}")
            
            # セキュリティ問題をシミュレート
            if i == 10:
                logger.warning("潜在的なセキュリティリスクを検出: 不明な権限要求")
            elif i == 15:
                logger.warning("証明書の検証に問題があります")
        
        logger.info("Phase 5: セキュリティ解析完了")
        
        logger.info(f"APK解析完了: {self.apk_path.name}")
        
        return {
            "apk_size": self.apk_size,
            "processing_complexity": processing_complexity,
            "dex_classes_analyzed": dex_classes,
            "resources_analyzed": resource_count,
            "native_libs_analyzed": native_libs,
            "security_checks": security_checks
        }
    
    def test_concurrent_apk_analysis(self):
        """並行処理でのAPK解析テスト"""
        logger = get_performance_logger("concurrent_apk_analyzer")
        
        def analyze_component(component_name, iterations):
            """コンポーネント解析ワーカー"""
            for i in range(iterations):
                logger.info(f"{component_name}: 解析 {i+1}/{iterations}")
                logger.debug(f"{component_name}: 詳細処理 {i+1}")
                time.sleep(0.001)  # 処理時間をシミュレート
        
        # 並行処理でコンポーネントを解析
        components = [
            ("マニフェスト解析", 30),
            ("DEX解析", 50),
            ("リソース解析", 40),
            ("ネイティブ解析", 20)
        ]
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for component, iterations in components:
                future = executor.submit(analyze_component, component, iterations)
                futures.append(future)
            
            # 全ワーカーの完了を待機
            for future in futures:
                future.result()
        
        return {
            "concurrent_components": len(components),
            "total_operations": sum(c[1] for c in components)
        }
    
    def test_high_load_apk_processing(self):
        """高負荷でのAPK処理シミュレーション"""
        logger = get_performance_logger("high_load_apk")
        conditional_logger = ConditionalLogger(logger, sample_rate=200)
        
        # 大量のファイル処理をシミュレート
        file_count = 1000
        
        logger.info(f"高負荷APK処理開始: {file_count}ファイル")
        
        start_time = time.time()
        for i in range(file_count):
            conditional_logger.debug_sampled(f"ファイル処理: {i+1}/{file_count}")
            
            # 重要なマイルストーン
            if i % 100 == 0:
                logger.info(f"処理進捗: {i}/{file_count}")
            
            # エラーシミュレーション
            if i == 500:
                logger.error("処理中にエラーが発生しましたが、継続します")
        
        processing_time = time.time() - start_time
        logger.info(f"高負荷APK処理完了: {processing_time:.3f}秒")
        
        return {
            "files_processed": file_count,
            "processing_time": round(processing_time, 3),
            "throughput": round(file_count / processing_time, 2)
        }
    
    def test_error_handling_scenarios(self):
        """エラーハンドリングシナリオのテスト"""
        logger = get_performance_logger("error_handling_apk")
        
        error_scenarios = [
            "APKファイル破損",
            "メモリ不足",
            "ディスク容量不足",
            "ネットワークタイムアウト",
            "権限不足エラー"
        ]
        
        handled_errors = 0
        for i, error_type in enumerate(error_scenarios):
            try:
                logger.info(f"エラーシナリオテスト: {error_type}")
                
                # エラーをシミュレート
                if i % 2 == 0:
                    raise Exception(f"{error_type}が発生しました")
                else:
                    logger.warning(f"{error_type}: 警告レベルで処理継続")
                
            except Exception as e:
                logger.error(f"エラーハンドリング: {e}", exc_info=True)
                handled_errors += 1
        
        return {
            "error_scenarios": len(error_scenarios),
            "handled_errors": handled_errors
        }
    
    def generate_comprehensive_report(self):
        """包括的なテスト結果レポートを生成"""
        print("\n" + "=" * 70)
        print("実際のAPKファイルでのログ最適化テスト結果")
        print("=" * 70)
        
        print(f"📱 対象APK: {self.apk_path.name}")
        print(f"📊 ファイルサイズ: {self.apk_size:,} bytes ({self.apk_size/1024/1024:.1f} MB)")
        
        total_tests = len(self.results)
        successful_tests = sum(1 for r in self.results.values() if r["status"] == "SUCCESS")
        total_time = sum(r["execution_time"] for r in self.results.values())
        
        print(f"\n📋 テスト概要:")
        print(f"   総テスト数: {total_tests}")
        print(f"   成功: {successful_tests}")
        print(f"   失敗: {total_tests - successful_tests}")
        print(f"   成功率: {successful_tests / total_tests * 100:.1f}%")
        print(f"   総実行時間: {total_time:.3f}秒")
        
        print(f"\n📊 詳細結果:")
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
        
        # パフォーマンス比較
        normal_test = self.results.get("通常ログでのAPK解析")
        optimized_test = self.results.get("最適化ログでのAPK解析")
        
        if normal_test and optimized_test and both_successful(normal_test, optimized_test):
            normal_time = normal_test["execution_time"]
            optimized_time = optimized_test["execution_time"]
            improvement = ((normal_time - optimized_time) / normal_time * 100) if normal_time > 0 else 0
            
            print(f"🚀 パフォーマンス比較:")
            print(f"   通常ログ実行時間: {normal_time}秒")
            print(f"   最適化ログ実行時間: {optimized_time}秒")
            print(f"   パフォーマンス改善: {improvement:+.2f}%")
        
        # ログファイル分析
        log_files = list(self.test_dir.glob("*.log"))
        if log_files:
            print(f"\n📁 生成されたログファイル:")
            for log_file in log_files:
                size = log_file.stat().st_size
                print(f"   {log_file.name}: {size:,} bytes")
        
        print(f"\n📁 ログファイル保存先: {self.test_dir}")
        print("実際のAPKファイルでのテスト完了!")

def both_successful(test1, test2):
    """両方のテストが成功したかチェック"""
    return test1["status"] == "SUCCESS" and test2["status"] == "SUCCESS"

def main():
    """メイン実行関数"""
    try:
        test = RealAPKAnalysisTest()
        test.run_comprehensive_apk_test()
    except FileNotFoundError as e:
        print(f"❌ エラー: {e}")
        print("APKファイルのパスを確認してください。")
    except Exception as e:
        print(f"❌ 予期しないエラー: {e}")

if __name__ == "__main__":
    main()