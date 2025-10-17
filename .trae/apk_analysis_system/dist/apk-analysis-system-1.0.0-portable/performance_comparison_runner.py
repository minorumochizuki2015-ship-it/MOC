"""
Performance Comparison Runner - APK解析システムの性能比較テスト
Mod版（既存システム）と自社開発版（Enhanced System）の詳細比較
"""
import os
import json
import time
import logging
import psutil
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('performance_comparison.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """システム性能監視クラス"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        self.start_cpu = self.process.cpu_percent()
    
    def get_memory_usage(self) -> float:
        """現在のメモリ使用量（MB）"""
        return self.process.memory_info().rss / 1024 / 1024
    
    def get_cpu_usage(self) -> float:
        """現在のCPU使用率（%）"""
        return self.process.cpu_percent()
    
    def get_elapsed_time(self) -> float:
        """経過時間（秒）"""
        return time.time() - self.start_time
    
    def get_memory_delta(self) -> float:
        """メモリ使用量の変化（MB）"""
        return self.get_memory_usage() - self.start_memory

class APKAnalysisComparator:
    """APK解析システム比較クラス"""
    
    def __init__(self, output_dir: str = "data/performance_comparison"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.monitor = PerformanceMonitor()
        
        logger.info(f"APK解析比較システム初期化完了: {self.output_dir}")
    
    def run_comparison(self, apk_path: str) -> Dict[str, Any]:
        """APK解析システムの性能比較実行"""
        logger.info(f"APK解析性能比較開始: {apk_path}")
        
        # APKファイル存在確認
        if not Path(apk_path).exists():
            logger.error(f"APKファイルが見つかりません: {apk_path}")
            return {"error": f"APKファイルが見つかりません: {apk_path}"}
        
        comparison_result = {
            "apk_path": apk_path,
            "apk_size_mb": Path(apk_path).stat().st_size / 1024 / 1024,
            "test_timestamp": datetime.now().isoformat(),
            "mod_version": {},
            "enhanced_version": {},
            "comparison_summary": {}
        }
        
        # Mod版（既存システム）の解析
        logger.info("Mod版APK解析開始...")
        mod_start = time.time()
        
        try:
            from core.utils.apk_analyzer import APKAnalyzer
            # APKAnalyzerはapk_pathを必須引数として受け取る
            mod_analyzer = APKAnalyzer(apk_path, output_dir=str(self.output_dir / "mod_analysis"))
            mod_result = mod_analyzer.analyze()  # analyzeメソッドを使用
            mod_time = time.time() - mod_start
            
            mod_performance = {
                "execution_time": mod_time,
                "memory_usage": self.monitor.get_memory_usage(),
                "cpu_usage": self.monitor.get_cpu_usage(),
                "analysis_result": mod_result
            }
            
            logger.info(f"Mod版解析完了: {mod_time:.2f}秒")
            
        except Exception as e:
            logger.error(f"Mod版解析エラー: {e}")
            mod_performance = {
                "execution_time": time.time() - mod_start,
                "memory_usage": self.monitor.get_memory_usage(),
                "cpu_usage": self.monitor.get_cpu_usage(),
                "error": str(e),
                "analysis_result": None
            }
        
        # Enhanced版（自社開発）の解析
        logger.info("Enhanced版APK解析開始...")
        enhanced_start = time.time()
        
        try:
            from core.utils.enhanced_apk_analyzer import EnhancedAPKAnalyzer, AnalysisConfig
            # EnhancedAPKAnalyzerはAnalysisConfigを受け取る
            config = AnalysisConfig(
                enable_deep_il2cpp=True,
                enable_dynamic_analysis=False,  # 動的解析は無効化（テスト環境）
                enable_memory_optimization=True,
                max_memory_mb=2048,
                parallel_workers=4,
                cache_results=True,
                timeout_seconds=300
            )
            enhanced_analyzer = EnhancedAPKAnalyzer(config=config)
            enhanced_result = enhanced_analyzer.analyze_apk_enhanced(apk_path)
            enhanced_time = time.time() - enhanced_start
            
            enhanced_performance = {
                "execution_time": enhanced_time,
                "memory_usage": self.monitor.get_memory_usage(),
                "cpu_usage": self.monitor.get_cpu_usage(),
                "analysis_result": enhanced_result
            }
            
            logger.info(f"Enhanced版解析完了: {enhanced_time:.2f}秒")
            
        except Exception as e:
            logger.error(f"Enhanced版解析エラー: {e}")
            enhanced_performance = {
                "execution_time": time.time() - enhanced_start,
                "memory_usage": self.monitor.get_memory_usage(),
                "cpu_usage": self.monitor.get_cpu_usage(),
                "error": str(e),
                "analysis_result": None
            }
        
        # 結果の格納
        comparison_result["mod_version"] = mod_performance
        comparison_result["enhanced_version"] = enhanced_performance
        
        # 比較分析
        comparison_result["comparison_summary"] = self._analyze_comparison(
            mod_performance, enhanced_performance
        )
        
        # 結果保存
        output_file = self.output_dir / f"comparison_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comparison_result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"比較結果保存完了: {output_file}")
        
        return comparison_result
    
    def _analyze_comparison(self, mod_perf: Dict[str, Any], enhanced_perf: Dict[str, Any]) -> Dict[str, Any]:
        """性能比較分析"""
        summary = {
            "performance_comparison": {},
            "functional_comparison": {},
            "recommendations": []
        }
        
        # 性能比較
        if "error" not in mod_perf and "error" not in enhanced_perf:
            mod_time = mod_perf.get("execution_time", 0)
            enhanced_time = enhanced_perf.get("execution_time", 0)
            
            if mod_time > 0 and enhanced_time > 0:
                time_improvement = ((mod_time - enhanced_time) / mod_time) * 100
                summary["performance_comparison"]["execution_time_improvement_percent"] = time_improvement
                
                if time_improvement > 0:
                    summary["recommendations"].append(f"Enhanced版は実行時間を{time_improvement:.1f}%改善")
                else:
                    summary["recommendations"].append(f"Mod版の方が{abs(time_improvement):.1f}%高速")
        
        # 機能比較
        mod_result = mod_perf.get("analysis_result")
        enhanced_result = enhanced_perf.get("analysis_result")
        
        if mod_result and enhanced_result:
            # Unity検出比較
            mod_unity = mod_result.get("unity_detected", False)
            enhanced_unity = enhanced_result.get("unity_detected", False)
            
            summary["functional_comparison"]["unity_detection"] = {
                "mod_detected": mod_unity,
                "enhanced_detected": enhanced_unity,
                "consistency": mod_unity == enhanced_unity
            }
            
            # IL2CPP検出比較
            mod_il2cpp = mod_result.get("il2cpp_detected", False)
            enhanced_il2cpp = enhanced_result.get("il2cpp_detected", False)
            
            summary["functional_comparison"]["il2cpp_detection"] = {
                "mod_detected": mod_il2cpp,
                "enhanced_detected": enhanced_il2cpp,
                "consistency": mod_il2cpp == enhanced_il2cpp
            }
        
        return summary
    
    def generate_detailed_report(self, comparison_result: Dict[str, Any]) -> str:
        """詳細レポート生成"""
        report_lines = [
            "# APK解析システム性能比較レポート",
            f"## テスト対象APK: {comparison_result['apk_path']}",
            f"## APKサイズ: {comparison_result['apk_size_mb']:.1f} MB",
            f"## テスト実行時刻: {comparison_result['test_timestamp']}",
            "",
            "## 性能比較結果",
            ""
        ]
        
        mod_perf = comparison_result.get("mod_version", {})
        enhanced_perf = comparison_result.get("enhanced_version", {})
        
        # Mod版結果
        report_lines.extend([
            "### Mod版（既存システム）",
            f"- 実行時間: {mod_perf.get('execution_time', 'N/A'):.2f}秒" if isinstance(mod_perf.get('execution_time'), (int, float)) else f"- 実行時間: {mod_perf.get('execution_time', 'N/A')}",
            f"- メモリ使用量: {mod_perf.get('memory_usage', 'N/A'):.1f}MB" if isinstance(mod_perf.get('memory_usage'), (int, float)) else f"- メモリ使用量: {mod_perf.get('memory_usage', 'N/A')}",
            f"- CPU使用率: {mod_perf.get('cpu_usage', 'N/A'):.1f}%" if isinstance(mod_perf.get('cpu_usage'), (int, float)) else f"- CPU使用率: {mod_perf.get('cpu_usage', 'N/A')}",
            ""
        ])
        
        if "error" in mod_perf:
            report_lines.append(f"- エラー: {mod_perf['error']}")
            report_lines.append("")
        
        # Enhanced版結果
        report_lines.extend([
            "### Enhanced版（自社開発）",
            f"- 実行時間: {enhanced_perf.get('execution_time', 'N/A'):.2f}秒" if isinstance(enhanced_perf.get('execution_time'), (int, float)) else f"- 実行時間: {enhanced_perf.get('execution_time', 'N/A')}",
            f"- メモリ使用量: {enhanced_perf.get('memory_usage', 'N/A'):.1f}MB" if isinstance(enhanced_perf.get('memory_usage'), (int, float)) else f"- メモリ使用量: {enhanced_perf.get('memory_usage', 'N/A')}",
            f"- CPU使用率: {enhanced_perf.get('cpu_usage', 'N/A'):.1f}%" if isinstance(enhanced_perf.get('cpu_usage'), (int, float)) else f"- CPU使用率: {enhanced_perf.get('cpu_usage', 'N/A')}",
            ""
        ])
        
        if "error" in enhanced_perf:
            report_lines.append(f"- エラー: {enhanced_perf['error']}")
            report_lines.append("")
        
        # 比較サマリー
        summary = comparison_result.get("comparison_summary", {})
        if summary:
            report_lines.extend([
                "## 比較サマリー",
                ""
            ])
            
            perf_comp = summary.get("performance_comparison", {})
            if "execution_time_improvement_percent" in perf_comp:
                improvement = perf_comp["execution_time_improvement_percent"]
                report_lines.append(f"- 実行時間改善: {improvement:.1f}%")
            
            func_comp = summary.get("functional_comparison", {})
            if func_comp:
                report_lines.extend([
                    "",
                    "### 機能比較",
                    ""
                ])
                
                unity_comp = func_comp.get("unity_detection", {})
                if unity_comp:
                    report_lines.append(f"- Unity検出: Mod={unity_comp.get('mod_detected')}, Enhanced={unity_comp.get('enhanced_detected')}, 一致={unity_comp.get('consistency')}")
                
                il2cpp_comp = func_comp.get("il2cpp_detection", {})
                if il2cpp_comp:
                    report_lines.append(f"- IL2CPP検出: Mod={il2cpp_comp.get('mod_detected')}, Enhanced={il2cpp_comp.get('enhanced_detected')}, 一致={il2cpp_comp.get('consistency')}")
            
            recommendations = summary.get("recommendations", [])
            if recommendations:
                report_lines.extend([
                    "",
                    "### 推奨事項",
                    ""
                ])
                for rec in recommendations:
                    report_lines.append(f"- {rec}")
        
        return "\n".join(report_lines)

def main():
    """メイン実行関数"""
    apk_path = r"C:\Users\User\Trae\MOC\tests\test_apk\HeyDooon_1.20_APKPure.apk"
    
    logger.info("APK解析システム性能比較テスト開始")
    
    comparator = APKAnalysisComparator()
    result = comparator.run_comparison(apk_path)
    
    # 詳細レポート生成
    report = comparator.generate_detailed_report(result)
    
    # レポート保存
    report_file = comparator.output_dir / f"detailed_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"詳細レポート保存完了: {report_file}")
    
    # コンソール出力
    print("\n" + "="*80)
    print("APK解析システム性能比較結果")
    print("="*80)
    print(report)
    print("="*80)
    
    return result

if __name__ == "__main__":
    main()