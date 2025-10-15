"""
Advanced APK Analysis Pipeline - 進化したAPK解析パイプライン
適応型解析エンジンとインテリジェントクローン生成器を統合したシステム
"""
import os
import json
import logging
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

from .adaptive_analysis_engine import AdaptiveAnalysisEngine, AdaptiveConfig, AnalysisStrategy
from .intelligent_clone_generator import IntelligentCloneGenerator, CloneQuality
from .enhanced_apk_analyzer import EnhancedAPKAnalyzer, AnalysisConfig

logger = logging.getLogger(__name__)

@dataclass
class PipelineConfig:
    """パイプライン設定"""
    # 適応型解析設定
    adaptive_config: AdaptiveConfig
    
    # クローン生成設定
    target_clone_quality: CloneQuality = CloneQuality.HIGH
    enable_intelligent_generation: bool = True
    
    # パイプライン設定
    enable_parallel_processing: bool = True
    max_concurrent_analyses: int = 3
    enable_result_caching: bool = True
    cache_duration_hours: int = 24
    
    # 品質管理設定
    min_analysis_quality: float = 50.0
    min_clone_rate: float = 0.6
    enable_quality_feedback: bool = True
    
    # 出力設定
    output_dir: str = "advanced_pipeline_output"
    enable_detailed_logging: bool = True
    generate_reports: bool = True

@dataclass
class PipelineResult:
    """パイプライン結果"""
    apk_path: str
    apk_hash: str
    pipeline_id: str
    start_time: datetime
    end_time: datetime
    
    # 解析結果
    analysis_result: Dict[str, Any]
    analysis_quality: float
    analysis_strategy: str
    
    # クローン生成結果
    clone_result: Optional[Dict[str, Any]] = None
    clone_quality: Optional[str] = None
    clone_rate: float = 0.0
    
    # パイプライン統計
    total_duration: float = 0.0
    analysis_duration: float = 0.0
    generation_duration: float = 0.0
    
    # 品質メトリクス
    success: bool = False
    error_message: Optional[str] = None
    quality_score: float = 0.0

class ResultCache:
    """結果キャッシュシステム"""
    
    def __init__(self, cache_dir: str, duration_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.duration_hours = duration_hours
    
    def get_cached_result(self, apk_hash: str) -> Optional[Dict[str, Any]]:
        """キャッシュされた結果を取得"""
        cache_file = self.cache_dir / f"{apk_hash}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)
            
            # キャッシュの有効期限をチェック
            cached_time = datetime.fromisoformat(cached_data.get("cached_at", ""))
            if (datetime.now() - cached_time).total_seconds() > (self.duration_hours * 3600):
                cache_file.unlink()  # 期限切れキャッシュを削除
                return None
            
            return cached_data.get("result")
            
        except Exception as e:
            logger.warning(f"キャッシュ読み込みエラー: {e}")
            return None
    
    def cache_result(self, apk_hash: str, result: Dict[str, Any]):
        """結果をキャッシュ"""
        cache_file = self.cache_dir / f"{apk_hash}.json"
        
        try:
            cache_data = {
                "cached_at": datetime.now().isoformat(),
                "apk_hash": apk_hash,
                "result": result
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.warning(f"キャッシュ保存エラー: {e}")

class QualityFeedbackSystem:
    """品質フィードバックシステム"""
    
    def __init__(self, feedback_db_path: str):
        self.feedback_db_path = Path(feedback_db_path)
        self.feedback_db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def record_pipeline_result(self, result: PipelineResult):
        """パイプライン結果を記録"""
        try:
            feedback_data = {
                "pipeline_id": result.pipeline_id,
                "apk_hash": result.apk_hash,
                "timestamp": result.end_time.isoformat(),
                "analysis_quality": result.analysis_quality,
                "clone_rate": result.clone_rate,
                "quality_score": result.quality_score,
                "success": result.success,
                "analysis_strategy": result.analysis_strategy,
                "total_duration": result.total_duration
            }
            
            # JSONファイルに追記
            feedback_file = self.feedback_db_path / "pipeline_feedback.jsonl"
            with open(feedback_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(feedback_data, ensure_ascii=False) + '\n')
                
        except Exception as e:
            logger.error(f"フィードバック記録エラー: {e}")
    
    def get_quality_trends(self, days: int = 7) -> Dict[str, Any]:
        """品質トレンドを取得"""
        try:
            feedback_file = self.feedback_db_path / "pipeline_feedback.jsonl"
            if not feedback_file.exists():
                return {"error": "フィードバックデータが見つかりません"}
            
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            recent_results = []
            
            with open(feedback_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        result_time = datetime.fromisoformat(data["timestamp"]).timestamp()
                        if result_time >= cutoff_time:
                            recent_results.append(data)
                    except:
                        continue
            
            if not recent_results:
                return {"error": "最近のデータがありません"}
            
            # 統計計算
            total_results = len(recent_results)
            successful_results = sum(1 for r in recent_results if r["success"])
            avg_quality = sum(r["analysis_quality"] for r in recent_results) / total_results
            avg_clone_rate = sum(r["clone_rate"] for r in recent_results) / total_results
            avg_duration = sum(r["total_duration"] for r in recent_results) / total_results
            
            return {
                "period_days": days,
                "total_analyses": total_results,
                "success_rate": successful_results / total_results,
                "avg_analysis_quality": avg_quality,
                "avg_clone_rate": avg_clone_rate,
                "avg_duration_seconds": avg_duration,
                "quality_trend": "improving" if avg_quality > 70 else "needs_improvement"
            }
            
        except Exception as e:
            logger.error(f"品質トレンド取得エラー: {e}")
            return {"error": str(e)}

class AdvancedAPKPipeline:
    """進化したAPK解析パイプライン"""
    
    def __init__(self, config: PipelineConfig = None):
        self.config = config or PipelineConfig(adaptive_config=AdaptiveConfig())
        
        # コンポーネントの初期化
        self.adaptive_engine = AdaptiveAnalysisEngine(self.config.adaptive_config)
        self.clone_generator = IntelligentCloneGenerator(
            output_dir=str(Path(self.config.output_dir) / "clones")
        )
        
        # キャッシュとフィードバックシステム
        if self.config.enable_result_caching:
            self.cache = ResultCache(
                cache_dir=str(Path(self.config.output_dir) / "cache"),
                duration_hours=self.config.cache_duration_hours
            )
        else:
            self.cache = None
        
        if self.config.enable_quality_feedback:
            self.feedback_system = QualityFeedbackSystem(
                feedback_db_path=str(Path(self.config.output_dir) / "feedback")
            )
        else:
            self.feedback_system = None
        
        # 出力ディレクトリの作成
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 並行処理用のセマフォ
        if self.config.enable_parallel_processing:
            self.semaphore = asyncio.Semaphore(self.config.max_concurrent_analyses)
        else:
            self.semaphore = None
    
    async def process_apk_advanced(self, apk_path: str) -> PipelineResult:
        """進化したAPK処理"""
        pipeline_id = self._generate_pipeline_id()
        apk_hash = self._calculate_apk_hash(apk_path)
        start_time = datetime.now()
        
        logger.info(f"進化したAPK処理開始: {apk_path} (ID: {pipeline_id})")
        
        result = PipelineResult(
            apk_path=apk_path,
            apk_hash=apk_hash,
            pipeline_id=pipeline_id,
            start_time=start_time,
            end_time=start_time  # 初期値
        )
        
        try:
            # 並行処理制御
            if self.semaphore:
                async with self.semaphore:
                    return await self._process_apk_internal(result)
            else:
                return await self._process_apk_internal(result)
                
        except Exception as e:
            result.end_time = datetime.now()
            result.total_duration = (result.end_time - result.start_time).total_seconds()
            result.success = False
            result.error_message = str(e)
            
            logger.error(f"パイプライン処理エラー: {e}")
            
            # フィードバック記録
            if self.feedback_system:
                self.feedback_system.record_pipeline_result(result)
            
            return result
    
    async def _process_apk_internal(self, result: PipelineResult) -> PipelineResult:
        """内部APK処理"""
        # キャッシュチェック
        if self.cache:
            cached_result = self.cache.get_cached_result(result.apk_hash)
            if cached_result:
                logger.info(f"キャッシュされた結果を使用: {result.apk_hash}")
                result.analysis_result = cached_result["analysis_result"]
                result.analysis_quality = cached_result["analysis_quality"]
                result.analysis_strategy = cached_result["analysis_strategy"]
                result.clone_result = cached_result.get("clone_result")
                result.clone_quality = cached_result.get("clone_quality")
                result.clone_rate = cached_result.get("clone_rate", 0.0)
                result.success = cached_result.get("success", False)
                result.quality_score = cached_result.get("quality_score", 0.0)
                result.end_time = datetime.now()
                result.total_duration = (result.end_time - result.start_time).total_seconds()
                return result
        
        # フェーズ1: 適応型解析
        analysis_start = time.time()
        logger.info("フェーズ1: 適応型解析開始")
        
        analysis_result = self.adaptive_engine.analyze_apk_adaptive(result.apk_path)
        
        analysis_end = time.time()
        result.analysis_duration = analysis_end - analysis_start
        result.analysis_result = analysis_result
        result.analysis_quality = self._calculate_analysis_quality(analysis_result)
        result.analysis_strategy = analysis_result.get("strategy_used", "unknown")
        
        logger.info(f"適応型解析完了: 品質 {result.analysis_quality:.2f}")
        
        # 品質チェック
        if result.analysis_quality < self.config.min_analysis_quality:
            logger.warning(f"解析品質が基準値を下回りました: {result.analysis_quality:.2f} < {self.config.min_analysis_quality}")
            
            # 品質向上のための再試行
            if result.analysis_quality > 30.0:  # 完全失敗でなければ再試行
                logger.info("品質向上のため保守的戦略で再試行")
                retry_result = await self._retry_with_conservative_strategy(result.apk_path)
                if retry_result and self._calculate_analysis_quality(retry_result) > result.analysis_quality:
                    result.analysis_result = retry_result
                    result.analysis_quality = self._calculate_analysis_quality(retry_result)
                    result.analysis_strategy = "conservative_retry"
        
        # フェーズ2: インテリジェントクローン生成
        if (self.config.enable_intelligent_generation and 
            result.analysis_quality >= self.config.min_analysis_quality):
            
            generation_start = time.time()
            logger.info("フェーズ2: インテリジェントクローン生成開始")
            
            clone_result = self.clone_generator.generate_intelligent_clone(
                result.analysis_result,
                self.config.target_clone_quality
            )
            
            generation_end = time.time()
            result.generation_duration = generation_end - generation_start
            result.clone_result = clone_result
            
            if clone_result.get("success"):
                result.clone_quality = clone_result["clone_info"]["achieved_quality"]
                result.clone_rate = clone_result["clone_info"]["actual_clone_rate"]
                logger.info(f"クローン生成完了: 品質 {result.clone_quality}, 率 {result.clone_rate:.2f}")
            else:
                logger.warning(f"クローン生成失敗: {clone_result.get('error')}")
        
        # 最終品質スコアの計算
        result.quality_score = self._calculate_final_quality_score(result)
        result.success = (result.analysis_quality >= self.config.min_analysis_quality and 
                         result.clone_rate >= self.config.min_clone_rate)
        
        result.end_time = datetime.now()
        result.total_duration = (result.end_time - result.start_time).total_seconds()
        
        # 結果のキャッシュ
        if self.cache and result.success:
            cache_data = {
                "analysis_result": result.analysis_result,
                "analysis_quality": result.analysis_quality,
                "analysis_strategy": result.analysis_strategy,
                "clone_result": result.clone_result,
                "clone_quality": result.clone_quality,
                "clone_rate": result.clone_rate,
                "success": result.success,
                "quality_score": result.quality_score
            }
            self.cache.cache_result(result.apk_hash, cache_data)
        
        # フィードバック記録
        if self.feedback_system:
            self.feedback_system.record_pipeline_result(result)
        
        # レポート生成
        if self.config.generate_reports:
            await self._generate_pipeline_report(result)
        
        logger.info(f"パイプライン処理完了: 品質スコア {result.quality_score:.2f}")
        return result
    
    async def _retry_with_conservative_strategy(self, apk_path: str) -> Optional[Dict[str, Any]]:
        """保守的戦略での再試行"""
        try:
            conservative_config = AnalysisConfig(
                enable_deep_il2cpp=False,
                enable_dynamic_analysis=False,
                enable_memory_optimization=True,
                max_memory_mb=1024,
                timeout_seconds=180
            )
            
            analyzer = EnhancedAPKAnalyzer(conservative_config)
            return analyzer.analyze_apk_enhanced(apk_path)
            
        except Exception as e:
            logger.error(f"保守的戦略での再試行エラー: {e}")
            return None
    
    def _calculate_analysis_quality(self, analysis_result: Dict[str, Any]) -> float:
        """解析品質の計算"""
        if not analysis_result.get("success"):
            return 0.0
        
        score = 0.0
        
        # Unity検出
        if analysis_result.get("analysis_result", {}).get("unity_analysis", {}).get("unity_detected"):
            score += 25.0
        
        # IL2CPP解析
        if analysis_result.get("analysis_result", {}).get("il2cpp_analysis", {}).get("dump_result"):
            score += 30.0
        
        # 動的解析
        dynamic_analysis = analysis_result.get("analysis_result", {}).get("dynamic_analysis", {})
        if dynamic_analysis and not dynamic_analysis.get("error"):
            score += 25.0
        
        # アセット抽出
        if analysis_result.get("analysis_result", {}).get("assets_extracted"):
            score += 20.0
        
        return min(score, 100.0)
    
    def _calculate_final_quality_score(self, result: PipelineResult) -> float:
        """最終品質スコアの計算"""
        analysis_weight = 0.4
        clone_weight = 0.6
        
        analysis_score = result.analysis_quality / 100.0
        clone_score = result.clone_rate if result.clone_rate > 0 else 0.0
        
        return (analysis_score * analysis_weight + clone_score * clone_weight) * 100.0
    
    async def _generate_pipeline_report(self, result: PipelineResult):
        """パイプラインレポートの生成"""
        try:
            report_data = {
                "pipeline_info": {
                    "id": result.pipeline_id,
                    "apk_path": result.apk_path,
                    "apk_hash": result.apk_hash,
                    "processed_at": result.end_time.isoformat()
                },
                "performance_metrics": {
                    "total_duration": result.total_duration,
                    "analysis_duration": result.analysis_duration,
                    "generation_duration": result.generation_duration,
                    "analysis_quality": result.analysis_quality,
                    "clone_rate": result.clone_rate,
                    "quality_score": result.quality_score
                },
                "analysis_summary": {
                    "strategy_used": result.analysis_strategy,
                    "success": result.success,
                    "error_message": result.error_message
                },
                "clone_summary": result.clone_result.get("clone_info", {}) if result.clone_result else {}
            }
            
            report_file = self.output_dir / "reports" / f"pipeline_report_{result.pipeline_id}.json"
            report_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"パイプラインレポート生成: {report_file}")
            
        except Exception as e:
            logger.error(f"レポート生成エラー: {e}")
    
    def _generate_pipeline_id(self) -> str:
        """パイプラインIDの生成"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"pipeline_{timestamp}_{os.getpid()}"
    
    def _calculate_apk_hash(self, apk_path: str) -> str:
        """APKファイルのハッシュ計算"""
        hash_md5 = hashlib.md5()
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    async def process_multiple_apks(self, apk_paths: List[str]) -> List[PipelineResult]:
        """複数APKの並行処理"""
        logger.info(f"複数APK処理開始: {len(apk_paths)}個のAPK")
        
        if self.config.enable_parallel_processing:
            tasks = [self.process_apk_advanced(apk_path) for apk_path in apk_paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 例外を結果に変換
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_result = PipelineResult(
                        apk_path=apk_paths[i],
                        apk_hash="error",
                        pipeline_id=self._generate_pipeline_id(),
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        analysis_result={},
                        analysis_quality=0.0,
                        analysis_strategy="error",
                        success=False,
                        error_message=str(result)
                    )
                    processed_results.append(error_result)
                else:
                    processed_results.append(result)
            
            return processed_results
        else:
            # 順次処理
            results = []
            for apk_path in apk_paths:
                result = await self.process_apk_advanced(apk_path)
                results.append(result)
            
            return results
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """パイプライン統計の取得"""
        stats = {
            "adaptive_engine_stats": self.adaptive_engine.get_learning_stats(),
            "config": asdict(self.config)
        }
        
        if self.feedback_system:
            quality_trends = self.feedback_system.get_quality_trends()
            stats["quality_trends"] = quality_trends
        
        return stats
    
    async def cleanup_cache(self, max_age_hours: int = 168):  # 1週間
        """古いキャッシュのクリーンアップ"""
        if not self.cache:
            return
        
        try:
            cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
            cache_files = list(self.cache.cache_dir.glob("*.json"))
            
            cleaned_count = 0
            for cache_file in cache_files:
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                    
                    cached_time = datetime.fromisoformat(cached_data.get("cached_at", ""))
                    if cached_time.timestamp() < cutoff_time:
                        cache_file.unlink()
                        cleaned_count += 1
                        
                except Exception:
                    # 破損したキャッシュファイルも削除
                    cache_file.unlink()
                    cleaned_count += 1
            
            logger.info(f"キャッシュクリーンアップ完了: {cleaned_count}個のファイルを削除")
            
        except Exception as e:
            logger.error(f"キャッシュクリーンアップエラー: {e}")

# 使用例とテスト用の関数
async def test_advanced_pipeline():
    """進化したパイプラインのテスト"""
    config = PipelineConfig(
        adaptive_config=AdaptiveConfig(
            learning_enabled=True,
            failure_threshold=2,
            memory_limit_mb=2048
        ),
        target_clone_quality=CloneQuality.HIGH,
        enable_parallel_processing=True,
        max_concurrent_analyses=2
    )
    
    pipeline = AdvancedAPKPipeline(config)
    
    # テスト用のAPKパス（実際のファイルパスに置き換えてください）
    test_apks = [
        "test_apk1.apk",
        "test_apk2.apk"
    ]
    
    # 存在するAPKファイルのみをフィルタ
    existing_apks = [apk for apk in test_apks if Path(apk).exists()]
    
    if existing_apks:
        results = await pipeline.process_multiple_apks(existing_apks)
        
        for result in results:
            print(f"APK: {result.apk_path}")
            print(f"成功: {result.success}")
            print(f"品質スコア: {result.quality_score:.2f}")
            print(f"クローン率: {result.clone_rate:.2f}")
            print("---")
    else:
        print("テスト用APKファイルが見つかりません")

if __name__ == "__main__":
    asyncio.run(test_advanced_pipeline())