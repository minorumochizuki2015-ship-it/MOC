"""
Adaptive Analysis Engine - 適応型解析エンジン
失敗事例から学習し、動的に解析戦略を調整するシステム
"""
import os
import json
import logging
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from datetime import datetime, timedelta
import hashlib

from .enhanced_apk_analyzer import EnhancedAPKAnalyzer, AnalysisConfig
from .unity_dll_analyzer import UnityDLLAnalyzer

logger = logging.getLogger(__name__)

class AnalysisStrategy(Enum):
    """解析戦略"""
    CONSERVATIVE = "conservative"  # 保守的（低リソース、高安定性）
    BALANCED = "balanced"         # バランス型（中リソース、中安定性）
    AGGRESSIVE = "aggressive"     # 積極的（高リソース、高精度）
    ADAPTIVE = "adaptive"         # 適応型（動的調整）

class FailureType(Enum):
    """失敗タイプ"""
    MEMORY_LEAK = "memory_leak"
    TIMEOUT = "timeout"
    SQLITE_ERROR = "sqlite_error"
    IMPORT_ERROR = "import_error"
    PATH_ERROR = "path_error"
    PERMISSION_ERROR = "permission_error"
    UNKNOWN = "unknown"

@dataclass
class AnalysisAttempt:
    """解析試行記録"""
    apk_hash: str
    strategy: AnalysisStrategy
    config: Dict[str, Any]
    start_time: datetime
    end_time: Optional[datetime] = None
    success: bool = False
    failure_type: Optional[FailureType] = None
    error_message: Optional[str] = None
    memory_peak_mb: float = 0.0
    duration_seconds: float = 0.0
    result_quality_score: float = 0.0

@dataclass
class AdaptiveConfig:
    """適応型設定"""
    learning_enabled: bool = True
    failure_threshold: int = 3  # 連続失敗回数の閾値
    success_rate_threshold: float = 0.7  # 成功率の閾値
    memory_limit_mb: int = 2048
    timeout_seconds: int = 300
    strategy_switch_cooldown: int = 300  # 戦略切り替えのクールダウン（秒）

class FailureLearningSystem:
    """失敗学習システム"""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        
    def _init_database(self):
        """データベース初期化"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_hash TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    success BOOLEAN NOT NULL,
                    failure_type TEXT,
                    error_message TEXT,
                    memory_peak_mb REAL,
                    duration_seconds REAL,
                    result_quality_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS strategy_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy TEXT NOT NULL,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    avg_duration REAL DEFAULT 0.0,
                    avg_memory_usage REAL DEFAULT 0.0,
                    avg_quality_score REAL DEFAULT 0.0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failure_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    failure_type TEXT NOT NULL,
                    error_pattern TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    recommended_strategy TEXT,
                    recommended_config TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    def record_attempt(self, attempt: AnalysisAttempt):
        """解析試行を記録"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO analysis_attempts 
                    (apk_hash, strategy, config_json, start_time, end_time, success, 
                     failure_type, error_message, memory_peak_mb, duration_seconds, result_quality_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    attempt.apk_hash,
                    attempt.strategy.value,
                    json.dumps(attempt.config),
                    attempt.start_time.isoformat(),
                    attempt.end_time.isoformat() if attempt.end_time else None,
                    attempt.success,
                    attempt.failure_type.value if attempt.failure_type else None,
                    attempt.error_message,
                    attempt.memory_peak_mb,
                    attempt.duration_seconds,
                    attempt.result_quality_score
                ))
                conn.commit()
                
                # 戦略パフォーマンスの更新
                self._update_strategy_performance(attempt)
                
                # 失敗パターンの記録
                if not attempt.success and attempt.failure_type:
                    self._record_failure_pattern(attempt)
                    
        except Exception as e:
            logger.error(f"解析試行記録エラー: {e}")
    
    def _update_strategy_performance(self, attempt: AnalysisAttempt):
        """戦略パフォーマンスの更新"""
        with sqlite3.connect(self.db_path) as conn:
            # 既存レコードの確認
            cursor = conn.execute(
                "SELECT id, success_count, failure_count, avg_duration, avg_memory_usage, avg_quality_score FROM strategy_performance WHERE strategy = ?",
                (attempt.strategy.value,)
            )
            row = cursor.fetchone()
            
            if row:
                # 既存レコードの更新
                record_id, success_count, failure_count, avg_duration, avg_memory, avg_quality = row
                
                if attempt.success:
                    success_count += 1
                else:
                    failure_count += 1
                
                total_attempts = success_count + failure_count
                
                # 移動平均の計算
                new_avg_duration = ((avg_duration * (total_attempts - 1)) + attempt.duration_seconds) / total_attempts
                new_avg_memory = ((avg_memory * (total_attempts - 1)) + attempt.memory_peak_mb) / total_attempts
                new_avg_quality = ((avg_quality * (total_attempts - 1)) + attempt.result_quality_score) / total_attempts
                
                conn.execute("""
                    UPDATE strategy_performance 
                    SET success_count = ?, failure_count = ?, avg_duration = ?, 
                        avg_memory_usage = ?, avg_quality_score = ?, last_updated = ?
                    WHERE id = ?
                """, (success_count, failure_count, new_avg_duration, new_avg_memory, new_avg_quality, datetime.now().isoformat(), record_id))
            else:
                # 新規レコードの作成
                conn.execute("""
                    INSERT INTO strategy_performance 
                    (strategy, success_count, failure_count, avg_duration, avg_memory_usage, avg_quality_score)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    attempt.strategy.value,
                    1 if attempt.success else 0,
                    0 if attempt.success else 1,
                    attempt.duration_seconds,
                    attempt.memory_peak_mb,
                    attempt.result_quality_score
                ))
            
            conn.commit()
    
    def _record_failure_pattern(self, attempt: AnalysisAttempt):
        """失敗パターンの記録"""
        if not attempt.error_message:
            return
        
        # エラーメッセージからパターンを抽出
        error_pattern = self._extract_error_pattern(attempt.error_message)
        
        with sqlite3.connect(self.db_path) as conn:
            # 既存パターンの確認
            cursor = conn.execute(
                "SELECT id, occurrence_count FROM failure_patterns WHERE failure_type = ? AND error_pattern = ?",
                (attempt.failure_type.value, error_pattern)
            )
            row = cursor.fetchone()
            
            if row:
                # 既存パターンの更新
                record_id, occurrence_count = row
                conn.execute("""
                    UPDATE failure_patterns 
                    SET occurrence_count = ?, last_seen = ?
                    WHERE id = ?
                """, (occurrence_count + 1, datetime.now().isoformat(), record_id))
            else:
                # 新規パターンの作成
                recommended_strategy, recommended_config = self._get_failure_recommendations(attempt.failure_type)
                conn.execute("""
                    INSERT INTO failure_patterns 
                    (failure_type, error_pattern, recommended_strategy, recommended_config)
                    VALUES (?, ?, ?, ?)
                """, (attempt.failure_type.value, error_pattern, recommended_strategy, json.dumps(recommended_config)))
            
            conn.commit()
    
    def _extract_error_pattern(self, error_message: str) -> str:
        """エラーメッセージからパターンを抽出"""
        # 一般的なエラーパターンの正規化
        patterns = [
            ("MemoryError", "memory_exhausted"),
            ("TimeoutError", "operation_timeout"),
            ("sqlite3.OperationalError", "sqlite_operational_error"),
            ("ImportError", "import_missing"),
            ("FileNotFoundError", "file_not_found"),
            ("PermissionError", "permission_denied"),
            ("ConnectionError", "connection_failed")
        ]
        
        for pattern, normalized in patterns:
            if pattern in error_message:
                return normalized
        
        # パターンが見つからない場合は最初の50文字を使用
        return error_message[:50]
    
    def _get_failure_recommendations(self, failure_type: FailureType) -> Tuple[str, Dict]:
        """失敗タイプに基づく推奨設定"""
        recommendations = {
            FailureType.MEMORY_LEAK: (
                AnalysisStrategy.CONSERVATIVE.value,
                {"max_memory_mb": 1024, "chunk_size": 512 * 1024, "parallel_workers": 2}
            ),
            FailureType.TIMEOUT: (
                AnalysisStrategy.CONSERVATIVE.value,
                {"timeout_seconds": 600, "enable_deep_il2cpp": False}
            ),
            FailureType.SQLITE_ERROR: (
                AnalysisStrategy.BALANCED.value,
                {"cache_results": False, "enable_memory_optimization": True}
            ),
            FailureType.IMPORT_ERROR: (
                AnalysisStrategy.CONSERVATIVE.value,
                {"enable_dynamic_analysis": False, "enable_deep_il2cpp": False}
            ),
            FailureType.PATH_ERROR: (
                AnalysisStrategy.BALANCED.value,
                {"enable_memory_optimization": True}
            )
        }
        
        return recommendations.get(failure_type, (AnalysisStrategy.CONSERVATIVE.value, {}))
    
    def get_best_strategy(self, apk_hash: str) -> Tuple[AnalysisStrategy, Dict[str, Any]]:
        """最適な戦略を取得"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 過去の成功事例を確認
                cursor = conn.execute("""
                    SELECT strategy, config_json, result_quality_score 
                    FROM analysis_attempts 
                    WHERE apk_hash = ? AND success = 1 
                    ORDER BY result_quality_score DESC, start_time DESC 
                    LIMIT 1
                """, (apk_hash,))
                
                row = cursor.fetchone()
                if row:
                    strategy_str, config_json, quality_score = row
                    return AnalysisStrategy(strategy_str), json.loads(config_json)
                
                # 全体的な戦略パフォーマンスを確認
                cursor = conn.execute("""
                    SELECT strategy, success_count, failure_count, avg_quality_score
                    FROM strategy_performance
                    WHERE success_count > 0
                    ORDER BY (success_count * 1.0 / (success_count + failure_count)) DESC, avg_quality_score DESC
                    LIMIT 1
                """)
                
                row = cursor.fetchone()
                if row:
                    strategy_str, success_count, failure_count, avg_quality = row
                    success_rate = success_count / (success_count + failure_count)
                    
                    if success_rate >= 0.7:  # 70%以上の成功率
                        return AnalysisStrategy(strategy_str), {}
                
        except Exception as e:
            logger.error(f"最適戦略取得エラー: {e}")
        
        # デフォルトはバランス型
        return AnalysisStrategy.BALANCED, {}

class AdaptiveAnalysisEngine:
    """適応型解析エンジン"""
    
    def __init__(self, config: AdaptiveConfig = None):
        logger.info("AdaptiveAnalysisEngine初期化開始")
        
        self.config = config or AdaptiveConfig()
        self.learning_system = FailureLearningSystem("data/adaptive_analysis/learning.db")
        logger.debug("学習システム初期化完了")
        
        # 戦略別の設定テンプレート
        self.strategy_configs = {
            AnalysisStrategy.CONSERVATIVE: AnalysisConfig(
                enable_deep_il2cpp=False,
                enable_dynamic_analysis=False,
                enable_memory_optimization=True,
                max_memory_mb=1024,
                chunk_size=512 * 1024,
                parallel_workers=2,
                timeout_seconds=180
            ),
            AnalysisStrategy.BALANCED: AnalysisConfig(
                enable_deep_il2cpp=True,
                enable_dynamic_analysis=False,
                enable_memory_optimization=True,
                max_memory_mb=2048,
                chunk_size=1024 * 1024,
                parallel_workers=4,
                timeout_seconds=300
            ),
            AnalysisStrategy.AGGRESSIVE: AnalysisConfig(
                enable_deep_il2cpp=True,
                enable_dynamic_analysis=True,
                enable_memory_optimization=False,
                max_memory_mb=4096,
                chunk_size=2048 * 1024,
                parallel_workers=8,
                timeout_seconds=600
            )
        }
        logger.debug(f"戦略設定テンプレート初期化完了: {len(self.strategy_configs)}種類")
        
        self.current_strategy = AnalysisStrategy.BALANCED
        self.last_strategy_switch = datetime.now()
        self.consecutive_failures = 0
        
        logger.info(f"AdaptiveAnalysisEngine初期化完了 - 初期戦略: {self.current_strategy.value}")
    
    def analyze_apk_adaptive(self, apk_path: str) -> Dict[str, Any]:
        """適応型APK解析"""
        logger.info(f"適応型APK解析開始: {apk_path}")
        
        apk_hash = self._calculate_apk_hash(apk_path)
        logger.debug(f"APKハッシュ計算完了: {apk_hash[:16]}...")
        
        # 最適戦略の決定
        if self.config.learning_enabled:
            logger.debug("学習システムから最適戦略を取得中...")
            strategy, custom_config = self.learning_system.get_best_strategy(apk_hash)
            logger.info(f"学習システム推奨戦略: {strategy.value}")
        else:
            strategy = self.current_strategy
            custom_config = {}
            logger.debug(f"現在の戦略を使用: {strategy.value}")
        
        # 設定の準備
        base_config = self.strategy_configs[strategy]
        if custom_config:
            # カスタム設定をマージ
            for key, value in custom_config.items():
                if hasattr(base_config, key):
                    setattr(base_config, key, value)
        
        # 解析試行の記録開始
        attempt = AnalysisAttempt(
            apk_hash=apk_hash,
            strategy=strategy,
            config=asdict(base_config),
            start_time=datetime.now()
        )
        
        logger.info(f"適応型解析開始: {apk_path} (戦略: {strategy.value})")
        
        try:
            # 解析実行
            analyzer = EnhancedAPKAnalyzer(base_config)
            result = analyzer.analyze_apk_enhanced(apk_path)
            
            # 成功時の記録
            attempt.end_time = datetime.now()
            attempt.duration_seconds = (attempt.end_time - attempt.start_time).total_seconds()
            attempt.success = result.get("success", False)
            attempt.memory_peak_mb = analyzer.memory_manager.get_memory_usage()
            attempt.result_quality_score = self._calculate_quality_score(result)
            
            if attempt.success:
                self.consecutive_failures = 0
                logger.info(f"適応型解析成功: 品質スコア {attempt.result_quality_score:.2f}")
            else:
                self.consecutive_failures += 1
                attempt.failure_type = self._classify_failure(result.get("error", ""))
                attempt.error_message = result.get("error", "")
                logger.warning(f"適応型解析失敗: {attempt.error_message}")
            
            # 学習システムに記録
            if self.config.learning_enabled:
                self.learning_system.record_attempt(attempt)
            
            # 戦略の適応的調整
            self._adapt_strategy(attempt)
            
            return result
            
        except Exception as e:
            # 例外時の記録
            attempt.end_time = datetime.now()
            attempt.duration_seconds = (attempt.end_time - attempt.start_time).total_seconds()
            attempt.success = False
            attempt.failure_type = self._classify_failure(str(e))
            attempt.error_message = str(e)
            
            self.consecutive_failures += 1
            
            if self.config.learning_enabled:
                self.learning_system.record_attempt(attempt)
            
            self._adapt_strategy(attempt)
            
            logger.error(f"適応型解析例外: {e}")
            return {
                "success": False,
                "error": str(e),
                "strategy_used": strategy.value,
                "adaptive_info": {
                    "consecutive_failures": self.consecutive_failures,
                    "current_strategy": self.current_strategy.value
                }
            }
    
    def _calculate_apk_hash(self, apk_path: str) -> str:
        """APKファイルのハッシュ計算"""
        logger.debug(f"APKハッシュ計算開始: {apk_path}")
        
        try:
            hash_md5 = hashlib.md5()
            with open(apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            
            hash_value = hash_md5.hexdigest()
            logger.debug(f"APKハッシュ計算完了: {hash_value[:16]}...")
            return hash_value
            
        except Exception as e:
            logger.error(f"APKハッシュ計算エラー: {e}")
            raise
    
    def _calculate_quality_score(self, result: Dict[str, Any]) -> float:
        """解析結果の品質スコア計算"""
        logger.debug("品質スコア計算開始")
        
        if not result.get("success"):
            logger.debug("解析失敗のため品質スコア: 0.0")
            return 0.0
        
        analysis_result = result.get("analysis_result", {})
        score = 0.0
        
        # Unity検出ボーナス
        if analysis_result.get("unity_analysis", {}).get("unity_detected"):
            score += 30.0
            logger.debug("Unity検出ボーナス: +30.0")
        
        # IL2CPP検出ボーナス
        if analysis_result.get("unity_analysis", {}).get("il2cpp_detected"):
            score += 25.0
            logger.debug("IL2CPP検出ボーナス: +25.0")
        
        # IL2CPP詳細解析ボーナス
        if analysis_result.get("il2cpp_analysis", {}).get("dump_result"):
            score += 25.0
            logger.debug("IL2CPP詳細解析ボーナス: +25.0")
        
        # 動的解析ボーナス
        if analysis_result.get("dynamic_analysis") and not analysis_result["dynamic_analysis"].get("error"):
            score += 20.0
            logger.debug("動的解析ボーナス: +20.0")
        
        final_score = min(score, 100.0)  # 最大100点
        logger.debug(f"品質スコア計算完了: {final_score}")
        return final_score
    
    def _classify_failure(self, error_message: str) -> FailureType:
        """エラーメッセージから失敗タイプを分類"""
        logger.debug(f"失敗タイプ分類開始: {error_message[:50]}...")
        
        error_lower = error_message.lower()
        
        if "memory" in error_lower or "memoryerror" in error_lower:
            failure_type = FailureType.MEMORY_LEAK
        elif "timeout" in error_lower or "timeouterror" in error_lower:
            failure_type = FailureType.TIMEOUT
        elif "sqlite" in error_lower:
            failure_type = FailureType.SQLITE_ERROR
        elif "import" in error_lower or "modulenotfounderror" in error_lower:
            failure_type = FailureType.IMPORT_ERROR
        elif "path" in error_lower or "filenotfounderror" in error_lower:
            failure_type = FailureType.PATH_ERROR
        elif "permission" in error_lower:
            failure_type = FailureType.PERMISSION_ERROR
        else:
            failure_type = FailureType.UNKNOWN
        
        logger.debug(f"失敗タイプ分類結果: {failure_type.value}")
        return failure_type
    
    def _adapt_strategy(self, attempt: AnalysisAttempt):
        """戦略の適応的調整"""
        logger.debug("戦略適応調整開始")
        
        now = datetime.now()
        
        # クールダウン期間中は調整しない
        cooldown_remaining = self.config.strategy_switch_cooldown - (now - self.last_strategy_switch).total_seconds()
        if cooldown_remaining > 0:
            logger.debug(f"戦略切り替えクールダウン中: 残り{cooldown_remaining:.1f}秒")
            return
        
        # 連続失敗による戦略調整
        if self.consecutive_failures >= self.config.failure_threshold:
            logger.warning(f"連続失敗数が閾値に到達: {self.consecutive_failures}/{self.config.failure_threshold}")
            
            if self.current_strategy == AnalysisStrategy.AGGRESSIVE:
                self.current_strategy = AnalysisStrategy.BALANCED
                logger.info("戦略をAGGRESSIVEからBALANCEDに変更")
            elif self.current_strategy == AnalysisStrategy.BALANCED:
                self.current_strategy = AnalysisStrategy.CONSERVATIVE
                logger.info("戦略をBALANCEDからCONSERVATIVEに変更")
            else:
                logger.debug("既にCONSERVATIVE戦略のため変更なし")
            
            self.last_strategy_switch = now
            self.consecutive_failures = 0
        
        # 成功による戦略調整（より積極的に）
        elif attempt.success and attempt.result_quality_score >= 80.0:
            logger.info(f"高品質解析成功により戦略昇格検討: スコア{attempt.result_quality_score:.2f}")
            
            if self.current_strategy == AnalysisStrategy.CONSERVATIVE:
                self.current_strategy = AnalysisStrategy.BALANCED
                logger.info("戦略をCONSERVATIVEからBALANCEDに変更")
            elif self.current_strategy == AnalysisStrategy.BALANCED:
                self.current_strategy = AnalysisStrategy.AGGRESSIVE
                logger.info("戦略をBALANCEDからAGGRESSIVEに変更")
            else:
                logger.debug("既にAGGRESSIVE戦略のため変更なし")
            
            self.last_strategy_switch = now
        else:
            logger.debug("戦略調整条件に該当せず")
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """学習統計の取得"""
        logger.debug("学習統計取得開始")
        
        try:
            with sqlite3.connect(self.learning_system.db_path) as conn:
                # 戦略別統計
                cursor = conn.execute("""
                    SELECT strategy, success_count, failure_count, avg_quality_score
                    FROM strategy_performance
                    ORDER BY (success_count * 1.0 / (success_count + failure_count)) DESC
                """)
                
                strategy_stats = []
                for row in cursor.fetchall():
                    strategy, success, failure, quality = row
                    total = success + failure
                    success_rate = success / total if total > 0 else 0
                    
                    strategy_stats.append({
                        "strategy": strategy,
                        "success_rate": success_rate,
                        "total_attempts": total,
                        "avg_quality_score": quality
                    })
                
                logger.debug(f"戦略統計取得完了: {len(strategy_stats)}件")
                
                # 失敗パターン統計
                cursor = conn.execute("""
                    SELECT failure_type, COUNT(*) as count
                    FROM failure_patterns
                    GROUP BY failure_type
                    ORDER BY count DESC
                """)
                
                failure_stats = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]
                logger.debug(f"失敗パターン統計取得完了: {len(failure_stats)}件")
                
                stats = {
                    "strategy_performance": strategy_stats,
                    "failure_patterns": failure_stats,
                    "current_strategy": self.current_strategy.value,
                    "consecutive_failures": self.consecutive_failures
                }
                
                logger.info("学習統計取得成功")
                return stats
                
        except Exception as e:
            logger.error(f"学習統計取得エラー: {e}")
            return {"error": str(e)}