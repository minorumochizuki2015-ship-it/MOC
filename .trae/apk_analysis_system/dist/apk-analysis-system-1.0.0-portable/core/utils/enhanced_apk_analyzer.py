"""
Enhanced APK Analyzer - 進化したAPK解析システム
メモリ効率化、動的解析機能、IL2CPP深層解析を統合
"""
import os
import gc
import json
import logging
import threading
import time
import weakref
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import zipfile
import tempfile
import shutil
import sqlite3
import psutil

from .unity_dll_analyzer import UnityDLLAnalyzer
from .il2cpp_dumper_integration import Il2CppDumperIntegration
from .frida_script_generator import FridaScriptGenerator
from .dynamic_analysis_system import DynamicAnalysisSystem

logger = logging.getLogger(__name__)

@dataclass
class AnalysisConfig:
    """解析設定"""
    enable_deep_il2cpp: bool = True
    enable_dynamic_analysis: bool = False
    enable_memory_optimization: bool = True
    max_memory_mb: int = 2048
    chunk_size: int = 1024 * 1024  # 1MB chunks
    parallel_workers: int = 4
    cache_results: bool = True
    timeout_seconds: int = 300

class MemoryManager:
    """メモリ管理クラス - メモリリーク防止"""
    
    def __init__(self, max_memory_mb: int = 2048):
        self.max_memory_mb = max_memory_mb
        self.tracked_objects = weakref.WeakSet()
        self._lock = threading.Lock()
        
    def track_object(self, obj):
        """オブジェクトの追跡"""
        with self._lock:
            self.tracked_objects.add(obj)
    
    def get_memory_usage(self) -> float:
        """現在のメモリ使用量（MB）"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def check_memory_limit(self) -> bool:
        """メモリ制限チェック"""
        current_mb = self.get_memory_usage()
        if current_mb > self.max_memory_mb:
            logger.warning(f"メモリ使用量が制限を超過: {current_mb:.1f}MB > {self.max_memory_mb}MB")
            self.force_gc()
            return False
        return True
    
    def force_gc(self):
        """強制ガベージコレクション"""
        logger.info("強制ガベージコレクションを実行中...")
        gc.collect()
        
    @contextmanager
    def memory_context(self):
        """メモリ管理コンテキスト"""
        initial_memory = self.get_memory_usage()
        try:
            yield
        finally:
            final_memory = self.get_memory_usage()
            if final_memory > initial_memory + 100:  # 100MB以上増加
                logger.warning(f"メモリ使用量が大幅増加: {initial_memory:.1f}MB -> {final_memory:.1f}MB")
                self.force_gc()

class DatabaseManager:
    """SQLiteデータベース管理 - 接続エラー対策"""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection_pool = []
        self._lock = threading.Lock()
        
    @contextmanager
    def get_connection(self):
        """堅牢なデータベース接続"""
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
        except sqlite3.Error as e:
            logger.error(f"データベース接続エラー: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def init_tables(self):
        """テーブル初期化"""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_path TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    result_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def save_result(self, apk_path: str, analysis_type: str, result_data: Dict):
        """結果保存（エラー処理付き）"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.get_connection() as conn:
                    conn.execute(
                        "INSERT INTO analysis_results (apk_path, analysis_type, result_data) VALUES (?, ?, ?)",
                        (apk_path, analysis_type, json.dumps(result_data))
                    )
                    conn.commit()
                    return True
            except sqlite3.Error as e:
                logger.warning(f"データベース保存試行 {attempt + 1}/{max_retries} 失敗: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"データベース保存に完全に失敗: {e}")
                    return False
                time.sleep(1)  # リトライ前の待機
        return False

class EnhancedAPKAnalyzer:
    """進化したAPK解析システム"""
    
    def __init__(self, config: AnalysisConfig = None):
        logger.info("EnhancedAPKAnalyzer初期化開始")
        
        self.config = config or AnalysisConfig()
        logger.debug(f"解析設定: {self.config.__dict__}")
        
        self.memory_manager = MemoryManager(self.config.max_memory_mb)
        logger.debug(f"メモリ管理システム初期化: 最大メモリ {self.config.max_memory_mb}MB")
        
        # 出力ディレクトリの設定
        self.output_dir = Path("data/enhanced_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"出力ディレクトリ設定: {self.output_dir}")
        
        # データベース管理
        logger.debug("データベース管理システム初期化中...")
        self.db_manager = DatabaseManager(self.output_dir / "analysis_cache.db")
        self.db_manager.init_tables()
        logger.debug("データベース管理システム初期化完了")
        
        # 解析コンポーネント
        logger.debug("解析コンポーネント初期化中...")
        self.unity_analyzer = UnityDLLAnalyzer(str(self.output_dir / "unity"))
        self.il2cpp_dumper = Il2CppDumperIntegration(str(self.output_dir / "il2cpp"))
        self.frida_generator = FridaScriptGenerator(str(self.output_dir / "frida"))
        logger.debug("解析コンポーネント初期化完了")
        
        if self.config.enable_dynamic_analysis:
            logger.debug("動的解析システム初期化中...")
            self.dynamic_analyzer = DynamicAnalysisSystem(str(self.output_dir / "dynamic"))
            logger.debug("動的解析システム初期化完了")
        else:
            logger.debug("動的解析システムは無効化されています")
        
        # 解析結果
        self.analysis_result = {
            "config": self.config.__dict__,
            "memory_stats": {},
            "static_analysis": {},
            "unity_analysis": {},
            "il2cpp_analysis": {},
            "dynamic_analysis": {},
            "implementation_hints": [],
            "performance_metrics": {}
        }
        logger.debug("解析結果構造を初期化")
        
        logger.info("EnhancedAPKAnalyzer初期化完了")
    
    def analyze_apk_enhanced(self, apk_path: str) -> Dict[str, Any]:
        """進化した包括的APK解析"""
        start_time = time.time()
        
        logger.info(f"Enhanced APK解析開始: {apk_path}")
        
        # APKファイルの存在確認
        if not Path(apk_path).exists():
            logger.error(f"APKファイルが見つかりません: {apk_path}")
            return {
                "success": False,
                "error": f"APKファイルが見つかりません: {apk_path}",
                "partial_result": self.analysis_result
            }
        
        # ファイルサイズ確認
        file_size = Path(apk_path).stat().st_size
        logger.info(f"APKファイルサイズ: {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")
        
        with self.memory_manager.memory_context():
            try:
                # Phase 1: 基本解析（メモリ効率化）
                logger.info("Phase 1: 基本解析開始")
                phase1_start = time.time()
                self._phase1_basic_analysis(apk_path)
                phase1_time = time.time() - phase1_start
                logger.info(f"Phase 1完了: {phase1_time:.2f}秒")
                
                # Phase 2: Unity深層解析
                logger.info("Phase 2: Unity深層解析開始")
                phase2_start = time.time()
                self._phase2_unity_deep_analysis(apk_path)
                phase2_time = time.time() - phase2_start
                logger.info(f"Phase 2完了: {phase2_time:.2f}秒")
                
                # Phase 3: IL2CPP詳細解析
                if self.config.enable_deep_il2cpp:
                    logger.info("Phase 3: IL2CPP詳細解析開始")
                    phase3_start = time.time()
                    self._phase3_il2cpp_deep_analysis()
                    phase3_time = time.time() - phase3_start
                    logger.info(f"Phase 3完了: {phase3_time:.2f}秒")
                else:
                    logger.debug("IL2CPP詳細解析はスキップされました")
                    phase3_time = 0
                
                # Phase 4: 動的解析（オプション）
                if self.config.enable_dynamic_analysis:
                    logger.info("Phase 4: 動的解析開始")
                    phase4_start = time.time()
                    self._phase4_dynamic_analysis(apk_path)
                    phase4_time = time.time() - phase4_start
                    logger.info(f"Phase 4完了: {phase4_time:.2f}秒")
                else:
                    logger.debug("動的解析はスキップされました")
                    phase4_time = 0
                
                # Phase 5: 結果統合と最適化
                logger.info("Phase 5: 結果統合と最適化開始")
                phase5_start = time.time()
                self._phase5_result_integration()
                phase5_time = time.time() - phase5_start
                logger.info(f"Phase 5完了: {phase5_time:.2f}秒")
                
                # パフォーマンス統計
                end_time = time.time()
                total_time = end_time - start_time
                peak_memory = self.memory_manager.get_memory_usage()
                
                self.analysis_result["performance_metrics"] = {
                    "total_time_seconds": total_time,
                    "peak_memory_mb": peak_memory,
                    "phases_completed": 5,
                    "phase_times": {
                        "phase1_basic": phase1_time,
                        "phase2_unity": phase2_time,
                        "phase3_il2cpp": phase3_time,
                        "phase4_dynamic": phase4_time,
                        "phase5_integration": phase5_time
                    }
                }
                
                logger.info(f"Enhanced APK解析完了 - 実行時間: {total_time:.2f}秒, ピークメモリ: {peak_memory:.1f}MB")
                
                # 結果保存
                if self.config.cache_results:
                    logger.debug("解析結果をキャッシュに保存中...")
                    self.db_manager.save_result(apk_path, "enhanced_analysis", self.analysis_result)
                    logger.debug("解析結果のキャッシュ保存完了")
                
                # 統計情報のログ出力
                static_files = len(self.analysis_result.get("static_analysis", {}))
                unity_components = len(self.analysis_result.get("unity_analysis", {}))
                il2cpp_classes = len(self.analysis_result.get("il2cpp_analysis", {}).get("game_logic", {}).get("classes", []))
                
                logger.info(f"解析統計: 静的ファイル={static_files}, Unity要素={unity_components}, IL2CPPクラス={il2cpp_classes}")
                
                return {
                    "success": True,
                    "analysis_result": self.analysis_result
                }
                
            except Exception as e:
                logger.error(f"Enhanced APK解析エラー: {e}", exc_info=True)
                return {
                    "success": False,
                    "error": str(e),
                    "partial_result": self.analysis_result
                }
    
    def _phase1_basic_analysis(self, apk_path: str):
        """Phase 1: 基本解析（メモリ効率化）"""
        logger.info("Phase 1: 基本解析（メモリ効率化）開始")
        
        try:
            # チャンク単位でAPKを解析
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                logger.debug(f"APK内ファイル数: {len(file_list)}")
                
                # ファイルを種類別に分類
                categorized_files = self._categorize_files(file_list)
                logger.debug(f"ファイル分類結果: {[(cat, len(files)) for cat, files in categorized_files.items()]}")
                
                # 並列処理で効率的に解析
                logger.debug(f"並列ワーカー数: {self.config.parallel_workers}")
                with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
                    futures = []
                    
                    for category, files in categorized_files.items():
                        if not self.memory_manager.check_memory_limit():
                            logger.warning("メモリ制限によりファイル解析を制限")
                            break
                        
                        logger.debug(f"カテゴリ '{category}' の解析を開始: {len(files)}ファイル")
                        future = executor.submit(self._analyze_file_category, apk_zip, category, files)
                        futures.append(future)
                    
                    # 結果収集
                    completed_categories = 0
                    for future in as_completed(futures):
                        try:
                            category_result = future.result(timeout=60)
                            self.analysis_result["static_analysis"].update(category_result)
                            completed_categories += 1
                            logger.debug(f"カテゴリ解析完了: {completed_categories}/{len(futures)}")
                        except Exception as e:
                            logger.error(f"ファイルカテゴリ解析エラー: {e}")
                    
                    logger.info(f"Phase 1完了: {completed_categories}カテゴリを解析")
        
        except Exception as e:
            logger.error(f"Phase 1基本解析エラー: {e}", exc_info=True)
            raise
    
    def _phase2_unity_deep_analysis(self, apk_path: str):
        """Phase 2: Unity深層解析"""
        logger.info("Phase 2: Unity深層解析開始")
        
        try:
            # Unity解析実行
            logger.debug("Unity解析を実行中...")
            unity_result = self.unity_analyzer.analyze_apk_for_unity(apk_path)
            self.analysis_result["unity_analysis"] = unity_result
            
            unity_detected = unity_result.get("unity_detected", False)
            il2cpp_detected = unity_result.get("il2cpp_detected", False)
            logger.info(f"Unity検出結果: Unity={unity_detected}, IL2CPP={il2cpp_detected}")
            
            # IL2CPPメタデータの詳細解析
            if unity_result.get("il2cpp_metadata"):
                logger.debug("IL2CPPメタデータの詳細解析を開始")
                self._analyze_il2cpp_metadata_deep(unity_result["il2cpp_metadata"])
                logger.debug("IL2CPPメタデータの詳細解析完了")
            else:
                logger.debug("IL2CPPメタデータが見つかりません")
            
            # ネイティブライブラリの詳細解析
            if unity_result.get("assembly_info"):
                logger.debug("ネイティブライブラリの詳細解析を開始")
                self._analyze_native_libraries_deep(unity_result["assembly_info"])
                logger.debug("ネイティブライブラリの詳細解析完了")
            else:
                logger.debug("アセンブリ情報が見つかりません")
            
            logger.info("Phase 2: Unity深層解析完了")
        
        except Exception as e:
            logger.error(f"Phase 2 Unity深層解析エラー: {e}", exc_info=True)
            raise
    
    def _phase3_il2cpp_deep_analysis(self):
        """Phase 3: IL2CPP詳細解析"""
        logger.info("Phase 3: IL2CPP詳細解析開始")
        
        try:
            unity_analysis = self.analysis_result.get("unity_analysis", {})
            assembly_info = unity_analysis.get("assembly_info", {})
            
            # libil2cpp.soとメタデータファイルを特定
            libil2cpp_path = None
            metadata_path = None
            
            logger.debug("libil2cpp.soファイルを検索中...")
            for file_path, info in assembly_info.items():
                if "libil2cpp.so" in file_path:
                    libil2cpp_path = file_path
                    logger.debug(f"libil2cpp.soを発見: {file_path}")
                    break
            
            logger.debug("global-metadata.datファイルを検索中...")
            il2cpp_metadata = unity_analysis.get("il2cpp_metadata", {})
            for file_path, info in il2cpp_metadata.items():
                if "global-metadata.dat" in file_path:
                    metadata_path = file_path
                    logger.debug(f"global-metadata.datを発見: {file_path}")
                    break
            
            if libil2cpp_path and metadata_path:
                logger.info(f"IL2CPP解析対象ファイル: libil2cpp={libil2cpp_path}, metadata={metadata_path}")
                try:
                    # Il2CppDumperを使用した詳細解析
                    logger.debug("Il2CppDumperによるメタデータダンプを開始")
                    il2cpp_result = self.il2cpp_dumper.dump_il2cpp_metadata(
                        libil2cpp_path, metadata_path
                    )
                    logger.debug("Il2CppDumperによるメタデータダンプ完了")
                    
                    # ゲームロジック抽出
                    logger.debug("ゲームロジック抽出を開始")
                    game_logic = self.il2cpp_dumper.extract_game_logic()
                    logger.debug("ゲームロジック抽出完了")
                    
                    self.analysis_result["il2cpp_analysis"] = {
                        "dump_result": il2cpp_result,
                        "game_logic": game_logic
                    }
                    
                    # 統計情報のログ出力
                    classes_count = len(game_logic.get("classes", []))
                    methods_count = sum(len(cls.get("methods", [])) for cls in game_logic.get("classes", []))
                    logger.info(f"IL2CPP解析結果: クラス数={classes_count}, メソッド数={methods_count}")
                    
                except Exception as e:
                    logger.error(f"IL2CPP詳細解析エラー: {e}", exc_info=True)
                    self.analysis_result["il2cpp_analysis"] = {"error": str(e)}
            else:
                missing_files = []
                if not libil2cpp_path:
                    missing_files.append("libil2cpp.so")
                if not metadata_path:
                    missing_files.append("global-metadata.dat")
                logger.warning(f"IL2CPP解析に必要なファイルが見つかりません: {', '.join(missing_files)}")
                self.analysis_result["il2cpp_analysis"] = {"error": f"必要なファイルが見つかりません: {', '.join(missing_files)}"}
            
            logger.info("Phase 3: IL2CPP詳細解析完了")
        
        except Exception as e:
            logger.error(f"Phase 3 IL2CPP詳細解析エラー: {e}", exc_info=True)
            raise
    
    def _phase4_dynamic_analysis(self, apk_path: str):
        """Phase 4: 動的解析（オプション）"""
        logger.info("Phase 4: 動的解析開始")
        
        if not hasattr(self, 'dynamic_analyzer'):
            logger.warning("動的解析システムが初期化されていません")
            return
        
        try:
            # Fridaスクリプト生成
            logger.debug("Fridaスクリプト生成を開始")
            frida_scripts = self._generate_enhanced_frida_scripts()
            script_count = len(frida_scripts)
            logger.debug(f"Fridaスクリプト生成完了: {script_count}スクリプト")
            
            # 動的解析実行（タイムアウト付き）
            logger.info(f"動的解析実行開始 (タイムアウト: {self.config.timeout_seconds}秒)")
            dynamic_result = self.dynamic_analyzer.analyze_with_timeout(
                apk_path, 
                frida_scripts,
                timeout=self.config.timeout_seconds
            )
            
            self.analysis_result["dynamic_analysis"] = dynamic_result
            
            # 動的解析結果の統計
            if dynamic_result.get("success"):
                api_calls = len(dynamic_result.get("api_calls", []))
                memory_samples = len(dynamic_result.get("memory_samples", []))
                network_samples = len(dynamic_result.get("network_samples", []))
                logger.info(f"動的解析結果: API呼び出し={api_calls}, メモリサンプル={memory_samples}, ネットワークサンプル={network_samples}")
            else:
                logger.warning(f"動的解析が失敗しました: {dynamic_result.get('error', '不明なエラー')}")
            
            logger.info("Phase 4: 動的解析完了")
            
        except Exception as e:
            logger.error(f"Phase 4動的解析エラー: {e}", exc_info=True)
            self.analysis_result["dynamic_analysis"] = {"error": str(e)}
    
    def _phase5_result_integration(self):
        """Phase 5: 結果統合と最適化"""
        logger.info("Phase 5: 結果統合と最適化開始")
        
        try:
            # 実装ヒントの生成
            logger.debug("実装ヒント生成を開始")
            hints = self._generate_enhanced_hints()
            self.analysis_result["implementation_hints"] = hints
            logger.debug(f"実装ヒント生成完了: {len(hints)}件")
            
            # メモリ統計の記録
            logger.debug("メモリ統計を記録中")
            peak_memory = self.memory_manager.get_memory_usage()
            tracked_objects = len(self.memory_manager.tracked_objects)
            self.analysis_result["memory_stats"] = {
                "peak_usage_mb": peak_memory,
                "tracked_objects": tracked_objects
            }
            logger.debug(f"メモリ統計: ピーク使用量={peak_memory:.1f}MB, 追跡オブジェクト={tracked_objects}")
            
            # 結果の最適化（不要なデータの削除）
            logger.debug("結果サイズ最適化を開始")
            self._optimize_result_size()
            logger.debug("結果サイズ最適化完了")
            
            logger.info("Phase 5: 結果統合と最適化完了")
        
        except Exception as e:
            logger.error(f"Phase 5結果統合エラー: {e}", exc_info=True)
            raise
    
    def _categorize_files(self, file_list: List[str]) -> Dict[str, List[str]]:
        """ファイルを種類別に分類"""
        logger.debug(f"ファイル分類開始: {len(file_list)}ファイル")
        
        categories = {
            "manifest": [],
            "resources": [],
            "assets": [],
            "native_libs": [],
            "dex_files": [],
            "other": []
        }
        
        for file_path in file_list:
            if file_path == "AndroidManifest.xml":
                categories["manifest"].append(file_path)
            elif file_path.startswith("res/"):
                categories["resources"].append(file_path)
            elif file_path.startswith("assets/"):
                categories["assets"].append(file_path)
            elif file_path.startswith("lib/") and file_path.endswith(".so"):
                categories["native_libs"].append(file_path)
            elif file_path.endswith(".dex"):
                categories["dex_files"].append(file_path)
            else:
                categories["other"].append(file_path)
        
        # 分類結果のログ出力
        for category, files in categories.items():
            if files:
                logger.debug(f"カテゴリ '{category}': {len(files)}ファイル")
        
        logger.debug("ファイル分類完了")
        return categories
    
    def _analyze_file_category(self, apk_zip: zipfile.ZipFile, category: str, files: List[str]) -> Dict:
        """ファイルカテゴリの解析"""
        logger.debug(f"カテゴリ解析開始: {category} ({len(files)}ファイル)")
        
        result = {category: {"files": len(files), "details": []}}
        
        # メモリ制限チェック
        if not self.memory_manager.check_memory_limit():
            logger.warning(f"メモリ制限によりカテゴリ解析をスキップ: {category}")
            return result
        
        try:
            # カテゴリ別の詳細解析
            if category == "native_libs":
                logger.debug(f"ネイティブライブラリ解析開始: {len(files)}ファイル")
                result[category]["details"] = self._analyze_native_libs_basic(apk_zip, files)
                logger.debug(f"ネイティブライブラリ解析完了: {len(result[category]['details'])}件")
            elif category == "assets":
                logger.debug(f"アセット解析開始: {len(files)}ファイル")
                result[category]["details"] = self._analyze_assets_basic(apk_zip, files)
                logger.debug(f"アセット解析完了: {len(result[category]['details'])}件")
            elif category == "resources":
                logger.debug(f"リソース解析開始: {len(files)}ファイル")
                result[category]["details"] = self._analyze_resources_basic(apk_zip, files)
                logger.debug(f"リソース解析完了: {len(result[category]['details'])}件")
            
            logger.debug(f"カテゴリ解析完了: {category}")
        except Exception as e:
            logger.error(f"カテゴリ解析エラー {category}: {e}")
            result[category]["error"] = str(e)
        
        return result
    
    def _analyze_native_libs_basic(self, apk_zip: zipfile.ZipFile, files: List[str]) -> List[Dict]:
        """ネイティブライブラリの基本解析"""
        logger.debug(f"ネイティブライブラリ基本解析開始: {len(files)}ファイル")
        
        libs = []
        unity_libs = 0
        
        for lib_path in files:
            try:
                info = apk_zip.getinfo(lib_path)
                is_unity = "unity" in lib_path.lower() or "il2cpp" in lib_path.lower()
                if is_unity:
                    unity_libs += 1
                
                libs.append({
                    "path": lib_path,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "is_unity": is_unity
                })
            except Exception as e:
                logger.warning(f"ネイティブライブラリ解析エラー {lib_path}: {e}")
        
        logger.debug(f"ネイティブライブラリ基本解析完了: {len(libs)}件 (Unity関連: {unity_libs}件)")
        return libs
    
    def _analyze_assets_basic(self, apk_zip: zipfile.ZipFile, files: List[str]) -> List[Dict]:
        """アセットファイルの基本解析"""
        logger.debug(f"アセット基本解析開始: {len(files)}ファイル")
        
        assets = []
        unity_assets = 0
        
        for asset_path in files:
            try:
                info = apk_zip.getinfo(asset_path)
                is_unity_asset = any(ext in asset_path.lower() for ext in ['.unity3d', '.asset', '.bundle'])
                if is_unity_asset:
                    unity_assets += 1
                
                assets.append({
                    "path": asset_path,
                    "size": info.file_size,
                    "is_unity_asset": is_unity_asset
                })
            except Exception as e:
                logger.warning(f"アセット解析エラー {asset_path}: {e}")
        
        logger.debug(f"アセット基本解析完了: {len(assets)}件 (Unity関連: {unity_assets}件)")
        return assets
    
    def _analyze_resources_basic(self, apk_zip: zipfile.ZipFile, files: List[str]) -> List[Dict]:
        """リソースファイルの基本解析"""
        logger.debug(f"リソース基本解析開始: {len(files)}ファイル")
        
        resources = []
        type_counts = {}
        
        for res_path in files:
            try:
                info = apk_zip.getinfo(res_path)
                file_type = res_path.split('/')[-1].split('.')[-1] if '.' in res_path else "unknown"
                type_counts[file_type] = type_counts.get(file_type, 0) + 1
                
                resources.append({
                    "path": res_path,
                    "size": info.file_size,
                    "type": file_type
                })
            except Exception as e:
                logger.warning(f"リソース解析エラー {res_path}: {e}")
        
        logger.debug(f"リソース基本解析完了: {len(resources)}件 (タイプ別: {type_counts})")
        return resources
    
    def _analyze_il2cpp_metadata_deep(self, metadata_info: Dict):
        """IL2CPPメタデータの深層解析"""
        logger.info("IL2CPPメタデータ深層解析開始...")
        
        analyzed_files = 0
        
        for file_path, info in metadata_info.items():
            if info.get("is_valid_metadata"):
                analyzed_files += 1
                # メタデータバージョン別の詳細解析
                version = info.get("version", 0)
                if version >= 29:  # Unity 2022.3+
                    logger.info(f"新しいIL2CPPメタデータ形式を検出: v{version} ({file_path})")
                    # 新形式の詳細解析ロジック
                elif version >= 24:  # Unity 2019.4+
                    logger.info(f"中間のIL2CPPメタデータ形式を検出: v{version} ({file_path})")
                    # 中間形式の詳細解析ロジック
                else:
                    logger.info(f"古いIL2CPPメタデータ形式を検出: v{version} ({file_path})")
                    # 古い形式の詳細解析ロジック
        
        logger.info(f"IL2CPPメタデータ深層解析完了: {analyzed_files}ファイル解析")
    
    def _analyze_native_libraries_deep(self, assembly_info: Dict):
        """ネイティブライブラリの深層解析"""
        logger.info("ネイティブライブラリ深層解析開始...")
        
        analyzed_libs = 0
        arch_counts = {}
        
        for lib_path, info in assembly_info.items():
            if info.get("type") == "native_library":
                analyzed_libs += 1
                # アーキテクチャ別の最適化ヒント
                arch = info.get("architecture", {}).get("architecture", "unknown")
                arch_counts[arch] = arch_counts.get(arch, 0) + 1
                
                if arch == "AArch64":
                    logger.debug(f"ARM64ライブラリを検出: {lib_path}")
                    # ARM64特有の解析ロジック
                elif arch == "x86_64":
                    logger.debug(f"x64ライブラリを検出: {lib_path}")
                    # x64特有の解析ロジック
        
        logger.info(f"ネイティブライブラリ深層解析完了: {analyzed_libs}ライブラリ解析 (アーキテクチャ別: {arch_counts})")
    
    def _generate_enhanced_frida_scripts(self) -> Dict[str, str]:
        """強化されたFridaスクリプト生成"""
        logger.debug("強化Fridaスクリプト生成開始...")
        
        scripts = {}
        
        unity_analysis = self.analysis_result.get("unity_analysis", {})
        
        # IL2CPPフックスクリプト
        if unity_analysis.get("il2cpp_detected"):
            logger.debug("IL2CPPフックスクリプト生成中...")
            symbols = unity_analysis.get("symbols", [])
            scripts["il2cpp_hook"] = self.frida_generator.generate_il2cpp_hook_script(
                symbols,
                "com.example.app"  # パッケージ名は実際の値に置き換え
            )
            logger.debug(f"IL2CPPフックスクリプト生成完了 ({len(symbols)}シンボル)")
        
        # メモリ監視スクリプト
        logger.debug("メモリ監視スクリプト生成中...")
        scripts["memory_monitor"] = self.frida_generator.generate_memory_monitor_script(
            "com.example.app"
        )
        logger.debug("メモリ監視スクリプト生成完了")
        
        logger.debug(f"強化Fridaスクリプト生成完了: {len(scripts)}スクリプト")
        return scripts
    
    def _generate_enhanced_hints(self) -> List[str]:
        """強化された実装ヒント生成"""
        logger.debug("強化実装ヒント生成開始...")
        
        hints = []
        
        unity_analysis = self.analysis_result.get("unity_analysis", {})
        il2cpp_analysis = self.analysis_result.get("il2cpp_analysis", {})
        
        # Unity検出ヒント
        if unity_analysis.get("unity_detected"):
            hints.append("Unity IL2CPPアプリケーションが検出されました")
            logger.debug("Unity検出ヒントを追加")
            
            # IL2CPP詳細㒲ント
            if il2cpp_analysis.get("dump_result"):
                hints.append("Il2CppDumperによる詳細解析が完了しました")
                hints.append("C#コードの復元が可能です")
                logger.debug("IL2CPP詳細㒲ントを追加")
            
            # メモリ最適化ヒント
            memory_usage = self.analysis_result.get("memory_stats", {}).get("peak_usage_mb", 0)
            if memory_usage > 1000:
                hints.append(f"高メモリ使用量を検出: {memory_usage:.1f}MB")
                hints.append("メモリ効率化が推奨されます")
                logger.debug(f"メモリ最適化ヒントを追加 (使用量: {memory_usage:.1f}MB)")
        
        # 動的解析ヒント
        if self.analysis_result.get("dynamic_analysis"):
            hints.append("動的解析データが利用可能です")
            hints.append("ランタイム動作の詳細な分析が可能です")
            logger.debug("動的解析ヒントを追加")
        
        logger.debug(f"強化実装ヒント生成完了: {len(hints)}件")
        return hints
    
    def _optimize_result_size(self):
        """結果サイズの最適化"""
        logger.debug("結果サイズ最適化開始...")
        
        original_size = 0
        optimized_size = 0
        
        # 大きなデータ構造の圧縮
        if "unity_analysis" in self.analysis_result:
            unity_data = self.analysis_result["unity_analysis"]
            
            # 文字列データの制限
            if "strings" in unity_data and len(unity_data["strings"]) > 1000:
                original_strings = len(unity_data["strings"])
                unity_data["strings"] = unity_data["strings"][:1000]
                unity_data["strings_truncated"] = True
                logger.debug(f"文字列データを制限: {original_strings} -> 1000")
            
            # シンボルデータの制限
            if "symbols" in unity_data and len(unity_data["symbols"]) > 500:
                original_symbols = len(unity_data["symbols"])
                unity_data["symbols"] = unity_data["symbols"][:500]
                unity_data["symbols_truncated"] = True
                logger.debug(f"シンボルデータを制限: {original_symbols} -> 500")
        
        logger.debug("結果サイズ最適化完了")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """解析結果のサマリー"""
        logger.debug("解析サマリー生成中...")
        
        summary = {
            "unity_detected": self.analysis_result.get("unity_analysis", {}).get("unity_detected", False),
            "il2cpp_detected": self.analysis_result.get("unity_analysis", {}).get("il2cpp_detected", False),
            "dynamic_analysis_enabled": self.config.enable_dynamic_analysis,
            "memory_optimized": self.config.enable_memory_optimization,
            "performance_metrics": self.analysis_result.get("performance_metrics", {}),
            "implementation_hints_count": len(self.analysis_result.get("implementation_hints", []))
        }
        
        logger.debug(f"解析サマリー生成完了: Unity={summary['unity_detected']}, IL2CPP={summary['il2cpp_detected']}, ヒント={summary['implementation_hints_count']}件")
        return summary