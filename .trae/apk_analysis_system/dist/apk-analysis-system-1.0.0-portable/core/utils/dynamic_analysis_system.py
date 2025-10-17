"""
動的解析システム - リアルタイムメモリ監視とAPI呼び出しトレース
"""
import os
import json
import logging
import threading
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import queue
import psutil

logger = logging.getLogger(__name__)

class DynamicAnalysisSystem:
    """リアルタイム動的解析システム"""
    
    def __init__(self, output_dir: str = "data/dynamic_analysis"):
        logger.info(f"DynamicAnalysisSystem初期化開始: output_dir={output_dir}")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"出力ディレクトリ作成完了: {self.output_dir}")
        
        self.is_monitoring = False
        self.monitoring_threads = []
        self.data_queue = queue.Queue()
        logger.debug("監視スレッドとデータキューを初期化")
        
        # 監視データ
        self.monitoring_data = {
            "memory_usage": [],
            "api_calls": [],
            "network_activity": [],
            "file_operations": [],
            "game_events": []
        }
        logger.debug("監視データ構造を初期化")
        
        # Fridaプロセス
        self.frida_process = None
        self.target_package = None
        
        logger.info("DynamicAnalysisSystem初期化完了")
    
    def start_monitoring(self, package_name: str, frida_script_path: str) -> bool:
        """動的監視を開始"""
        logger.info(f"動的監視開始要求: package={package_name}, script={frida_script_path}")
        
        if not package_name:
            logger.error("パッケージ名が空です")
            return False
        
        if not Path(frida_script_path).exists():
            logger.error(f"Fridaスクリプトファイルが見つかりません: {frida_script_path}")
            return False
        
        if self.is_monitoring:
            logger.warning("既に監視が実行中です。停止してから再開してください")
            return False
        
        try:
            self.target_package = package_name
            self.is_monitoring = True
            logger.debug("監視フラグを有効化")
            
            # Fridaスクリプトの実行
            logger.info("Frida監視を開始中...")
            self._start_frida_monitoring(frida_script_path)
            
            # メモリ監視スレッドの開始
            logger.debug("メモリ監視スレッドを開始中...")
            memory_thread = threading.Thread(target=self._monitor_memory)
            memory_thread.daemon = True
            memory_thread.start()
            self.monitoring_threads.append(memory_thread)
            logger.debug("メモリ監視スレッド開始完了")
            
            # ネットワーク監視スレッドの開始
            logger.debug("ネットワーク監視スレッドを開始中...")
            network_thread = threading.Thread(target=self._monitor_network)
            network_thread.daemon = True
            network_thread.start()
            self.monitoring_threads.append(network_thread)
            logger.debug("ネットワーク監視スレッド開始完了")
            
            # データ処理スレッドの開始
            logger.debug("データ処理スレッドを開始中...")
            data_thread = threading.Thread(target=self._process_monitoring_data)
            data_thread.daemon = True
            data_thread.start()
            self.monitoring_threads.append(data_thread)
            logger.debug("データ処理スレッド開始完了")
            
            logger.info(f"動的監視を開始しました: {package_name} (監視スレッド数: {len(self.monitoring_threads)})")
            return True
            
        except Exception as e:
            logger.error(f"動的監視開始エラー: {e}", exc_info=True)
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self):
        """動的監視を停止"""
        logger.info("動的監視停止要求")
        
        if not self.is_monitoring:
            logger.warning("監視は実行されていません")
            return
        
        logger.debug("監視フラグを無効化")
        self.is_monitoring = False
        
        # Fridaプロセスの終了
        if self.frida_process:
            logger.debug("Fridaプロセスを終了中...")
            try:
                self.frida_process.terminate()
                self.frida_process.wait(timeout=5)
                logger.debug("Fridaプロセス終了完了")
            except subprocess.TimeoutExpired:
                logger.warning("Fridaプロセスの正常終了がタイムアウト。強制終了します")
                self.frida_process.kill()
            except Exception as e:
                logger.error(f"Fridaプロセス終了エラー: {e}", exc_info=True)
            finally:
                self.frida_process = None
        
        # 監視スレッドの終了を待機
        logger.debug(f"監視スレッドの終了を待機中... ({len(self.monitoring_threads)}個)")
        for thread in self.monitoring_threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        # 監視データの保存
        logger.info("監視結果を保存中...")
        self._save_monitoring_results()
        
        # スレッドリストをクリア
        self.monitoring_threads.clear()
        
        logger.info("動的監視を停止しました")
    
    def _start_frida_monitoring(self, script_path: str):
        """Fridaによる監視を開始"""
        logger.debug(f"Frida監視開始: script_path={script_path}, target_package={self.target_package}")
        
        try:
            cmd = [
                "frida",
                "-U",  # USB接続のデバイス
                "-f", self.target_package,  # パッケージ名
                "-l", script_path,  # スクリプトファイル
                "--no-pause"
            ]
            logger.debug(f"Fridaコマンド: {' '.join(cmd)}")
            
            self.frida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            logger.debug(f"Fridaプロセス開始: PID={self.frida_process.pid}")
            
            # Frida出力の監視
            logger.debug("Frida出力監視スレッドを開始中...")
            frida_thread = threading.Thread(target=self._monitor_frida_output)
            frida_thread.daemon = True
            frida_thread.start()
            self.monitoring_threads.append(frida_thread)
            logger.debug("Frida出力監視スレッド開始完了")
            
            logger.info(f"Frida監視を開始しました: {self.target_package}")
            
        except Exception as e:
            logger.error(f"Frida監視開始エラー: {e}", exc_info=True)
    
    def _monitor_frida_output(self):
        """Frida出力の監視"""
        logger.debug("Frida出力監視開始")
        
        if not self.frida_process:
            logger.error("Fridaプロセスが存在しません")
            return
        
        output_count = 0
        while self.is_monitoring and self.frida_process.poll() is None:
            try:
                line = self.frida_process.stdout.readline()
                if line:
                    output_count += 1
                    self._parse_frida_output(line.strip())
                    
                    # 100行ごとに進捗をログ出力
                    if output_count % 100 == 0:
                        logger.debug(f"Frida出力処理中: {output_count}行処理済み")
                        
            except Exception as e:
                logger.error(f"Frida出力監視エラー: {e}", exc_info=True)
                break
        
        logger.debug(f"Frida出力監視終了: 合計{output_count}行処理")
    
    def _parse_frida_output(self, line: str):
        """Frida出力の解析"""
        timestamp = datetime.now().isoformat()
        
        try:
            # API呼び出しの検出
            if "[API]" in line:
                api_call = {
                    "timestamp": timestamp,
                    "type": "api_call",
                    "data": line
                }
                self.data_queue.put(api_call)
                logger.debug(f"API呼び出し検出: {line[:100]}...")
            
            # メモリ操作の検出
            elif "[MEMORY]" in line:
                memory_event = {
                    "timestamp": timestamp,
                    "type": "memory_operation",
                    "data": line
                }
                self.data_queue.put(memory_event)
                logger.debug(f"メモリ操作検出: {line[:100]}...")
            
            # ゲーム状態の検出
            elif "[GAME_STATE]" in line:
                game_event = {
                    "timestamp": timestamp,
                    "type": "game_state",
                    "data": line
                }
                self.data_queue.put(game_event)
                logger.info(f"ゲーム状態変化検出: {line[:100]}...")
            
            # ファイル操作の検出
            elif "[FILE]" in line:
                file_event = {
                    "timestamp": timestamp,
                    "type": "file_operation",
                    "data": line
                }
                self.data_queue.put(file_event)
                logger.debug(f"ファイル操作検出: {line[:100]}...")
            
            # ネットワーク活動の検出
            elif "[NETWORK]" in line:
                network_event = {
                    "timestamp": timestamp,
                    "type": "network_activity",
                    "data": line
                }
                self.data_queue.put(network_event)
                logger.info(f"ネットワーク活動検出: {line[:100]}...")
                
        except Exception as e:
            logger.error(f"Frida出力解析エラー: {e} (line: {line[:100]}...)", exc_info=True)
    
    def _monitor_memory(self):
        """システムメモリの監視"""
        logger.debug("メモリ監視開始")
        sample_count = 0
        
        while self.is_monitoring:
            try:
                # システム全体のメモリ使用量
                memory_info = psutil.virtual_memory()
                
                # 対象プロセスのメモリ使用量（可能な場合）
                process_memory = None
                process_found = False
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                        if self.target_package in proc.info['name']:
                            process_memory = proc.info['memory_info'].rss
                            process_found = True
                            break
                except:
                    pass
                
                memory_data = {
                    "timestamp": datetime.now().isoformat(),
                    "system_memory": {
                        "total": memory_info.total,
                        "available": memory_info.available,
                        "percent": memory_info.percent,
                        "used": memory_info.used,
                        "free": memory_info.free
                    },
                    "process_memory": process_memory
                }
                
                self.monitoring_data["memory_usage"].append(memory_data)
                sample_count += 1
                
                # 10サンプルごとに進捗をログ出力
                if sample_count % 10 == 0:
                    logger.debug(f"メモリ監視中: {sample_count}サンプル収集済み (システム使用率: {memory_info.percent:.1f}%)")
                
                # 対象プロセスが見つからない場合の警告（最初の数回のみ）
                if not process_found and sample_count <= 3:
                    logger.warning(f"対象プロセス '{self.target_package}' が見つかりません")
                
                # メモリ使用量が異常に高い場合の警告
                if memory_info.percent > 90:
                    logger.warning(f"高メモリ使用量を検出: {memory_info.percent}%")
                elif memory_info.percent > 80:
                    logger.info(f"メモリ使用量が高めです: {memory_info.percent}%")
                
                time.sleep(5)  # 5秒間隔
                
            except Exception as e:
                logger.error(f"メモリ監視エラー: {e}", exc_info=True)
                time.sleep(5)
        
        logger.debug(f"メモリ監視終了: 合計{sample_count}サンプル収集")
    
    def _monitor_network(self):
        """ネットワーク活動の監視"""
        logger.debug("ネットワーク監視開始")
        sample_count = 0
        prev_bytes_sent = 0
        prev_bytes_recv = 0
        
        while self.is_monitoring:
            try:
                # ネットワーク統計の取得
                net_io = psutil.net_io_counters()
                
                network_data = {
                    "timestamp": datetime.now().isoformat(),
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                }
                
                self.monitoring_data["network_activity"].append(network_data)
                sample_count += 1
                
                # ネットワーク活動の変化を検出
                if sample_count > 1:
                    sent_diff = net_io.bytes_sent - prev_bytes_sent
                    recv_diff = net_io.bytes_recv - prev_bytes_recv
                    
                    if sent_diff > 1024 * 1024:  # 1MB以上の送信
                        logger.info(f"大量データ送信検出: {sent_diff / 1024 / 1024:.2f}MB")
                    if recv_diff > 1024 * 1024:  # 1MB以上の受信
                        logger.info(f"大量データ受信検出: {recv_diff / 1024 / 1024:.2f}MB")
                
                prev_bytes_sent = net_io.bytes_sent
                prev_bytes_recv = net_io.bytes_recv
                
                # 5サンプルごとに進捗をログ出力
                if sample_count % 5 == 0:
                    logger.debug(f"ネットワーク監視中: {sample_count}サンプル収集済み")
                
                time.sleep(10)  # 10秒間隔
                
            except Exception as e:
                logger.error(f"ネットワーク監視エラー: {e}", exc_info=True)
                time.sleep(10)
        
        logger.debug(f"ネットワーク監視終了: 合計{sample_count}サンプル収集")
    
    def _process_monitoring_data(self):
        """監視データの処理"""
        logger.debug("監視データ処理開始")
        processed_count = 0
        data_type_counts = {}
        
        while self.is_monitoring:
            try:
                # キューからデータを取得
                try:
                    data = self.data_queue.get(timeout=1)
                    
                    # データタイプに応じて分類
                    data_type = data.get("type", "unknown")
                    data_type_counts[data_type] = data_type_counts.get(data_type, 0) + 1
                    processed_count += 1
                    
                    if data_type == "api_call":
                        self.monitoring_data["api_calls"].append(data)
                    elif data_type == "memory_operation":
                        # メモリ操作の詳細解析
                        self._analyze_memory_operation(data)
                    elif data_type == "game_state":
                        self.monitoring_data["game_events"].append(data)
                        # ゲーム状態の変化を解析
                        self._analyze_game_state_change(data)
                    elif data_type == "file_operation":
                        self.monitoring_data["file_operations"].append(data)
                    elif data_type == "network_activity":
                        # ネットワーク活動の解析
                        self._analyze_network_activity(data)
                    else:
                        logger.warning(f"未知のデータタイプ: {data_type}")
                    
                    self.data_queue.task_done()
                    
                    # 50件ごとに進捗をログ出力
                    if processed_count % 50 == 0:
                        logger.debug(f"データ処理中: {processed_count}件処理済み (タイプ別: {data_type_counts})")
                    
                except queue.Empty:
                    continue
                    
            except Exception as e:
                logger.error(f"データ処理エラー: {e}", exc_info=True)
        
        logger.debug(f"監視データ処理終了: 合計{processed_count}件処理 (タイプ別: {data_type_counts})")
    
    def _analyze_memory_operation(self, data: Dict):
        """メモリ操作の詳細解析"""
        try:
            line = data.get("data", "")
            
            # 大きなメモリ割り当ての検出
            if "Large allocation" in line:
                size_match = line.split("bytes")
                if len(size_match) > 1:
                    logger.info(f"大きなメモリ割り当てを検出: {line}")
            
            # メモリリークの可能性
            if "allocation" in line.lower() and "free" not in line.lower():
                logger.debug(f"メモリ割り当て検出: {line[:100]}...")
                # メモリ割り当て回数をカウント
                pass
            
            # メモリ解放の検出
            if "free" in line.lower():
                logger.debug(f"メモリ解放検出: {line[:100]}...")
                
        except Exception as e:
            logger.error(f"メモリ操作解析エラー: {e} (data: {data})", exc_info=True)
    
    def _analyze_game_state_change(self, data: Dict):
        """ゲーム状態変化の解析"""
        try:
            line = data.get("data", "")
            
            # スコア変更の検出
            if "score" in line.lower() or "point" in line.lower():
                logger.info(f"スコア変更を検出: {line}")
            
            # レベル変更の検出
            if "level" in line.lower():
                logger.info(f"レベル変更を検出: {line}")
            
            # ライフ/HP変更の検出
            if "life" in line.lower() or "hp" in line.lower() or "health" in line.lower():
                logger.info(f"ライフ/HP変更を検出: {line}")
            
            # ゲーム状態の変更
            if "state" in line.lower():
                logger.info(f"ゲーム状態変更を検出: {line}")
                
        except Exception as e:
            logger.error(f"ゲーム状態解析エラー: {e} (data: {data})", exc_info=True)
    
    def _analyze_network_activity(self, data: Dict):
        """ネットワーク活動の解析"""
        try:
            line = data.get("data", "")
            
            # 外部サーバーへの接続
            if "Connection" in line or "connect" in line.lower():
                logger.info(f"ネットワーク接続を検出: {line}")
            
            # HTTPリクエストの検出
            if "http" in line.lower() or "https" in line.lower():
                logger.info(f"HTTP通信を検出: {line}")
            
            # データ送受信の検出
            if "send" in line.lower() or "recv" in line.lower():
                logger.debug(f"データ送受信を検出: {line[:100]}...")
                
        except Exception as e:
            logger.error(f"ネットワーク活動解析エラー: {e} (data: {data})", exc_info=True)
    
    def _save_monitoring_results(self):
        """監視結果の保存"""
        logger.info("監視結果の保存を開始")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = self.output_dir / f"dynamic_analysis_{timestamp}.json"
            
            # 統計情報の生成
            logger.debug("統計情報を生成中...")
            stats = self._generate_statistics()
            logger.debug(f"統計情報生成完了: {stats}")
            
            result_data = {
                "analysis_info": {
                    "target_package": self.target_package,
                    "start_time": timestamp,
                    "duration_seconds": len(self.monitoring_data["memory_usage"]) * 5
                },
                "statistics": stats,
                "monitoring_data": self.monitoring_data
            }
            
            logger.debug(f"結果ファイルに保存中: {result_file}")
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            # ファイルサイズを取得
            file_size = result_file.stat().st_size
            logger.info(f"動的解析結果を保存しました: {result_file} (サイズ: {file_size:,} bytes)")
            
            # データ統計をログ出力
            logger.info(f"保存データ統計: API呼び出し={stats['total_api_calls']}, "
                       f"メモリサンプル={stats['total_memory_samples']}, "
                       f"ネットワークサンプル={stats['total_network_samples']}, "
                       f"ファイル操作={stats['total_file_operations']}, "
                       f"ゲームイベント={stats['total_game_events']}")
            
        except Exception as e:
            logger.error(f"結果保存エラー: {e}", exc_info=True)
    
    def _generate_statistics(self) -> Dict:
        """統計情報の生成"""
        logger.debug("統計情報生成開始")
        
        stats = {
            "total_api_calls": len(self.monitoring_data["api_calls"]),
            "total_memory_samples": len(self.monitoring_data["memory_usage"]),
            "total_network_samples": len(self.monitoring_data["network_activity"]),
            "total_file_operations": len(self.monitoring_data["file_operations"]),
            "total_game_events": len(self.monitoring_data["game_events"])
        }
        
        logger.debug(f"基本統計: {stats}")
        
        # メモリ使用量の統計
        if self.monitoring_data["memory_usage"]:
            memory_percents = [
                sample["system_memory"]["percent"] 
                for sample in self.monitoring_data["memory_usage"]
            ]
            stats["memory_stats"] = {
                "max_usage": max(memory_percents),
                "min_usage": min(memory_percents),
                "avg_usage": sum(memory_percents) / len(memory_percents)
            }
            logger.debug(f"メモリ統計: {stats['memory_stats']}")
        else:
            logger.warning("メモリ使用量データが存在しません")
        
        logger.debug("統計情報生成完了")
        return stats
    
    def get_real_time_stats(self) -> Dict:
        """リアルタイム統計の取得"""
        logger.debug("リアルタイム統計取得要求")
        
        if not self.is_monitoring:
            logger.debug("監視が実行されていません")
            return {"status": "not_monitoring"}
        
        stats = {
            "status": "monitoring",
            "target_package": self.target_package,
            "current_stats": self._generate_statistics(),
            "monitoring_duration": len(self.monitoring_data["memory_usage"]) * 5
        }
        
        logger.debug(f"リアルタイム統計: 監視時間={stats['monitoring_duration']}秒")
        return stats
    
    def export_analysis_report(self) -> str:
        """解析レポートのエクスポート"""
        logger.info("解析レポートのエクスポート開始")
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.output_dir / f"analysis_report_{timestamp}.md"
            
            logger.debug("統計情報を取得中...")
            stats = self._generate_statistics()
            
            logger.debug("レポート内容を生成中...")
            report_content = f"""# 動的解析レポート

## 解析対象
- パッケージ名: {self.target_package}
- 解析時間: {stats.get('monitoring_duration', 0)}秒

## 統計情報
- API呼び出し総数: {stats['total_api_calls']}
- メモリサンプル数: {stats['total_memory_samples']}
- ネットワークサンプル数: {stats['total_network_samples']}
- ファイル操作数: {stats['total_file_operations']}
- ゲームイベント数: {stats['total_game_events']}

## メモリ使用量
"""
            
            if "memory_stats" in stats:
                memory_stats = stats["memory_stats"]
                report_content += f"""
- 最大使用量: {memory_stats['max_usage']:.1f}%
- 最小使用量: {memory_stats['min_usage']:.1f}%
- 平均使用量: {memory_stats['avg_usage']:.1f}%
"""
                logger.debug("メモリ統計をレポートに追加")
            else:
                logger.warning("メモリ統計が利用できません")
            
            report_content += f"""
## 主要なAPI呼び出し
"""
            
            # 頻繁に呼び出されるAPIの分析
            api_calls = self.monitoring_data["api_calls"]
            if api_calls:
                logger.debug(f"API呼び出し分析中: {len(api_calls)}件")
                api_count = {}
                for call in api_calls:
                    api_name = call.get("data", "").split(" ")[0]
                    api_count[api_name] = api_count.get(api_name, 0) + 1
                
                sorted_apis = sorted(api_count.items(), key=lambda x: x[1], reverse=True)
                logger.debug(f"上位API: {sorted_apis[:5]}")
                
                for api, count in sorted_apis[:10]:
                    report_content += f"- {api}: {count}回\n"
            else:
                logger.warning("API呼び出しデータが存在しません")
                report_content += "- データなし\n"
            
            logger.debug(f"レポートファイルに保存中: {report_file}")
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            # ファイルサイズを取得
            file_size = report_file.stat().st_size
            logger.info(f"解析レポートを生成しました: {report_file} (サイズ: {file_size:,} bytes)")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"レポート生成エラー: {e}", exc_info=True)
            return ""