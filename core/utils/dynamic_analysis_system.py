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
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.is_monitoring = False
        self.monitoring_threads = []
        self.data_queue = queue.Queue()
        
        # 監視データ
        self.monitoring_data = {
            "memory_usage": [],
            "api_calls": [],
            "network_activity": [],
            "file_operations": [],
            "game_events": []
        }
        
        # Fridaプロセス
        self.frida_process = None
        self.target_package = None
    
    def start_monitoring(self, package_name: str, frida_script_path: str) -> bool:
        """動的監視を開始"""
        try:
            self.target_package = package_name
            self.is_monitoring = True
            
            # Fridaスクリプトの実行
            self._start_frida_monitoring(frida_script_path)
            
            # メモリ監視スレッドの開始
            memory_thread = threading.Thread(target=self._monitor_memory)
            memory_thread.daemon = True
            memory_thread.start()
            self.monitoring_threads.append(memory_thread)
            
            # ネットワーク監視スレッドの開始
            network_thread = threading.Thread(target=self._monitor_network)
            network_thread.daemon = True
            network_thread.start()
            self.monitoring_threads.append(network_thread)
            
            # データ処理スレッドの開始
            data_thread = threading.Thread(target=self._process_monitoring_data)
            data_thread.daemon = True
            data_thread.start()
            self.monitoring_threads.append(data_thread)
            
            logger.info(f"動的監視を開始しました: {package_name}")
            return True
            
        except Exception as e:
            logger.error(f"動的監視開始エラー: {e}")
            return False
    
    def stop_monitoring(self):
        """動的監視を停止"""
        self.is_monitoring = False
        
        # Fridaプロセスの終了
        if self.frida_process:
            self.frida_process.terminate()
            self.frida_process = None
        
        # 監視データの保存
        self._save_monitoring_results()
        
        logger.info("動的監視を停止しました")
    
    def _start_frida_monitoring(self, script_path: str):
        """Fridaによる監視を開始"""
        try:
            cmd = [
                "frida",
                "-U",  # USB接続のデバイス
                "-f", self.target_package,  # パッケージ名
                "-l", script_path,  # スクリプトファイル
                "--no-pause"
            ]
            
            self.frida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Frida出力の監視
            frida_thread = threading.Thread(target=self._monitor_frida_output)
            frida_thread.daemon = True
            frida_thread.start()
            self.monitoring_threads.append(frida_thread)
            
        except Exception as e:
            logger.error(f"Frida監視開始エラー: {e}")
    
    def _monitor_frida_output(self):
        """Frida出力の監視"""
        if not self.frida_process:
            return
        
        while self.is_monitoring and self.frida_process.poll() is None:
            try:
                line = self.frida_process.stdout.readline()
                if line:
                    self._parse_frida_output(line.strip())
            except Exception as e:
                logger.error(f"Frida出力監視エラー: {e}")
                break
    
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
            
            # メモリ操作の検出
            elif "[MEMORY]" in line:
                memory_event = {
                    "timestamp": timestamp,
                    "type": "memory_operation",
                    "data": line
                }
                self.data_queue.put(memory_event)
            
            # ゲーム状態の検出
            elif "[GAME_STATE]" in line:
                game_event = {
                    "timestamp": timestamp,
                    "type": "game_state",
                    "data": line
                }
                self.data_queue.put(game_event)
            
            # ファイル操作の検出
            elif "[FILE]" in line:
                file_event = {
                    "timestamp": timestamp,
                    "type": "file_operation",
                    "data": line
                }
                self.data_queue.put(file_event)
            
            # ネットワーク活動の検出
            elif "[NETWORK]" in line:
                network_event = {
                    "timestamp": timestamp,
                    "type": "network_activity",
                    "data": line
                }
                self.data_queue.put(network_event)
                
        except Exception as e:
            logger.error(f"Frida出力解析エラー: {e}")
    
    def _monitor_memory(self):
        """システムメモリの監視"""
        while self.is_monitoring:
            try:
                # システム全体のメモリ使用量
                memory_info = psutil.virtual_memory()
                
                # 対象プロセスのメモリ使用量（可能な場合）
                process_memory = None
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                        if self.target_package in proc.info['name']:
                            process_memory = proc.info['memory_info'].rss
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
                
                # メモリ使用量が異常に高い場合の警告
                if memory_info.percent > 90:
                    logger.warning(f"高メモリ使用量を検出: {memory_info.percent}%")
                
                time.sleep(5)  # 5秒間隔
                
            except Exception as e:
                logger.error(f"メモリ監視エラー: {e}")
                time.sleep(5)
    
    def _monitor_network(self):
        """ネットワーク活動の監視"""
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
                
                time.sleep(10)  # 10秒間隔
                
            except Exception as e:
                logger.error(f"ネットワーク監視エラー: {e}")
                time.sleep(10)
    
    def _process_monitoring_data(self):
        """監視データの処理"""
        while self.is_monitoring:
            try:
                # キューからデータを取得
                try:
                    data = self.data_queue.get(timeout=1)
                    
                    # データタイプに応じて分類
                    data_type = data.get("type", "unknown")
                    
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
                    
                    self.data_queue.task_done()
                    
                except queue.Empty:
                    continue
                    
            except Exception as e:
                logger.error(f"データ処理エラー: {e}")
    
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
                # メモリ割り当て回数をカウント
                pass
                
        except Exception as e:
            logger.error(f"メモリ操作解析エラー: {e}")
    
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
                
        except Exception as e:
            logger.error(f"ゲーム状態解析エラー: {e}")
    
    def _analyze_network_activity(self, data: Dict):
        """ネットワーク活動の解析"""
        try:
            line = data.get("data", "")
            
            # 外部サーバーへの接続
            if "Connection" in line:
                logger.info(f"ネットワーク接続を検出: {line}")
                
        except Exception as e:
            logger.error(f"ネットワーク活動解析エラー: {e}")
    
    def _save_monitoring_results(self):
        """監視結果の保存"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = self.output_dir / f"dynamic_analysis_{timestamp}.json"
            
            # 統計情報の生成
            stats = self._generate_statistics()
            
            result_data = {
                "analysis_info": {
                    "target_package": self.target_package,
                    "start_time": timestamp,
                    "duration_seconds": len(self.monitoring_data["memory_usage"]) * 5
                },
                "statistics": stats,
                "monitoring_data": self.monitoring_data
            }
            
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"動的解析結果を保存しました: {result_file}")
            
        except Exception as e:
            logger.error(f"結果保存エラー: {e}")
    
    def _generate_statistics(self) -> Dict:
        """統計情報の生成"""
        stats = {
            "total_api_calls": len(self.monitoring_data["api_calls"]),
            "total_memory_samples": len(self.monitoring_data["memory_usage"]),
            "total_network_samples": len(self.monitoring_data["network_activity"]),
            "total_file_operations": len(self.monitoring_data["file_operations"]),
            "total_game_events": len(self.monitoring_data["game_events"])
        }
        
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
        
        return stats
    
    def get_real_time_stats(self) -> Dict:
        """リアルタイム統計の取得"""
        if not self.is_monitoring:
            return {"status": "not_monitoring"}
        
        return {
            "status": "monitoring",
            "target_package": self.target_package,
            "current_stats": self._generate_statistics(),
            "monitoring_duration": len(self.monitoring_data["memory_usage"]) * 5
        }
    
    def export_analysis_report(self) -> str:
        """解析レポートのエクスポート"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.output_dir / f"analysis_report_{timestamp}.md"
            
            stats = self._generate_statistics()
            
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
            
            report_content += f"""
## 主要なAPI呼び出し
"""
            
            # 頻繁に呼び出されるAPIの分析
            api_calls = self.monitoring_data["api_calls"]
            if api_calls:
                api_count = {}
                for call in api_calls:
                    api_name = call.get("data", "").split(" ")[0]
                    api_count[api_name] = api_count.get(api_name, 0) + 1
                
                sorted_apis = sorted(api_count.items(), key=lambda x: x[1], reverse=True)
                for api, count in sorted_apis[:10]:
                    report_content += f"- {api}: {count}回\n"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"解析レポートを生成しました: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"レポート生成エラー: {e}")
            return ""