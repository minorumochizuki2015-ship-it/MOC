"""
Frida動的解析システム - ランタイムでのメモリ解析とAPIフック
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import threading

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Fridaが利用できません。pip install frida を実行してください。")

logger = logging.getLogger(__name__)

class FridaHookingSystem:
    """Fridaを使用したランタイム解析システム"""
    
    def __init__(self, package_name: str = "com.heydoon.game", output_dir: str = "data/frida_analysis"):
        logger.info(f"FridaHookingSystemを初期化中: package={package_name}, output_dir={output_dir}")
        self.package_name = package_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.device = None
        self.session = None
        self.script = None
        
        self.analysis_result = {
            "hooked_functions": [],
            "memory_dumps": [],
            "api_calls": [],
            "game_state_captures": [],
            "implementation_hints": []
        }
        logger.info("FridaHookingSystemの初期化が完了しました")
    
    def connect_to_device(self) -> bool:
        """デバイスに接続"""
        logger.info("デバイスへの接続を開始します")
        if not FRIDA_AVAILABLE:
            logger.error("Fridaが利用できません")
            return False
        
        try:
            # USBデバイスに接続を試行
            logger.debug("USBデバイスの検索中...")
            self.device = frida.get_usb_device()
            logger.info(f"デバイスに接続しました: {self.device}")
            return True
        except Exception as e:
            logger.error(f"デバイス接続エラー: {e}")
            return False
    
    def attach_to_app(self) -> bool:
        """アプリにアタッチ"""
        logger.info(f"アプリ '{self.package_name}' へのアタッチを開始します")
        if not self.device:
            logger.error("デバイスが接続されていません")
            return False
        
        try:
            logger.debug(f"パッケージ '{self.package_name}' を検索中...")
            self.session = self.device.attach(self.package_name)
            logger.info(f"アプリにアタッチしました: {self.package_name}")
            return True
        except Exception as e:
            logger.error(f"アプリアタッチエラー: {e}")
            return False
    
    def create_hook_script(self) -> str:
        """フックスクリプトを生成"""
        logger.info("Fridaフックスクリプトを生成中...")
        script_code = """
        // Unity IL2CPP関数のフック
        var il2cpp_base = Module.findBaseAddress("libil2cpp.so");
        
        if (il2cpp_base) {
            console.log("libil2cpp.so found at: " + il2cpp_base);
            
            // ゲーム状態関連の関数をフック
            var game_update_addr = il2cpp_base.add(0x123456); // 実際のオフセットに置き換え
            
            Interceptor.attach(game_update_addr, {
                onEnter: function(args) {
                    console.log("Game Update called");
                    send({
                        type: "function_call",
                        function: "GameUpdate",
                        timestamp: Date.now()
                    });
                },
                onLeave: function(retval) {
                    // 戻り値の処理
                }
            });
            
            // メモリ読み取り関数
            function readGameState() {
                var game_state_addr = il2cpp_base.add(0x789ABC); // 実際のオフセット
                var state_data = Memory.readByteArray(game_state_addr, 1024);
                
                send({
                    type: "memory_dump",
                    address: game_state_addr.toString(),
                    data: Array.from(new Uint8Array(state_data)),
                    timestamp: Date.now()
                });
            }
            
            // 定期的なメモリダンプ
            setInterval(readGameState, 1000);
        }
        
        // Unity関数のフック
        var unity_base = Module.findBaseAddress("libunity.so");
        
        if (unity_base) {
            console.log("libunity.so found at: " + unity_base);
            
            // Input処理のフック
            var input_handler = Module.findExportByName("libunity.so", "UnityEngine_Input_GetTouch");
            
            if (input_handler) {
                Interceptor.attach(input_handler, {
                    onEnter: function(args) {
                        send({
                            type: "input_event",
                            function: "GetTouch",
                            args: args,
                            timestamp: Date.now()
                        });
                    }
                });
            }
        }
        """
        logger.info("Fridaフックスクリプトの生成が完了しました")
        return script_code
    
    def start_hooking(self) -> bool:
        """フックを開始"""
        logger.info("Fridaフックの開始処理を実行中...")
        if not self.session:
            logger.error("セッションが確立されていません")
            return False
        
        try:
            logger.debug("フックスクリプトを作成中...")
            script_code = self.create_hook_script()
            self.script = self.session.create_script(script_code)
            
            # メッセージハンドラーを設定
            logger.debug("メッセージハンドラーを設定中...")
            self.script.on('message', self._on_message)
            
            # スクリプトをロード
            logger.debug("スクリプトをロード中...")
            self.script.load()
            
            logger.info("フックを開始しました")
            return True
            
        except Exception as e:
            logger.error(f"フック開始エラー: {e}")
            return False
    
    def _on_message(self, message, data):
        """Fridaからのメッセージを処理"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                logger.debug(f"Fridaメッセージを受信: {payload.get('type', 'unknown')}")
                
                if payload['type'] == 'function_call':
                    self.analysis_result['api_calls'].append(payload)
                    logger.debug(f"API呼び出しを記録: {payload.get('function', 'unknown')}")
                elif payload['type'] == 'memory_dump':
                    self.analysis_result['memory_dumps'].append(payload)
                    logger.debug(f"メモリダンプを記録: {payload.get('address', 'unknown')}")
                elif payload['type'] == 'input_event':
                    self.analysis_result['game_state_captures'].append(payload)
                    logger.debug(f"入力イベントを記録: {payload.get('function', 'unknown')}")
                
                # リアルタイムでファイルに保存
                self._save_realtime_data(payload)
                
        except Exception as e:
            logger.error(f"メッセージ処理エラー: {e}")
    
    def _save_realtime_data(self, data: Dict):
        """リアルタイムデータを保存"""
        try:
            timestamp = int(time.time())
            filename = f"frida_data_{timestamp}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.debug(f"リアルタイムデータを保存: {filepath}")
        except Exception as e:
            logger.error(f"リアルタイムデータ保存エラー: {e}")
    
    def analyze_memory_patterns(self) -> Dict[str, Any]:
        """メモリパターンを解析"""
        logger.info("メモリパターンの解析を開始します")
        patterns = {
            "game_state_offsets": [],
            "score_locations": [],
            "timer_addresses": [],
            "input_buffers": []
        }
        
        logger.debug(f"解析対象のメモリダンプ数: {len(self.analysis_result['memory_dumps'])}")
        
        for dump in self.analysis_result['memory_dumps']:
            # メモリダンプからパターンを検出
            data = dump.get('data', [])
            address = dump.get('address', '')
            
            # スコア値のパターンを検索
            score_pattern = self._find_score_pattern(data)
            if score_pattern:
                patterns['score_locations'].append({
                    'address': address,
                    'offset': score_pattern['offset'],
                    'value': score_pattern['value']
                })
                logger.debug(f"スコアパターンを検出: address={address}, value={score_pattern['value']}")
        
        logger.info(f"メモリパターン解析完了: スコア位置={len(patterns['score_locations'])}個")
        return patterns
    
    def _find_score_pattern(self, data: List[int]) -> Optional[Dict]:
        """スコア値のパターンを検索"""
        # 4バイト整数値を検索
        for i in range(len(data) - 3):
            value = (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24))
            
            # スコアらしい値（0-999999の範囲）を検出
            if 0 <= value <= 999999:
                return {
                    'offset': i,
                    'value': value
                }
        
        return None
    
    def generate_game_logic_map(self) -> Dict[str, Any]:
        """ゲームロジックマップを生成"""
        logic_map = {
            "input_handling": [],
            "game_state_transitions": [],
            "scoring_logic": [],
            "timer_logic": []
        }
        
        # API呼び出しパターンから推論
        for call in self.analysis_result['api_calls']:
            function_name = call.get('function', '')
            
            if 'input' in function_name.lower():
                logic_map['input_handling'].append(call)
            elif 'score' in function_name.lower():
                logic_map['scoring_logic'].append(call)
            elif 'timer' in function_name.lower():
                logic_map['timer_logic'].append(call)
        
        return logic_map
    
    def stop_hooking(self):
        """フックを停止"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        
        logger.info("フックを停止しました")
    
    def save_analysis_results(self):
        """解析結果を保存"""
        results_file = self.output_dir / "frida_analysis_results.json"
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.analysis_result, f, indent=2, ensure_ascii=False)
        
        logger.info(f"解析結果を保存しました: {results_file}")