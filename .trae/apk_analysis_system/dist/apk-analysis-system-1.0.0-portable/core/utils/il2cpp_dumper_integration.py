"""
Il2CppDumper統合モジュール - Unity IL2CPPからC#コードを復元
"""
import os
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile
import shutil

logger = logging.getLogger(__name__)

class Il2CppDumperIntegration:
    """Il2CppDumperを統合してC#コードを復元するクラス"""
    
    def __init__(self, output_dir: str = "data/il2cpp_analysis"):
        logger.info(f"Il2CppDumper統合モジュールを初期化中: output_dir={output_dir}")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Il2CppDumperの実行可能ファイルパス
        logger.info("Il2CppDumperの実行可能ファイルを検索中...")
        self.il2cpp_dumper_path = self._find_il2cpp_dumper()
        
        if self.il2cpp_dumper_path:
            logger.info(f"Il2CppDumperが見つかりました: {self.il2cpp_dumper_path}")
        else:
            logger.warning("Il2CppDumperが見つかりませんでした")
        
        self.analysis_result = {
            "metadata_info": {},
            "dumped_classes": [],
            "dumped_methods": [],
            "game_logic": {},
            "implementation_hints": []
        }
        logger.info("Il2CppDumper統合モジュールの初期化が完了しました")
    
    def _find_il2cpp_dumper(self) -> Optional[str]:
        """Il2CppDumperの実行可能ファイルを検索"""
        logger.info("Il2CppDumperの実行可能ファイルを検索中...")
        
        # 一般的なパスを検索
        possible_paths = [
            "tools/Il2CppDumper/Il2CppDumper.exe",
            "Il2CppDumper.exe",
            "Il2CppDumper/Il2CppDumper.exe"
        ]
        
        for path in possible_paths:
            logger.debug(f"パスを確認中: {path}")
            if os.path.exists(path):
                logger.info(f"Il2CppDumperが見つかりました: {path}")
                return path
        
        logger.warning("Il2CppDumperが見つかりません。手動でダウンロードしてください。")
        return None
    
    def dump_il2cpp_metadata(self, libil2cpp_path: str, metadata_path: str) -> Dict[str, Any]:
        """IL2CPPメタデータをダンプしてC#コードを復元"""
        logger.info(f"IL2CPPメタデータのダンプを開始: libil2cpp={libil2cpp_path}, metadata={metadata_path}")
        
        if not self.il2cpp_dumper_path:
            logger.error("Il2CppDumperが利用できません")
            return {"error": "Il2CppDumperが利用できません"}
        
        # ファイル存在確認
        logger.debug("必要なファイルの存在確認を開始")
        if not os.path.exists(libil2cpp_path):
            logger.error(f"libil2cpp.soファイルが見つかりません: {libil2cpp_path}")
            return {"error": f"libil2cpp.soファイルが見つかりません: {libil2cpp_path}"}
            
        if not os.path.exists(metadata_path):
            logger.error(f"メタデータファイルが見つかりません: {metadata_path}")
            return {"error": f"メタデータファイルが見つかりません: {metadata_path}"}
        
        logger.info("必要なファイルの存在確認が完了しました")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                logger.info(f"一時ディレクトリを作成: {temp_dir}")
                
                # Il2CppDumperを実行
                cmd = [
                    self.il2cpp_dumper_path,
                    libil2cpp_path,
                    metadata_path,
                    temp_dir
                ]
                
                logger.info(f"Il2CppDumperを実行中: {' '.join(cmd)}")
                logger.debug(f"実行コマンド詳細: {cmd}")
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    logger.info("Il2CppDumperの実行が成功しました")
                    logger.debug(f"Il2CppDumper標準出力: {result.stdout}")
                    
                    # 結果を解析
                    logger.info("ダンプ結果を解析中...")
                    self._parse_dumper_output(temp_dir)
                    logger.info("IL2CPPメタデータのダンプが完了しました")
                    
                    # 解析結果の統計情報をログ出力
                    classes_count = len(self.analysis_result.get("dumped_classes", []))
                    methods_count = len(self.analysis_result.get("dumped_methods", []))
                    logger.info(f"解析結果: クラス数={classes_count}, メソッド数={methods_count}")
                    
                    return self.analysis_result
                else:
                    logger.error(f"Il2CppDumper実行エラー (終了コード: {result.returncode})")
                    logger.error(f"標準エラー出力: {result.stderr}")
                    logger.debug(f"標準出力: {result.stdout}")
                    return {"error": result.stderr}
                    
        except subprocess.TimeoutExpired:
            logger.error("Il2CppDumperの実行がタイムアウトしました (300秒)")
            return {"error": "Il2CppDumperの実行がタイムアウトしました"}
        except Exception as e:
            logger.error(f"Il2CppDumper統合エラー: {e}", exc_info=True)
            return {"error": str(e)}
    
    def _parse_dumper_output(self, output_dir: str):
        """Il2CppDumperの出力を解析"""
        logger.info(f"Il2CppDumperの出力解析を開始: {output_dir}")
        output_path = Path(output_dir)
        
        # 出力ディレクトリの内容を確認
        output_files = list(output_path.glob("*"))
        logger.debug(f"出力ファイル一覧: {[f.name for f in output_files]}")
        
        # dump.csファイルを解析
        dump_cs_path = output_path / "dump.cs"
        if dump_cs_path.exists():
            logger.info("dump.csファイルを解析中...")
            file_size = dump_cs_path.stat().st_size
            logger.debug(f"dump.csファイルサイズ: {file_size} bytes")
            self._parse_dump_cs(dump_cs_path)
            logger.info("dump.csファイルの解析が完了しました")
        else:
            logger.warning("dump.csファイルが見つかりません")
        
        # script.jsonファイルを解析
        script_json_path = output_path / "script.json"
        if script_json_path.exists():
            logger.info("script.jsonファイルを解析中...")
            file_size = script_json_path.stat().st_size
            logger.debug(f"script.jsonファイルサイズ: {file_size} bytes")
            self._parse_script_json(script_json_path)
            logger.info("script.jsonファイルの解析が完了しました")
        else:
            logger.warning("script.jsonファイルが見つかりません")
        
        logger.info("Il2CppDumperの出力解析が完了しました")
    
    def _parse_dump_cs(self, dump_cs_path: Path):
        """dump.csファイルからクラスとメソッドを抽出"""
        logger.info(f"dump.csファイルの解析を開始: {dump_cs_path}")
        try:
            with open(dump_cs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            logger.debug(f"dump.csファイルの内容サイズ: {len(content)} 文字")
            
            # クラス定義を抽出
            logger.info("クラス定義の抽出を開始")
            classes = self._extract_classes_from_cs(content)
            self.analysis_result["dumped_classes"] = classes
            logger.info(f"クラス定義の抽出が完了: {len(classes)} クラス")
            
            # メソッド定義を抽出
            logger.info("メソッド定義の抽出を開始")
            methods = self._extract_methods_from_cs(content)
            self.analysis_result["dumped_methods"] = methods
            logger.info(f"メソッド定義の抽出が完了: {len(methods)} メソッド")
            
        except UnicodeDecodeError as e:
            logger.error(f"dump.csファイルの文字エンコーディングエラー: {e}")
        except Exception as e:
            logger.error(f"dump.cs解析エラー: {e}", exc_info=True)
    
    def _parse_script_json(self, script_json_path: Path):
        """script.jsonファイルからメタデータ情報を抽出"""
        logger.info(f"script.jsonファイルの解析を開始: {script_json_path}")
        try:
            with open(script_json_path, 'r', encoding='utf-8') as f:
                script_data = json.load(f)
            
            logger.debug(f"script.jsonデータのキー数: {len(script_data) if isinstance(script_data, dict) else 'N/A'}")
            
            self.analysis_result["metadata_info"] = script_data
            logger.info("script.jsonファイルの解析が完了しました")
            
        except json.JSONDecodeError as e:
            logger.error(f"script.jsonファイルのJSON解析エラー: {e}")
        except UnicodeDecodeError as e:
            logger.error(f"script.jsonファイルの文字エンコーディングエラー: {e}")
        except Exception as e:
            logger.error(f"script.json解析エラー: {e}", exc_info=True)
    
    def _extract_classes_from_cs(self, content: str) -> List[Dict]:
        """C#コードからクラス定義を抽出"""
        logger.debug("C#コードからクラス定義を抽出中...")
        classes = []
        lines = content.split('\n')
        
        logger.debug(f"解析対象行数: {len(lines)}")
        
        current_class = None
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # クラス定義の検出
            if line.startswith('public class ') or line.startswith('internal class '):
                class_name = line.split('class ')[1].split(' ')[0].split(':')[0]
                current_class = {
                    "name": class_name,
                    "definition": line,
                    "methods": [],
                    "fields": [],
                    "line_number": line_num
                }
                classes.append(current_class)
                logger.debug(f"クラス検出: {class_name} (行 {line_num})")
            
            # メソッド定義の検出
            elif current_class and ('public ' in line or 'private ' in line) and '(' in line and ')' in line:
                current_class["methods"].append(line)
                logger.debug(f"メソッド検出: {line[:50]}... (クラス: {current_class['name']})")
            
            # フィールド定義の検出
            elif current_class and ('public ' in line or 'private ' in line) and ';' in line:
                current_class["fields"].append(line)
                logger.debug(f"フィールド検出: {line[:50]}... (クラス: {current_class['name']})")
        
        logger.debug(f"クラス抽出完了: {len(classes)} クラス")
        return classes
    
    def _extract_methods_from_cs(self, content: str) -> List[Dict]:
        """C#コードからメソッド定義を抽出"""
        logger.debug("C#コードからメソッド定義を抽出中...")
        methods = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # メソッド定義の検出
            if ('public ' in line or 'private ' in line) and '(' in line and ')' in line and '{' not in line:
                method_info = {
                    "signature": line,
                    "return_type": self._extract_return_type(line),
                    "name": self._extract_method_name(line),
                    "parameters": self._extract_parameters(line),
                    "line_number": line_num
                }
                methods.append(method_info)
                logger.debug(f"メソッド検出: {method_info['name']} (行 {line_num})")
        
        logger.debug(f"メソッド抽出完了: {len(methods)} メソッド")
        return methods
    
    def _extract_return_type(self, method_signature: str) -> str:
        """メソッドシグネチャから戻り値の型を抽出"""
        parts = method_signature.split()
        for i, part in enumerate(parts):
            if '(' in part:
                return parts[i-1] if i > 0 else "void"
        return "unknown"
    
    def _extract_method_name(self, method_signature: str) -> str:
        """メソッドシグネチャからメソッド名を抽出"""
        if '(' in method_signature:
            before_params = method_signature.split('(')[0]
            return before_params.split()[-1]
        return "unknown"
    
    def _extract_parameters(self, method_signature: str) -> List[str]:
        """メソッドシグネチャからパラメータを抽出"""
        if '(' in method_signature and ')' in method_signature:
            params_str = method_signature.split('(')[1].split(')')[0]
            if params_str.strip():
                return [param.strip() for param in params_str.split(',')]
        return []
    
    def extract_game_logic(self) -> Dict[str, Any]:
        """ダンプされたコードからゲームロジックを抽出"""
        logger.info("ゲームロジックの抽出を開始")
        
        game_logic = {
            "game_classes": [],
            "ui_classes": [],
            "logic_classes": [],
            "data_classes": []
        }
        
        dumped_classes = self.analysis_result.get("dumped_classes", [])
        logger.debug(f"解析対象クラス数: {len(dumped_classes)}")
        
        for class_info in dumped_classes:
            class_name = class_info["name"].lower()
            
            # ゲーム関連クラスの分類
            if any(keyword in class_name for keyword in ["game", "play", "challenge", "score"]):
                game_logic["game_classes"].append(class_info)
                logger.debug(f"ゲームクラス検出: {class_info['name']}")
            elif any(keyword in class_name for keyword in ["ui", "button", "panel", "menu"]):
                game_logic["ui_classes"].append(class_info)
                logger.debug(f"UIクラス検出: {class_info['name']}")
            elif any(keyword in class_name for keyword in ["logic", "manager", "controller", "system"]):
                game_logic["logic_classes"].append(class_info)
                logger.debug(f"ロジッククラス検出: {class_info['name']}")
            elif any(keyword in class_name for keyword in ["data", "config", "setting", "save"]):
                game_logic["data_classes"].append(class_info)
                logger.debug(f"データクラス検出: {class_info['name']}")
        
        # 統計情報をログ出力
        logger.info(f"ゲームロジック抽出完了:")
        logger.info(f"  - ゲームクラス: {len(game_logic['game_classes'])}")
        logger.info(f"  - UIクラス: {len(game_logic['ui_classes'])}")
        logger.info(f"  - ロジッククラス: {len(game_logic['logic_classes'])}")
        logger.info(f"  - データクラス: {len(game_logic['data_classes'])}")
        
        self.analysis_result["game_logic"] = game_logic
        return game_logic
    
    def generate_implementation_hints(self) -> List[str]:
        """実装ヒントを生成"""
        hints = []
        
        game_logic = self.analysis_result.get("game_logic", {})
        
        if game_logic.get("game_classes"):
            hints.append(f"ゲーム関連クラス {len(game_logic['game_classes'])}個が検出されました")
            hints.append("これらのクラスからゲームメカニクスを復元できます")
        
        if game_logic.get("ui_classes"):
            hints.append(f"UI関連クラス {len(game_logic['ui_classes'])}個が検出されました")
            hints.append("UI構造とレイアウトを完全に復元できます")
        
        if game_logic.get("logic_classes"):
            hints.append(f"ロジック関連クラス {len(game_logic['logic_classes'])}個が検出されました")
            hints.append("ゲームの制御フローを正確に実装できます")
        
        self.analysis_result["implementation_hints"] = hints
        return hints