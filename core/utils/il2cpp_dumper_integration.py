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
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Il2CppDumperの実行可能ファイルパス
        self.il2cpp_dumper_path = self._find_il2cpp_dumper()
        
        self.analysis_result = {
            "metadata_info": {},
            "dumped_classes": [],
            "dumped_methods": [],
            "game_logic": {},
            "implementation_hints": []
        }
    
    def _find_il2cpp_dumper(self) -> Optional[str]:
        """Il2CppDumperの実行可能ファイルを検索"""
        # 一般的なパスを検索
        possible_paths = [
            "tools/Il2CppDumper/Il2CppDumper.exe",
            "Il2CppDumper.exe",
            "Il2CppDumper/Il2CppDumper.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        logger.warning("Il2CppDumperが見つかりません。手動でダウンロードしてください。")
        return None
    
    def dump_il2cpp_metadata(self, libil2cpp_path: str, metadata_path: str) -> Dict[str, Any]:
        """IL2CPPメタデータをダンプしてC#コードを復元"""
        if not self.il2cpp_dumper_path:
            return {"error": "Il2CppDumperが利用できません"}
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Il2CppDumperを実行
                cmd = [
                    self.il2cpp_dumper_path,
                    libil2cpp_path,
                    metadata_path,
                    temp_dir
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # 結果を解析
                    self._parse_dumper_output(temp_dir)
                    return self.analysis_result
                else:
                    logger.error(f"Il2CppDumper実行エラー: {result.stderr}")
                    return {"error": result.stderr}
                    
        except Exception as e:
            logger.error(f"Il2CppDumper統合エラー: {e}")
            return {"error": str(e)}
    
    def _parse_dumper_output(self, output_dir: str):
        """Il2CppDumperの出力を解析"""
        output_path = Path(output_dir)
        
        # dump.csファイルを解析
        dump_cs_path = output_path / "dump.cs"
        if dump_cs_path.exists():
            self._parse_dump_cs(dump_cs_path)
        
        # script.jsonファイルを解析
        script_json_path = output_path / "script.json"
        if script_json_path.exists():
            self._parse_script_json(script_json_path)
    
    def _parse_dump_cs(self, dump_cs_path: Path):
        """dump.csファイルからクラスとメソッドを抽出"""
        try:
            with open(dump_cs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # クラス定義を抽出
            classes = self._extract_classes_from_cs(content)
            self.analysis_result["dumped_classes"] = classes
            
            # メソッド定義を抽出
            methods = self._extract_methods_from_cs(content)
            self.analysis_result["dumped_methods"] = methods
            
        except Exception as e:
            logger.error(f"dump.cs解析エラー: {e}")
    
    def _parse_script_json(self, script_json_path: Path):
        """script.jsonファイルからメタデータ情報を抽出"""
        try:
            with open(script_json_path, 'r', encoding='utf-8') as f:
                script_data = json.load(f)
            
            self.analysis_result["metadata_info"] = script_data
            
        except Exception as e:
            logger.error(f"script.json解析エラー: {e}")
    
    def _extract_classes_from_cs(self, content: str) -> List[Dict]:
        """C#コードからクラス定義を抽出"""
        classes = []
        lines = content.split('\n')
        
        current_class = None
        for line in lines:
            line = line.strip()
            
            # クラス定義の検出
            if line.startswith('public class ') or line.startswith('internal class '):
                class_name = line.split('class ')[1].split(' ')[0].split(':')[0]
                current_class = {
                    "name": class_name,
                    "definition": line,
                    "methods": [],
                    "fields": []
                }
                classes.append(current_class)
            
            # メソッド定義の検出
            elif current_class and ('public ' in line or 'private ' in line) and '(' in line and ')' in line:
                current_class["methods"].append(line)
            
            # フィールド定義の検出
            elif current_class and ('public ' in line or 'private ' in line) and ';' in line:
                current_class["fields"].append(line)
        
        return classes
    
    def _extract_methods_from_cs(self, content: str) -> List[Dict]:
        """C#コードからメソッド定義を抽出"""
        methods = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # メソッド定義の検出
            if ('public ' in line or 'private ' in line) and '(' in line and ')' in line and '{' not in line:
                method_info = {
                    "signature": line,
                    "return_type": self._extract_return_type(line),
                    "name": self._extract_method_name(line),
                    "parameters": self._extract_parameters(line)
                }
                methods.append(method_info)
        
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
        game_logic = {
            "game_classes": [],
            "ui_classes": [],
            "logic_classes": [],
            "data_classes": []
        }
        
        for class_info in self.analysis_result.get("dumped_classes", []):
            class_name = class_info["name"].lower()
            
            # ゲーム関連クラスの分類
            if any(keyword in class_name for keyword in ["game", "play", "challenge", "score"]):
                game_logic["game_classes"].append(class_info)
            elif any(keyword in class_name for keyword in ["ui", "button", "panel", "menu"]):
                game_logic["ui_classes"].append(class_info)
            elif any(keyword in class_name for keyword in ["manager", "controller", "logic"]):
                game_logic["logic_classes"].append(class_info)
            elif any(keyword in class_name for keyword in ["data", "config", "setting"]):
                game_logic["data_classes"].append(class_info)
        
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