"""
APK解析システム - HeyDooon APKファイルの構造とデータを解析
"""
import os
import zipfile
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

# Unity DLL解析機能をインポート
from .unity_dll_analyzer import UnityDLLAnalyzer

# ログ設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APKAnalyzer:
    """APKファイルの解析を行うクラス"""
    
    def __init__(self, apk_path: str, output_dir: str = "data/apk_analysis"):
        """
        APK解析器の初期化
        
        Args:
            apk_path: APKファイルのパス
            output_dir: 解析結果の出力ディレクトリ
        """
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Unity DLL解析器の初期化
        self.unity_analyzer = UnityDLLAnalyzer(str(self.output_dir / "unity"))
        
        # 解析結果を格納する辞書
        self.analysis_result = {
            "apk_info": {},
            "manifest": {},
            "resources": {},
            "assets": {},
            "strings": {},
            "file_structure": {},
            "unity_analysis": {},  # Unity DLL解析結果を追加
            "implementation_hints": []
        }
    
    def analyze(self, include_unity_analysis: bool = True) -> Dict[str, Any]:
        """
        APKファイルの完全解析を実行
        
        Args:
            include_unity_analysis: Unity DLL解析を含めるかどうか
            
        Returns:
            解析結果の辞書（successフィールドを含む）
        """
        logger.info(f"APK解析開始: {self.apk_path}")
        
        if not self.apk_path.exists():
            error_msg = f"APKファイルが見つかりません: {self.apk_path}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "analysis_result": {}
            }
        
        try:
            # 基本情報の取得
            self._extract_basic_info()
            
            # APKファイルをZIPとして開いて解析
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # ファイル構造の解析
                self._analyze_file_structure(apk_zip)
                
                # AndroidManifest.xmlの解析
                self._analyze_manifest(apk_zip)
                
                # リソースファイルの解析
                self._analyze_resources(apk_zip)
                
                # アセットファイルの解析
                self._analyze_assets(apk_zip)
                
                # 文字列リソースの抽出
                self._extract_strings(apk_zip)
            
            # Unity DLL解析（オプション）
            if include_unity_analysis:
                logger.info("Unity DLL解析を開始します...")
                unity_result = self.unity_analyzer.analyze_apk_for_unity(str(self.apk_path))
                self.analysis_result["unity_analysis"] = unity_result
                
                # Unity解析結果を実装ヒントに統合
                if "implementation_hints" in unity_result:
                    self.analysis_result["implementation_hints"].extend(unity_result["implementation_hints"])
            
            # 実装ヒントの生成
            self._generate_implementation_hints()
            
            # 結果の保存
            self._save_results()
            
            # 成功判定ロジック
            success = self._validate_analysis_success()
            
            logger.info(f"APK解析完了 - 成功: {success}")
            
            # 成功フラグを追加して結果を返す
            result = {
                "success": success,
                "analysis_result": self.analysis_result.copy()
            }
            
            # 成功時は解析結果をトップレベルにも展開
            if success:
                result.update(self.analysis_result)
            
            return result
            
        except Exception as e:
            error_msg = f"APK解析エラー: {e}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "analysis_result": self.analysis_result.copy()
            }
    
    def _validate_analysis_success(self) -> bool:
        """
        解析の成功を判定する
        
        Returns:
            解析が成功したかどうか
        """
        try:
            # 基本的な解析結果の存在確認
            required_sections = ["apk_info", "manifest", "resources", "assets", "file_structure"]
            
            for section in required_sections:
                if section not in self.analysis_result:
                    logger.warning(f"必須セクション '{section}' が見つかりません")
                    return False
            
            # APK基本情報の確認
            apk_info = self.analysis_result.get("apk_info", {})
            if not apk_info.get("file_size", 0) > 0:
                logger.warning("APKファイルサイズが無効です")
                return False
            
            # ファイル構造の確認
            file_structure = self.analysis_result.get("file_structure", {})
            if not file_structure.get("total_files", 0) > 0:
                logger.warning("ファイル構造の解析に失敗しました")
                return False
            
            # Unity解析が実行された場合の確認
            unity_analysis = self.analysis_result.get("unity_analysis", {})
            if unity_analysis:
                # Unity解析が実行されたが、基本的な結果が得られているかチェック
                if "unity_detected" not in unity_analysis:
                    logger.warning("Unity解析が不完全です")
                    return False
            
            logger.info("解析成功の検証が完了しました")
            return True
            
        except Exception as e:
            logger.error(f"解析成功判定エラー: {e}")
            return False

    def _extract_basic_info(self):
        """APKファイルの基本情報を取得"""
        stat = self.apk_path.stat()
        self.analysis_result["apk_info"] = {
            "file_name": self.apk_path.name,
            "file_size": stat.st_size,
            "file_size_mb": round(stat.st_size / (1024 * 1024), 2),
            "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "analysis_time": datetime.now().isoformat()
        }
    
    def _analyze_file_structure(self, apk_zip: zipfile.ZipFile):
        """APK内のファイル構造を解析"""
        file_list = apk_zip.namelist()
        
        structure = {
            "total_files": len(file_list),
            "directories": set(),
            "file_types": {},
            "notable_files": []
        }
        
        for file_path in file_list:
            # ディレクトリの抽出
            if '/' in file_path:
                dir_path = '/'.join(file_path.split('/')[:-1])
                structure["directories"].add(dir_path)
            
            # ファイル拡張子の統計
            if '.' in file_path:
                ext = file_path.split('.')[-1].lower()
                structure["file_types"][ext] = structure["file_types"].get(ext, 0) + 1
            
            # 注目すべきファイルの特定
            if any(keyword in file_path.lower() for keyword in 
                   ['config', 'setting', 'data', 'game', 'level', 'score']):
                structure["notable_files"].append(file_path)
        
        structure["directories"] = sorted(list(structure["directories"]))
        self.analysis_result["file_structure"] = structure
    
    def _analyze_manifest(self, apk_zip: zipfile.ZipFile):
        """AndroidManifest.xmlを解析"""
        try:
            manifest_data = apk_zip.read('AndroidManifest.xml')
            # バイナリXMLの場合は簡易解析
            self.analysis_result["manifest"] = {
                "found": True,
                "size": len(manifest_data),
                "note": "バイナリXML形式のため、詳細解析にはaapt2が必要"
            }
        except KeyError:
            self.analysis_result["manifest"] = {
                "found": False,
                "note": "AndroidManifest.xmlが見つかりません"
            }
    
    def _analyze_resources(self, apk_zip: zipfile.ZipFile):
        """リソースファイルを解析"""
        resource_files = [f for f in apk_zip.namelist() if f.startswith('res/')]
        
        resources = {
            "total_resources": len(resource_files),
            "resource_types": {},
            "images": [],
            "layouts": [],
            "values": []
        }
        
        for res_file in resource_files:
            parts = res_file.split('/')
            if len(parts) >= 2:
                res_type = parts[1]
                resources["resource_types"][res_type] = resources["resource_types"].get(res_type, 0) + 1
                
                # 画像ファイル
                if res_type.startswith('drawable') or res_type.startswith('mipmap'):
                    resources["images"].append(res_file)
                
                # レイアウトファイル
                elif res_type.startswith('layout'):
                    resources["layouts"].append(res_file)
                
                # 値ファイル
                elif res_type.startswith('values'):
                    resources["values"].append(res_file)
        
        self.analysis_result["resources"] = resources
    
    def _analyze_assets(self, apk_zip: zipfile.ZipFile):
        """assetsフォルダを解析"""
        asset_files = [f for f in apk_zip.namelist() if f.startswith('assets/')]
        
        assets = {
            "total_assets": len(asset_files),
            "asset_files": asset_files,
            "data_files": [],
            "config_files": []
        }
        
        for asset_file in asset_files:
            if any(ext in asset_file.lower() for ext in ['.json', '.xml', '.txt', '.csv']):
                assets["data_files"].append(asset_file)
            
            if any(keyword in asset_file.lower() for keyword in ['config', 'setting', 'pref']):
                assets["config_files"].append(asset_file)
        
        self.analysis_result["assets"] = assets
    
    def _extract_strings(self, apk_zip: zipfile.ZipFile):
        """文字列リソースを抽出（可能な範囲で）"""
        strings = {
            "extracted_strings": [],
            "note": "完全な文字列抽出にはaapt2が必要"
        }
        
        # classes.dexから簡易的に文字列を抽出
        try:
            dex_data = apk_zip.read('classes.dex')
            # 簡易的な文字列抽出（完全ではない）
            text_strings = []
            current_string = ""
            
            for byte in dex_data:
                if 32 <= byte <= 126:  # 印刷可能なASCII文字
                    current_string += chr(byte)
                else:
                    if len(current_string) > 5:  # 5文字以上の文字列のみ
                        text_strings.append(current_string)
                    current_string = ""
            
            # 重複を除去し、ゲーム関連の文字列を抽出
            unique_strings = list(set(text_strings))
            game_related = [s for s in unique_strings if any(keyword in s.lower() 
                           for keyword in ['game', 'score', 'level', 'play', 'start', 'menu'])]
            
            strings["extracted_strings"] = game_related[:50]  # 最初の50個
            
        except Exception as e:
            strings["error"] = f"文字列抽出エラー: {e}"
        
        self.analysis_result["strings"] = strings
    
    def _generate_implementation_hints(self):
        """解析結果から実装ヒントを生成"""
        hints = []
        
        # ファイル構造からの推測
        structure = self.analysis_result["file_structure"]
        
        # Unity関連の検出
        unity_indicators = []
        for file_type, count in structure["file_types"].items():
            if file_type in ['so', 'dll']:
                unity_indicators.append(f"ネイティブライブラリ (.{file_type}): {count}個")
        
        if unity_indicators:
            hints.append("Unity/ネイティブコンポーネントが検出されました:")
            hints.extend([f"  • {indicator}" for indicator in unity_indicators])
        
        # Unity DLL解析結果の統合
        if self.analysis_result.get("unity_analysis") and not self.analysis_result["unity_analysis"].get("error"):
            unity_analysis = self.analysis_result["unity_analysis"]
            
            if unity_analysis.get("il2cpp_metadata"):
                hints.append("IL2CPP Unity ゲームです - 高度な逆アセンブル技術が必要")
            
            if unity_analysis.get("assembly_info"):
                hints.append("ネイティブアセンブリが検出されました - メモリダンプ/パッチが可能")
            
            symbol_count = len(unity_analysis.get("symbols", []))
            if symbol_count > 0:
                hints.append(f"デバッグシンボル {symbol_count}個が利用可能 - フック対象の特定が容易")
        
        # ゲーム特有のファイル検出
        notable_files = structure.get("notable_files", [])
        game_files = [f for f in notable_files if any(keyword in f.lower() for keyword in 
                     ['level', 'stage', 'player', 'enemy', 'weapon', 'item'])]
        
        if game_files:
            hints.append("ゲーム要素ファイルが検出されました:")
            hints.extend([f"  • {os.path.basename(f)}" for f in game_files[:5]])
        
        # データベース/設定ファイル
        config_files = [f for f in notable_files if any(keyword in f.lower() for keyword in 
                       ['config', 'setting', 'preference', 'save'])]
        
        if config_files:
            hints.append("設定/セーブデータファイル:")
            hints.extend([f"  • {os.path.basename(f)}" for f in config_files[:3]])
        
        # リソース分析
        resources = self.analysis_result["resources"]
        if resources["images"]:
            hints.append(f"画像リソース {len(resources['images'])}個 - UI/アセット改変が可能")
        
        if resources["layouts"]:
            hints.append(f"レイアウト {len(resources['layouts'])}個 - UI構造の解析が可能")
        
        # アセット分析
        assets = self.analysis_result["assets"]
        if assets["total_assets"] > 0:
            hints.append(f"アセットファイル {assets['total_assets']}個 - ゲームデータの抽出が可能")
        
        # 実装推奨事項
        hints.append("\n推奨される解析アプローチ:")
        
        if self.analysis_result.get("unity_analysis") and not self.analysis_result["unity_analysis"].get("error"):
            hints.append("  1. Il2CppDumper/Il2CppInspectorでメタデータ解析")
            hints.append("  2. Ghidra/IDA Proでネイティブコード逆アセンブル")
            hints.append("  3. Frida/Xposedでランタイムフック")
        else:
            hints.append("  1. APKTool/jadxでJavaコード逆コンパイル")
            hints.append("  2. リソース/アセットファイルの直接編集")
        
        hints.append("  4. メモリダンプ/パッチによる動的解析")
        hints.append("  5. ネットワーク通信の傍受・改変")
        
        self.analysis_result["implementation_hints"] = hints

    def _save_results(self):
        """解析結果をJSONファイルに保存"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"apk_analysis_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_result, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"解析結果を保存しました: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"結果保存エラー: {e}")
            raise

    def save_analysis(self):
        """解析結果の保存（外部呼び出し用）"""
        return self._save_results()

    def print_summary(self):
        """解析結果のサマリーを表示"""
        print("\n" + "="*60)
        print("APK解析結果サマリー")
        print("="*60)
        
        # 基本情報
        apk_info = self.analysis_result["apk_info"]
        print(f"ファイル名: {apk_info['file_name']}")
        print(f"ファイルサイズ: {apk_info['file_size_mb']} MB")
        
        # ファイル構造
        structure = self.analysis_result["file_structure"]
        print(f"\n総ファイル数: {structure['total_files']}")
        print(f"ディレクトリ数: {len(structure['directories'])}")
        print("主要なファイル形式:")
        for ext, count in sorted(structure["file_types"].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  .{ext}: {count}個")
        
        # リソース
        resources = self.analysis_result["resources"]
        print(f"\nリソースファイル: {resources['total_resources']}個")
        print(f"画像リソース: {len(resources['images'])}個")
        print(f"レイアウト: {len(resources['layouts'])}個")
        
        # アセット
        assets = self.analysis_result["assets"]
        print(f"アセットファイル: {assets['total_assets']}個")
        
        # Unity解析結果
        unity_analysis = self.analysis_result.get("unity_analysis", {})
        if unity_analysis and not unity_analysis.get("error"):
            print(f"\n--- Unity DLL解析結果 ---")
            print(f"検出されたUnityファイル: {len(unity_analysis.get('assembly_info', {}))}")
            print(f"IL2CPPメタデータ: {len(unity_analysis.get('il2cpp_metadata', {}))}")
            print(f"抽出されたシンボル: {len(unity_analysis.get('symbols', []))}")
            print(f"抽出された文字列: {len(unity_analysis.get('strings', []))}")
        elif unity_analysis.get("error"):
            print(f"\nUnity解析: {unity_analysis['error']}")
        
        # 実装ヒント
        print("\n実装ヒント:")
        for hint in self.analysis_result["implementation_hints"]:
            print(f"  • {hint}")
        
        print("\n" + "="*60)
        
        # Unity解析結果の詳細表示
        if unity_analysis and not unity_analysis.get("error"):
            self.unity_analyzer.analysis_result = unity_analysis
            self.unity_analyzer.print_unity_summary()

def main():
    """メイン実行関数"""
    # APKファイルのパスを指定
    apk_path = "HeyDooon_1.20_APKPure.apk"
    
    if not os.path.exists(apk_path):
        print(f"エラー: APKファイルが見つかりません: {apk_path}")
        print("APKファイルをプロジェクトルートに配置してください。")
        return
    
    try:
        # APK解析器を作成して実行
        analyzer = APKAnalyzer(apk_path)
        result = analyzer.analyze()
        
        # 結果の表示
        analyzer.print_summary()
        
        print(f"\n詳細な解析結果は data/apk_analysis/ フォルダに保存されました。")
        
    except Exception as e:
        print(f"解析エラー: {e}")

if __name__ == "__main__":
    main()