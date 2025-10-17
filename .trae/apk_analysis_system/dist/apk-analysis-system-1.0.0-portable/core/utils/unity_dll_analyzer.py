"""
Unity DLL逆アセンブル機能 - IL2CPP バイナリの解析とメタデータ抽出
"""
import os
import struct
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import zipfile
import tempfile
import shutil

try:
    import pefile
    import capstone
    from elftools.elf.elffile import ELFFile
    DISASM_AVAILABLE = True
except ImportError:
    DISASM_AVAILABLE = False
    logging.warning("Unity DLL逆アセンブル用ライブラリが不足しています。pip install pefile capstone pyelftools を実行してください。")

"""
Unity DLL解析システム - Unity APKファイルからDLL/ネイティブライブラリを解析
"""
import os
import sys
import zipfile
import json
import struct
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from datetime import datetime

# スタンドアロン実行のためのパス設定
if __name__ == "__main__":
    # スクリプトが直接実行された場合、プロジェクトルートをパスに追加
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent  # core/utils -> core -> MOC
    sys.path.insert(0, str(project_root))

# 共通ログ設定をインポート
try:
    from core.config.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    # フォールバック: 基本的なログ設定
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

class UnityDLLAnalyzer:
    """Unity APKファイルのDLL/ネイティブライブラリ解析クラス"""
    
    def __init__(self, output_dir: str = "data/unity_analysis"):
        """
        Unity DLL解析器の初期化
        
        Args:
            output_dir: 解析結果の出力ディレクトリ
        """
        logger.info("Unity DLL解析器初期化開始")
        logger.debug(f"出力ディレクトリ設定: {output_dir}")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"出力ディレクトリ作成完了: {self.output_dir}")
        
        # 解析結果を格納する辞書
        self.analysis_result = {
            "unity_detected": False,
            "unity_version": None,
            "il2cpp_metadata": {},
            "assembly_info": {},
            "native_libraries": [],
            "symbols": [],
            "strings": [],
            "implementation_hints": []
        }
        logger.debug("解析結果辞書初期化完了")
        logger.info("Unity DLL解析器初期化完了")

    def analyze_apk_for_unity(self, apk_path: str) -> Dict[str, Any]:
        """
        APKファイルからUnity関連ファイルを抽出して解析
        
        Args:
            apk_path: APKファイルのパス
            
        Returns:
            Unity解析結果の辞書（unity_detectedフィールドを含む）
        """
        logger.info(f"Unity APK解析開始: {apk_path}")
        
        if not DISASM_AVAILABLE:
            logger.error("逆アセンブル用ライブラリが不足しています")
            return {
                "error": "逆アセンブル用ライブラリが不足しています",
                "unity_detected": False
            }
        
        try:
            # APKファイルの存在確認
            if not os.path.exists(apk_path):
                logger.error(f"APKファイルが見つかりません: {apk_path}")
                return {"error": f"APKファイルが見つかりません: {apk_path}", "unity_detected": False}
            
            logger.debug(f"APKファイル存在確認完了: {apk_path}")
            logger.info("APKファイルからUnity関連ファイルを検索開始")
            
            result = self.analyze_apk(apk_path)
            
            if result.get("unity_detected", False):
                logger.info("Unity APK検出成功")
            else:
                logger.warning("Unity APK検出失敗")
                
            logger.info(f"Unity APK解析完了: unity_detected={result.get('unity_detected', False)}")
            return result
            
        except Exception as e:
            logger.error(f"Unity APK解析中にエラーが発生: {str(e)}")
            return {
                "error": f"解析エラー: {str(e)}",
                "unity_detected": False
            }
    
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """
        APKファイルを解析してUnity関連情報を抽出
        
        Args:
            apk_path: APKファイルのパス
            
        Returns:
            解析結果の辞書
        """
        logger.info(f"APK解析開始: {apk_path}")
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                logger.debug("APKファイルを開きました")
                
                # Unity関連ファイルの検索
                logger.info("Unity関連ファイル検索開始")
                unity_files = self._find_unity_files(apk_zip)
                
                # Unity検出フラグを設定
                unity_detected = len(unity_files) > 0
                logger.info(f"Unity関連ファイル検出結果: {len(unity_files)}個")
                
                if not unity_files:
                    logger.warning("Unity IL2CPP関連ファイルが見つかりません")
                    return {
                        "error": "Unity IL2CPP関連ファイルが見つかりません",
                        "unity_detected": False
                    }
                
                # 一時ディレクトリに抽出
                logger.info("Unity関連ファイルを一時ディレクトリに抽出開始")
                with tempfile.TemporaryDirectory() as temp_dir:
                    logger.debug(f"一時ディレクトリ作成: {temp_dir}")
                    extracted_files = self._extract_unity_files(apk_zip, unity_files, Path(temp_dir))
                    logger.debug(f"ファイル抽出完了: {len(extracted_files)}個")
                    
                    # 各ファイルを解析
                    logger.info("抽出ファイル解析開始")
                    for file_type, file_path in extracted_files.items():
                        logger.debug(f"ファイル解析中: {file_type} - {file_path}")
                        try:
                            self._analyze_unity_file({'type': file_type, 'path': str(file_path)})
                            logger.debug(f"ファイル解析完了: {file_type}")
                        except Exception as e:
                            logger.warning(f"ファイル解析エラー ({file_type}): {e}")
                
                # 実装ヒントの生成
                logger.info("実装ヒント生成開始")
                self._generate_unity_hints()
                logger.debug("実装ヒント生成完了")
                
                # 結果の保存
                logger.info("解析結果保存開始")
                self._save_unity_results()
                logger.debug("解析結果保存完了")
                
                # Unity検出フラグを結果に追加
                self.analysis_result["unity_detected"] = unity_detected
                
                # IL2CPP検出フラグも追加
                il2cpp_detected = bool(self.analysis_result.get("il2cpp_metadata"))
                self.analysis_result["il2cpp_detected"] = il2cpp_detected
                
                logger.info(f"APK解析完了 - Unity検出: {unity_detected}, IL2CPP検出: {il2cpp_detected}")
                return self.analysis_result
                
        except Exception as e:
            logger.error(f"APK解析中にエラーが発生: {str(e)}")
            return {
                "error": f"APK解析エラー: {str(e)}",
                "unity_detected": False
            }

    def _find_unity_files(self, apk_zip: zipfile.ZipFile) -> List[Dict[str, Any]]:
        """APK内のUnity関連ファイルを検索"""
        logger.debug("Unity関連ファイル検索開始")
        unity_files = []
        
        # Unity関連ファイルのパターン定義
        unity_patterns = [
            'libil2cpp.so',
            'libunity.so',
            'libmain.so',
            'assets/bin/data/',
            'assets/aa/',
            'assets/streamingassets/',
            'lib/arm64-v8a/',
            'lib/armeabi-v7a/',
            'lib/x86/',
            'lib/x86_64/',
            'global-metadata.dat',
            'data.unity3d',
            'sharedassets',
            'resources.assets'
        ]
        logger.debug(f"検索パターン数: {len(unity_patterns)}")
        
        file_count = 0
        for file_info in apk_zip.infolist():
            file_count += 1
            file_path = file_info.filename
            path_obj = Path(file_path)
            file_lower = str(path_obj).lower()
            
            # Unity関連ファイルのパターンマッチング
            if any(pattern in file_lower for pattern in unity_patterns):
                file_type = self._classify_unity_file(path_obj)
                unity_files.append({
                    'path': file_path,
                    'size': file_info.file_size,
                    'compressed_size': file_info.compress_size,
                    'type': file_type
                })
                logger.debug(f"Unity関連ファイル発見: {file_path} (type: {file_type}, size: {file_info.file_size})")
        
        logger.debug(f"APK内ファイル総数: {file_count}")
        logger.info(f"Unity関連ファイル検索完了: {len(unity_files)}個発見")
        return unity_files

    def _classify_unity_file(self, path_obj: Path) -> str:
        """Unityファイルの種類を分類"""
        file_lower = str(path_obj).lower()
        
        if 'libil2cpp.so' in file_lower:
            return 'il2cpp_native'
        elif 'libunity.so' in file_lower:
            return 'unity_engine'
        elif 'global-metadata.dat' in file_lower:
            return 'il2cpp_metadata'
        elif path_obj.suffix.lower() in ['.so', '.dll']:
            return 'native_library'
        elif 'assets' in file_lower:
            return 'unity_asset'
        else:
            return 'unity_data'

    def _extract_unity_files(self, apk_zip: zipfile.ZipFile, unity_files: List[Dict[str, Any]], temp_dir: Path) -> Dict[str, Path]:
        """Unity関連ファイルを一時ディレクトリに抽出"""
        logger.info(f"Unity関連ファイルの抽出を開始: {len(unity_files)}個")
        extracted_files = {}
        
        for file_info in unity_files:
            file_path = file_info['path']
            try:
                # pathlibを使用してファイル名を取得
                file_name = Path(file_path).name
                extract_path = temp_dir / file_name
                
                with apk_zip.open(file_path) as source, open(extract_path, 'wb') as target:
                    shutil.copyfileobj(source, target)
                
                extracted_files[file_info['type']] = extract_path
                logger.debug(f"抽出完了: {file_name} -> {extract_path}")
                
            except Exception as e:
                logger.warning(f"ファイル抽出エラー {file_path}: {e}")
        
        logger.info(f"Unity関連ファイル抽出完了: {len(extracted_files)}個")
        return extracted_files

    def _analyze_unity_file(self, file_info: Dict):
        """個別のUnityファイルを解析"""
        file_path = file_info['extracted_path']
        file_type = file_info['type']
        
        try:
            if file_type == 'native_library':
                self._analyze_native_library(file_path, file_info)
            elif file_type == 'il2cpp_metadata':
                self._analyze_il2cpp_metadata(file_path, file_info)
            elif file_type == 'managed_assembly':
                self._analyze_managed_assembly(file_path, file_info)
            elif file_type == 'unity_assets':
                self._analyze_unity_assets(file_path, file_info)
                
        except Exception as e:
            logger.error(f"ファイル解析エラー {file_path}: {e}")
    
    def _analyze_native_library(self, file_path: str, file_info: Dict):
        """ネイティブライブラリ(.so)の解析"""
        try:
            with open(file_path, 'rb') as f:
                # ELFヘッダーの確認
                elf = ELFFile(f)
                
                # 基本情報の取得
                arch_info = {
                    'architecture': elf.get_machine_arch(),
                    'class': elf.elfclass,
                    'endianness': elf.little_endian,
                    'entry_point': hex(elf.header['e_entry'])
                }
                
                # シンボルテーブルの解析
                symbols = self._extract_elf_symbols(elf)
                
                # IL2CPP関連シンボルの検索
                il2cpp_symbols = [s for s in symbols if 'il2cpp' in s['name'].lower()]
                
                # 文字列の抽出
                strings = self._extract_elf_strings(f)
                unity_strings = [s for s in strings if any(keyword in s.lower() for keyword in [
                    'unity', 'il2cpp', 'mono', 'assembly', 'metadata'
                ])]
                
                # 結果の保存
                self.analysis_result['assembly_info'][file_info['path']] = {
                    'type': 'native_library',
                    'architecture': arch_info,
                    'total_symbols': len(symbols),
                    'il2cpp_symbols': len(il2cpp_symbols),
                    'unity_strings': len(unity_strings),
                    'file_size': file_info['size']
                }
                
                self.analysis_result['symbols'].extend(il2cpp_symbols[:50])  # 最初の50個のみ
                self.analysis_result['strings'].extend(unity_strings[:100])  # 最初の100個のみ
                
                logger.info(f"ネイティブライブラリ解析完了: {file_path}")
                
        except Exception as e:
            logger.error(f"ネイティブライブラリ解析エラー: {e}")
    
    def _analyze_il2cpp_metadata(self, file_path: str, file_info: Dict):
        """IL2CPPメタデータファイルの解析"""
        try:
            with open(file_path, 'rb') as f:
                # メタデータヘッダーの読み取り
                header = f.read(32)
                
                # マジックナンバーの確認
                if len(header) >= 4:
                    magic = struct.unpack('<I', header[:4])[0]
                    
                    metadata_info = {
                        'magic_number': hex(magic),
                        'file_size': file_info['size'],
                        'is_valid_metadata': magic == 0xFAB11BAF,  # IL2CPPメタデータのマジックナンバー
                    }
                    
                    if metadata_info['is_valid_metadata']:
                        # バージョン情報の取得
                        version = struct.unpack('<I', header[4:8])[0]
                        metadata_info['version'] = version
                        
                        # 文字列プールの検索
                        f.seek(0)
                        content = f.read()
                        strings = self._extract_metadata_strings(content)
                        
                        metadata_info['extracted_strings'] = len(strings)
                        self.analysis_result['strings'].extend(strings[:200])
                    
                    self.analysis_result['il2cpp_metadata'][file_info['path']] = metadata_info
                    
                    logger.info(f"IL2CPPメタデータ解析完了: {file_path}")
                
        except Exception as e:
            logger.error(f"IL2CPPメタデータ解析エラー: {e}")
    
    def _analyze_managed_assembly(self, file_path: str, file_info: Dict):
        """マネージドアセンブリ(.dll)の解析"""
        try:
            # PEファイルとして解析
            pe = pefile.PE(file_path)
            
            assembly_info = {
                'machine_type': hex(pe.FILE_HEADER.Machine),
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'timestamp': pe.FILE_HEADER.TimeDateStamp,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase)
            }
            
            # エクスポートテーブルの解析
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            
            # インポートテーブルの解析
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll_name}::{imp.name.decode('utf-8', errors='ignore')}")
            
            assembly_info['exports'] = len(exports)
            assembly_info['imports'] = len(imports)
            
            self.analysis_result['assembly_info'][file_info['path']] = assembly_info
            
            logger.info(f"マネージドアセンブリ解析完了: {file_path}")
            
        except Exception as e:
            logger.error(f"マネージドアセンブリ解析エラー: {e}")
    
    def _analyze_unity_assets(self, file_path: str, file_info: Dict):
        """Unityアセットファイルの解析"""
        try:
            with open(file_path, 'rb') as f:
                # アセットファイルヘッダーの読み取り
                header = f.read(20)
                
                if len(header) >= 20:
                    # Unity アセットファイルの基本情報
                    metadata_size = struct.unpack('>I', header[0:4])[0]
                    file_size = struct.unpack('>I', header[4:8])[0]
                    version = struct.unpack('>I', header[8:12])[0]
                    data_offset = struct.unpack('>I', header[12:16])[0]
                    
                    assets_info = {
                        'metadata_size': metadata_size,
                        'version': version,
                        'data_offset': data_offset,
                        'file_size': file_size
                    }
                    
                    self.analysis_result['unity_info'][file_info['path']] = assets_info
                    
                    logger.info(f"Unityアセット解析完了: {file_path}")
                
        except Exception as e:
            logger.error(f"Unityアセット解析エラー: {e}")
    
    def _extract_elf_symbols(self, elf: ELFFile) -> List[Dict]:
        """ELFファイルからシンボルを抽出"""
        symbols = []
        
        try:
            for section in elf.iter_sections():
                if section.name in ['.symtab', '.dynsym']:
                    for symbol in section.iter_symbols():
                        if symbol.name:
                            symbols.append({
                                'name': symbol.name,
                                'address': hex(symbol['st_value']),
                                'size': symbol['st_size'],
                                'type': symbol['st_info']['type']
                            })
        except Exception as e:
            logger.warning(f"シンボル抽出エラー: {e}")
        
        return symbols
    
    def _extract_elf_strings(self, file_obj) -> List[str]:
        """ELFファイルから文字列を抽出"""
        strings = []
        
        try:
            file_obj.seek(0)
            content = file_obj.read()
            
            # 印刷可能な文字列を検索（最小長4文字）
            current_string = ""
            for byte in content:
                if 32 <= byte <= 126:  # 印刷可能なASCII文字
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
            
            # 最後の文字列
            if len(current_string) >= 4:
                strings.append(current_string)
                
        except Exception as e:
            logger.warning(f"文字列抽出エラー: {e}")
        
        return strings
    
    def _extract_metadata_strings(self, content: bytes) -> List[str]:
        """メタデータから文字列を抽出"""
        strings = []
        
        try:
            # UTF-8文字列の検索
            current_string = ""
            for i, byte in enumerate(content):
                if 32 <= byte <= 126:  # 印刷可能なASCII文字
                    current_string += chr(byte)
                elif byte == 0:  # NULL終端
                    if len(current_string) >= 3:
                        strings.append(current_string)
                    current_string = ""
                else:
                    if len(current_string) >= 3:
                        strings.append(current_string)
                    current_string = ""
            
        except Exception as e:
            logger.warning(f"メタデータ文字列抽出エラー: {e}")
        
        return strings
    
    def _generate_unity_hints(self):
        """Unity解析結果から実装ヒントを生成"""
        hints = []
        
        # IL2CPPメタデータの存在確認
        if self.analysis_result['il2cpp_metadata']:
            hints.append("IL2CPPメタデータが検出されました - Unity IL2CPPビルドです")
            hints.append("Il2CppDumperやIl2CppInspectorを使用してより詳細な解析が可能です")
        
        # ネイティブライブラリの確認
        native_libs = [info for info in self.analysis_result['assembly_info'].values() 
                      if info.get('type') == 'native_library']
        if native_libs:
            hints.append(f"{len(native_libs)}個のネイティブライブラリが見つかりました")
            hints.append("Ghidra、IDA Pro、またはradare2を使用した逆アセンブルが推奨されます")
        
        # シンボル情報の確認
        if self.analysis_result['symbols']:
            il2cpp_symbols = [s for s in self.analysis_result['symbols'] if 'il2cpp' in s['name'].lower()]
            if il2cpp_symbols:
                hints.append(f"{len(il2cpp_symbols)}個のIL2CPP関連シンボルが見つかりました")
                hints.append("これらのシンボルを使用してAPIフックやメモリパッチが可能です")
        
        # 文字列情報の確認
        unity_strings = [s for s in self.analysis_result['strings'] if 'unity' in s.lower()]
        if unity_strings:
            hints.append(f"{len(unity_strings)}個のUnity関連文字列が見つかりました")
        
        # アーキテクチャ情報
        architectures = set()
        for info in self.analysis_result['assembly_info'].values():
            if 'architecture' in info:
                architectures.add(info['architecture'].get('architecture', 'unknown'))
        
        if architectures:
            hints.append(f"対象アーキテクチャ: {', '.join(architectures)}")
        
        self.analysis_result['implementation_hints'] = hints
    
    def _save_unity_results(self):
        """Unity解析結果をファイルに保存"""
        try:
            # JSON形式で保存
            output_file = self.output_dir / "unity_analysis_result.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_result, f, ensure_ascii=False, indent=2)
            
            # テキスト形式のサマリーも保存
            summary_file = self.output_dir / "unity_analysis_summary.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("Unity DLL解析結果サマリー\n")
                f.write("=" * 50 + "\n\n")
                
                # 基本情報
                f.write("検出されたUnityファイル:\n")
                for path, info in self.analysis_result['assembly_info'].items():
                    f.write(f"  {path}: {info.get('type', 'unknown')}\n")
                
                f.write(f"\n抽出されたシンボル数: {len(self.analysis_result['symbols'])}\n")
                f.write(f"抽出された文字列数: {len(self.analysis_result['strings'])}\n")
                
                # 実装ヒント
                f.write("\n実装ヒント:\n")
                for hint in self.analysis_result['implementation_hints']:
                    f.write(f"  • {hint}\n")
            
            logger.info(f"Unity解析結果を保存しました: {output_file}")
            return output_file
        
        except Exception as e:
            logger.error(f"結果保存エラー: {e}")
            return None

    def print_unity_summary(self):
        """Unity解析結果のサマリーを表示"""
        try:
            print("\n=== Unity解析結果サマリー ===")
            
            # Unity検出状況
            unity_detected = bool(self.analysis_result.get("unity_info"))
            il2cpp_detected = bool(self.analysis_result.get("il2cpp_metadata"))
            
            print(f"Unity検出: {'はい' if unity_detected else 'いいえ'}")
            print(f"IL2CPP検出: {'はい' if il2cpp_detected else 'いいえ'}")
            
            # ファイル情報
            assembly_count = len(self.analysis_result.get('assembly_info', {}))
            print(f"解析されたアセンブリ数: {assembly_count}")
            
            # シンボル・文字列情報
            symbols_count = len(self.analysis_result.get('symbols', []))
            strings_count = len(self.analysis_result.get('strings', []))
            print(f"抽出されたシンボル数: {symbols_count}")
            print(f"抽出された文字列数: {strings_count}")
            
            # 実装ヒント
            hints = self.analysis_result.get('implementation_hints', [])
            if hints:
                print(f"\n実装ヒント ({len(hints)}件):")
                for i, hint in enumerate(hints[:5], 1):  # 最初の5件のみ表示
                    print(f"  {i}. {hint}")
                if len(hints) > 5:
                    print(f"  ... 他{len(hints) - 5}件")
            
            print("=" * 40)
            
        except Exception as e:
            logger.error(f"Unity解析サマリー表示エラー: {e}")
            print(f"サマリー表示エラー: {e}")

    def save_results(self):
        """解析結果を保存（後方互換性のため）"""
        return self._save_unity_results()


def main():
    """メイン実行関数 - スタンドアロン実行用"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Unity APK解析ツール')
    parser.add_argument('apk_path', nargs='?', help='解析するAPKファイルのパス')
    parser.add_argument('--output', '-o', default='data/unity_analysis', 
                       help='出力ディレクトリ (デフォルト: data/unity_analysis)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='詳細ログを表示')
    
    args = parser.parse_args()
    
    # ログレベル設定
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # APKパスが指定されていない場合、対話的に入力を求める
    if not args.apk_path:
        print("Unity APK解析ツール")
        print("=" * 40)
        apk_path = input("解析するAPKファイルのパスを入力してください: ").strip()
        if not apk_path:
            print("APKファイルのパスが指定されていません。")
            return 1
    else:
        apk_path = args.apk_path
    
    # APKファイルの存在確認
    if not os.path.exists(apk_path):
        print(f"エラー: APKファイルが見つかりません: {apk_path}")
        return 1
    
    try:
        # Unity解析実行
        analyzer = UnityDLLAnalyzer(output_dir=args.output)
        print(f"Unity解析を開始します: {apk_path}")
        
        result = analyzer.analyze_apk_for_unity(apk_path)
        
        # 結果表示
        analyzer.print_unity_summary()
        
        # 結果保存
        output_file = analyzer.save_results()
        print(f"\n解析結果を保存しました: {output_file}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Unity解析エラー: {e}")
        print(f"エラー: {e}")
        return 1


if __name__ == "__main__":
    exit(main())