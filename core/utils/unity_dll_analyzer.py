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

logger = logging.getLogger(__name__)

class UnityDLLAnalyzer:
    """Unity IL2CPP DLLの逆アセンブルと解析を行うクラス"""
    
    def __init__(self, output_dir: str = "data/unity_analysis"):
        """
        Unity DLL解析器の初期化
        
        Args:
            output_dir: 解析結果の出力ディレクトリ
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 解析結果を格納する辞書
        self.analysis_result = {
            "unity_info": {},
            "il2cpp_metadata": {},
            "assembly_info": {},
            "symbols": [],
            "strings": [],
            "methods": [],
            "classes": [],
            "disassembly": {},
            "implementation_hints": []
        }
    
    def analyze_apk_for_unity(self, apk_path: str) -> Dict[str, Any]:
        """
        APKファイルからUnity関連ファイルを抽出して解析
        
        Args:
            apk_path: APKファイルのパス
            
        Returns:
            Unity解析結果の辞書（unity_detectedフィールドを含む）
        """
        if not DISASM_AVAILABLE:
            return {
                "error": "逆アセンブル用ライブラリが不足しています",
                "unity_detected": False
            }
        
        logger.info(f"Unity DLL解析開始: {apk_path}")
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Unity関連ファイルの検索
                unity_files = self._find_unity_files(apk_zip)
                
                # Unity検出フラグを設定
                unity_detected = len(unity_files) > 0
                
                if not unity_files:
                    return {
                        "error": "Unity IL2CPP関連ファイルが見つかりません",
                        "unity_detected": False
                    }
                
                # 一時ディレクトリに抽出
                with tempfile.TemporaryDirectory() as temp_dir:
                    extracted_files = self._extract_unity_files(apk_zip, unity_files, temp_dir)
                    
                    # 各ファイルを解析
                    for file_info in extracted_files:
                        self._analyze_unity_file(file_info)
                
                # 実装ヒントの生成
                self._generate_unity_hints()
                
                # 結果の保存
                self._save_unity_results()
                
                # Unity検出フラグを結果に追加
                self.analysis_result["unity_detected"] = unity_detected
                
                # IL2CPP検出フラグも追加
                il2cpp_detected = bool(self.analysis_result.get("il2cpp_metadata"))
                self.analysis_result["il2cpp_detected"] = il2cpp_detected
                
                logger.info(f"Unity DLL解析完了 - Unity検出: {unity_detected}, IL2CPP検出: {il2cpp_detected}")
                return self.analysis_result
                
        except Exception as e:
            logger.error(f"Unity DLL解析エラー: {e}")
            return {
                "error": str(e),
                "unity_detected": False
            }
    
    def _find_unity_files(self, apk_zip: zipfile.ZipFile) -> List[Dict[str, str]]:
        """APK内のUnity関連ファイルを検索"""
        unity_files = []
        
        for file_path in apk_zip.namelist():
            file_lower = file_path.lower()
            
            # IL2CPP関連ファイルの検索
            if any(pattern in file_lower for pattern in [
                'libil2cpp.so',
                'gameassembly.dll', 
                'assembly-csharp.dll',
                'unityengine.dll',
                'global-metadata.dat'
            ]):
                unity_files.append({
                    'path': file_path,
                    'type': self._determine_file_type(file_path),
                    'size': apk_zip.getinfo(file_path).file_size
                })
            
            # lib/arm64-v8a/ や lib/armeabi-v7a/ 内のネイティブライブラリ
            elif file_path.startswith('lib/') and file_path.endswith('.so'):
                if any(unity_lib in file_lower for unity_lib in [
                    'unity', 'il2cpp', 'mono', 'game'
                ]):
                    unity_files.append({
                        'path': file_path,
                        'type': 'native_library',
                        'size': apk_zip.getinfo(file_path).file_size
                    })
            
            # assets/bin/Data/ 内のメタデータ
            elif 'assets/bin/data/' in file_lower:
                if any(data_file in file_lower for data_file in [
                    'global-metadata.dat',
                    'metadata.dat',
                    'resources.assets',
                    'sharedassets'
                ]):
                    unity_files.append({
                        'path': file_path,
                        'type': 'unity_data',
                        'size': apk_zip.getinfo(file_path).file_size
                    })
        
        return unity_files
    
    def _determine_file_type(self, file_path: str) -> str:
        """ファイルパスからファイルタイプを判定"""
        file_lower = file_path.lower()
        
        if file_lower.endswith('.dll'):
            return 'managed_assembly'
        elif file_lower.endswith('.so'):
            return 'native_library'
        elif 'metadata.dat' in file_lower:
            return 'il2cpp_metadata'
        elif file_lower.endswith('.assets'):
            return 'unity_assets'
        else:
            return 'unknown'
    
    def _extract_unity_files(self, apk_zip: zipfile.ZipFile, unity_files: List[Dict], temp_dir: str) -> List[Dict]:
        """Unity関連ファイルを一時ディレクトリに抽出"""
        extracted_files = []
        
        for file_info in unity_files:
            try:
                # ファイルを抽出
                extracted_path = os.path.join(temp_dir, os.path.basename(file_info['path']))
                with apk_zip.open(file_info['path']) as source:
                    with open(extracted_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
                
                file_info['extracted_path'] = extracted_path
                extracted_files.append(file_info)
                
                logger.info(f"抽出完了: {file_info['path']} -> {extracted_path}")
                
            except Exception as e:
                logger.warning(f"ファイル抽出失敗: {file_info['path']} - {e}")
        
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
            
        except Exception as e:
            logger.error(f"結果保存エラー: {e}")
    
    def print_unity_summary(self):
        """Unity解析結果のサマリーを表示"""
        print("\n" + "="*60)
        print("Unity DLL解析結果")
        print("="*60)
        
        # 検出されたファイル
        print("検出されたUnityファイル:")
        for path, info in self.analysis_result['assembly_info'].items():
            print(f"  {os.path.basename(path)}: {info.get('type', 'unknown')}")
        
        # IL2CPPメタデータ
        if self.analysis_result['il2cpp_metadata']:
            print(f"\nIL2CPPメタデータ: {len(self.analysis_result['il2cpp_metadata'])}個")
            for path, info in self.analysis_result['il2cpp_metadata'].items():
                if info.get('is_valid_metadata'):
                    print(f"  {os.path.basename(path)}: バージョン {info.get('version', 'unknown')}")
        
        # シンボルと文字列
        print(f"\n抽出されたシンボル: {len(self.analysis_result['symbols'])}個")
        print(f"抽出された文字列: {len(self.analysis_result['strings'])}個")
        
        # 実装ヒント
        print("\n実装ヒント:")
        for hint in self.analysis_result['implementation_hints']:
            print(f"  • {hint}")
        
        print("\n" + "="*60)