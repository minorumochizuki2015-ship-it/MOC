#!/usr/bin/env python3
"""
HeyDooon APKからゲーム情報を抽出するスクリプト
"""

import zipfile
import json
from pathlib import Path
import sys

def extract_game_info(apk_path: str, output_dir: str):
    """APKファイルからゲーム情報を抽出"""
    
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not apk_path.exists():
        print(f"Error: APK file not found: {apk_path}")
        return False
    
    try:
        # APKからAndroidManifest.xmlを抽出
        with zipfile.ZipFile(apk_path, 'r') as apk:
            manifest_data = apk.read('AndroidManifest.xml')
            
            # バイナリXMLをファイルに保存
            with open(output_dir / 'AndroidManifest_binary.xml', 'wb') as f:
                f.write(manifest_data)
            
            # APK内のファイル一覧を取得
            file_list = apk.namelist()
            
            # ゲーム関連ファイルを分析
            game_analysis = {
                'manifest_size': len(manifest_data),
                'total_files': len(file_list),
                'unity_assets': [f for f in file_list if 'unity' in f.lower() or 'data.unity3d' in f],
                'scripts': [f for f in file_list if f.endswith('.cs') or 'script' in f.lower()],
                'textures': [f for f in file_list if f.endswith(('.png', '.jpg', '.jpeg', '.dds'))],
                'audio': [f for f in file_list if f.endswith(('.ogg', '.wav', '.mp3', '.aac'))],
                'models': [f for f in file_list if f.endswith(('.fbx', '.obj', '.dae', '.3ds'))],
                'shaders': [f for f in file_list if 'shader' in f.lower() or f.endswith('.shader')],
                'config_files': [f for f in file_list if f.endswith(('.json', '.xml', '.cfg', '.ini'))],
                'all_files': file_list
            }
            
            # 結果を保存
            with open(output_dir / 'game_analysis.json', 'w', encoding='utf-8') as f:
                json.dump(game_analysis, f, indent=2, ensure_ascii=False)
            
            print(f"AndroidManifest.xml extracted: {len(manifest_data)} bytes")
            print(f"Total files in APK: {len(file_list)}")
            print(f"Unity assets found: {len(game_analysis['unity_assets'])}")
            print(f"Texture files: {len(game_analysis['textures'])}")
            print(f"Audio files: {len(game_analysis['audio'])}")
            print(f"Config files: {len(game_analysis['config_files'])}")
            
            # Unity関連ファイルの詳細表示
            if game_analysis['unity_assets']:
                print("\nUnity Assets:")
                for asset in game_analysis['unity_assets'][:10]:  # 最初の10個のみ表示
                    print(f"  - {asset}")
                if len(game_analysis['unity_assets']) > 10:
                    print(f"  ... and {len(game_analysis['unity_assets']) - 10} more")
            
            return True
            
    except Exception as e:
        print(f"Error extracting game info: {e}")
        return False

if __name__ == "__main__":
    apk_path = "C:/Users/User/Downloads/HeyDooon_1.20_APKPure.apk"
    output_dir = "data/apk_analysis/heydoon_structure"
    
    success = extract_game_info(apk_path, output_dir)
    sys.exit(0 if success else 1)