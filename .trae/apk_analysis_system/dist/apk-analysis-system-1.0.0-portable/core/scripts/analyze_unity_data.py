#!/usr/bin/env python3
"""
Unity data.unity3dファイルを解析してゲームの詳細情報を抽出
"""

import zipfile
import json
import struct
from pathlib import Path
import sys

def analyze_unity_data(apk_path: str, output_dir: str):
    """Unity data.unity3dファイルを解析"""
    
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not apk_path.exists():
        print(f"Error: APK file not found: {apk_path}")
        return False
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Unity data.unity3dファイルを抽出
            unity_data = apk.read('assets/bin/Data/data.unity3d')
            
            # バイナリファイルを保存
            with open(output_dir / 'data.unity3d', 'wb') as f:
                f.write(unity_data)
            
            # ファイルヘッダーを解析
            header_info = analyze_unity_header(unity_data)
            
            # ScriptingAssemblies.jsonを解析
            try:
                scripting_json = apk.read('assets/bin/Data/ScriptingAssemblies.json')
                scripting_data = json.loads(scripting_json.decode('utf-8'))
                
                with open(output_dir / 'ScriptingAssemblies.json', 'w', encoding='utf-8') as f:
                    json.dump(scripting_data, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                print(f"Warning: Could not read ScriptingAssemblies.json: {e}")
                scripting_data = {}
            
            # RuntimeInitializeOnLoads.jsonを解析
            try:
                runtime_json = apk.read('assets/bin/Data/RuntimeInitializeOnLoads.json')
                runtime_data = json.loads(runtime_json.decode('utf-8'))
                
                with open(output_dir / 'RuntimeInitializeOnLoads.json', 'w', encoding='utf-8') as f:
                    json.dump(runtime_data, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                print(f"Warning: Could not read RuntimeInitializeOnLoads.json: {e}")
                runtime_data = {}
            
            # 解析結果をまとめる
            unity_analysis = {
                'data_unity3d_size': len(unity_data),
                'header_info': header_info,
                'scripting_assemblies': scripting_data,
                'runtime_initialize': runtime_data,
                'file_signature': unity_data[:16].hex() if len(unity_data) >= 16 else '',
                'estimated_game_type': estimate_game_type(unity_data, scripting_data, runtime_data)
            }
            
            # 結果を保存
            with open(output_dir / 'unity_analysis.json', 'w', encoding='utf-8') as f:
                json.dump(unity_analysis, f, indent=2, ensure_ascii=False)
            
            print(f"Unity data.unity3d size: {len(unity_data)} bytes")
            print(f"File signature: {unity_data[:16].hex()}")
            print(f"Header info: {header_info}")
            print(f"Estimated game type: {unity_analysis['estimated_game_type']}")
            
            if scripting_data:
                print(f"Scripting assemblies: {len(scripting_data.get('names', []))}")
            
            return True
            
    except Exception as e:
        print(f"Error analyzing Unity data: {e}")
        return False

def analyze_unity_header(data: bytes) -> dict:
    """Unityファイルのヘッダーを解析"""
    if len(data) < 32:
        return {"error": "File too small"}
    
    try:
        # Unity Asset Bundleの基本的なヘッダー構造を推測
        signature = data[:16].hex()
        
        # 一般的なUnityファイルの特徴を検索
        header_info = {
            "signature": signature,
            "size": len(data),
            "has_unity_signature": b"UnityFS" in data[:100] or b"Unity" in data[:100],
            "has_asset_bundle": b"AssetBundle" in data[:200],
            "compression_detected": detect_compression(data),
            "estimated_format": "Unity Asset Bundle" if b"UnityFS" in data[:100] else "Unity Data File"
        }
        
        return header_info
        
    except Exception as e:
        return {"error": str(e)}

def detect_compression(data: bytes) -> str:
    """圧縮形式を検出"""
    if data[:2] == b'\x1f\x8b':
        return "gzip"
    elif data[:4] == b'PK\x03\x04':
        return "zip"
    elif data[:3] == b'BZh':
        return "bzip2"
    elif data[:6] == b'\xfd7zXZ':
        return "xz"
    else:
        return "none or unknown"

def estimate_game_type(unity_data: bytes, scripting_data: dict, runtime_data: dict) -> str:
    """ゲームタイプを推定"""
    
    # スクリプト名から推測
    script_names = scripting_data.get('names', [])
    
    # 2Dゲームの特徴
    if any('2D' in name or 'Sprite' in name for name in script_names):
        return "2D Game"
    
    # 3Dゲームの特徴
    if any('3D' in name or 'Mesh' in name or 'Camera' in name for name in script_names):
        return "3D Game"
    
    # パズルゲームの特徴
    if any('Puzzle' in name or 'Match' in name or 'Grid' in name for name in script_names):
        return "Puzzle Game"
    
    # アクションゲームの特徴
    if any('Action' in name or 'Player' in name or 'Enemy' in name for name in script_names):
        return "Action Game"
    
    # データサイズから推測
    if len(unity_data) > 50 * 1024 * 1024:  # 50MB以上
        return "Large 3D Game"
    elif len(unity_data) > 10 * 1024 * 1024:  # 10MB以上
        return "Medium Game"
    else:
        return "Small/Casual Game"

if __name__ == "__main__":
    apk_path = "C:/Users/User/Downloads/HeyDooon_1.20_APKPure.apk"
    output_dir = "data/apk_analysis/heydoon_structure"
    
    success = analyze_unity_data(apk_path, output_dir)
    sys.exit(0 if success else 1)