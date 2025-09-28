#!/usr/bin/env python3
"""
テスト用のサンプルAPKファイル作成スクリプト
Unity APKの構造を模擬したテスト用ファイルを生成します。
"""

import os
import zipfile
import json
from pathlib import Path

def create_test_apk():
    """テスト用のサンプルAPKファイルを作成"""
    
    # テスト用APKファイルのパス
    test_apk_path = Path("data/test_inputs/sample_unity_app.apk")
    test_apk_path.parent.mkdir(parents=True, exist_ok=True)
    
    # APKファイル（実際はZIPファイル）を作成
    with zipfile.ZipFile(test_apk_path, 'w', zipfile.ZIP_DEFLATED) as apk_zip:
        
        # AndroidManifest.xml（簡易版）
        manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.unityapp"
    android:versionCode="1"
    android:versionName="1.0">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    
    <application
        android:label="Unity Test App"
        android:icon="@drawable/app_icon">
        
        <activity android:name="com.unity3d.player.UnityPlayerActivity"
                  android:label="@string/app_name">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
        apk_zip.writestr("AndroidManifest.xml", manifest_content)
        
        # Unity関連ファイル
        # assets/bin/Data/Managed/Assembly-CSharp.dll（ダミー）
        apk_zip.writestr("assets/bin/Data/Managed/Assembly-CSharp.dll", b"DUMMY_ASSEMBLY_CSHARP_DLL_CONTENT")
        apk_zip.writestr("assets/bin/Data/Managed/UnityEngine.dll", b"DUMMY_UNITY_ENGINE_DLL_CONTENT")
        apk_zip.writestr("assets/bin/Data/Managed/mscorlib.dll", b"DUMMY_MSCORLIB_DLL_CONTENT")
        
        # IL2CPP関連ファイル
        apk_zip.writestr("assets/bin/Data/il2cpp_data/Metadata/global-metadata.dat", b"DUMMY_IL2CPP_METADATA")
        
        # ネイティブライブラリ
        apk_zip.writestr("lib/arm64-v8a/libil2cpp.so", b"DUMMY_IL2CPP_NATIVE_LIBRARY")
        apk_zip.writestr("lib/arm64-v8a/libunity.so", b"DUMMY_UNITY_NATIVE_LIBRARY")
        apk_zip.writestr("lib/armeabi-v7a/libil2cpp.so", b"DUMMY_IL2CPP_NATIVE_LIBRARY_ARM")
        
        # Unity設定ファイル
        unity_config = {
            "unity_version": "2022.3.15f1",
            "scripting_backend": "IL2CPP",
            "target_architectures": ["ARM64", "ARMv7"],
            "compression": "LZ4",
            "development_build": False
        }
        apk_zip.writestr("assets/bin/Data/boot.config", json.dumps(unity_config, indent=2))
        
        # リソースファイル
        apk_zip.writestr("assets/bin/Data/sharedassets0.assets", b"DUMMY_SHARED_ASSETS")
        apk_zip.writestr("assets/bin/Data/level0", b"DUMMY_LEVEL_DATA")
        
        # classes.dex（Android DEXファイル）
        apk_zip.writestr("classes.dex", b"DUMMY_DEX_FILE_CONTENT")
        
        # META-INF（署名情報）
        apk_zip.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        apk_zip.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        apk_zip.writestr("META-INF/CERT.RSA", b"DUMMY_CERTIFICATE")
    
    print(f"テスト用APKファイルを作成しました: {test_apk_path}")
    print(f"ファイルサイズ: {test_apk_path.stat().st_size} bytes")
    
    return str(test_apk_path)

def create_heydoon_test_apk():
    """HeyDooon風のテスト用APKファイルを作成"""
    
    test_apk_path = Path("data/test_inputs/heydoon_test.apk")
    test_apk_path.parent.mkdir(parents=True, exist_ok=True)
    
    with zipfile.ZipFile(test_apk_path, 'w', zipfile.ZIP_DEFLATED) as apk_zip:
        
        # HeyDooon特有のファイル構造を模擬
        manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.heydoon.app"
    android:versionCode="100"
    android:versionName="2.1.0">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.CAMERA" />
    
    <application
        android:label="HeyDooon"
        android:icon="@drawable/heydoon_icon">
        
        <activity android:name="com.unity3d.player.UnityPlayerActivity"
                  android:label="HeyDooon">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
        apk_zip.writestr("AndroidManifest.xml", manifest_content)
        
        # HeyDooon特有のアセット
        apk_zip.writestr("assets/bin/Data/Managed/Assembly-CSharp.dll", b"HEYDOON_ASSEMBLY_CSHARP")
        apk_zip.writestr("assets/bin/Data/Managed/HeyDooonCore.dll", b"HEYDOON_CORE_ASSEMBLY")
        apk_zip.writestr("assets/bin/Data/Managed/NetworkManager.dll", b"HEYDOON_NETWORK_MANAGER")
        
        # HeyDooon設定
        heydoon_config = {
            "app_name": "HeyDooon",
            "version": "2.1.0",
            "unity_version": "2022.3.15f1",
            "features": ["chat", "video_call", "file_sharing", "ai_assistant"],
            "server_endpoints": ["api.heydoon.com", "cdn.heydoon.com"],
            "encryption": "AES256"
        }
        apk_zip.writestr("assets/heydoon_config.json", json.dumps(heydoon_config, indent=2))
        
        # ネイティブライブラリ
        apk_zip.writestr("lib/arm64-v8a/libil2cpp.so", b"HEYDOON_IL2CPP_NATIVE")
        apk_zip.writestr("lib/arm64-v8a/libheydoon.so", b"HEYDOON_NATIVE_LIBRARY")
        
    print(f"HeyDooonテスト用APKファイルを作成しました: {test_apk_path}")
    return str(test_apk_path)

if __name__ == "__main__":
    print("=== テスト用APKファイル作成 ===")
    
    # 基本的なUnity APK
    unity_apk = create_test_apk()
    
    # HeyDooon風APK
    heydoon_apk = create_heydoon_test_apk()
    
    print("\n=== 作成完了 ===")
    print(f"Unity テストAPK: {unity_apk}")
    print(f"HeyDooon テストAPK: {heydoon_apk}")
    print("\nこれらのファイルを使用してシステムテストを実行できます。")