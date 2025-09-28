#!/usr/bin/env python3
"""
実際のバイナリ形式に近いテスト用APKファイルを作成するスクリプト
95%実現度達成のための改良版
"""

import zipfile
import os
from pathlib import Path
import struct
import json

def create_realistic_dll_content():
    """実際のDLLファイルに近いバイナリコンテンツを生成"""
    # DOS Header (MZ signature)
    dos_header = b'MZ'  # DOS signature
    dos_header += b'\x90\x00'  # Bytes on last page
    dos_header += b'\x03\x00'  # Pages in file
    dos_header += b'\x00\x00'  # Relocations
    dos_header += b'\x04\x00'  # Size of header in paragraphs
    dos_header += b'\x00\x00'  # Minimum extra paragraphs
    dos_header += b'\xFF\xFF'  # Maximum extra paragraphs
    dos_header += b'\x00\x00'  # Initial relative SS
    dos_header += b'\xB8\x00'  # Initial SP
    dos_header += b'\x00\x00'  # Checksum
    dos_header += b'\x00\x00'  # Initial IP
    dos_header += b'\x00\x00'  # Initial relative CS
    dos_header += b'\x40\x00'  # Address of relocation table
    dos_header += b'\x00\x00'  # Overlay number
    dos_header += b'\x00' * 32  # Reserved
    dos_header += b'\x80\x00\x00\x00'  # PE header offset
    
    # DOS stub
    dos_stub = b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'
    dos_stub += b'This program cannot be run in DOS mode.\r\r\n$'
    dos_stub += b'\x00' * (0x80 - len(dos_header) - len(dos_stub))
    
    # PE Header
    pe_header = b'PE\x00\x00'  # PE signature
    pe_header += b'\x4C\x01'   # Machine (i386)
    pe_header += b'\x03\x00'   # Number of sections
    pe_header += struct.pack('<L', 0x12345678)  # Timestamp
    pe_header += b'\x00' * 12  # Symbol table and string table
    pe_header += b'\xE0\x00'   # Size of optional header
    pe_header += b'\x02\x01'   # Characteristics
    
    # Optional Header
    optional_header = b'\x0B\x01'  # Magic (PE32)
    optional_header += b'\x0E\x00'  # Linker version
    optional_header += struct.pack('<L', 0x1000)  # Size of code
    optional_header += struct.pack('<L', 0x1000)  # Size of initialized data
    optional_header += b'\x00' * (0xE0 - len(optional_header))
    
    return dos_header + dos_stub + pe_header + optional_header

def create_realistic_so_content():
    """実際のSOファイルに近いバイナリコンテンツを生成"""
    # ELF Header
    elf_header = b'\x7fELF'  # ELF magic
    elf_header += b'\x02'     # 64-bit
    elf_header += b'\x01'     # Little endian
    elf_header += b'\x01'     # ELF version
    elf_header += b'\x00'     # System V ABI
    elf_header += b'\x00' * 8  # ABI version and padding
    elf_header += b'\x03\x00'  # Shared object file
    elf_header += b'\x3E\x00'  # x86-64
    elf_header += struct.pack('<L', 1)  # ELF version
    elf_header += struct.pack('<Q', 0x1000)  # Entry point
    elf_header += struct.pack('<Q', 64)  # Program header offset
    elf_header += struct.pack('<Q', 0)   # Section header offset
    elf_header += struct.pack('<L', 0)   # Flags
    elf_header += struct.pack('<H', 64)  # ELF header size
    elf_header += struct.pack('<H', 56)  # Program header size
    elf_header += struct.pack('<H', 1)   # Number of program headers
    elf_header += struct.pack('<H', 64)  # Section header size
    elf_header += struct.pack('<H', 0)   # Number of section headers
    elf_header += struct.pack('<H', 0)   # Section header string table index
    
    return elf_header + b'\x00' * (1024 - len(elf_header))

def create_realistic_metadata():
    """実際のIL2CPPメタデータに近いコンテンツを生成"""
    # IL2CPP Metadata Header
    metadata = b'IL2CPP'  # Signature
    metadata += struct.pack('<L', 24)  # Version
    metadata += struct.pack('<L', 100)  # String count
    metadata += struct.pack('<L', 50)   # Type count
    metadata += struct.pack('<L', 200)  # Method count
    metadata += struct.pack('<L', 30)   # Assembly count
    
    # Sample string data
    strings = [
        "UnityEngine",
        "Assembly-CSharp",
        "System.Object",
        "MonoBehaviour",
        "GameObject",
        "Transform",
        "Vector3",
        "Quaternion",
        "Start",
        "Update",
        "FixedUpdate",
        "LateUpdate"
    ]
    
    for s in strings:
        metadata += struct.pack('<L', len(s))
        metadata += s.encode('utf-8')
        metadata += b'\x00'  # Null terminator
    
    return metadata

def create_realistic_unity_assets():
    """実際のUnityアセットファイルに近いコンテンツを生成"""
    # Unity Asset File Header
    assets = b'UnityFS'  # Signature
    assets += struct.pack('<L', 6)  # Format version
    assets += b'5.6.1f1\x00' * 2  # Unity version
    assets += struct.pack('<Q', 1024)  # File size
    assets += struct.pack('<L', 64)   # Header size
    assets += struct.pack('<L', 0)    # Flags
    
    # Asset bundle data
    assets += b'\x00' * (1024 - len(assets))
    
    return assets

def create_realistic_apk():
    """実際のUnity APKに近い構造のテストファイルを作成"""
    
    output_dir = Path("data/test_inputs")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    apk_path = output_dir / "realistic_unity_app.apk"
    
    print(f"🔧 実際のバイナリ形式に近いAPKファイルを作成中: {apk_path}")
    
    with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
        
        # AndroidManifest.xml (実際のバイナリXML形式に近い)
        manifest_content = b'\x03\x00\x08\x00'  # Binary XML header
        manifest_content += b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        manifest_content += b'<application android:label="Unity Test App">'
        manifest_content += b'<activity android:name="com.unity3d.player.UnityPlayerActivity">'
        manifest_content += b'</activity></application></manifest>'
        apk.writestr("AndroidManifest.xml", manifest_content)
        
        # 実際のDLL形式のマネージドアセンブリ
        dll_content = create_realistic_dll_content()
        apk.writestr("assets/bin/Data/Managed/Assembly-CSharp.dll", dll_content)
        apk.writestr("assets/bin/Data/Managed/UnityEngine.dll", dll_content)
        apk.writestr("assets/bin/Data/Managed/System.Core.dll", dll_content)
        
        # 実際のSO形式のネイティブライブラリ
        so_content = create_realistic_so_content()
        apk.writestr("lib/arm64-v8a/libil2cpp.so", so_content)
        apk.writestr("lib/arm64-v8a/libunity.so", so_content)
        apk.writestr("lib/armeabi-v7a/libil2cpp.so", so_content)
        
        # 実際のIL2CPPメタデータ
        metadata_content = create_realistic_metadata()
        apk.writestr("assets/bin/Data/il2cpp_data/Metadata/global-metadata.dat", metadata_content)
        
        # 実際のUnityアセット
        assets_content = create_realistic_unity_assets()
        apk.writestr("assets/bin/Data/sharedassets0.assets", assets_content)
        apk.writestr("assets/bin/Data/level0", assets_content)
        
        # リソースファイル
        apk.writestr("resources.arsc", b'\x02\x00\x0C\x00' + b'\x00' * 1020)
        
        # classes.dex (Dalvik bytecode)
        dex_header = b'dex\n035\x00'  # DEX magic and version
        dex_header += struct.pack('<L', 0x12345678)  # Checksum
        dex_header += b'\x00' * 20  # SHA-1 signature
        dex_header += struct.pack('<L', 1024)  # File size
        dex_header += struct.pack('<L', 112)   # Header size
        dex_content = dex_header + b'\x00' * (1024 - len(dex_header))
        apk.writestr("classes.dex", dex_content)
        
        # META-INF (署名情報)
        apk.writestr("META-INF/MANIFEST.MF", 
                    b"Manifest-Version: 1.0\nCreated-By: Unity Test\n")
        apk.writestr("META-INF/CERT.SF", 
                    b"Signature-Version: 1.0\nCreated-By: Unity Test\n")
        apk.writestr("META-INF/CERT.RSA", b'\x30\x82' + b'\x00' * 1022)
        
        # Unity特有のファイル
        apk.writestr("assets/bin/Data/unity_builtin_extra", b'Unity builtin resources')
        apk.writestr("assets/bin/Data/RuntimeInitializeOnLoads.json", 
                    json.dumps({
                        "root": {
                            "assemblyTypes": [],
                            "managerTypes": []
                        }
                    }).encode())
        
        # ゲーム固有のアセット
        apk.writestr("assets/StreamingAssets/config.json", 
                    json.dumps({
                        "version": "1.0.0",
                        "gameMode": "production",
                        "features": ["multiplayer", "analytics", "iap"]
                    }).encode())
    
    print(f"✅ 実際のバイナリ形式APKファイルを作成しました: {apk_path}")
    print(f"📊 ファイルサイズ: {apk_path.stat().st_size:,} bytes")
    
    return apk_path

if __name__ == "__main__":
    create_realistic_apk()