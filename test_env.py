#!/usr/bin/env python3
"""環境変数テスト用スクリプト"""

import os
import sys

def test_environment():
    print("=== Environment Variable Test ===")
    print(f"ORCH_MCP_TOKEN exists: {'ORCH_MCP_TOKEN' in os.environ}")
    print(f"ORCH_MCP_TOKEN value: {repr(os.environ.get('ORCH_MCP_TOKEN'))}")
    print(f"ORCH_MCP_TOKEN bool: {bool(os.environ.get('ORCH_MCP_TOKEN'))}")
    print(f"ORCH_HOST: {repr(os.environ.get('ORCH_HOST'))}")
    print(f"ORCH_PORT: {repr(os.environ.get('ORCH_PORT'))}")
    print()
    
    # 全環境変数でORCHで始まるものを表示
    print("=== ORCH Environment Variables ===")
    for key, value in sorted(os.environ.items()):
        if key.startswith('ORCH'):
            print(f"{key}: {repr(value)}")
    print()
    
    # Pythonプロセス情報
    print("=== Python Process Info ===")
    print(f"Python executable: {sys.executable}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Process ID: {os.getpid()}")

if __name__ == "__main__":
    test_environment()