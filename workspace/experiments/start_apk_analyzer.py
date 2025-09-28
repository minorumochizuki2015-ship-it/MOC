#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK解析アプリケーション起動スクリプト
"""

import sys
import os
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from src.app_ui.apk_analyzer_app import APKAnalyzerApp
    
    def main():
        """APK解析アプリを起動"""
        print("APK解析アプリを起動しています...")
        
        # 必要なディレクトリを作成
        data_dir = project_root / "data" / "apk_analysis"
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # アプリ起動
        app = APKAnalyzerApp()
        app.run()
    
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"モジュールのインポートエラー: {e}")
    print("必要な依存関係をインストールしてください:")
    print("pip install customtkinter lxml xmltodict")
    sys.exit(1)
except Exception as e:
    print(f"アプリケーション起動エラー: {e}")
    sys.exit(1)