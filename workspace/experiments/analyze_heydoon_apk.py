#!/usr/bin/env python3
"""
HeyDooon APK解析実行スクリプト
"""
import sys
import os
from pathlib import Path

# プロジェクトルートをPythonパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.apk_analyzer import APKAnalyzer

def main():
    """HeyDooon APKファイルを解析"""
    print("HeyDooon APK解析システム")
    print("=" * 50)
    
    # APKファイルのパスを確認
    apk_files = [
        "HeyDooon_1.20_APKPure.apk",
        "data/HeyDooon_1.20_APKPure.apk",
        "assets/HeyDooon_1.20_APKPure.apk"
    ]
    
    apk_path = None
    for path in apk_files:
        if os.path.exists(path):
            apk_path = path
            break
    
    if not apk_path:
        print("APKファイルが見つかりません。")
        print("以下のいずれかの場所にAPKファイルを配置してください:")
        for path in apk_files:
            print(f"  - {path}")
        print("\nまたは、APKファイルのパスを引数で指定してください:")
        print("  python analyze_heydoon_apk.py path/to/your.apk")
        
        if len(sys.argv) > 1:
            apk_path = sys.argv[1]
            if not os.path.exists(apk_path):
                print(f"指定されたファイルが存在しません: {apk_path}")
                return
        else:
            return
    
    try:
        print(f"APKファイル: {apk_path}")
        print("解析を開始します...\n")
        
        # APK解析を実行
        analyzer = APKAnalyzer(apk_path)
        result = analyzer.analyze()
        
        # 結果の表示
        analyzer.print_summary()
        
        # 実装に役立つ情報を表示
        print("\n" + "="*60)
        print("実装活用のための追加情報")
        print("="*60)
        
        # ファイル構造の詳細
        structure = result["file_structure"]
        if structure["notable_files"]:
            print("\n注目すべきファイル:")
            for file in structure["notable_files"][:10]:
                print(f"  • {file}")
        
        # アセットファイルの詳細
        assets = result["assets"]
        if assets["data_files"]:
            print("\nデータファイル:")
            for file in assets["data_files"][:10]:
                print(f"  • {file}")
        
        # 抽出された文字列
        strings = result["strings"]
        if strings["extracted_strings"]:
            print("\nゲーム関連の文字列:")
            for string in strings["extracted_strings"][:10]:
                print(f"  • {string}")
        
        print(f"\n解析完了！詳細結果は data/apk_analysis/ に保存されました。")
        
    except Exception as e:
        print(f"解析エラー: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()