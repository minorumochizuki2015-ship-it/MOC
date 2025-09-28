#!/usr/bin/env python3
"""
修正されたAPK解析システムのテスト
CompleteCloneGeneratorとAPKAnalyzerの連携を検証
"""

import sys
import os
from pathlib import Path
import json
import logging

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

from utils.complete_clone_generator import CompleteCloneGenerator

# ログ設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_fixed_apk_analysis():
    """修正されたAPK解析システムのテスト"""
    print("=== 修正されたAPK解析システムのテスト ===")
    
    # テスト用APKファイルのパス
    test_apks = [
        "data/test_inputs/realistic_unity_app.apk",
        "data/test_inputs/heydoon_test.apk",
        "data/test_inputs/sample_unity_app.apk"
    ]
    
    results = {}
    
    for apk_path in test_apks:
        apk_file = Path(apk_path)
        if not apk_file.exists():
            print(f"⚠️  APKファイルが見つかりません: {apk_path}")
            continue
            
        print(f"\n📱 テスト対象APK: {apk_path}")
        
        try:
            # CompleteCloneGeneratorを初期化
            generator = CompleteCloneGenerator(
                output_dir="data/fixed_analysis_test"
            )
            
            # 完全クローン生成を実行
            print("🔄 完全クローン生成を開始...")
            result = generator.generate_complete_clone(str(apk_file))
            
            # 結果の詳細表示
            print(f"✅ 完了率: {result.get('completion_percentage', 0):.1f}%")
            print(f"🎯 成功状態: {result.get('success', False)}")
            print(f"📊 現在のフェーズ: {result.get('current_phase', 'unknown')}")
            print(f"📈 進捗: {result.get('progress_percentage', 0):.1f}%")
            
            # エラーがある場合は表示
            errors = result.get('errors', [])
            if errors:
                print(f"❌ エラー数: {len(errors)}")
                for i, error in enumerate(errors[:3]):  # 最初の3つのエラーのみ表示
                    print(f"   {i+1}. {error}")
            
            # 完了したフェーズの表示
            completed_phases = result.get('completed_phases', [])
            if completed_phases:
                print(f"✅ 完了フェーズ: {', '.join(completed_phases)}")
            
            results[apk_path] = result
            
        except Exception as e:
            print(f"❌ テスト中にエラーが発生: {e}")
            results[apk_path] = {"error": str(e), "success": False}
    
    # 結果の保存
    output_file = Path("data/fixed_analysis_test_results.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 詳細結果を保存: {output_file}")
    
    # 成功率の計算
    successful_tests = sum(1 for result in results.values() if result.get('success', False))
    total_tests = len(results)
    success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
    
    print(f"\n📊 テスト結果サマリー:")
    print(f"   成功: {successful_tests}/{total_tests} ({success_rate:.1f}%)")
    
    # 95%目標に向けた分析
    max_completion = max((result.get('completion_percentage', 0) for result in results.values()), default=0)
    print(f"   最高完了率: {max_completion:.1f}%")
    print(f"   95%目標まで: {95 - max_completion:.1f}%")
    
    if max_completion >= 95:
        print("🎉 95%目標を達成しました！")
    else:
        print("🔧 さらなる改善が必要です")
    
    return results

if __name__ == "__main__":
    test_fixed_apk_analysis()