#!/usr/bin/env python3
"""
改善されたシステムのテストスクリプト
IL2CPP解析と動的解析の改善効果を確認する
"""

import os
import sys
import json
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.complete_clone_generator import CompleteCloneGenerator

def test_improved_system():
    """改善されたシステムをテストし、完了率の向上を確認"""
    
    # テスト用APKファイルのパス
    test_apks = [
        "data/test_inputs/sample_unity_app.apk",
        "data/test_inputs/realistic_unity_app.apk",
        "data/test_inputs/heydoon_test.apk"
    ]
    
    results = []
    
    for apk_path in test_apks:
        if not os.path.exists(apk_path):
            print(f"⚠️ APKファイルが見つかりません: {apk_path}")
            continue
            
        print(f"\n🔍 テスト中: {apk_path}")
        
        try:
            # CompleteCloneGeneratorを初期化
            generator = CompleteCloneGenerator()
            
            # 完全クローン生成を実行
            result = generator.generate_complete_clone(
                apk_path=apk_path,
                package_name=None  # パッケージ名は自動推定
            )
            
            # 結果を記録
            completion_rate = result.get("completion_percentage", 0)
            success = result.get("success", False)
            
            results.append({
                "apk_path": apk_path,
                "success": success,
                "completion_rate": completion_rate,
                "phases_completed": result.get("generation_state", {}).get("completed_phases", []),
                "errors": result.get("generation_state", {}).get("errors", [])
            })
            
            print(f"✅ 成功: {success}")
            print(f"📊 完了率: {completion_rate:.1f}%")
            print(f"🔄 完了フェーズ: {len(result.get('generation_state', {}).get('completed_phases', []))}")
            
            if result.get("generation_state", {}).get("errors"):
                print(f"⚠️ エラー数: {len(result['generation_state']['errors'])}")
                for error in result["generation_state"]["errors"][:3]:  # 最初の3つのエラーを表示
                    print(f"   - {error}")
            
        except Exception as e:
            print(f"❌ エラー: {str(e)}")
            results.append({
                "apk_path": apk_path,
                "success": False,
                "completion_rate": 0,
                "error": str(e)
            })
    
    # 結果の要約
    print("\n" + "="*60)
    print("📈 改善されたシステムのテスト結果")
    print("="*60)
    
    successful_tests = [r for r in results if r.get("success", False)]
    completion_rates = [r["completion_rate"] for r in successful_tests]
    
    if completion_rates:
        max_completion = max(completion_rates)
        avg_completion = sum(completion_rates) / len(completion_rates)
        
        print(f"✅ 成功したテスト: {len(successful_tests)}/{len(results)}")
        print(f"📊 最高完了率: {max_completion:.1f}%")
        print(f"📊 平均完了率: {avg_completion:.1f}%")
        
        # 95%目標との比較
        target_rate = 95.0
        if max_completion >= target_rate:
            print(f"🎉 目標達成！ {target_rate}%を上回りました")
        else:
            improvement_needed = target_rate - max_completion
            print(f"📈 目標まで: {improvement_needed:.1f}%の改善が必要")
        
        # 改善効果の分析
        print(f"\n🔍 改善効果の分析:")
        for result in successful_tests:
            phases = result.get("phases_completed", [])
            print(f"  {os.path.basename(result['apk_path'])}: {result['completion_rate']:.1f}% ({len(phases)}フェーズ完了)")
            
            # IL2CPP解析と動的解析の状況を確認
            il2cpp_completed = "il2cpp_analysis" in phases
            dynamic_completed = "dynamic_analysis" in phases
            print(f"    - IL2CPP解析: {'✅' if il2cpp_completed else '❌'}")
            print(f"    - 動的解析: {'✅' if dynamic_completed else '❌'}")
            
            # エラー情報も表示
            if result.get("errors"):
                print(f"    - エラー: {len(result['errors'])}件")
                for error in result["errors"][:2]:  # 最初の2つのエラーを表示
                    print(f"      • {error}")
    else:
        print("❌ 成功したテストがありません")
    
    # 結果をファイルに保存
    output_file = "data/test_outputs/improved_system_test_results.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "test_summary": {
                "total_tests": len(results),
                "successful_tests": len(successful_tests),
                "max_completion_rate": max(completion_rates) if completion_rates else 0,
                "avg_completion_rate": sum(completion_rates) / len(completion_rates) if completion_rates else 0,
                "target_achieved": max(completion_rates) >= 95.0 if completion_rates else False
            },
            "detailed_results": results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 詳細結果を保存しました: {output_file}")
    
    return results

if __name__ == "__main__":
    test_improved_system()