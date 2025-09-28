#!/usr/bin/env python3
"""
実際のバイナリ形式APKでの完全クローン解析テスト
95%実現度達成のためのテストスクリプト
"""

import sys
sys.path.append('src')

from utils.complete_clone_generator import CompleteCloneGenerator
from pathlib import Path
import json

def test_realistic_apk_analysis():
    """実際のバイナリ形式APKで完全解析をテスト"""
    
    apk_file = 'data/test_inputs/realistic_unity_app.apk'
    
    print(f'🔍 {apk_file} の完全解析を開始...')
    print('📋 実際のバイナリ形式での95%実現度達成テスト')
    
    if not Path(apk_file).exists():
        print(f'❌ APKファイルが見つかりません: {apk_file}')
        return False
    
    output_dir = f'data/complete_clone_analysis/realistic_unity_app'
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    generator = CompleteCloneGenerator(output_dir)
    result = generator.generate_complete_clone(apk_file)
    
    if result:
        completion = result.get('completion_percentage', 0)
        success = result.get('success', False)
        
        print(f'\n📊 完全解析結果:')
        print(f'   完成度: {completion:.1f}%')
        print(f'   成功: {success}')
        
        if 'generation_state' in result:
            state = result['generation_state']
            print(f'   現在のフェーズ: {state.get("current_phase", "unknown")}')
            print(f'   進捗: {state.get("progress", 0):.1f}%')
            print(f'   完了フェーズ数: {len(state.get("completed_phases", []))}')
            
            if state.get('errors'):
                print(f'   エラー数: {len(state["errors"])}')
                for i, error in enumerate(state['errors'][:3]):
                    print(f'     {i+1}. {error}')
        
        # 詳細結果を保存
        result_data = {
            'apk_file': apk_file,
            'completion_percentage': completion,
            'success': success,
            'output_dir': output_dir,
            'details': result,
            'target_completion': 95.0
        }
        
        with open('data/realistic_apk_analysis_results.json', 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        print(f'\n📄 詳細結果を保存しました: data/realistic_apk_analysis_results.json')
        
        if completion >= 95.0:
            print('🎉 目標の95%実現度を達成しました！')
            return True
        else:
            remaining = 95.0 - completion
            print(f'⚠️ 目標まで残り {remaining:.1f}% です')
            
            # 改善提案を表示
            print('\n🔧 改善提案:')
            if completion < 25:
                print('   - 静的解析の成功率を向上させる')
                print('   - DLLファイルの解析精度を改善する')
            elif completion < 50:
                print('   - 動的解析機能を強化する')
                print('   - IL2CPPメタデータ解析を最適化する')
            elif completion < 75:
                print('   - ML解析機能を追加する')
                print('   - ゲームロジック抽出を改善する')
            else:
                print('   - アセット解析を強化する')
                print('   - 実装ヒント生成を最適化する')
            
            return False
            
    else:
        print('❌ 完全解析に失敗しました')
        return False

if __name__ == "__main__":
    success = test_realistic_apk_analysis()
    exit(0 if success else 1)