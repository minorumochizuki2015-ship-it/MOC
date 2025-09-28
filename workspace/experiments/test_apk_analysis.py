#!/usr/bin/env python3
"""
APK解析システムの自動テストスクリプト
作成したテスト用APKファイルを使用してシステムの各機能をテストします。
"""

import os
import sys
import json
import time
from pathlib import Path

# プロジェクトのsrcディレクトリをパスに追加
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_apk_selection_and_analysis():
    """APKファイルの選択と基本解析機能をテスト"""
    print("=== APKファイル選択・解析テスト ===")
    
    try:
        from utils.apk_analyzer import APKAnalyzer
        
        # テスト用APKファイルのパス
        test_apk_path = Path("data/test_inputs/sample_unity_app.apk")
        output_dir = Path("data/test_outputs")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if not test_apk_path.exists():
            print(f"❌ テスト用APKファイルが見つかりません: {test_apk_path}")
            return False
        
        print(f"📱 テスト対象APK: {test_apk_path}")
        print(f"📁 出力ディレクトリ: {output_dir}")
        
        # APKAnalyzerを初期化
        analyzer = APKAnalyzer(str(test_apk_path), str(output_dir))
        
        # 基本解析を実行
        print("🔍 基本解析を開始...")
        result = analyzer.analyze()
        
        if result:
            print("✅ 基本解析が正常に完了しました")
            print(f"📊 解析結果: {json.dumps(result, indent=2, ensure_ascii=False)}")
            return True
        else:
            print("❌ 基本解析に失敗しました")
            return False
            
    except Exception as e:
        print(f"❌ APK解析テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_unity_extraction():
    """Unity関連ファイルの抽出機能をテスト"""
    print("\n=== Unity関連ファイル抽出テスト ===")
    
    try:
        from utils.unity_analyzer import UnityAnalyzer
        
        test_apk_path = Path("data/test_inputs/sample_unity_app.apk")
        output_dir = Path("data/test_outputs/unity_extraction")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🎮 Unity解析対象: {test_apk_path}")
        
        # UnityAnalyzerを初期化
        unity_analyzer = UnityAnalyzer(str(output_dir))
        
        # Unity関連ファイルの抽出
        print("🔍 Unity関連ファイルを抽出中...")
        result = unity_analyzer.analyze_apk(str(test_apk_path))
        
        if result:
            print("✅ Unity関連ファイルの抽出が完了しました")
            
            # 抽出されたファイルを確認
            extracted_files = list(output_dir.rglob("*"))
            print(f"📁 抽出されたファイル数: {len(extracted_files)}")
            
            for file_path in extracted_files[:10]:  # 最初の10ファイルを表示
                if file_path.is_file():
                    print(f"  📄 {file_path.relative_to(output_dir)}")
            
            return True
        else:
            print("❌ Unity関連ファイルの抽出に失敗しました")
            return False
            
    except Exception as e:
        print(f"❌ Unity抽出テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_il2cpp_analysis():
    """IL2CPPメタデータの解析機能をテスト"""
    print("\n=== IL2CPPメタデータ解析テスト ===")
    
    try:
        from utils.unity_dll_analyzer import UnityDLLAnalyzer
        
        test_apk_path = Path("data/test_inputs/sample_unity_app.apk")
        output_dir = Path("data/test_outputs/il2cpp_analysis")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🔧 IL2CPP解析対象: {test_apk_path}")
        
        # UnityDLLAnalyzerを初期化
        dll_analyzer = UnityDLLAnalyzer(str(output_dir))
        
        # IL2CPPメタデータの解析
        print("🔍 IL2CPPメタデータを解析中...")
        result = dll_analyzer.analyze_apk_for_unity(str(test_apk_path))
        
        if result:
            print("✅ IL2CPPメタデータの解析が完了しました")
            print(f"📊 解析結果: {json.dumps(result, indent=2, ensure_ascii=False)}")
            return True
        else:
            print("❌ IL2CPPメタデータの解析に失敗しました")
            return False
            
    except Exception as e:
        print(f"❌ IL2CPP解析テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_native_disassembly():
    """ネイティブライブラリの逆アセンブル機能をテスト"""
    print("\n=== ネイティブライブラリ逆アセンブルテスト ===")
    
    try:
        # UnityDLLAnalyzerのネイティブライブラリ解析機能を使用
        from utils.unity_dll_analyzer import UnityDLLAnalyzer
        
        test_apk_path = Path("data/test_inputs/sample_unity_app.apk")
        output_dir = Path("data/test_outputs/native_analysis")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"⚙️ ネイティブ解析対象: {test_apk_path}")
        
        # UnityDLLAnalyzerを初期化
        unity_analyzer = UnityDLLAnalyzer(str(output_dir))
        
        # ネイティブライブラリの解析（APK内のネイティブライブラリを解析）
        print("🔍 ネイティブライブラリを解析中...")
        result = unity_analyzer.analyze_apk_for_unity(str(test_apk_path))
        
        if result:
            print("✅ ネイティブライブラリの解析が完了しました")
            
            # ネイティブライブラリ関連の結果を抽出
            native_info = {}
            if "assembly_info" in result:
                native_libs = {k: v for k, v in result["assembly_info"].items() 
                             if v.get("type") == "native_library"}
                native_info["native_libraries"] = native_libs
                native_info["native_library_count"] = len(native_libs)
            
            print(f"📊 ネイティブライブラリ解析結果: {json.dumps(native_info, indent=2, ensure_ascii=False)}")
            return True
        else:
            print("❌ ネイティブライブラリの解析に失敗しました")
            return False
            
    except Exception as e:
        print(f"❌ ネイティブ解析テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_result_management():
    """解析結果の保存と履歴管理機能をテスト"""
    print("\n=== 解析結果保存・履歴管理テスト ===")
    
    try:
        from utils.complete_clone_generator import CompleteCloneGenerator
        
        test_apk_path = Path("data/test_inputs/heydoon_test.apk")
        output_dir = Path("data/test_outputs/complete_analysis")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"💾 完全解析対象: {test_apk_path}")
        
        # CompleteCloneGeneratorを初期化
        clone_generator = CompleteCloneGenerator(str(output_dir))
        
        # 完全解析を実行
        print("🔍 完全解析を実行中...")
        result = clone_generator.generate_complete_clone(str(test_apk_path))
        
        if result and result.get("success", False):
            print("✅ 完全解析と結果保存が完了しました")
            
            # 保存された結果ファイルを確認
            result_files = list(output_dir.rglob("*.json"))
            print(f"📁 保存された結果ファイル数: {len(result_files)}")
            
            for result_file in result_files[:5]:  # 最初の5ファイルを表示
                print(f"  📄 {result_file.relative_to(output_dir)}")
            
            # 結果の概要を表示
            completion = result.get("completion_percentage", 0)
            print(f"📊 完成度: {completion:.1f}%")
            
            return True
        else:
            error_msg = result.get("error", "Unknown error") if result else "No result returned"
            print(f"❌ 完全解析に失敗しました: {error_msg}")
            return False
            
    except Exception as e:
        print(f"❌ 結果管理テスト中にエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_comprehensive_test():
    """包括的なシステムテストを実行"""
    print("🚀 拡張Unity解析システム - 包括的テスト開始")
    print("=" * 60)
    
    test_results = []
    
    # 各テストを順次実行
    tests = [
        ("APK選択・解析", test_apk_selection_and_analysis),
        ("Unity抽出", test_unity_extraction),
        ("IL2CPP解析", test_il2cpp_analysis),
        ("ネイティブ逆アセンブル", test_native_disassembly),
        ("結果管理", test_result_management)
    ]
    
    for test_name, test_func in tests:
        print(f"\n🧪 {test_name}テストを実行中...")
        start_time = time.time()
        
        try:
            result = test_func()
            elapsed_time = time.time() - start_time
            
            test_results.append({
                "test_name": test_name,
                "result": "PASS" if result else "FAIL",
                "elapsed_time": elapsed_time
            })
            
            if result:
                print(f"✅ {test_name}テスト: PASS ({elapsed_time:.2f}秒)")
            else:
                print(f"❌ {test_name}テスト: FAIL ({elapsed_time:.2f}秒)")
                
        except Exception as e:
            elapsed_time = time.time() - start_time
            test_results.append({
                "test_name": test_name,
                "result": "ERROR",
                "elapsed_time": elapsed_time,
                "error": str(e)
            })
            print(f"💥 {test_name}テスト: ERROR ({elapsed_time:.2f}秒) - {e}")
    
    # テスト結果のサマリー
    print("\n" + "=" * 60)
    print("📊 テスト結果サマリー")
    print("=" * 60)
    
    passed = sum(1 for r in test_results if r["result"] == "PASS")
    failed = sum(1 for r in test_results if r["result"] == "FAIL")
    errors = sum(1 for r in test_results if r["result"] == "ERROR")
    total_time = sum(r["elapsed_time"] for r in test_results)
    
    print(f"✅ 成功: {passed}")
    print(f"❌ 失敗: {failed}")
    print(f"💥 エラー: {errors}")
    print(f"⏱️ 総実行時間: {total_time:.2f}秒")
    
    # 詳細結果をJSONで保存
    results_file = Path("data/test_outputs/test_results.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "total_time": total_time
            },
            "details": test_results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"📄 詳細結果を保存しました: {results_file}")
    
    # 全体的な成功判定
    if failed == 0 and errors == 0:
        print("\n🎉 全てのテストが正常に完了しました！")
        return True
    else:
        print(f"\n⚠️ {failed + errors}個のテストで問題が発生しました。")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)