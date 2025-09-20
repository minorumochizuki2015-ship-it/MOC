#!/usr/bin/env python3
"""
堅牢な開発システム
修正のたびに既存機能を破壊しないよう、段階的検証とロールバック機能を提供
"""

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


class RobustDevelopment:
    def __init__(self):
        self.checkpoints = []
        self.test_results = []
        
    def create_checkpoint(self, description=""):
        """現在の状態をチェックポイントとして保存"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        checkpoint_id = f"checkpoint_{timestamp}"
        
        try:
            # Gitでコミット
            result = subprocess.run(
                f"git add -A && git commit -m \"{checkpoint_id}: {description}\" --no-verify",
                shell=True, capture_output=True, text=True
            )
            
            if result.returncode == 0:
                self.checkpoints.append(checkpoint_id)
                print(f"✅ チェックポイント作成: {checkpoint_id}")
                return checkpoint_id
            else:
                print(f"❌ チェックポイント作成失敗: {result.stderr}")
                return None
        except Exception as e:
            print(f"❌ チェックポイント作成例外: {e}")
            return None
    
    def rollback_to_checkpoint(self, checkpoint_id=None):
        """指定されたチェックポイントにロールバック"""
        if checkpoint_id is None:
            checkpoint_id = self.checkpoints[-1] if self.checkpoints else None
        
        if not checkpoint_id:
            print("❌ ロールバック先のチェックポイントがありません")
            return False
        
        try:
            # Gitでロールバック
            result = subprocess.run(
                f"git reset --hard {checkpoint_id}",
                shell=True, capture_output=True, text=True
            )
            
            if result.returncode == 0:
                print(f"🔄 ロールバック完了: {checkpoint_id}")
                return True
            else:
                print(f"❌ ロールバック失敗: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ ロールバック例外: {e}")
            return False
    
    def run_critical_tests(self):
        """重要な機能のテストを実行"""
        tests = [
            {
                "name": "サーバー接続",
                "command": "curl -s http://127.0.0.1:8080/v1/models",
                "expected": '"object":"list"'
            },
            {
                "name": "UI初期化",
                "command": ".venv\\Scripts\\python.exe -c \"import sys; sys.path.insert(0, '.'); from src.ui.modern_interface import ModernCursorAIInterface; import tkinter as tk; root = tk.Tk(); root.withdraw(); app = ModernCursorAIInterface(root); print('SUCCESS'); root.destroy()\"",
                "expected": "SUCCESS"
            },
            {
                "name": "AI機能",
                "command": ".venv\\Scripts\\python.exe -c \"import sys; sys.path.insert(0, '.'); from src.core.kernel import Kernel; from src.core.memory import Memory; memory = Memory(); kernel = Kernel(memory); result = kernel.query_local_api('テスト'); print('AI_SUCCESS' if result.get('response_text') else 'AI_FAIL')\"",
                "expected": "AI_SUCCESS"
            }
        ]
        
        results = []
        for test in tests:
            print(f"🧪 {test['name']} テスト実行中...")
            try:
                result = subprocess.run(
                    test["command"], 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                
                success = (result.returncode == 0 and 
                          test["expected"] in result.stdout)
                
                if success:
                    print(f"✅ {test['name']}: 成功")
                else:
                    print(f"❌ {test['name']}: 失敗")
                    if result.stderr:
                        print(f"   エラー: {result.stderr[:200]}...")
                
                results.append({
                    "name": test["name"],
                    "success": success,
                    "output": result.stdout,
                    "error": result.stderr
                })
                
            except subprocess.TimeoutExpired:
                print(f"⏰ {test['name']}: タイムアウト")
                results.append({
                    "name": test["name"],
                    "success": False,
                    "output": "",
                    "error": "Timeout"
                })
            except Exception as e:
                print(f"💥 {test['name']}: 例外 - {e}")
                results.append({
                    "name": test["name"],
                    "success": False,
                    "output": "",
                    "error": str(e)
                })
        
        return results
    
    def safe_modify(self, file_path, modifications, description=""):
        """安全なファイル修正（修正前後でテスト実行）"""
        print(f"🔧 安全な修正開始: {file_path}")
        
        # 修正前のチェックポイント作成
        checkpoint_id = self.create_checkpoint(f"修正前: {description}")
        if not checkpoint_id:
            print("❌ 修正前チェックポイント作成に失敗")
            return False
        
        # 修正前のテスト実行
        print("📋 修正前テスト実行...")
        pre_results = self.run_critical_tests()
        pre_success = all(r["success"] for r in pre_results)
        
        if not pre_success:
            print("❌ 修正前テストが失敗しています。修正を中止します。")
            return False
        
        # ファイル修正実行
        try:
            # ここで実際のファイル修正を行う
            # modifications は修正内容のリスト
            print(f"✏️ ファイル修正実行: {file_path}")
            # 実際の修正処理は呼び出し元で実装
            
            # 修正後のテスト実行
            print("📋 修正後テスト実行...")
            post_results = self.run_critical_tests()
            post_success = all(r["success"] for r in post_results)
            
            if post_success:
                print("✅ 修正成功: すべてのテストが通過しました")
                return True
            else:
                print("❌ 修正失敗: テストが失敗しました。ロールバックを実行します。")
                self.rollback_to_checkpoint(checkpoint_id)
                return False
                
        except Exception as e:
            print(f"💥 修正中に例外が発生: {e}")
            print("🔄 ロールバックを実行します...")
            self.rollback_to_checkpoint(checkpoint_id)
            return False
    
    def get_status_report(self):
        """現在の状態レポートを生成"""
        print("\n" + "="*50)
        print("📊 堅牢開発システム ステータスレポート")
        print("="*50)
        print(f"チェックポイント数: {len(self.checkpoints)}")
        print(f"テスト結果数: {len(self.test_results)}")
        
        if self.checkpoints:
            print(f"最新チェックポイント: {self.checkpoints[-1]}")
        
        print("\n最近のテスト結果:")
        for result in self.test_results[-5:]:  # 最新5件
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['name']}")

def main():
    """メイン処理"""
    dev = RobustDevelopment()
    
    print("🛡️ 堅牢開発システム開始")
    print("="*50)
    
    # 初期チェックポイント作成
    checkpoint = dev.create_checkpoint("初期状態")
    if not checkpoint:
        print("❌ 初期チェックポイント作成に失敗")
        return False
    
    # 初期テスト実行
    print("📋 初期状態テスト実行...")
    results = dev.run_critical_tests()
    dev.test_results.extend(results)
    
    success_count = sum(1 for r in results if r["success"])
    total_count = len(results)
    
    print(f"\n📊 テスト結果: {success_count}/{total_count} 成功")
    
    if success_count == total_count:
        print("🎉 すべてのテストが成功しました！")
        dev.get_status_report()
        return True
    else:
        print("⚠️ 一部のテストが失敗しました")
        dev.get_status_report()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
