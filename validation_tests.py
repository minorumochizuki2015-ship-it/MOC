#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GPT提案の検証テスト（T01-T03）
"""

import os
import subprocess
import sys
import tempfile
import time

sys.path.append(".")

from src.core.kernel import generate_chat


class ValidationTests:
    """GPT提案の検証テストクラス"""

    def __init__(self):
        self.results = {}
        self.start_time = time.time()

    def run_all_tests(self):
        """すべてのテストを実行"""
        print("=== GPT提案検証テスト開始 ===")
        print(f"開始時刻: {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # T01: 整数リストソート関数生成テスト
        self.test_t01_generate_sort()

        # T02: 既存関数補完テスト
        self.test_t02_complete_imports()

        # T03: 関数リファクタリングテスト
        self.test_t03_refactor_safe()

        # 結果サマリー
        self.print_summary()

    def test_t01_generate_sort(self):
        """T01: 整数リストを昇順にソートする関数生成テスト"""
        print("\n--- T01: 整数リストソート関数生成テスト ---")

        try:
            prompt = "整数リストを昇順にソートする関数を生成してください。関数名はsort_integersとし、完全なコードを提供してください。"

            start_time = time.time()
            result = generate_chat([], prompt, max_tokens=1000, task_type="generate")
            generation_time = time.time() - start_time

            print(f"生成時間: {generation_time:.2f}秒")
            print(f"生成コード:\n{result}")

            # 構文チェック
            compile_success = self._check_compile(result)

            # 簡易ユニットテスト
            test_success = self._test_sort_function(result)

            self.results["T01"] = {
                "compile_success": compile_success,
                "test_success": test_success,
                "generation_time": generation_time,
                "code_length": len(result),
            }

            if compile_success and test_success:
                print("✅ T01: 成功")
            else:
                print("❌ T01: 失敗")

        except Exception as e:
            print(f"❌ T01: エラー - {e}")
            self.results["T01"] = {"error": str(e)}

    def test_t02_complete_imports(self):
        """T02: 既存関数の補完（import保持）テスト"""
        print("\n--- T02: 既存関数補完テスト ---")

        try:
            # 既存コード（import文あり）
            existing_code = """import os
import sys
from pathlib import Path

def process_file(file_path):
    # この関数を完成させてください
    pass"""

            prompt = f"以下のコードを完成させてください。import文は保持してください:\n\n{existing_code}"

            start_time = time.time()
            result = generate_chat([], prompt, max_tokens=1000, task_type="complete")
            generation_time = time.time() - start_time

            print(f"生成時間: {generation_time:.2f}秒")
            print(f"補完コード:\n{result}")

            # import文の保持確認
            imports_preserved = self._check_imports_preserved(existing_code, result)

            # 構文チェック
            compile_success = self._check_compile(result)

            self.results["T02"] = {
                "compile_success": compile_success,
                "imports_preserved": imports_preserved,
                "generation_time": generation_time,
                "code_length": len(result),
            }

            if compile_success and imports_preserved:
                print("✅ T02: 成功")
            else:
                print("❌ T02: 失敗")

        except Exception as e:
            print(f"❌ T02: エラー - {e}")
            self.results["T02"] = {"error": str(e)}

    def test_t03_refactor_safe(self):
        """T03: 関数を純粋関数化リファクタリングテスト"""
        print("\n--- T03: 関数リファクタリングテスト ---")

        try:
            # 副作用のある関数
            original_code = """import random

def process_data(data):
    result = []
    for item in data:
        # 副作用: グローバル変数変更とランダム要素
        global_counter = getattr(process_data, 'counter', 0)
        process_data.counter = global_counter + 1
        
        processed = item * 2 + random.randint(1, 10)
        result.append(processed)
    
    print(f"処理済み: {len(result)}件")  # 副作用: 出力
    return result"""

            prompt = f"以下の関数を純粋関数にリファクタリングしてください。副作用を除去し、同じ入力に対して同じ出力を返すようにしてください:\n\n{original_code}"

            start_time = time.time()
            result = generate_chat([], prompt, max_tokens=1000, task_type="refactor")
            generation_time = time.time() - start_time

            print(f"生成時間: {generation_time:.2f}秒")
            print(f"リファクタリングコード:\n{result}")

            # 構文チェック
            compile_success = self._check_compile(result)

            # 副作用除去確認
            side_effects_removed = self._check_side_effects_removed(result)

            self.results["T03"] = {
                "compile_success": compile_success,
                "side_effects_removed": side_effects_removed,
                "generation_time": generation_time,
                "code_length": len(result),
            }

            if compile_success and side_effects_removed:
                print("✅ T03: 成功")
            else:
                print("❌ T03: 失敗")

        except Exception as e:
            print(f"❌ T03: エラー - {e}")
            self.results["T03"] = {"error": str(e)}

    def _check_compile(self, code: str) -> bool:
        """コードの構文チェック"""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                temp_file = f.name

            result = subprocess.run(
                ["python", "-m", "py_compile", temp_file],
                capture_output=True,
                text=True,
                timeout=10,
            )

            os.unlink(temp_file)
            return result.returncode == 0

        except Exception as e:
            print(f"構文チェックエラー: {e}")
            return False

    def _test_sort_function(self, code: str) -> bool:
        """ソート関数の簡易テスト"""
        try:
            # テスト用のコードを実行
            test_code = f"""
{code}

# テスト実行
test_data = [3, 1, 4, 1, 5, 9, 2, 6]
result = sort_integers(test_data)
expected = [1, 1, 2, 3, 4, 5, 6, 9]

print(f"入力: {{test_data}}")
print(f"結果: {{result}}")
print(f"期待: {{expected}}")
print(f"テスト成功: {{result == expected}}")
"""

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(test_code)
                temp_file = f.name

            result = subprocess.run(
                ["python", temp_file], capture_output=True, text=True, timeout=10
            )

            os.unlink(temp_file)

            if result.returncode == 0 and "テスト成功: True" in result.stdout:
                return True
            else:
                print(f"テスト出力: {result.stdout}")
                print(f"テストエラー: {result.stderr}")
                return False

        except Exception as e:
            print(f"テスト実行エラー: {e}")
            return False

    def _check_imports_preserved(self, original: str, result: str) -> bool:
        """import文が保持されているかチェック"""
        original_imports = [
            line.strip()
            for line in original.split("\n")
            if line.strip().startswith(("import ", "from "))
        ]
        result_imports = [
            line.strip()
            for line in result.split("\n")
            if line.strip().startswith(("import ", "from "))
        ]

        for imp in original_imports:
            if imp not in result_imports:
                print(f"import文が失われました: {imp}")
                return False

        return True

    def _check_side_effects_removed(self, code: str) -> bool:
        """副作用が除去されているかチェック"""
        side_effect_patterns = [
            "print(",
            "global ",
            "random.",
            "input(",
            "open(",
            "file(",
            "exec(",
            "eval(",
        ]

        for pattern in side_effect_patterns:
            if pattern in code:
                print(f"副作用が残っています: {pattern}")
                return False

        return True

    def print_summary(self):
        """結果サマリーを表示"""
        total_time = time.time() - self.start_time

        print("\n" + "=" * 50)
        print("検証テスト結果サマリー")
        print("=" * 50)

        success_count = 0
        total_count = len(self.results)

        for test_id, result in self.results.items():
            if "error" in result:
                print(f"{test_id}: ❌ エラー - {result['error']}")
            else:
                compile_ok = result.get("compile_success", False)
                test_ok = (
                    result.get("test_success", False)
                    or result.get("imports_preserved", False)
                    or result.get("side_effects_removed", False)
                )

                if compile_ok and test_ok:
                    print(f"{test_id}: ✅ 成功")
                    success_count += 1
                else:
                    print(f"{test_id}: ❌ 失敗")

        print(
            f"\n成功率: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)"
        )
        print(f"総実行時間: {total_time:.2f}秒")

        # GPT提案の目標値との比較
        target_success_rate = 0.90  # 90%
        actual_success_rate = success_count / total_count

        if actual_success_rate >= target_success_rate:
            print(
                f"✅ 目標達成: {actual_success_rate*100:.1f}% >= {target_success_rate*100:.1f}%"
            )
        else:
            print(
                f"❌ 目標未達成: {actual_success_rate*100:.1f}% < {target_success_rate*100:.1f}%"
            )


if __name__ == "__main__":
    tests = ValidationTests()
    tests.run_all_tests()
