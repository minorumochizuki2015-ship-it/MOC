#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kernelファイル構造分析
"""

import os
import sys
from pathlib import Path


def analyze_kernel_structure():
    """Kernelファイルの構造と問題点を分析"""
    print("Kernelファイル構造分析")
    print("=" * 50)

    # 1. Kernelファイルの存在確認
    print("1. Kernelファイルの存在確認")
    print("-" * 30)

    kernel_files = ["kernel.py", "src/core/kernel.py"]

    for file_path in kernel_files:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"✓ {file_path}: {size} bytes")
        else:
            print(f"✗ {file_path}: 存在しない")

    # 2. 内容の比較
    print("\n2. 内容の比較")
    print("-" * 30)

    try:
        with open("kernel.py", "r", encoding="utf-8") as f:
            root_kernel = f.read()

        with open("src/core/kernel.py", "r", encoding="utf-8") as f:
            src_kernel = f.read()

        if root_kernel == src_kernel:
            print("✓ 両ファイルの内容は同一")
        else:
            print("⚠️ 両ファイルの内容が異なる")

            # 新機能の確認
            new_features = ["generate_chat", "read_paths", "healthcheck"]
            for feature in new_features:
                root_has = feature in root_kernel
                src_has = feature in src_kernel
                print(f"  {feature}: ルート={root_has}, src={src_has}")

    except Exception as e:
        print(f"✗ ファイル読み込みエラー: {e}")

    # 3. インポートパターンの分析
    print("\n3. インポートパターンの分析")
    print("-" * 30)

    import_patterns = [
        "from src.core.kernel import",
        "from kernel import",
        "import kernel",
        "import src.core.kernel",
    ]

    for pattern in import_patterns:
        count = 0
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                            if pattern in content:
                                count += 1
                                print(f"  {file_path}: {pattern}")
                    except:
                        pass
        print(f"  {pattern}: {count}ファイルで使用")

    # 4. 問題点の特定
    print("\n4. 問題点の特定")
    print("-" * 30)

    problems = []

    # 重複ファイル
    if os.path.exists("kernel.py") and os.path.exists("src/core/kernel.py"):
        problems.append("重複: kernel.pyが2箇所に存在")

    # インポートの不整合
    if (
        "from kernel import"
        in open("tests/test_advanced_features.py", "r", encoding="utf-8").read()
    ):
        problems.append("不整合: tests/test_advanced_features.pyがルートkernelを参照")

    # 新機能の不整合
    try:
        with open("kernel.py", "r", encoding="utf-8") as f:
            root_content = f.read()
        with open("src/core/kernel.py", "r", encoding="utf-8") as f:
            src_content = f.read()

        if "generate_chat" in root_content and "generate_chat" not in src_content:
            problems.append("不整合: 新機能がルートkernelにのみ存在")
        elif "generate_chat" not in root_content and "generate_chat" in src_content:
            problems.append("不整合: 新機能がsrc/core/kernelにのみ存在")
    except:
        pass

    if problems:
        for i, problem in enumerate(problems, 1):
            print(f"{i}. {problem}")
    else:
        print("✓ 重大な問題は検出されませんでした")

    # 5. 推奨解決策
    print("\n5. 推奨解決策")
    print("-" * 30)

    print("1. ルートkernel.pyを削除し、src/core/kernel.pyのみを使用")
    print("2. すべてのインポートを 'from src.core.kernel import' に統一")
    print("3. 新機能をsrc/core/kernel.pyに集約")
    print("4. テストファイルのインポートパスを修正")

    return problems


if __name__ == "__main__":
    problems = analyze_kernel_structure()
    print(f"\n分析完了: {len(problems)}個の問題を検出")
