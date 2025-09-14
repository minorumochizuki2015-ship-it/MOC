import ast
import os
from typing import Set


def extract_defined_functions(filepath: str) -> Set[str]:
    """ファイル内で定義された関数を抽出"""
    with open(filepath, "r", encoding="utf-8") as file:
        node = ast.parse(file.read())
    return {n.name for n in ast.walk(node) if isinstance(n, ast.FunctionDef)}


def extract_imported_functions(filepath: str) -> Set[str]:
    """import文で読み込まれている関数名（from X import Y）を抽出"""
    with open(filepath, "r", encoding="utf-8") as file:
        node = ast.parse(file.read())

    imported = set()
    for n in ast.walk(node):
        if isinstance(n, ast.ImportFrom) and n.module:
            imported.update(alias.name for alias in n.names)
    return imported


def compare_functions(defined: Set[str], used: Set[str]) -> Set[str]:
    """使用している関数の中で定義されていないもの"""
    return used - defined


def main():
    project_dir = "C:/Users/User/PhoenixCodex/GoverningCore_v5_Sliced/"
    main_file = os.path.join(project_dir, "governance.py")
    test_file = os.path.join(project_dir, "test_governance.py")

    defined_funcs = extract_defined_functions(main_file)
    imported_funcs = extract_imported_functions(test_file)

    missing = compare_functions(defined_funcs, imported_funcs)

    print("✅ 定義済み関数:", sorted(defined_funcs))
    print("🔍 テストで使用されている関数:", sorted(imported_funcs))

    if missing:
        print("\n❌ 定義されていない関数（誤スペル・未実装の可能性）:")
        for m in sorted(missing):
            print(f" - {m}")
    else:
        print("\n✅ すべての使用関数が正しく定義されています。")


if __name__ == "__main__":
    main()
