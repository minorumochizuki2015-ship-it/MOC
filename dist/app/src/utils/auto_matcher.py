import argparse
import ast
import difflib
import os


def extract_functions(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        tree = ast.parse(file.read(), filename=file_path)

    functions = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            start_line = node.lineno - 1
            end_line = max(
                (child.lineno for child in ast.walk(node) if hasattr(child, "lineno")),
                default=start_line,
            )
            with open(file_path, "r", encoding="utf-8") as file:
                lines = file.readlines()
                function_code = "".join(lines[start_line:end_line])
                functions.append((node.name, function_code))
                print(
                    f"[DEBUG] Extracted function: {node.name}"
                )  # 可視化用デバッグ出力
    return functions


def compare_functions(funcs1, funcs2):
    matches = []
    for name1, code1 in funcs1:
        best_match = None
        highest_score = 0.0
        for name2, code2 in funcs2:
            score = difflib.SequenceMatcher(None, code1, code2).ratio()
            if score > highest_score:
                highest_score = score
                best_match = (name2, code2)
        matches.append(
            (name1, code1, best_match[0] if best_match else None, highest_score)
        )
    return matches


def main():
    parser = argparse.ArgumentParser(
        description="Compare functions in two Python files."
    )
    parser.add_argument("file1", help="Path to the first Python file")
    parser.add_argument("file2", help="Path to the second Python file")
    args = parser.parse_args()

    if not os.path.exists(args.file1) or not os.path.exists(args.file2):
        print("One or both files do not exist.")
        return

    functions1 = extract_functions(args.file1)
    functions2 = extract_functions(args.file2)

    matches = compare_functions(functions1, functions2)

    for i, (name1, code1, name2, score) in enumerate(matches, 1):
        print(f"Match {i}: Similarity Score = {score:.2f}")
        print("-" * 40)
        print(f"Function from File 1:\n{code1.strip()}")
        print("\nMost Similar Function from File 2:")
        if name2:
            matched_code = next(code for name, code in functions2 if name == name2)
            print(matched_code.strip())
        else:
            print("None")
        print("=" * 80)


if __name__ == "__main__":
    main()
