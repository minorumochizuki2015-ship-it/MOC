# ai_assistant.py
# 統治核AI - AI支援コード生成・補完システム

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.core.code_executor import CodeExecutor
from core.core.file_manager import FileManager
from core.core.kernel import Kernel


class AIAssistant:
    """AI支援によるコード生成・補完・リファクタリングを行うクラス"""

    def __init__(
        self, kernel: Kernel, file_manager: FileManager, code_executor: CodeExecutor
    ):
        self.kernel = kernel
        self.file_manager = file_manager
        self.code_executor = code_executor
        self.code_patterns = self._load_code_patterns()
        self.completion_cache: Dict[str, Any] = {}

    def _load_code_patterns(self) -> Dict[str, List[str]]:
        """コードパターンのテンプレートを読み込み"""
        return {
            "python": [
                'def {function_name}({parameters}):\n    """{docstring}"""\n    {body}',
                'class {class_name}:\n    """{docstring}"""\n    \n    def __init__(self{init_params}):\n        {init_body}',
                "if {condition}:\n    {true_body}\nelse:\n    {false_body}",
                "for {item} in {iterable}:\n    {body}",
                "while {condition}:\n    {body}",
                "try:\n    {body}\nexcept {exception} as {error}:\n    {error_body}",
                "import {module}\nfrom {module} import {item}",
                "@{decorator}\ndef {function_name}({parameters}):\n    {body}",
            ],
            "javascript": [
                "function {function_name}({parameters}) {\n    {body}\n}",
                "const {function_name} = ({parameters}) => {\n    {body}\n};",
                "class {class_name} {\n    constructor({constructor_params}) {\n        {constructor_body}\n    }\n}",
                "if ({condition}) {\n    {true_body}\n} else {\n    {false_body}\n}",
                "for (let {item} of {iterable}) {\n    {body}\n}",
                "try {\n    {body}\n} catch ({error}) {\n    {error_body}\n}",
                "import { {imports} } from '{module}';",
                "export { {exports} } from '{module}';",
            ],
            "html": [
                "<{tag} {attributes}>\n    {content}\n</{tag}>",
                "<{tag} {attributes} />",
                "<!DOCTYPE html>\n<html>\n<head>\n    <title>{title}</title>\n</head>\n<body>\n    {body}\n</body>\n</html>",
            ],
            "css": [
                ".{class_name} {\n    {properties}\n}",
                "#{id_name} {\n    {properties}\n}",
                "@media {media_query} {\n    {rules}\n}",
            ],
        }

    def generate_code(
        self,
        description: str,
        language: str = "python",
        context: str = None,
        style: str = "standard",
    ) -> Dict[str, Any]:
        """自然言語の説明からコードを生成"""
        try:
            # プロンプトを構築
            prompt = self._build_generation_prompt(
                description, language, context, style
            )

            # AIに問い合わせ
            response = self.kernel.query_local_api(prompt)
            generated_code = response.get("response_text", "")

            # コードを解析・検証
            parsed_code = self._parse_generated_code(generated_code, language)

            return {
                "success": True,
                "code": parsed_code["code"],
                "language": language,
                "functions": parsed_code["functions"],
                "classes": parsed_code["classes"],
                "imports": parsed_code["imports"],
                "suggestions": parsed_code["suggestions"],
                "raw_response": generated_code,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "code": "", "language": language}

    def complete_code(
        self,
        partial_code: str,
        language: str = "python",
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """部分的なコードを補完"""
        try:
            # キャッシュをチェック
            cache_key = f"{hash(partial_code)}_{language}"
            if cache_key in self.completion_cache:
                return self.completion_cache[cache_key]

            # プロンプトを構築
            prompt = self._build_completion_prompt(partial_code, language, context)

            # AIに問い合わせ
            response = self.kernel.query_local_api(prompt)
            completion = response.get("response_text", "")

            # 補完結果を解析
            completed_code = self._merge_code(partial_code, completion, language)

            result = {
                "success": True,
                "original_code": partial_code,
                "completion": completion,
                "completed_code": completed_code,
                "suggestions": self._generate_suggestions(completed_code, language),
            }

            # キャッシュに保存
            self.completion_cache[cache_key] = result

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "original_code": partial_code,
                "completion": "",
                "completed_code": partial_code,
            }

    def refactor_code(
        self, code: str, language: str = "python", refactor_type: str = "optimize"
    ) -> Dict[str, Any]:
        """コードをリファクタリング"""
        try:
            # リファクタリングタイプに応じてプロンプトを構築
            prompt = self._build_refactor_prompt(code, language, refactor_type)

            # AIに問い合わせ
            response = self.kernel.query_local_api(prompt)
            refactored_code = response.get("response_text", "")

            # 変更点を分析
            changes = self._analyze_changes(code, refactored_code)

            return {
                "success": True,
                "original_code": code,
                "refactored_code": refactored_code,
                "changes": changes,
                "refactor_type": refactor_type,
                "improvements": self._analyze_improvements(code, refactored_code),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "original_code": code,
                "refactored_code": code,
            }

    def explain_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """コードの説明を生成"""
        try:
            prompt = f"""
以下の{language}コードを詳しく説明してください：

```{language}
{code}
```

説明に含める内容：
1. コードの全体的な目的
2. 各関数・クラスの役割
3. 重要なアルゴリズムやロジック
4. 使用されている主要な概念
5. 改善提案があれば

日本語で簡潔に説明してください。
"""

            response = self.kernel.query_local_api(prompt)
            explanation = response.get("response_text", "")

            # コードの構造を解析
            structure = self._analyze_code_structure(code, language)

            return {
                "success": True,
                "code": code,
                "explanation": explanation,
                "structure": structure,
                "complexity": self._calculate_complexity(code, language),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "code": code, "explanation": ""}

    def debug_code(
        self, code: str, language: str = "python", error_message: str = None
    ) -> Dict[str, Any]:
        """コードのデバッグ支援"""
        try:
            # エラーメッセージがある場合はそれも含める
            if error_message:
                prompt = f"""
以下の{language}コードにエラーがあります。デバッグしてください：

```{language}
{code}
```

エラーメッセージ：
{error_message}

以下の点を確認してください：
1. エラーの原因
2. 修正方法
3. 修正されたコード
4. 予防策

日本語で説明してください。
"""
            else:
                prompt = f"""
以下の{language}コードをデバッグしてください：

```{language}
{code}
```

潜在的な問題を特定し、修正案を提示してください。
"""

            response = self.kernel.query_local_api(prompt)
            debug_info = response.get("response_text", "")

            # 静的解析による問題検出
            static_issues = self._static_analysis(code, language)

            return {
                "success": True,
                "code": code,
                "debug_info": debug_info,
                "static_issues": static_issues,
                "suggestions": self._generate_debug_suggestions(code, language),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "code": code, "debug_info": ""}

    def _build_generation_prompt(
        self, description: str, language: str, context: Optional[str], style: str
    ) -> str:
        """コード生成用のプロンプトを構築"""
        context_info = f"\n\nコンテキスト:\n{context}" if context else ""

        return f"""
以下の要求に基づいて{language}コードを生成してください：

要求: {description}
{context_info}

コードスタイル: {style}

以下の要件を満たしてください：
1. 適切なコメントを含める
2. エラーハンドリングを含める
3. 読みやすいコードにする
4. ベストプラクティスに従う

コードのみを出力し、説明は不要です。
"""

    def _build_completion_prompt(
        self, partial_code: str, language: str, context: Optional[Dict[str, Any]]
    ) -> str:
        """コード補完用のプロンプトを構築"""
        context_info = ""
        if context:
            context_info = f"\n\nコンテキスト:\n{json.dumps(context, ensure_ascii=False, indent=2)}"

        return f"""
以下の{language}コードを完成させてください：

```{language}
{partial_code}
```

{context_info}

コードの意図を推測し、適切に補完してください。
補完部分のみを出力し、既存のコードは含めないでください。
"""

    def _build_refactor_prompt(
        self, code: str, language: str, refactor_type: str
    ) -> str:
        """リファクタリング用のプロンプトを構築"""
        refactor_instructions = {
            "optimize": "パフォーマンスを最適化してください",
            "clean": "コードをクリーンアップし、可読性を向上させてください",
            "modernize": "モダンな{language}の機能を使用して書き直してください",
            "simplify": "コードを簡素化してください",
            "secure": "セキュリティを向上させてください",
        }

        instruction = refactor_instructions.get(
            refactor_type, "コードを改善してください"
        )

        return f"""
以下の{language}コードを{instruction}：

```{language}
{code}
```

改善されたコードを出力してください。
変更点の説明も含めてください。
"""

    def _parse_generated_code(self, code: str, language: str) -> Dict[str, Any]:
        """生成されたコードを解析"""
        # コードブロックを抽出
        code_match = re.search(
            r"```(?:" + language + r")?\s*\n(.*?)\n```", code, re.DOTALL
        )
        if code_match:
            clean_code = code_match.group(1)
        else:
            clean_code = code.strip()

        # 関数・クラス・インポートを抽出
        functions = self._extract_functions(clean_code, language)
        classes = self._extract_classes(clean_code, language)
        imports = self._extract_imports(clean_code, language)

        return {
            "code": clean_code,
            "functions": functions,
            "classes": classes,
            "imports": imports,
            "suggestions": self._generate_suggestions(clean_code, language),
        }

    def _extract_functions(self, code: str, language: str) -> List[Dict[str, Any]]:
        """関数を抽出"""
        functions = []

        if language == "python":
            pattern = r"def\s+(\w+)\s*\([^)]*\):"
            for match in re.finditer(pattern, code):
                functions.append(
                    {
                        "name": match.group(1),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )
        elif language == "javascript":
            patterns = [
                r"function\s+(\w+)\s*\(",
                r"const\s+(\w+)\s*=\s*\([^)]*\)\s*=>",
                r"(\w+)\s*:\s*function",
            ]
            for pattern in patterns:
                for match in re.finditer(pattern, code):
                    functions.append(
                        {
                            "name": match.group(1),
                            "line": code[: match.start()].count("\n") + 1,
                        }
                    )

        return functions

    def _extract_classes(self, code: str, language: str) -> List[Dict[str, Any]]:
        """クラスを抽出"""
        classes: List[Dict[str, Any]] = []

        if language == "python":
            pattern = r"class\s+(\w+)"
        elif language == "javascript":
            pattern = r"class\s+(\w+)"
        else:
            return classes

        for match in re.finditer(pattern, code):
            classes.append(
                {"name": match.group(1), "line": code[: match.start()].count("\n") + 1}
            )

        return classes

    def _extract_imports(self, code: str, language: str) -> List[Dict[str, Any]]:
        """インポート文を抽出"""
        imports: List[Dict[str, Any]] = []

        if language == "python":
            patterns = [r"import\s+(\w+)", r"from\s+(\w+)\s+import\s+([^#\n]+)"]
        elif language == "javascript":
            patterns = [
                r'import\s+([^"\']+)',
                r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
            ]
        else:
            return imports

        for pattern in patterns:
            for match in re.finditer(pattern, code):
                imports.append(
                    {
                        "statement": match.group(0),
                        "line": code[: match.start()].count("\n") + 1,
                    }
                )

        return imports

    def _merge_code(self, original: str, completion: str, language: str) -> str:
        """元のコードと補完をマージ"""
        # 簡単なマージ実装
        lines = original.splitlines()
        if lines and not lines[-1].strip():
            lines.pop()

        completion_lines = completion.splitlines()
        return "\n".join(lines + completion_lines)

    def _generate_suggestions(self, code: str, language: str) -> List[str]:
        """コード改善提案を生成"""
        suggestions = []

        # 基本的な提案
        if language == "python":
            if "print(" in code and "logging" not in code:
                suggestions.append(
                    "print文の代わりにloggingモジュールの使用を検討してください"
                )
            if "except:" in code:
                suggestions.append("具体的な例外をキャッチすることを推奨します")
            if "eval(" in code:
                suggestions.append("eval()の使用はセキュリティリスクがあります")

        return suggestions

    def _analyze_changes(self, original: str, refactored: str) -> List[Dict[str, Any]]:
        """コードの変更点を分析"""
        # 簡易的な変更分析
        changes = []

        original_lines = original.splitlines()
        refactored_lines = refactored.splitlines()

        # 行数の変化
        if len(refactored_lines) != len(original_lines):
            changes.append(
                {
                    "type": "line_count",
                    "original": len(original_lines),
                    "refactored": len(refactored_lines),
                }
            )

        # 関数数の変化
        original_funcs = len(re.findall(r"def\s+\w+", original))
        refactored_funcs = len(re.findall(r"def\s+\w+", refactored))

        if original_funcs != refactored_funcs:
            changes.append(
                {
                    "type": "function_count",
                    "original": original_funcs,
                    "refactored": refactored_funcs,
                }
            )

        return changes

    def _analyze_improvements(self, original: str, refactored: str) -> List[str]:
        """改善点を分析"""
        improvements = []

        # コメントの追加
        if refactored.count("#") > original.count("#"):
            improvements.append("コメントが追加されました")

        # エラーハンドリングの追加
        if refactored.count("try:") > original.count("try:"):
            improvements.append("エラーハンドリングが追加されました")

        # 型ヒントの追加（Python）
        if refactored.count("->") > original.count("->"):
            improvements.append("型ヒントが追加されました")

        return improvements

    def _analyze_code_structure(self, code: str, language: str) -> Dict[str, Any]:
        """コードの構造を解析"""
        return {
            "lines": len(code.splitlines()),
            "characters": len(code),
            "functions": len(self._extract_functions(code, language)),
            "classes": len(self._extract_classes(code, language)),
            "imports": len(self._extract_imports(code, language)),
        }

    def _calculate_complexity(self, code: str, language: str) -> int:
        """コードの複雑度を計算（簡易版）"""
        complexity = 0

        # 制御構造の数をカウント
        control_structures = ["if", "for", "while", "try", "except", "with"]
        for structure in control_structures:
            complexity += code.count(structure)

        # ネストレベルを考慮
        lines = code.splitlines()
        max_indent = 0
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                max_indent = max(max_indent, indent)

        complexity += max_indent // 4  # 4スペース = 1レベル

        return complexity

    def _static_analysis(self, code: str, language: str) -> List[Dict[str, Any]]:
        """静的解析による問題検出"""
        issues = []

        if language == "python":
            # 未使用変数の検出（簡易版）
            lines = code.splitlines()
            for i, line in enumerate(lines, 1):
                if "=" in line and "==" not in line:
                    var_name = line.split("=")[0].strip()
                    if var_name and var_name not in code[code.find(line) + len(line) :]:
                        issues.append(
                            {
                                "type": "unused_variable",
                                "line": i,
                                "message": f"未使用の変数: {var_name}",
                            }
                        )

        return issues

    def _generate_debug_suggestions(self, code: str, language: str) -> List[str]:
        """デバッグ提案を生成"""
        suggestions = []

        if language == "python":
            if "print(" in code:
                suggestions.append(
                    "デバッグ用のprint文をlogging.debug()に置き換えることを検討してください"
                )
            if "input(" in code:
                suggestions.append(
                    "input()の使用はテストが困難です。引数や設定ファイルからの読み込みを検討してください"
                )

        return suggestions
