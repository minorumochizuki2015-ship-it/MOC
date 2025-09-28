from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.core.ai_assistant import AIAssistant
from src.core.code_executor import CodeExecutor
from src.core.file_manager import FileManager
from src.core.kernel import Kernel


class TestAIAssistant:
    """AIAssistantクラスのテスト"""

    @pytest.fixture
    def mock_kernel(self):
        """Kernelのモック"""
        kernel = Mock(spec=Kernel)
        kernel.query_local_api.return_value = {
            "response_text": "def test_function():\n    return 42"
        }
        return kernel

    @pytest.fixture
    def mock_file_manager(self):
        """FileManagerのモック"""
        return Mock(spec=FileManager)

    @pytest.fixture
    def mock_code_executor(self):
        """CodeExecutorのモック"""
        return Mock(spec=CodeExecutor)

    @pytest.fixture
    def ai_assistant(self, mock_kernel, mock_file_manager, mock_code_executor):
        """AIAssistantインスタンス"""
        return AIAssistant(mock_kernel, mock_file_manager, mock_code_executor)

    def test_init(self, ai_assistant):
        """初期化のテスト"""
        assert ai_assistant.kernel is not None
        assert ai_assistant.file_manager is not None
        assert ai_assistant.code_executor is not None
        assert isinstance(ai_assistant.code_patterns, dict)
        assert isinstance(ai_assistant.completion_cache, dict)

    def test_load_code_patterns(self, ai_assistant):
        """コードパターンの読み込みテスト"""
        patterns = ai_assistant.code_patterns
        assert "python" in patterns
        assert "javascript" in patterns
        assert "html" in patterns
        assert "css" in patterns

        # Pythonパターンの確認
        python_patterns = patterns["python"]
        assert any("def {function_name}" in pattern for pattern in python_patterns)
        assert any("class {class_name}" in pattern for pattern in python_patterns)

    def test_generate_code_success(self, ai_assistant, mock_kernel):
        """コード生成成功のテスト"""
        mock_kernel.query_local_api.return_value = {
            "response_text": "def hello_world():\n    print('Hello, World!')\n    return 'success'"
        }

        result = ai_assistant.generate_code(
            "Create a hello world function", language="python"
        )

        assert result["success"] is True
        assert "def hello_world" in result["code"]
        assert result["language"] == "python"
        assert "functions" in result
        assert "classes" in result
        assert "imports" in result

    def test_generate_code_failure(self, ai_assistant, mock_kernel):
        """コード生成失敗のテスト"""
        mock_kernel.query_local_api.side_effect = Exception("API Error")

        result = ai_assistant.generate_code("Create a function")

        assert result["success"] is False
        assert "error" in result
        assert result["code"] == ""

    def test_complete_code(self, ai_assistant, mock_kernel):
        """コード補完のテスト"""
        mock_kernel.query_local_api.return_value = {
            "response_text": "def incomplete_func():\n    return 42"
        }

        partial_code = "def incomplete_func():"
        result = ai_assistant.complete_code(partial_code, language="python")

        assert result["success"] is True
        assert "return 42" in result["completed_code"]

    def test_refactor_code(self, ai_assistant, mock_kernel):
        """コードリファクタリングのテスト"""
        mock_kernel.query_local_api.return_value = {
            "response_text": "def optimized_func(x):\n    return x ** 2  # More efficient"
        }

        original_code = "def slow_func(x):\n    return x * x"
        result = ai_assistant.refactor_code(original_code, refactor_type="optimize")

        assert result["success"] is True
        assert "optimized_func" in result["refactored_code"]
        assert "changes" in result
        assert "improvements" in result

    def test_explain_code(self, ai_assistant, mock_kernel):
        """コード説明のテスト"""
        mock_kernel.query_local_api.return_value = {
            "response_text": "This function calculates the square of a number."
        }

        code = "def square(x):\n    return x * x"
        result = ai_assistant.explain_code(code)

        assert result["success"] is True
        assert "explanation" in result
        assert "structure" in result

    def test_debug_code(self, ai_assistant, mock_kernel):
        """コードデバッグのテスト"""
        mock_kernel.query_local_api.return_value = {
            "response_text": "The issue is a missing return statement."
        }

        buggy_code = "def broken_func(x):\n    x * 2  # Missing return"
        result = ai_assistant.debug_code(
            buggy_code, error_message="Function returns None"
        )

        assert result["success"] is True
        assert "debug_info" in result
        assert "suggestions" in result

    def test_parse_generated_code_python(self, ai_assistant):
        """Pythonコードの解析テスト"""
        code = """
import os
from pathlib import Path

def test_func(x: int) -> str:
    return str(x)

class TestClass:
    def __init__(self):
        pass
"""

        parsed = ai_assistant._parse_generated_code(code, "python")

        assert parsed["code"] == code.strip()
        assert len(parsed["functions"]) == 1
        assert len(parsed["classes"]) == 1
        assert len(parsed["imports"]) == 2
        assert isinstance(parsed["suggestions"], list)

    def test_extract_functions_python(self, ai_assistant):
        """Python関数抽出のテスト"""
        code = """
def simple_func():
    pass

def complex_func(a: int, b: str = "default") -> dict:
    return {"a": a, "b": b}
"""

        functions = ai_assistant._extract_functions(code, "python")

        assert len(functions) == 2
        assert functions[0]["name"] == "simple_func"
        assert functions[1]["name"] == "complex_func"
        assert "parameters" in functions[1]

    def test_extract_classes_python(self, ai_assistant):
        """Pythonクラス抽出のテスト"""
        code = """
class SimpleClass:
    pass

class ComplexClass(BaseClass):
    def __init__(self, value):
        self.value = value
"""

        classes = ai_assistant._extract_classes(code, "python")

        assert len(classes) == 2
        assert classes[0]["name"] == "SimpleClass"
        assert classes[1]["name"] == "ComplexClass"

    def test_extract_imports_python(self, ai_assistant):
        """Pythonインポート抽出のテスト"""
        code = """
import os
import sys
from pathlib import Path
from typing import Dict, List
"""

        imports = ai_assistant._extract_imports(code, "python")

        assert len(imports) == 4
        assert any(imp["module"] == "os" for imp in imports)
        assert any(imp["module"] == "pathlib" for imp in imports)

    def test_calculate_complexity(self, ai_assistant):
        """コード複雑度計算のテスト"""
        simple_code = "def simple():\n    return 42"
        complex_code = """
def complex_func(x):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                try:
                    result = i * 2
                except:
                    result = 0
            else:
                result = i
        return result
    else:
        return 0
"""

        simple_complexity = ai_assistant._calculate_complexity(simple_code, "python")
        complex_complexity = ai_assistant._calculate_complexity(complex_code, "python")

        assert simple_complexity < complex_complexity
        assert simple_complexity >= 1
        assert complex_complexity > 5
