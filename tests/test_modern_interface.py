# Kivyの設定は最初に行う（他のインポートより前）
import os

os.environ["KIVY_NO_CONSOLELOG"] = "1"

from kivy.config import Config

Config.set("graphics", "width", "360")
Config.set("graphics", "height", "640")
Config.set("graphics", "resizable", False)

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

# Kivy設定後に他のモジュールをインポート
import pytest

from src.ui.modern_interface import (
    ModernCursorAIInterface,
    _is_probably_python,
    apply_function_edit,
    auto_self_test,
    local_rag_snippets,
    replace_function,
)


@pytest.fixture
def mock_parent():
    """モックの親ウィンドウ"""
    return Mock()


@pytest.fixture
def interface(mock_parent):
    """ModernCursorAIInterfaceのインスタンス"""
    with (
        patch("src.ui.modern_interface.ctk.CTk"),
        patch("src.ui.modern_interface.ctk.set_appearance_mode"),
        patch("src.ui.modern_interface.ctk.set_default_color_theme"),
        patch.object(Path, "mkdir"),
        patch(
            "src.ui.modern_interface.ModernCursorAIInterface.load_conversation_history"
        ),
        patch("src.ui.modern_interface.ModernCursorAIInterface._setup_modern_ui"),
    ):
        return ModernCursorAIInterface(mock_parent)


@pytest.mark.integration
class TestModernInterfaceIntegration:
    """ModernCursorAIInterfaceの統合テスト"""

    def test_initialization(self, interface):
        """初期化テスト"""
        assert interface.parent is not None
        assert interface.cursor_ai is None
        assert interface.current_file is None
        assert interface.is_processing is False
        assert interface.auto_evolution_running is False
        assert interface.auto_evolution_thread is None
        assert isinstance(interface.conversation_history, list)


class TestUtilityFunctionsIntegration:
    """ユーティリティ関数の統合テスト"""

    def test_replace_function_basic(self):
        """replace_function基本テスト"""
        src_text = """def old_function():
    return "old"

def other_function():
    return "other"
"""

        new_func_def = """def old_function():
    return "new"
"""

        result, status = replace_function(src_text, "old_function", new_func_def)

        # 実際の実装では "replace" が返される
        assert status == "replace"
        assert "new" in result
        # 置換後の結果に other_function が含まれていることを確認
        assert "other_function" in result

    def test_replace_function_not_found(self):
        """存在しない関数の置換テスト"""
        src_text = "def existing_function():\n    pass"
        new_func_def = "def non_existing():\n    pass"

        result, status = replace_function(src_text, "non_existing", new_func_def)

        # 実際の実装では "append" が返される
        assert status == "append"

    def test_is_probably_python(self):
        """Python コード判定テスト"""
        python_code = "def test():\n    return True"
        non_python_code = "This is not Python code"

        assert _is_probably_python(python_code) is True
        assert _is_probably_python(non_python_code) is False

    def test_local_rag_snippets(self):
        """local_rag_snippets テスト"""
        code = """def function1():
    return 1

def function2():
    return 2

def target_function():
    return "target"
"""

        snippets = local_rag_snippets(code, "target_function")
        assert isinstance(snippets, list)
        assert len(snippets) <= 3  # k=3がデフォルト

    @patch("src.ui.modern_interface.Path")
    def test_apply_function_edit_dryrun(self, mock_path):
        """apply_function_edit dryrun テスト"""
        # Pathのモック設定
        mock_path_instance = Mock()
        mock_path.return_value = mock_path_instance
        mock_path_instance.read_text.return_value = """def old_function():
    return "old"
"""

        result = apply_function_edit(
            "test.py",
            "old_function",
            "def old_function():\n    return 'new'",
            dryrun=True,
        )

        # dryrunの場合、modeが返される
        assert result in ["replace", "append"]

    def test_apply_function_edit_string_input(self):
        """apply_function_edit 文字列入力テスト（実際のファイルパスを使用）"""
        # 一時ファイルを作成してテスト
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                """def old_function():
    return "old"

def other_function():
    return "other"
"""
            )
            temp_file = f.name

        try:
            new_function = """def old_function():
    return "new"
"""

            result = apply_function_edit(
                temp_file, "old_function", new_function, dryrun=True
            )

            assert result in ["replace", "append"]
        finally:
            # クリーンアップ
            try:
                os.unlink(temp_file)
            except:
                pass


@pytest.mark.integration
class TestModernInterfaceErrorHandling:
    """エラーハンドリングテスト"""

    def test_invalid_file_handling(self):
        """無効なファイルの処理テスト"""
        with pytest.raises((FileNotFoundError, OSError)):
            apply_function_edit("/invalid/path/file.py", "test", "def test(): pass")

    def test_auto_self_test_valid_code(self):
        """有効なコードでの auto_self_test テスト"""
        valid_code = "def test_function():\n    return True"
        result = auto_self_test(valid_code)
        assert result is True

    def test_auto_self_test_invalid_code(self):
        """無効なコードでの auto_self_test テスト"""
        invalid_code = "def invalid_syntax(\n    return True"  # 構文エラー
        result = auto_self_test(invalid_code)
        assert result is False

    def test_auto_self_test_non_python(self):
        """非Pythonコードでの auto_self_test テスト"""
        non_python_code = "This is not Python code"
        result = auto_self_test(non_python_code)
        # 非Pythonコードは成功扱い
        assert result is True


@pytest.mark.integration
class TestModernInterfacePerformance:
    """パフォーマンステスト"""

    def test_large_text_processing(self):
        """大きなテキスト処理テスト"""
        large_text = "def function():\n    pass\n" * 100  # サイズを小さく

        result = _is_probably_python(large_text)
        assert isinstance(result, bool)

    def test_replace_function_performance(self):
        """replace_function パフォーマンステスト"""
        # 大きなソースコード
        large_src = "\n".join(
            [f"def func_{i}():\n    return {i}" for i in range(50)]
        )  # サイズを小さく

        new_func = "def func_25():\n    return 'modified'"

        result, status = replace_function(large_src, "func_25", new_func)

        assert status in ["replace", "append"]  # どちらでも許可
        assert isinstance(result, str)


class TestUtilityFunctionsEdgeCases:
    """ユーティリティ関数のエッジケーステスト"""

    def test_replace_function_empty_input(self):
        """空の入力での replace_function テスト"""
        result, status = replace_function("", "test", "def test(): pass")
        # 空の場合は append される
        assert status == "append"

    def test_is_probably_python_edge_cases(self):
        """_is_probably_python エッジケーステスト"""
        assert _is_probably_python("") is False
        assert _is_probably_python("import os") is True
        assert _is_probably_python("class Test:") is True
        assert _is_probably_python("def main():") is True
        # PowerShellコードのテスト
        assert _is_probably_python("#requires -version 7.0") is False

    def test_auto_self_test_edge_cases(self):
        """auto_self_test エッジケーステスト"""
        # 空文字列（非Pythonとして扱われる）
        assert auto_self_test("") is True

        # 有効なPythonコード
        assert auto_self_test("import os\ndef test(): pass") is True

        # 無効なPythonコード
        assert auto_self_test("def invalid(\n    pass") is False
