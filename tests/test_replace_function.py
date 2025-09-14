import io
import textwrap

from src.ui.modern_interface import _is_probably_python, replace_function


def T(s):
    return textwrap.dedent(s).lstrip("\n")


def test_replace_basic():
    src = T(
        """
    def a(): pass
    def target(x): return x+1
    """
    )
    new = T(
        """
    def target(x): 
        return x*2
    """
    )
    out, mode = replace_function(src, "target", new)
    assert "return x*2" in out and mode == "replace"


def test_append_when_missing():
    src = T("def a():\n    pass\n")
    new = T("def target():\n    return 1\n")
    out, mode = replace_function(src, "target", new)
    assert out.rstrip().endswith("return 1") and mode == "append"


def test_nested_same_name_kept_top_level():
    src = T(
        """
    def target(): 
        def target(): 
            return 0
        return 1
    """
    )
    new = T("def target():\n    return 2\n")
    out, mode = replace_function(src, "target", new)
    assert "return 2" in out and "return 0" in out


def test_language_gate():
    ps = T(
        """
    #requires -version 7.0
    Param([string]$x)
    """
    )
    assert _is_probably_python(ps) is False
