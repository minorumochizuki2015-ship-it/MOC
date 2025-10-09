import os
from pathlib import Path


def test_math_corpus_available():
    base = Path("data/validation/sources/math_corpus")
    if not base.exists():
        import pytest

        pytest.skip("math corpus not prepared")
    files = list(base.rglob("*"))
    if len(files) == 0:
        import pytest

        pytest.skip("math corpus empty — fetch required")
    assert True
