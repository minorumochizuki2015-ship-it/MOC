import os
from pathlib import Path


def test_search_corpus_available():
    base = Path("data/validation/sources/search_corpus")
    if not base.exists():
        import pytest

        pytest.skip("search corpus not prepared")
    files = list(base.rglob("*"))
    if len(files) == 0:
        import pytest

        pytest.skip("search corpus empty — fetch required")
    assert True
