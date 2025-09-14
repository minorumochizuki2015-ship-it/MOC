from pathlib import Path

import pytest
from mypy import api

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "src/core/ai_assistant.py",
    ROOT / "src/core/code_executor.py",
    ROOT / "src/core/agent_mode.py",
    ROOT / "src/core/cursor_ai_system.py",
    ROOT / "src/ui/modern_interface.py",
]
ARGS = ["--config-file", str(ROOT / "pyproject.toml"), "--python-version=3.10"]


@pytest.mark.parametrize("path", FILES)
def test_mypy_file_passes(path: Path) -> None:
    stdout, stderr, status = api.run(ARGS + [str(path)])
    assert status == 0, f"{path} failed:\n{stdout}\n{stderr}"
