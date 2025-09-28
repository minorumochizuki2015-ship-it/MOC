import os
import socket
import sys
from pathlib import Path

import pytest

# プロジェクトルートをPythonパスに追加
ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _tcp_up(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items):
    run_integration = os.getenv("RUN_INTEGRATION") == "1"
    if run_integration:
        return
    skip_integ = pytest.mark.skip(
        reason="integration/e2e/slow are skipped by default (set RUN_INTEGRATION=1 to run)"
    )
    for it in items:
        if any(m.name in {"integration", "e2e", "slow"} for m in it.iter_markers()):
            it.add_marker(skip_integ)


@pytest.fixture(scope="session")
def localai_ready() -> bool:
    return _tcp_up("127.0.0.1", 8080)


pytest.register_assert_rewrite(__name__)
