import os, importlib.util, pytest
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")); MODULE_PATH = os.path.join(REPO_ROOT, "scripts", "ops", "scan_secrets.py")
if not os.path.exists(MODULE_PATH): pytest.skip("scan_secrets.py missing; skip secret pattern tests", allow_module_level=True)
spec = importlib.util.spec_from_file_location("scan_secrets", MODULE_PATH); scan = importlib.util.module_from_spec(spec); spec.loader.exec_module(scan)  # type: ignore
PATTERNS = getattr(scan, "PATTERNS"); SAFE = getattr(scan, "SAFE_LINE_SUBSTRINGS")

@pytest.mark.parametrize("line,expected", [
    ("AK"+"IA"+"A"*16, "AWS Access Key"),
    ("SECRET_KEY"+"="+"Abcd1234EFGH5678", "Generic SECRET"),
    ("Authorization: "+"Bearer "+"A"*25, "Bearer Token"),
    ("-----BEGIN "+"RSA"+" PRIVATE KEY-----", "Private Key"),
    ("SECRET_KEY"+"="+"REDACTED"+"12345", None),
])
def test_secret_patterns_runtime_strings(line, expected):
    found = None
    for name, rx in PATTERNS:
        if rx.search(line) and not any(s in line for s in SAFE): found = name; break
    assert found == expected
