import importlib.util
import os
from typing import Optional

# Load the scan_secrets module directly from file to avoid package import issues
MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "ops", "scan_secrets.py")
spec = importlib.util.spec_from_file_location("scan_secrets", MODULE_PATH)
scan_secrets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_secrets)  # type: ignore

PATTERNS = scan_secrets.PATTERNS
SAFE_LINE_SUBSTRINGS = scan_secrets.SAFE_LINE_SUBSTRINGS


def detect_line(line: str) -> Optional[str]:
    """Replicates scan_secrets.py detection logic for a single line.

    Returns the name of the pattern if detected, otherwise None.
    Applies SAFE_LINE_SUBSTRINGS allowlist to reduce false positives.
    """
    for name, rx in PATTERNS:
        if rx.search(line):
            if any(s in line for s in SAFE_LINE_SUBSTRINGS):
                return None
            return name
    return None


def test_aws_access_key_detection_runtime_string():
    # Construct secret-like content at runtime to avoid repository-level scanners
    line = "prefix-" + "AKIA" + ("A" * 16) + "-suffix"
    assert detect_line(line) == "AWS Access Key"


def test_generic_secret_detection_runtime_string():
    value = "Abcd1234EFGH5678"  # >= 12 chars
    line = "SECRET_KEY" + "=" + value
    assert detect_line(line) == "Generic SECRET"


def test_bearer_token_detection_runtime_string():
    token = "A" * 25
    line = "Authorization: " + "Bearer " + token
    assert detect_line(line) == "Bearer Token"


def test_private_key_header_detection_runtime_string():
    line = "-----BEGIN " + "RSA" + " PRIVATE KEY-----"
    assert detect_line(line) == "Private Key"


def test_allowlist_skips_detection():
    # Line contains a placeholder that should be allowlisted
    value = "REDACTED" + "12345"
    line = "SECRET_KEY" + "=" + value
    assert detect_line(line) is None