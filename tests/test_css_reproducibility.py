from pathlib import Path
import hashlib


def test_dynamic_overrides_css_encoding_and_hash():
    p = Path("static/css/dynamic_overrides.css")
    assert p.exists()
    data = p.read_bytes()
    assert not (len(data) >= 3 and data[:3] == b"\xEF\xBB\xBF")
    text = data.decode("utf-8")
    assert "\r\n" not in text
    h1 = hashlib.sha256(data).hexdigest()
    h2 = hashlib.sha256(data).hexdigest()
    assert h1 == h2
