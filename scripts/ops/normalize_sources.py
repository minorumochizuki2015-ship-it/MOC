import json
import re
from pathlib import Path

FILTERS_PATH = Path("scripts/ops/source_filters.json")
BASE_DIR = Path("data/validation/sources")
OUT_DIR = Path("data/validation/benchmarks/trae_credit_bench_20251009/normalized")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d")


def load_filters():
    return json.loads(FILTERS_PATH.read_text(encoding="utf-8"))


def scrub_pii(text: str):
    text = EMAIL_RE.sub("[email]", text)
    text = PHONE_RE.sub("[phone]", text)
    return text


def clamp_len(text: str, min_len: int, max_len: int):
    if len(text) < min_len:
        return ""
    if len(text) > max_len:
        return text[:max_len]
    return text


def normalize_file(path: Path, filters: dict, category: str):
    text = path.read_text(encoding="utf-8", errors="ignore")
    if filters.get("pii_scrub"):
        text = scrub_pii(text)
    text = clamp_len(
        text,
        filters.get("doc_text_char_min", 0),
        filters.get("doc_text_char_max", 10**9),
    )
    if not text:
        return None
    rec = {
        "source_path": str(path),
        "category": category,
        "text": text,
        "chars": len(text),
    }
    return rec


def main():
    filters = load_filters()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # search corpus
    for p in (BASE_DIR / "search_corpus").rglob("*.txt"):
        rec = normalize_file(p, filters, "search")
        if rec:
            out = OUT_DIR / (p.stem + ".search.json")
            out.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    # math corpus
    for p in (BASE_DIR / "math_corpus").rglob("*.txt"):
        rec = normalize_file(p, filters, "math")
        if rec:
            out = OUT_DIR / (p.stem + ".math.json")
            out.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
