import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "quality_criteria.md"
OUT_PATH = REPO_ROOT / "data" / "results" / "quality_doc_validation.json"

REQUIRED_MARKERS = [
    "段階的合格判定",
    "推奨しきい値",
    "HTTP API",
    "SSE",
    "自動判定",
]

# 柔軟な正規表現で強制しきい値の存在を検証（表記揺れに耐性）
FORCED_PATTERNS = [
    (
        r"成功[率]?(?:\s*[:：]?\s*)?(?:≥|>=)?\s*95%",
        "HTTP 成功率の強制しきい値(95%)が明記されていません",
    ),
    (
        r"P95(?:\s*レイテンシ)?(?:\s*[:：]?\s*)?(?:≤|<=)?\s*1500\s*ms",
        "HTTP P95 1500ms の強制しきい値が明記されていません",
    ),
    (
        r"(再接続|reconnect).{0,30}(?:≤|<=)?\s*5\s*(秒|s)",
        "SSE 再接続 ≤ 5s の強制しきい値が明記されていません",
    ),
    (
        r"(ドロップ率|drop\s*rate).{0,30}(?:≤|<=)?\s*5\s*%",
        "SSE ドロップ率 ≤ 5% の強制しきい値が明記されていません",
    ),
]


def validate(strict: bool = False) -> int:
    status = {
        "doc_exists": DOC_PATH.exists(),
        "markers_present": {},
        "forced_thresholds_present": {},
        "errors": [],
    }

    if not DOC_PATH.exists():
        status["errors"].append("docs/quality_criteria.md が存在しません")
        return write_out(status, strict)

    text = DOC_PATH.read_text(encoding="utf-8")

    # Markers
    for mk in REQUIRED_MARKERS:
        present = mk in text
        status["markers_present"][mk] = present
        if not present:
            status["errors"].append(f"必須セクション '{mk}' が見つかりません")

    # Forced thresholds by regex
    import re

    for pattern, err in FORCED_PATTERNS:
        present = re.search(pattern, text, re.IGNORECASE) is not None
        status["forced_thresholds_present"][pattern] = present
        if not present:
            status["errors"].append(err)

    return write_out(status, strict)


def write_out(status: dict, strict: bool) -> int:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")

    has_error = len(status.get("errors", [])) > 0
    if has_error:
        print("[validate_quality_doc] NG: 不備があります", file=sys.stderr)
        for e in status["errors"]:
            print(f" - {e}", file=sys.stderr)
        return 1 if strict else 0
    else:
        print("[validate_quality_doc] OK: 文書は要件を満たしています")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate docs/quality_criteria.md structure and thresholds"
    )
    parser.add_argument("--strict", action="store_true", help="不備があれば非ゼロで終了")
    args = parser.parse_args()
    rc = validate(strict=args.strict)
    sys.exit(rc)


if __name__ == "__main__":
    main()
