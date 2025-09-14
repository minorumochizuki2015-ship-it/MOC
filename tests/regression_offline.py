import json
import sys

from interface import _extract_themes

CASES = [
    ("おはよう。今日は良い朝ごはんを提案して", ["朝", "ごはん", "提案"], 3),
    ("現在のAI理論について君の目線で提示せよ", ["AI", "理論", "目線"], 3),
    ("量子ではなく古典で堅牢に。短文テスト", ["古典", "堅牢", "短文"], 3),
]

ok = True
for text, hints, k in CASES:
    got = _extract_themes(text, top_k=k, window=4, alpha=0.8)
    # ヒント語が1つ以上含まれているか簡易検証
    if not any(h in got for h in hints):
        print("FAIL:", text, "->", got)
        ok = False
    else:
        print("PASS:", got)

sys.exit(0 if ok else 1)
