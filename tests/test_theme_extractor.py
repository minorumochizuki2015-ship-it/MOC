import csv
import importlib.util
import os
import re
import statistics as st
from pathlib import Path

ROOT = Path(r"C:\Users\User\PhoenixCodex\GoverningCore_v5_Slice")
mod_path = ROOT / "interface.py"

# interface.py から _extract_themes を安全にロード
spec = importlib.util.spec_from_file_location("iface", mod_path)
iface = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iface)  # GUIは __main__ ガード下なので起動しない

extract = iface._extract_themes
WORD_RE = iface._WORD_RE
STOP = iface._STOP

# テスト入力（短文/中文/タスク）
CASES = {
    "A_short": "おはよう。今日の朝食は何が良い？",
    "B_food": "たんぱく質を多めに、10分以内で作れる朝食の案を3つ。",
    "C_task": "READMEを日本語で要約し、箇条書き3点で重要点を列挙して。",
}

EXTRACTORS = ["degree", "poorpr"]  # UIトグルと一致
ALPHAS = [0.7, 0.8, 0.9]
WINDOWS = [3, 4]
TOPK = 5
REPEATS = 3


def content_ratio(themes):
    # ざっくり“内容語率”（ストップ語を除外）
    if not themes:
        return 0.0
    cnt = sum(1 for w in themes if w not in STOP and len(w) >= 2)
    return cnt / len(themes)


def stability(top_lists):
    # 3回の上位集合のJaccard平均
    from itertools import combinations

    sets = [set(xs) for xs in top_lists]
    if len(sets) < 2:
        return 1.0
    j = []
    for a, b in combinations(sets, 2):
        inter = len(a & b)
        union = max(1, len(a | b))
        j.append(inter / union)
    return sum(j) / len(j)


out_csv = ROOT / "theme_extractor_eval.csv"
with out_csv.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(
        [
            "case",
            "extractor",
            "alpha",
            "window",
            "repeat_themes",
            "stability",
            "content_ratio_mean",
        ]
    )
    CAUSES = CASES
    for case_name, text in CAUSES.items():
        for ext in EXTRACTORS:
            use_pr = ext == "poorpr"
            for a in ALPHAS:
                for win in WINDOWS:
                    tops = []
                    for _ in range(REPEATS):
                        th = extract(
                            text,
                            top_k=TOPK,
                            window=win,
                            alpha=a,
                            use_poor_pagerank=use_pr,
                        )
                        tops.append(th)
                    stab = stability(tops)
                    cr = st.mean(content_ratio(t) for t in tops)
                    w.writerow(
                        [
                            case_name,
                            ext,
                            a,
                            win,
                            "|".join([",".join(t) for t in tops]),
                            f"{stab:.3f}",
                            f"{cr:.3f}",
                        ]
                    )

print(f"OK: {out_csv}")
