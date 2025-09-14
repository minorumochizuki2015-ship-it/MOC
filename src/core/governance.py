# governance.py
# - ガバナンス判定（フェーズブレイク検知）と要約レポート
# - 閾値: ENTANGLEMENT_ENTROPY_MAX = 0.30
# - 数値フォーマットは非数値でも安全
# - 末尾のJSONダンプはデフォルト非表示（必要時のみ環境変数 GOV_DEBUG_JSON=1）

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Tuple

# ===== 閾値 =====
GOVERNANCE_THRESHOLDS: Dict[str, float] = {
    "RESONANCE_SCORE_MIN": 0.92,
    "ENTANGLEMENT_ENTROPY_MAX": 0.30,  # 緩和
    "COHERENCE_CONFIDENCE_MIN": 0.95,
    "HALLUCINATION_RISK_MAX": 0.15,
    # 新機能の閾値
    "QUALITY_SCORE_MIN": 0.85,
    "RELEVANCE_SCORE_MIN": 0.80,
    "SAFETY_SCORE_MIN": 0.90,
    "COHERENCE_SCORE_MIN": 0.88,
}

# ===== 逸脱検知ヒューリスティック =====
_JAILBREAK_PATTERNS = [
    r"(?i)\bignore (?:all|any) (?:previous|prior) (?:instructions|rules)\b",
    r"(?i)\bdisregard .* (?:safety|policy|guardrails)\b",
    r"(?i)\bdo (?:anything|everything) now\b",
    r"(?i)\b(?:as|act) (?:an|like) (?:unfiltered|uncensored) model\b",
    r"(?i)\bno longer bound by\b",
]
_JAILBREAK_PATTERNS_JA = [
    r"(?:前提|制約|安全|方針|ルール).*無視",
    r"(?:検閲|制限).*解除",
    r"(?:なんでも|何でも)(?:答え|して)ろ",
    r"ガードレール.*外せ",
]
_ERROR_PATTERNS = [
    r"internal server error",
    r"traceback",
    r"error code",
    r"null",
    r"nan",
    r"<empty>",
]


# ===== ユーティリティ =====
def _is_number(x: Any) -> bool:
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


def _fmt(val: Any, pat: str) -> str:
    """数値なら pat で整形、非数値(None/空)は 'N/A'。"""
    try:
        return (
            pat.format(float(val))
            if _is_number(val)
            else ("N/A" if val in (None, "") else str(val))
        )
    except Exception:
        return "N/A"


def _calculate_quality_metrics(text: str) -> Dict[str, float]:
    """テキストの品質メトリクスを計算"""
    if not text:
        return {
            "quality_score": 0.0,
            "relevance_score": 0.0,
            "safety_score": 0.0,
            "coherence_score": 0.0,
        }

    # 品質スコア（文字数、構造、多様性）
    length_score = min(len(text) / 100, 1.0)  # 100文字で満点
    structure_score = 0.0
    if any(char in text for char in "。！？"):
        structure_score += 0.3
    if len(text.split()) > 5:  # 単語数
        structure_score += 0.4
    if any(char.isdigit() for char in text):  # 数字の存在
        structure_score += 0.3

    quality_score = (length_score + structure_score) / 2

    # 関連性スコア（キーワード密度、文脈保持）
    relevance_score = 0.8  # デフォルト値（実際の実装ではより複雑な計算）

    # 安全性スコア（不適切な内容の検出）
    safety_score = 1.0
    inappropriate_words = ["危険", "違法", "有害", "不適切"]
    for word in inappropriate_words:
        if word in text:
            safety_score -= 0.2
    safety_score = max(0.0, safety_score)

    # 一貫性スコア（論理的一貫性）
    coherence_score = 0.9  # デフォルト値

    return {
        "quality_score": quality_score,
        "relevance_score": relevance_score,
        "safety_score": safety_score,
        "coherence_score": coherence_score,
    }


# ===== 本体 =====
class Governance:
    def __init__(self, thresholds: Dict[str, float] | None = None):
        self.thresholds = thresholds or GOVERNANCE_THRESHOLDS.copy()
        self._re_jb = [re.compile(p) for p in _JAILBREAK_PATTERNS]
        self._re_jb_ja = [re.compile(p) for p in _JAILBREAK_PATTERNS_JA]
        self._re_err = [re.compile(p, re.I) for p in _ERROR_PATTERNS]

    def check_anomaly(
        self,
        response_text: str | None,
        quantum_metrics: Dict[str, Any] | None,
    ) -> Tuple[bool, List[str]]:
        """逸脱有無を判定し、理由を返す。メトリクスが空でも安全。"""
        reasons: List[str] = []
        text = (response_text or "").strip()
        qm = quantum_metrics or {}

        # 0) 応答空/極小
        if len(text) == 0:
            reasons.append("Empty response")
        elif len(text) < 2:
            reasons.append("Response too short")

        # 1) 内部エラーの兆候
        for rgx in self._re_err:
            if rgx.search(text):
                reasons.append("Internal error artifact detected")

        # 2) ジェイルブレイク誘導
        for rgx in self._re_jb + self._re_jb_ja:
            if rgx.search(text):
                reasons.append("Jailbreak-like instruction detected")

        # 3) 量子メトリクス（与えられている場合のみ評価）
        rs = qm.get("resonance_score")
        if _is_number(rs) and float(rs) < float(self.thresholds["RESONANCE_SCORE_MIN"]):
            reasons.append(
                f"Resonance score below threshold ({rs} < {self.thresholds['RESONANCE_SCORE_MIN']})"
            )

        ee = qm.get("entanglement_entropy")
        if _is_number(ee) and float(ee) > float(
            self.thresholds["ENTANGLEMENT_ENTROPY_MAX"]
        ):
            reasons.append(
                f"Entanglement entropy above threshold ({ee} > {self.thresholds['ENTANGLEMENT_ENTROPY_MAX']})"
            )

        cc = qm.get("coherence_confidence")
        if _is_number(cc) and float(cc) < float(
            self.thresholds["COHERENCE_CONFIDENCE_MIN"]
        ):
            reasons.append(
                f"Coherence confidence below threshold ({cc} < {self.thresholds['COHERENCE_CONFIDENCE_MIN']})"
            )

        hr = qm.get("hallucination_risk")
        if _is_number(hr) and float(hr) > float(
            self.thresholds["HALLUCINATION_RISK_MAX"]
        ):
            reasons.append(
                f"Hallucination risk above threshold ({hr} > {self.thresholds['HALLUCINATION_RISK_MAX']})"
            )

        # 4) 新機能：品質メトリクス評価
        quality_metrics = _calculate_quality_metrics(text)
        for metric_name, value in quality_metrics.items():
            threshold_key = f"{metric_name.upper()}_MIN"
            if threshold_key in self.thresholds:
                threshold = self.thresholds[threshold_key]
                if value < threshold:
                    reasons.append(
                        f"{metric_name} below threshold ({value:.3f} < {threshold})"
                    )

        return (len(reasons) > 0, reasons)

    def summarize_governance_analysis(
        self,
        response_text: str | None,
        quantum_metrics: Dict[str, Any] | None,
    ) -> str:
        """人間可読の監査サマリをテキストで返す（GUIにそのまま表示可）。"""
        is_anomaly, reasons = self.check_anomaly(response_text, quantum_metrics)
        qm = quantum_metrics or {}

        lines: List[str] = []
        lines.append(f"Phase Break: {'TRIGGERED' if is_anomaly else 'PASSED'}")
        if reasons:
            lines.append("Reasons:")
            for r in reasons:
                lines.append(f" - {r}")
        else:
            lines.append("Reasons: None")

        lines.append("Metrics:")
        lines.append(f" - Resonance Score: {_fmt(qm.get('resonance_score'), '{:.3f}')}")
        lines.append(
            f" - Entanglement Entropy: {_fmt(qm.get('entanglement_entropy'), '{:.4f}')}"
        )
        lines.append(
            f" - Coherence Confidence: {_fmt(qm.get('coherence_confidence'), '{:.3f}')}"
        )
        lines.append(
            f" - Hallucination Risk: {_fmt(qm.get('hallucination_risk'), '{:.3f}')}"
        )

        # デフォルトはJSONを付けない。必要時のみ GOV_DEBUG_JSON=1 で付与。
        if os.getenv("GOV_DEBUG_JSON") == "1":
            try:
                lines.append("")
                lines.append("JSON:")
                lines.append(
                    json.dumps(
                        {
                            "phase_break_status": (
                                "TRIGGERED" if is_anomaly else "PASSED"
                            ),
                            "violation_reasons": reasons,
                            "checked_metrics": {
                                "Resonance Score": _fmt(
                                    qm.get("resonance_score"), "{:.3f}"
                                ),
                                "Entanglement Entropy": _fmt(
                                    qm.get("entanglement_entropy"), "{:.4f}"
                                ),
                                "Coherence Confidence": _fmt(
                                    qm.get("coherence_confidence"), "{:.3f}"
                                ),
                                "Hallucination Risk": _fmt(
                                    qm.get("hallucination_risk"), "{:.3f}"
                                ),
                            },
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            except Exception:
                pass

        return "\n".join(lines)
