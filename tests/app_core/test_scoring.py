from __future__ import annotations

"""scoring モジュールのロジックを検証するテスト。"""

from app_core.scoring import PlayerSnapshot, build_false_start_outcome, evaluate_round


def test_tie_within_threshold() -> None:
    """同着閾値内では勝者なしになることを確認する。"""
    reveal = 1_000_000_000
    deadline = reveal + int(2.5 * 1_000_000_000)
    snapshots = [
        PlayerSnapshot(player_id="P1", up_timestamp_ns=reveal + 7_000_000),
        PlayerSnapshot(player_id="P2", up_timestamp_ns=reveal + 9_000_000),
    ]
    outcome = evaluate_round(
        reveal_timestamp_ns=reveal,
        deadline_ns=deadline,
        snapshots=snapshots,
        now_ns=reveal + 10_000_000,
        tie_threshold_ms=8,
        penalty_ms=500,
    )
    assert outcome.has_tie is True
    assert outcome.winner_id is None


def test_false_start_outcome_marks_player() -> None:
    """フライングしたプレイヤーが記録されることを確認する。"""
    outcome = build_false_start_outcome(["P1", "P2"], "P1", 500)
    assert outcome.false_start_player_id == "P1"
    assert outcome.reactions["P1"].false_start is True
    assert outcome.winner_id == "P2"
