from __future__ import annotations

"""スコアリングと勝敗判定を行うモジュール。"""

from dataclasses import dataclass
from typing import Dict, Optional, Sequence

from .timing import ns_to_ms


@dataclass(slots=True)
class Reaction:
    """プレイヤーごとの反応時間を保持する。"""

    player_id: str
    delta_ms: float
    false_start: bool = False
    penalty_ms: int = 0


@dataclass(slots=True)
class PlayerSnapshot:
    """集計時点のプレイヤー状態をスナップショットする。"""

    player_id: str
    up_timestamp_ns: Optional[int]
    false_start: bool = False


@dataclass(slots=True)
class RoundOutcome:
    """1ラウンド分の結果。"""

    winner_id: Optional[str]
    has_tie: bool
    reactions: Dict[str, Reaction]
    false_start_player_id: Optional[str] = None


def _effective_ms(reaction: Reaction) -> float:
    """勝敗判定に用いる実効ミリ秒値を返す。"""
    if reaction.false_start:
        return float("inf")
    return reaction.delta_ms + reaction.penalty_ms


def build_false_start_outcome(
    active_player_ids: Sequence[str], fault_player_id: str, penalty_ms: int
) -> RoundOutcome:
    """フライング発生時の結果を生成する。"""
    reactions: Dict[str, Reaction] = {}
    winner_id: Optional[str] = None
    for player_id in active_player_ids:
        if player_id == fault_player_id:
            reactions[player_id] = Reaction(
                player_id=player_id,
                delta_ms=0.0,
                false_start=True,
                penalty_ms=penalty_ms,
            )
        else:
            reactions[player_id] = Reaction(player_id=player_id, delta_ms=0.0)
            if winner_id is None:
                winner_id = player_id
    return RoundOutcome(
        winner_id=winner_id,
        has_tie=False,
        reactions=reactions,
        false_start_player_id=fault_player_id,
    )


def evaluate_round(
    reveal_timestamp_ns: int,
    deadline_ns: int,
    snapshots: Sequence[PlayerSnapshot],
    now_ns: int,
    tie_threshold_ms: int,
    penalty_ms: int,
) -> RoundOutcome:
    """反応時間に基づき勝者を決定する。"""
    reactions: Dict[str, Reaction] = {}
    for snapshot in snapshots:
        if snapshot.false_start:
            reactions[snapshot.player_id] = Reaction(
                player_id=snapshot.player_id,
                delta_ms=0.0,
                false_start=True,
                penalty_ms=penalty_ms,
            )
            continue
        up_ns = snapshot.up_timestamp_ns
        if up_ns is None:
            base_ns = max(deadline_ns, now_ns)
            base_delta_ms = ns_to_ms(max(base_ns - reveal_timestamp_ns, 0))
            reactions[snapshot.player_id] = Reaction(
                player_id=snapshot.player_id,
                delta_ms=base_delta_ms,
                penalty_ms=penalty_ms,
            )
            continue
        delta_ns = max(up_ns - reveal_timestamp_ns, 0)
        delta_ms = ns_to_ms(delta_ns)
        penalty = penalty_ms if up_ns > deadline_ns else 0
        reactions[snapshot.player_id] = Reaction(
            player_id=snapshot.player_id,
            delta_ms=delta_ms,
            penalty_ms=penalty,
        )
    ordered = sorted(reactions.values(), key=_effective_ms)
    if not ordered:
        return RoundOutcome(winner_id=None, has_tie=False, reactions=reactions)
    best = ordered[0]
    best_time = _effective_ms(best)
    if best_time == float("inf"):
        return RoundOutcome(winner_id=None, has_tie=False, reactions=reactions)
    has_tie = False
    if len(ordered) > 1:
        runner_time = _effective_ms(ordered[1])
        if (
            runner_time != float("inf")
            and abs(runner_time - best_time) < tie_threshold_ms
        ):
            has_tie = True
    winner_id = None if has_tie else best.player_id
    return RoundOutcome(winner_id=winner_id, has_tie=has_tie, reactions=reactions)
