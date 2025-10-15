from __future__ import annotations

"""ゲームの状態管理を司るモジュール。"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .rng import PCG32
from .scoring import (
    PlayerSnapshot,
    RoundOutcome,
    build_false_start_outcome,
    evaluate_round,
)

ARMING_GRACE_NS: int = int(0.2 * 1_000_000_000)
MAX_PLAYERS: int = 4
DEFAULT_DEADLINE_NS: int = int(2.5 * 1_000_000_000)


class Phase(str, Enum):
    """ラウンドの状態を表す列挙。"""

    IDLE = "idle"
    ARMING = "arming"
    WAIT_REVEAL = "wait_reveal"
    REVEALED = "revealed"
    SCORING = "scoring"
    FINISHED = "finished"


@dataclass(slots=True)
class PlayerSlot:
    """プレイヤーと指の割当状態を保持するデータ構造。"""

    player_id: str
    color_hex: str
    down: bool = False
    down_timestamp_ns: Optional[int] = None
    up_timestamp_ns: Optional[int] = None
    false_start: bool = False

    def mark_down(self, timestamp_ns: int) -> None:
        """指が置かれたタイミングを記録する。"""
        if self.down:
            return
        self.down = True
        self.down_timestamp_ns = timestamp_ns
        self.up_timestamp_ns = None
        self.false_start = False

    def mark_up(self, timestamp_ns: int) -> None:
        """指が離れたタイミングを記録する。"""
        self.down = False
        self.up_timestamp_ns = timestamp_ns

    def reset_round(self) -> None:
        """ラウンド用の一時情報をクリアする。"""
        self.up_timestamp_ns = None
        self.false_start = False

    def reset_all(self) -> None:
        """プレイヤー割当を完全に初期化する。"""
        self.down = False
        self.down_timestamp_ns = None
        self.up_timestamp_ns = None
        self.false_start = False


@dataclass(slots=True)
class RoundConfig:
    """ラウンド全体の設定値をまとめる。"""

    reveal_delay_min_s: float = 1.2
    reveal_delay_max_s: float = 3.5
    tie_threshold_ms: int = 8
    no_up_penalty_ms: int = 500
    deadline_offset_ns: int = DEFAULT_DEADLINE_NS


@dataclass(slots=True)
class RoundContext:
    """進行中ラウンドのタイムスタンプを保持する。"""

    armed_at_ns: Optional[int] = None
    arming_lock_ns: Optional[int] = None
    scheduled_reveal_ns: Optional[int] = None
    reveal_timestamp_ns: Optional[int] = None
    deadline_ns: Optional[int] = None
    category_id: Optional[str] = None
    quiz_item_id: Optional[str] = None


@dataclass(slots=True)
class GameStateMachine:
    """ゲームの状態遷移を管理する。"""

    players: Dict[str, PlayerSlot]
    config: RoundConfig
    rng: PCG32
    phase: Phase = Phase.IDLE
    active_player_ids: List[str] = field(default_factory=list)
    context: RoundContext = field(default_factory=RoundContext)
    outcome: Optional[RoundOutcome] = None
    history: List[RoundOutcome] = field(default_factory=list)

    def reset(self) -> None:
        """ゲーム全体を初期状態に戻す。"""
        self.phase = Phase.IDLE
        self.active_player_ids.clear()
        self.context = RoundContext()
        self.outcome = None
        for slot in self.players.values():
            slot.reset_all()

    def prepare_next_round(self) -> None:
        """結果表示後に次ラウンドを始められる状態にする。"""
        self.phase = Phase.IDLE
        self.active_player_ids.clear()
        self.context = RoundContext()
        self.outcome = None
        for slot in self.players.values():
            slot.reset_round()

    def handle_touch_down(self, player_id: str, timestamp_ns: int) -> None:
        """指が置かれたときの処理。"""
        if self.phase in (Phase.SCORING, Phase.FINISHED):
            return
        slot = self._require_player(player_id)
        slot.mark_down(timestamp_ns)
        if self.phase == Phase.IDLE:
            if (
                player_id not in self.active_player_ids
                and len(self.active_player_ids) < MAX_PLAYERS
            ):
                self.active_player_ids.append(player_id)
        elif self.phase == Phase.ARMING:
            if (
                player_id not in self.active_player_ids
                and len(self.active_player_ids) < MAX_PLAYERS
                and self.context.arming_lock_ns is not None
                and timestamp_ns <= self.context.arming_lock_ns
            ):
                self.active_player_ids.append(player_id)

    def handle_touch_up(self, player_id: str, timestamp_ns: int) -> None:
        """指が離れたときの処理。"""
        slot = self._require_player(player_id)
        if self.phase in (Phase.SCORING, Phase.FINISHED):
            slot.down = False
            return
        if self.phase == Phase.IDLE:
            if player_id in self.active_player_ids:
                self.active_player_ids.remove(player_id)
            slot.reset_round()
            slot.down = False
            return
        if player_id not in self.active_player_ids:
            slot.down = False
            return
        if self.phase in (Phase.ARMING, Phase.WAIT_REVEAL):
            slot.false_start = True
            slot.mark_up(timestamp_ns)
            self._finish(
                build_false_start_outcome(
                    self.active_player_ids, player_id, self.config.no_up_penalty_ms
                )
            )
            return
        if self.phase == Phase.REVEALED:
            slot.mark_up(timestamp_ns)
            self._check_completion(timestamp_ns)

    def handle_start(self, timestamp_ns: int) -> None:
        """START ボタン押下時の処理を行う。"""
        if self.phase is not Phase.IDLE:
            raise RuntimeError("ラウンド進行中はSTARTできない。")
        participants = [pid for pid in self.active_player_ids if self.players[pid].down]
        if len(participants) < 2:
            raise ValueError("参加者が2人未満のため開始できない。")
        self.active_player_ids = participants[:MAX_PLAYERS]
        for pid in self.active_player_ids:
            self.players[pid].reset_round()
        delay_range = max(
            self.config.reveal_delay_max_s - self.config.reveal_delay_min_s, 0.0
        )
        random_factor = self.rng.random_float()
        delay_s = self.config.reveal_delay_min_s + random_factor * delay_range
        scheduled_reveal_ns = timestamp_ns + int(delay_s * 1_000_000_000)
        self.context = RoundContext(
            armed_at_ns=timestamp_ns,
            arming_lock_ns=timestamp_ns + ARMING_GRACE_NS,
            scheduled_reveal_ns=scheduled_reveal_ns,
            reveal_timestamp_ns=None,
            deadline_ns=scheduled_reveal_ns + self.config.deadline_offset_ns,
        )
        self.outcome = None
        self.phase = Phase.ARMING

    def tick(self, current_timestamp_ns: int) -> None:
        """時間経過に応じた状態遷移を処理する。"""
        if self.phase == Phase.ARMING and self.context.arming_lock_ns is not None:
            if current_timestamp_ns >= self.context.arming_lock_ns:
                self.phase = Phase.WAIT_REVEAL
        if self.phase in (Phase.ARMING, Phase.WAIT_REVEAL):
            if (
                self.context.scheduled_reveal_ns is not None
                and current_timestamp_ns >= self.context.scheduled_reveal_ns
            ):
                self._enter_revealed(self.context.scheduled_reveal_ns)
        if self.phase == Phase.REVEALED:
            self._check_completion(current_timestamp_ns)

    def _check_completion(self, current_timestamp_ns: int) -> None:
        """全員離脱またはタイムアウトを検知する。"""
        if self.context.reveal_timestamp_ns is None:
            return
        if self._all_resolved():
            self._finalize(current_timestamp_ns)
            return
        deadline_ns = self.context.deadline_ns or (
            self.context.reveal_timestamp_ns + self.config.deadline_offset_ns
        )
        if current_timestamp_ns >= deadline_ns:
            self._finalize(current_timestamp_ns)

    def _finalize(self, current_timestamp_ns: int) -> None:
        """ラウンド結果を集計して終了する。"""
        reveal_ts = self.context.reveal_timestamp_ns
        if reveal_ts is None:
            return
        deadline_ns = self.context.deadline_ns or (
            reveal_ts + self.config.deadline_offset_ns
        )
        snapshots = [
            PlayerSnapshot(
                player_id=pid,
                up_timestamp_ns=self.players[pid].up_timestamp_ns,
                false_start=self.players[pid].false_start,
            )
            for pid in self.active_player_ids
        ]
        outcome = evaluate_round(
            reveal_timestamp_ns=reveal_ts,
            deadline_ns=deadline_ns,
            snapshots=snapshots,
            now_ns=current_timestamp_ns,
            tie_threshold_ms=self.config.tie_threshold_ms,
            penalty_ms=self.config.no_up_penalty_ms,
        )
        self._finish(outcome)

    def _finish(self, outcome: RoundOutcome) -> None:
        """結果を記録して状態をFINISHEDにする。"""
        self.phase = Phase.SCORING
        self.outcome = outcome
        self.history.append(outcome)
        self.phase = Phase.FINISHED

    def _enter_revealed(self, reveal_timestamp_ns: int) -> None:
        """合図表示状態へ遷移する。"""
        if self.phase == Phase.REVEALED:
            return
        self.phase = Phase.REVEALED
        self.context.reveal_timestamp_ns = reveal_timestamp_ns

    def _all_resolved(self) -> bool:
        """全参加者の入力が確定したかを判定する。"""
        return all(
            self.players[pid].false_start
            or self.players[pid].up_timestamp_ns is not None
            for pid in self.active_player_ids
        )

    def _require_player(self, player_id: str) -> PlayerSlot:
        """指定IDのプレイヤースロットを取得する。"""
        try:
            return self.players[player_id]
        except KeyError as exc:
            raise KeyError(f"未知のプレイヤーID: {player_id}") from exc
