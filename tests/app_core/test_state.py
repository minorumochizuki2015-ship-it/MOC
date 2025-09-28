from __future__ import annotations

"""state モジュールの状態遷移を検証するテスト。"""

from app_core.rng import seed_from_int
from app_core.state import GameStateMachine, Phase, PlayerSlot, RoundConfig


def _create_machine() -> GameStateMachine:
    """テスト用のステートマシンを生成する。"""
    players = {
        "P1": PlayerSlot(player_id="P1", color_hex="#FF3B30"),
        "P2": PlayerSlot(player_id="P2", color_hex="#007AFF"),
        "P3": PlayerSlot(player_id="P3", color_hex="#34C759"),
        "P4": PlayerSlot(player_id="P4", color_hex="#FFCC00"),
    }
    return GameStateMachine(
        players=players, config=RoundConfig(), rng=seed_from_int(2024)
    )


def test_state_flow_success() -> None:
    """通常フローで勝者が決定することを確認する。"""
    machine = _create_machine()
    machine.handle_touch_down("P1", 0)
    machine.handle_touch_down("P2", 0)
    machine.handle_start(0)
    arming_lock = machine.context.arming_lock_ns or 0
    machine.tick(arming_lock)
    reveal = machine.context.scheduled_reveal_ns or 0
    machine.tick(reveal)
    machine.handle_touch_up("P1", reveal + 5_000_000)
    machine.handle_touch_up("P2", reveal + 20_000_000)
    assert machine.phase is Phase.FINISHED
    assert machine.outcome is not None
    assert machine.outcome.winner_id == "P1"
    assert machine.outcome.has_tie is False


def test_state_false_start_finishes_round() -> None:
    """フライングで即終了することを確認する。"""
    machine = _create_machine()
    machine.handle_touch_down("P1", 0)
    machine.handle_touch_down("P2", 0)
    machine.handle_start(0)
    reveal = machine.context.scheduled_reveal_ns or 0
    machine.handle_touch_up("P1", max(reveal - 1, 0))
    assert machine.phase is Phase.FINISHED
    assert machine.outcome is not None
    assert machine.outcome.false_start_player_id == "P1"
    assert machine.outcome.winner_id == "P2"
