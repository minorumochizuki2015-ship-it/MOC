from __future__ import annotations

"""rng モジュールの振る舞いを検証するテスト。"""

from app_core.rng import seed_from_int


def test_pcg32_deterministic() -> None:
    """固定シードで同一系列が得られることを確認する。"""
    rng = seed_from_int(12345)
    values = [rng.random_uint32() for _ in range(3)]
    assert values == [2280515124, 880540696, 2165172963]


def test_random_range_bounds() -> None:
    """random_range の下限上限が守られることを確認する。"""
    rng = seed_from_int(999)
    for _ in range(64):
        value = rng.random_range(5)
        assert 0 <= value < 5
