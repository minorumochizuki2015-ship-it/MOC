from __future__ import annotations

"""時間計測ユーティリティ。"""

import time
from typing import Protocol


class MonotonicClock(Protocol):
    """モノトニッククロックを抽象化するプロトコル。"""

    def __call__(self) -> int:
        """現在時刻のナノ秒値を返す。"""
        ...


def monotonic_time_ns() -> int:
    """monotonic_ns ラッパー。"""
    return time.monotonic_ns()


def ns_to_ms(delta_ns: int) -> float:
    """ナノ秒差分をミリ秒に変換する。"""
    return delta_ns / 1_000_000


def clamp_delay(value_s: float, minimum_s: float, maximum_s: float) -> float:
    """設定値の範囲を保証する。"""
    return max(minimum_s, min(value_s, maximum_s))
