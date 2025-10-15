from __future__ import annotations

"""PCG32 乱数生成器のラッパー。"""

from dataclasses import dataclass
from typing import Sequence, TypeVar

MASK_64: int = (1 << 64) - 1
OUTPUT_MASK_32: int = (1 << 32) - 1
MULTIPLIER: int = 6364136223846793005
DEFAULT_INCREMENT: int = 1442695040888963407

T = TypeVar("T")


@dataclass(slots=True)
class PCG32:
    """PCG32 アルゴリズムによる疑似乱数生成器。"""

    state: int
    inc: int = DEFAULT_INCREMENT

    def __post_init__(self) -> None:
        """インクリメントが奇数であることを保証する。"""
        self.inc |= 1
        self.state &= MASK_64

    def random_uint32(self) -> int:
        """32bit の符号なし整数を返す。"""
        old_state = self.state
        self.state = (old_state * MULTIPLIER + self.inc) & MASK_64
        xorshifted = ((old_state >> 18) ^ old_state) >> 27
        rot = old_state >> 59
        value = ((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & OUTPUT_MASK_32
        return value

    def random_bits(self, bits: int = 32) -> int:
        """指定ビット数の乱数を返す。"""
        if not 0 < bits <= 32:
            raise ValueError("bits は1〜32の範囲で指定する必要がある。")
        return self.random_uint32() >> (32 - bits)

    def random_float(self) -> float:
        """[0,1) の浮動小数を返す。"""
        return self.random_uint32() / (OUTPUT_MASK_32 + 1)

    def random_range(self, stop: int) -> int:
        """0以上stop未満の整数を返す。"""
        if stop <= 0:
            raise ValueError("stop は正の整数でなければならない。")
        threshold = (-stop) % stop
        while True:
            value = self.random_uint32()
            if value >= threshold:
                return value % stop

    def choice(self, items: Sequence[T]) -> T:
        """シーケンスから要素を等確率で選ぶ。"""
        if not items:
            raise ValueError("空のシーケンスからは選択できない。")
        index = self.random_range(len(items))
        return items[index]

    def advance(self, delta: int) -> None:
        """指定回数分だけ状態を進める。"""
        if delta < 0:
            raise ValueError("delta は0以上でなければならない。")
        cur_mult = MULTIPLIER
        cur_plus = self.inc
        acc_mult = 1
        acc_plus = 0
        value = delta
        while value > 0:
            if value & 1:
                acc_mult = (acc_mult * cur_mult) & MASK_64
                acc_plus = (acc_plus * cur_mult + cur_plus) & MASK_64
            cur_plus = (cur_mult + 1) * cur_plus & MASK_64
            cur_mult = (cur_mult * cur_mult) & MASK_64
            value >>= 1
        self.state = (acc_mult * self.state + acc_plus) & MASK_64


def seed_from_int(seed: int, sequence: int = 1) -> PCG32:
    """整数シードから PCG32 を生成する。"""
    inc = ((sequence << 1) | 1) & MASK_64
    rng = PCG32(state=0, inc=inc)
    rng.random_uint32()
    rng.state = (rng.state + (seed & MASK_64)) & MASK_64
    rng.random_uint32()
    return rng
