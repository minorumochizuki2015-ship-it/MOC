from __future__ import annotations

"""出題キューを生成するモジュール。"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .categories import (
    Category,
    QuizItem,
    group_quiz_items_by_category,
    select_category,
)
from .rng import PCG32


@dataclass(slots=True)
class CueContent:
    """UI に渡す出題内容。"""

    category_id: str
    item_id: str
    item_type: str
    noise_text: str
    target_text: str
    prompt_text: str
    image_file: Optional[str] = None


class QuizEngine:
    """出題カテゴリとアイテムを管理するエンジン。"""

    def __init__(
        self, categories: Sequence[Category], quiz_items: Sequence[QuizItem], rng: PCG32
    ) -> None:
        self._categories = list(categories)
        self._items_by_category = group_quiz_items_by_category(quiz_items)
        self._category_map = {category.id: category for category in self._categories}
        self._rng = rng
        self._game_mode: Optional[str] = None
        self._available_categories: List[Category] = []
        self._enabled_ids: set[str] = set()
        self._decks: Dict[str, List[QuizItem]] = {}
        self._refresh_available_categories(initial=True)

    def set_game_mode(self, mode: Optional[str]) -> None:
        """ゲームモードを設定し、利用カテゴリを更新する。"""

        self._game_mode = mode
        self._refresh_available_categories(initial=False)

    def get_category(self, category_id: str) -> Optional[Category]:
        """カテゴリIDに対応する定義を取得する。"""

        return self._category_map.get(category_id)

    @property
    def available_categories(self) -> List[Category]:
        """利用可能なカテゴリ一覧を返す。"""

        return list(self._available_categories)

    @property
    def enabled_category_ids(self) -> List[str]:
        """現在有効なカテゴリIDを返す。"""

        return sorted(self._enabled_ids)

    def set_enabled_categories(self, category_ids: Sequence[str]) -> List[str]:
        """有効化するカテゴリを設定し、実際に適用されたIDを返す。"""

        desired = [cid for cid in category_ids if cid in self._items_by_category]
        if not desired:
            desired = [category.id for category in self._available_categories]
        self._enabled_ids = {
            cid
            for cid in desired
            if any(category.id == cid for category in self._available_categories)
        }
        if not self._enabled_ids:
            self._enabled_ids = {category.id for category in self._available_categories}
        return sorted(self._enabled_ids)

    def count_items(self, category_ids: Sequence[str]) -> int:
        """指定カテゴリに紐づく問題数を返す。"""

        total = 0
        for cid in category_ids:
            total += len(self._items_by_category.get(cid, []))
        return total

    def next_cue(self) -> CueContent:
        """次に表示する出題を決定する。"""

        enabled = [
            category
            for category in self._available_categories
            if category.id in self._enabled_ids
        ]
        if not enabled:
            enabled = self._available_categories
        category = select_category(enabled, self._rng)
        item = self._draw_item(category.id)
        item_type = item.item_type
        payload = item.payload
        image_file = payload.get("file") if item_type == "image" else None
        noise_text = payload.get("noise", "")
        target_text = payload.get("text") or payload.get("label") or item.answer_key
        prompt_text = payload.get("prompt") or f"「{target_text}」が出たら指を離す"
        return CueContent(
            category_id=category.id,
            item_id=item.id,
            item_type=item_type,
            noise_text=noise_text,
            target_text=target_text,
            prompt_text=prompt_text,
            image_file=image_file,
        )

    def _draw_item(self, category_id: str) -> QuizItem:
        """カテゴリごとのデッキから1件取り出す。"""

        deck = self._decks.setdefault(category_id, [])
        if not deck:
            base_items = self._items_by_category.get(category_id, [])
            if not base_items:
                raise ValueError("クイズ項目が定義されていません。")
            deck.extend(self._shuffle_items(base_items))
        return deck.pop()

    def _shuffle_items(self, items: List[QuizItem]) -> List[QuizItem]:
        """PCG32 を利用してアイテム順をシャッフルする。"""

        pool = list(items)
        for index in range(len(pool) - 1, 0, -1):
            swap_index = self._rng.random_range(index + 1)
            pool[index], pool[swap_index] = pool[swap_index], pool[index]
        return pool

    def _refresh_available_categories(self, initial: bool) -> None:
        def matches_mode(category: Category) -> bool:
            if not self._game_mode:
                return True
            return not category.modes or self._game_mode in category.modes

        filtered = [
            category
            for category in self._categories
            if category.id in self._items_by_category and matches_mode(category)
        ]
        if not filtered:
            filtered = [
                category
                for category in self._categories
                if category.id in self._items_by_category
            ]
        self._available_categories = filtered
        if initial or not self._enabled_ids:
            self._enabled_ids = {category.id for category in self._available_categories}
        else:
            self._enabled_ids = {
                cid
                for cid in self._enabled_ids
                if any(category.id == cid for category in self._available_categories)
            } or {category.id for category in self._available_categories}
        self._decks = {
            category.id: self._decks.get(category.id, [])
            for category in self._available_categories
        }
