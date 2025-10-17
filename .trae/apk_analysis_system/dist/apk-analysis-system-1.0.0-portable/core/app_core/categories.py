from __future__ import annotations

"""カテゴリ定義と出題データの管理を担当するモジュール。"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from .rng import PCG32

DATA_DIR = Path("data/quiz")
CATEGORIES_FILE = DATA_DIR / "categories.json"
QUIZ_ITEMS_FILE = DATA_DIR / "quiz_items.json"


class QuizDataError(RuntimeError):
    """クイズデータ読み込み時の例外。"""


@dataclass(slots=True)
class Category:
    """出題カテゴリを表すデータ構造。"""

    id: str
    name: str
    effects: Sequence[str] = field(default_factory=tuple)
    weight: float = 1.0
    difficulty: str = "med"
    modes: Sequence[str] = field(default_factory=tuple)


@dataclass(slots=True)
class QuizItem:
    """個別の出題データを表す。"""

    id: str
    category: str
    item_type: str
    payload: Dict[str, str]
    answer_key: str


def _load_json(path: Path) -> List[Dict[str, object]]:
    if not path.exists():
        raise QuizDataError(f"データファイルが見つかりません: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise QuizDataError(f"JSONの読み込みに失敗しました: {path}") from exc


def load_default_categories() -> List[Category]:
    """categories.json からカテゴリ一覧を読み込む。"""

    records = _load_json(CATEGORIES_FILE)
    categories: List[Category] = []
    for record in records:
        categories.append(
            Category(
                id=str(record["id"]),
                name=str(record["name"]),
                effects=tuple(record.get("effects", [])),
                weight=float(record.get("weight", 1.0)),
                difficulty=str(record.get("difficulty", "med")),
                modes=tuple(record.get("modes", [])),
            )
        )
    return categories


def load_quiz_items(category_ids: Sequence[str] | None = None) -> List[QuizItem]:
    """quiz_items.json からクイズデータを読み込む。"""

    records = _load_json(QUIZ_ITEMS_FILE)
    allowed = set(category_ids) if category_ids is not None else None
    items: List[QuizItem] = []
    for record in records:
        category_id = str(record["category"])
        if allowed is not None and category_id not in allowed:
            continue
        payload = {str(k): str(v) for k, v in record.get("payload", {}).items()}
        answer_key = payload.get("text") or payload.get("file") or category_id
        items.append(
            QuizItem(
                id=str(record["id"]),
                category=category_id,
                item_type=str(record.get("type", "text")),
                payload=payload,
                answer_key=str(answer_key),
            )
        )
    return items


def filter_enabled(
    categories: Sequence[Category], enabled_ids: Sequence[str]
) -> List[Category]:
    """使用するカテゴリだけを抽出する。"""

    enabled = set(enabled_ids)
    return [category for category in categories if category.id in enabled]


def select_category(categories: Sequence[Category], rng: PCG32) -> Category:
    """重み付きでカテゴリを抽選する。"""

    if not categories:
        raise ValueError("カテゴリが一つも指定されていない。")
    total = sum(max(category.weight, 0.0) for category in categories)
    if total <= 0.0:
        raise ValueError("カテゴリの重み合計が0以下になっている。")
    threshold = rng.random_float() * total
    cursor = 0.0
    for category in categories:
        cursor += max(category.weight, 0.0)
        if threshold < cursor:
            return category
    return categories[-1]


def list_effects(categories: Iterable[Category]) -> List[str]:
    """効果の集合を安定した順序で返す。"""

    effects: List[str] = []
    for category in categories:
        for effect in category.effects:
            if effect not in effects:
                effects.append(effect)
    return effects


def group_quiz_items_by_category(
    quiz_items: Sequence[QuizItem],
) -> Dict[str, List[QuizItem]]:
    """カテゴリごとにクイズ項目をグループ化する。"""

    grouped: Dict[str, List[QuizItem]] = {}
    for item in quiz_items:
        grouped.setdefault(item.category, []).append(item)
    return grouped
