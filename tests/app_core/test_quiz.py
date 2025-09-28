from __future__ import annotations

"""quiz モジュールの挙動を検証するテスト。"""

from app_core.categories import load_default_categories, load_quiz_items
from app_core.quiz import QuizEngine
from app_core.rng import seed_from_int


def _build_engine() -> QuizEngine:
    categories = load_default_categories()
    items = load_quiz_items()
    return QuizEngine(categories, items, seed_from_int(1234, sequence=5))


def test_quiz_engine_produces_cue() -> None:
    """next_cue がノイズとターゲットを含むことを確認する。"""
    engine = _build_engine()
    cue = engine.next_cue()
    assert cue.category_id
    assert cue.item_id
    assert cue.target_text
    assert cue.noise_text is not None
    if cue.item_type == "image":
        assert cue.image_file
    else:
        assert cue.image_file is None


def test_quiz_engine_enabled_fallback() -> None:
    """存在しないカテゴリを指定した場合でも全カテゴリへフォールバックする。"""
    engine = _build_engine()
    applied = engine.set_enabled_categories(["unknown"])
    assert applied == engine.enabled_category_ids
    assert applied


def test_quiz_engine_item_count_matches_selection() -> None:
    """count_items が選択カテゴリに紐づく総数を返す。"""
    engine = _build_engine()
    ids = engine.enabled_category_ids[:2]
    total = engine.count_items(ids)
    assert total > 0
    engine.set_enabled_categories(ids)
    assert total == engine.count_items(engine.enabled_category_ids)
