from __future__ import annotations

"""アプリ設定の読み書きを提供するモジュール。"""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List


@dataclass(slots=True)
class AppSettings:
    """アプリ全体で共有する設定値。"""

    selected_categories: List[str]


DEFAULT_SETTINGS = AppSettings(selected_categories=[])


class SettingsRepository:
    """設定ファイルの読み書きを司る。"""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> AppSettings:
        """設定ファイルを読み込む。存在しない場合は既定値を返す。"""

        if not self._path.exists():
            return DEFAULT_SETTINGS
        try:
            data = self._path.read_text(encoding="utf-8")
        except OSError:
            return DEFAULT_SETTINGS
        import json

        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            return DEFAULT_SETTINGS
        selected = payload.get("selected_categories", [])
        if not isinstance(selected, list):
            selected = []
        selected_str = [str(value) for value in selected]
        return AppSettings(selected_categories=selected_str)

    def save(self, settings: AppSettings) -> None:
        """設定をJSONとして保存する。"""

        import json

        payload = json.dumps(asdict(settings), ensure_ascii=False, indent=2)
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_path.write_text(payload + "\n", encoding="utf-8")
        tmp_path.replace(self._path)
