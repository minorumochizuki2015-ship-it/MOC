#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UI安定化システム
ボタン押下時の画面崩れを防ぐ
"""

import threading
import time
from typing import Any, Callable


class UIStabilizer:
    """UIの安定化を管理するクラス"""

    def __init__(self):
        self._button_locks = {}
        self._update_queue = []
        self._is_processing = False

    def stabilize_button_click(
        self, button_name: str, callback: Callable, *args, **kwargs
    ):
        """ボタンクリックを安定化"""
        if button_name in self._button_locks:
            return  # 既に処理中

        self._button_locks[button_name] = True

        def safe_callback():
            try:
                # UI更新をキューに追加
                self._queue_update(lambda: callback(*args, **kwargs))
            except Exception as e:
                print(f"UI安定化エラー ({button_name}): {e}")
            finally:
                # ロック解除（少し遅延）
                time.sleep(0.1)
                if button_name in self._button_locks:
                    del self._button_locks[button_name]

        # 別スレッドで実行
        thread = threading.Thread(target=safe_callback, daemon=True)
        thread.start()

    def _queue_update(self, update_func: Callable):
        """UI更新をキューに追加"""
        self._update_queue.append(update_func)
        if not self._is_processing:
            self._process_update_queue()

    def _process_update_queue(self):
        """更新キューを処理"""
        if self._is_processing or not self._update_queue:
            return

        self._is_processing = True

        def process():
            try:
                while self._update_queue:
                    update_func = self._update_queue.pop(0)
                    try:
                        update_func()
                    except Exception as e:
                        print(f"UI更新エラー: {e}")
                    time.sleep(0.05)  # 更新間隔
            finally:
                self._is_processing = False

        thread = threading.Thread(target=process, daemon=True)
        thread.start()

    def is_button_locked(self, button_name: str) -> bool:
        """ボタンがロックされているかチェック"""
        return button_name in self._button_locks


# グローバルインスタンス
ui_stabilizer = UIStabilizer()


def stabilize_button(button_name: str):
    """ボタン安定化デコレータ"""

    def decorator(func):
        def wrapper(*args, **kwargs):
            ui_stabilizer.stabilize_button_click(button_name, func, *args, **kwargs)

        return wrapper

    return decorator


def safe_ui_update(update_func: Callable):
    """安全なUI更新"""
    ui_stabilizer._queue_update(update_func)
