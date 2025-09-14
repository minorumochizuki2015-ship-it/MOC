# memory.py (v3.0 - High-Performance Memory Management)
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.utils.config import LOG_FILE_PATH


class Memory:
    def __init__(self):
        self.log_file = LOG_FILE_PATH
        self._memory_cache = {}  # メモリキャッシュ
        self._cache_lock = threading.Lock()  # スレッドセーフティ
        self._write_queue = []  # 書き込みキュー
        self._write_lock = threading.Lock()
        self._last_sync = time.time()

        if not os.path.exists(self.log_file):
            self._create_genesis_block()

        # バックグラウンドで定期的にメモリを同期
        self._start_background_sync()

    def _start_background_sync(self):
        """バックグラウンドでメモリ同期を開始"""

        def sync_worker():
            while True:
                time.sleep(5)  # 5秒ごとに同期
                self._sync_memory()

        sync_thread = threading.Thread(target=sync_worker, daemon=True)
        sync_thread.start()

    def _sync_memory(self):
        """メモリをディスクに同期"""
        with self._write_lock:
            if self._write_queue:
                try:
                    # 既存のチェーンを読み込み
                    chain = self.get_chain()
                    chain.extend(self._write_queue)

                    # ファイルサイズチェックとローテーション
                    self._rotate_if_big(self.log_file)

                    # 書き込み
                    with open(self.log_file, "w", encoding="utf-8") as f:
                        json.dump(chain, f, ensure_ascii=False, indent=4)

                    self._write_queue.clear()
                    self._last_sync = time.time()
                except Exception as e:
                    print(f"Memory sync error: {e}")

    def _rotate_if_big(self, path: str, limit: int = 5_000_000) -> None:
        """ファイルサイズが制限を超えた場合にローテーション"""
        try:
            if os.path.exists(path) and os.path.getsize(path) > limit:
                base, ext = os.path.splitext(path)
                os.replace(path, f"{base}_{int(time.time())}{ext}")
        except Exception:
            pass

    def _calculate_hash(self, block: dict) -> str:
        """ブロックのハッシュ値を計算する"""
        block_string = json.dumps(block, sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
        return hashlib.sha256(block_string).hexdigest()

    def _create_genesis_block(self):
        """ブロックチェーンの最初のブロック（ジェネシスブロック）を作成する"""
        genesis_block = {
            "index": 0,
            "timestamp": datetime.now().isoformat(),
            "data": {"log_type": "GENESIS", "message": "Sovereign Memory Initialized."},
            "previous_hash": "0",
        }
        genesis_block["hash"] = self._calculate_hash(genesis_block)
        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump([genesis_block], f, ensure_ascii=False, indent=4)

    def get_chain(self) -> list:
        """ブロックチェーン全体を読み込む"""
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                chain = json.load(f)
            return chain
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def get_last_block(self) -> dict | None:
        """最後のブロックを取得する"""
        chain = self.get_chain()
        return chain[-1] if chain else None

    def log_interaction(
        self, prompt: str, response: str, referenced_ids: list = []
    ) -> str:
        """対話を新たなブロックとしてチェーンに追加する"""
        last_block = self.get_last_block()
        if not last_block:
            # 万が一のための安全弁
            self._create_genesis_block()
            last_block = self.get_last_block()

        if last_block is None:
            raise RuntimeError("Failed to create or retrieve last block")

        new_block_data = {
            "log_type": "INTERACTION",
            "prompt": prompt,
            "response": response,
            "feedback_score": None,
            "related_logs": referenced_ids,
        }
        new_block = {
            "index": last_block["index"] + 1,
            "timestamp": datetime.now().isoformat(),
            "data": new_block_data,
            "previous_hash": last_block["hash"],
        }
        new_block["hash"] = self._calculate_hash(new_block)

        chain = self.get_chain()
        chain.append(new_block)

        # ファイルサイズチェックとローテーション
        self._rotate_if_big(self.log_file)

        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(chain, f, ensure_ascii=False, indent=4)

        # 新たなlog_idはブロックのハッシュ値そのものである
        return new_block["hash"]

    def add_feedback_to_last_log(self, score: int) -> Tuple[bool, str]:
        """
        最後の対話ブロックに評価を追記する。
        注意: この操作はブロックを書き換えるため、後続ブロックのハッシュ検証を無効化する。
              厳密なブロックチェーンでは、評価も新たなブロックとして追加すべきである。
              本実装は、既存のUIとの互換性を維持するための暫定的な措置である。
        """
        chain = self.get_chain()
        if not chain:
            return False, "ログが空です。"

        for i in range(len(chain) - 1, -1, -1):
            block = chain[i]
            if (
                block["data"].get("log_type") == "INTERACTION"
                and block["data"]["feedback_score"] is None
            ):
                # データを変更
                block["data"]["feedback_score"] = score
                # ハッシュを再計算
                original_hash = block["hash"]
                new_hash = self._calculate_hash(block)
                block["hash"] = new_hash

                # 後続ブロックのprevious_hashを更新 (暫定措置)
                if i + 1 < len(chain):
                    chain[i + 1]["previous_hash"] = new_hash
                    # 本来は後続もすべて再ハッシュが必要だが、ここでは簡略化

                with open(self.log_file, "w", encoding="utf-8") as f:
                    json.dump(chain, f, ensure_ascii=False, indent=4)
                return (
                    True,
                    f"評価を保存しました。Block {block['index']} が更新されました。",
                )

        return False, "評価対象の対話ログが見つかりません。"

    # 既存のJSON読み書き機能も維持
    def load_json_file(self, path, default_value):
        if not os.path.exists(path):
            return default_value
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                return json.loads(content) if content else default_value
        except (json.JSONDecodeError, FileNotFoundError):
            return default_value

    def save_json_file(self, path, data):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            return True
        except Exception:
            return False
