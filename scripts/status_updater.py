#!/usr/bin/env python3
"""
ORCH-Next Status Updater
状態更新自動化スクリプト

このスクリプトは以下の機能を提供します:
- タスク状態の自動更新
- ロック管理（TTL付き）
- ハートビート機能
- 承認ゲートとの連携
"""

import atexit
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional


# ログ設定（ディレクトリ作成後に設定）
def setup_logging(workspace_root: Path):
    """ログ設定をセットアップ"""
    log_dir = workspace_root / "data" / "logs" / "current"
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "status_updater.log"),
            logging.StreamHandler(),
        ],
    )
    # プロセス終了時にロギングを安全にシャットダウン（ハンドラのクローズを保証）
    atexit.register(logging.shutdown)
    return logging.getLogger(__name__)


class TaskState(Enum):
    """タスク状態の定義"""

    PLAN = "PLAN"
    READY = "READY"
    DOING = "DOING"
    REVIEW = "REVIEW"
    FIX = "FIX"
    DONE = "DONE"
    HOLD = "HOLD"
    DROP = "DROP"


class Owner(Enum):
    """所有者の定義"""

    CMD = "CMD"
    WORK = "WORK"
    AUDIT = "AUDIT"


@dataclass
class Task:
    """タスク情報"""

    id: str
    title: str
    state: TaskState
    owner: Owner
    due: str
    acceptance: List[str]
    lock: str = "-"
    lock_owner: str = "-"
    lock_expires_at: str = "-"
    notes: str = ""


class StatusUpdater:
    """状態更新管理クラス"""

    def __init__(self, workspace_root: str = "C:\\Users\\User\\Trae\\ORCH-Next"):
        self.workspace_root = Path(workspace_root)
        self.tasks_file = self.workspace_root / "ORCH" / "STATE" / "TASKS.md"
        self.approvals_file = self.workspace_root / "ORCH" / "STATE" / "APPROVALS.md"
        self.lock_dir = self.workspace_root / "data" / "locks"

        # ディレクトリ作成
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace_root / "data" / "logs" / "current").mkdir(parents=True, exist_ok=True)
        (self.workspace_root / "ORCH" / "STATE").mkdir(parents=True, exist_ok=True)

        # ログ設定
        self.logger = setup_logging(self.workspace_root)

    def get_utc_timestamp(self) -> str:
        """UTC タイムスタンプを取得"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """タイムスタンプ文字列をパース"""
        if timestamp_str == "-":
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def is_lock_expired(self, expires_at: str, grace_minutes: int = 5) -> bool:
        """ロックが期限切れかチェック（猶予時間付き）"""
        if expires_at == "-":
            return True

        expire_time = self.parse_timestamp(expires_at)
        if not expire_time:
            return True

        now = datetime.now(timezone.utc)
        grace_time = expire_time + timedelta(minutes=grace_minutes)
        return now > grace_time

    def acquire_lock(self, task_id: str, owner: Owner, ttl_minutes: int = 30) -> bool:
        """タスクロックを取得"""
        try:
            now_utc = datetime.now(timezone.utc)
            expires_at = now_utc + timedelta(minutes=ttl_minutes)

            lock_info = {
                "task_id": task_id,
                "owner": owner.value,
                "acquired_at": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "pid": os.getpid(),
            }

            lock_file = self.lock_dir / f"task_{task_id}.lock"

            # 既存ロックのチェック
            if lock_file.exists():
                try:
                    with open(lock_file, "r", encoding="utf-8") as f:
                        existing_lock = json.load(f)

                    if not self.is_lock_expired(existing_lock.get("expires_at", "-")):
                        self.logger.warning(
                            f"Task {task_id} is already locked by {existing_lock.get('owner')}"
                        )
                        return False
                except (json.JSONDecodeError, KeyError):
                    self.logger.warning(f"Invalid lock file for task {task_id}, removing")
                    lock_file.unlink()

            # ロック取得
            with open(lock_file, "w", encoding="utf-8") as f:
                json.dump(lock_info, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Lock acquired for task {task_id} by {owner.value}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to acquire lock for task {task_id}: {e}")
            return False

    def release_lock(self, task_id: str) -> bool:
        """タスクロックを解放"""
        try:
            lock_file = self.lock_dir / f"task_{task_id}.lock"
            if lock_file.exists():
                lock_file.unlink()
                self.logger.info(f"Lock released for task {task_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to release lock for task {task_id}: {e}")
            return False

    def extend_lock(self, task_id: str, ttl_minutes: int = 30) -> bool:
        """ロックのTTLを延長（ハートビート）"""
        try:
            lock_file = self.lock_dir / f"task_{task_id}.lock"
            if not lock_file.exists():
                self.logger.warning(f"No lock file found for task {task_id}")
                return False

            with open(lock_file, "r", encoding="utf-8") as f:
                lock_info = json.load(f)

            # TTL延長
            now_utc = datetime.now(timezone.utc)
            expires_at = now_utc + timedelta(minutes=ttl_minutes)
            lock_info["expires_at"] = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            lock_info["last_heartbeat"] = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

            with open(lock_file, "w", encoding="utf-8") as f:
                json.dump(lock_info, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Lock extended for task {task_id} until {lock_info['expires_at']}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to extend lock for task {task_id}: {e}")
            return False

    def update_task_state(
        self, task_id: str, new_state: TaskState, owner: Owner, notes: str = ""
    ) -> bool:
        """タスク状態を更新"""
        try:
            # DOING状態への遷移時はロック取得
            if new_state == TaskState.DOING:
                if not self.acquire_lock(task_id, owner):
                    return False

            # HOLD状態への遷移時はロック解放
            elif new_state == TaskState.HOLD:
                self.release_lock(task_id)

            # TASKS.mdファイルの更新（実際の実装では適切なファイル操作を行う）
            self.logger.info(f"Task {task_id} state updated: {new_state.value} by {owner.value}")
            if notes:
                self.logger.info(f"Notes: {notes}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to update task {task_id} state: {e}")
            return False

    def cleanup_expired_locks(self) -> int:
        """期限切れロックのクリーンアップ"""
        cleaned_count = 0
        try:
            for lock_file in self.lock_dir.glob("task_*.lock"):
                try:
                    with open(lock_file, "r", encoding="utf-8") as f:
                        lock_info = json.load(f)

                    if self.is_lock_expired(lock_info.get("expires_at", "-")):
                        lock_file.unlink()
                        self.logger.info(f"Cleaned expired lock: {lock_file.name}")
                        cleaned_count += 1

                except (json.JSONDecodeError, KeyError):
                    lock_file.unlink()
                    self.logger.info(f"Cleaned invalid lock file: {lock_file.name}")
                    cleaned_count += 1

        except Exception as e:
            self.logger.error(f"Error during lock cleanup: {e}")

        return cleaned_count

    def heartbeat_loop(self, task_id: str, interval_minutes: int = 10):
        """ハートビートループ（別スレッドで実行）"""
        self.logger.info(f"Starting heartbeat loop for task {task_id}")

        try:
            while True:
                time.sleep(interval_minutes * 60)
                if not self.extend_lock(task_id):
                    self.logger.error(
                        f"Failed to extend lock for task {task_id}, stopping heartbeat"
                    )
                    break

        except KeyboardInterrupt:
            self.logger.info(f"Heartbeat loop interrupted for task {task_id}")
        except Exception as e:
            self.logger.error(f"Error in heartbeat loop for task {task_id}: {e}")
        finally:
            self.release_lock(task_id)


def main():
    """メイン関数"""
    if len(sys.argv) < 2:
        print("Usage: python status_updater.py <command> [args...]")
        print("Commands:")
        print("  acquire <task_id> <owner>     - Acquire lock for task")
        print("  release <task_id>             - Release lock for task")
        print("  extend <task_id>              - Extend lock TTL")
        print("  cleanup                       - Clean expired locks")
        print("  heartbeat <task_id>           - Start heartbeat loop")
        print("  update <task_id> <state> <owner> [notes] - Update task state")
        sys.exit(1)

    updater = StatusUpdater()
    command = sys.argv[1].lower()

    try:
        if command == "acquire":
            task_id = sys.argv[2]
            owner = Owner(sys.argv[3])
            success = updater.acquire_lock(task_id, owner)
            sys.exit(0 if success else 1)

        elif command == "release":
            task_id = sys.argv[2]
            success = updater.release_lock(task_id)
            sys.exit(0 if success else 1)

        elif command == "extend":
            task_id = sys.argv[2]
            success = updater.extend_lock(task_id)
            sys.exit(0 if success else 1)

        elif command == "cleanup":
            count = updater.cleanup_expired_locks()
            print(f"Cleaned {count} expired locks")
            sys.exit(0)

        elif command == "heartbeat":
            task_id = sys.argv[2]
            updater.heartbeat_loop(task_id)
            sys.exit(0)

        elif command == "update":
            task_id = sys.argv[2]
            state = TaskState(sys.argv[3])
            owner = Owner(sys.argv[4])
            notes = sys.argv[5] if len(sys.argv) > 5 else ""
            success = updater.update_task_state(task_id, state, owner, notes)
            sys.exit(0 if success else 1)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except (IndexError, ValueError) as e:
        print(f"Invalid arguments: {e}")
        sys.exit(1)
    except Exception as e:
        updater.logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        # 明示的に FileHandler をクローズしてリソースリークを防止
        try:
            root_logger = logging.getLogger()
            for h in list(root_logger.handlers):
                if isinstance(h, logging.FileHandler):
                    h.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
