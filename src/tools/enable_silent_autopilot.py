#!/usr/bin/env python3
"""
サイレントオートパイロットモード有効化スクリプト
通知スパム対策を適用し、重要な通知のみを許可
"""

import json
from pathlib import Path


def enable_silent_autopilot():
    """サイレントオートパイロットモードを有効化"""

    # 監視設定の更新
    monitoring_config_path = Path("config/monitoring.json")
    if monitoring_config_path.exists():
        with open(monitoring_config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        # スパム対策設定を更新
        config.setdefault("spam_filter", {})
        config["spam_filter"].update(
            {
                "silent_autopilot_mode": True,
                "todo_write_enabled": False,
                "critical_only_mode": True,
                "max_notifications_per_hour": 5,  # さらに制限
                "duplicate_threshold_hours": 24,
            }
        )

        with open(monitoring_config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print("✓ 監視設定を更新しました")

    # コンソールポリシーの確認
    console_policy_path = Path("ORCH/STATE/CONSOLE_POLICY.md")
    if console_policy_path.exists():
        print("✓ コンソールポリシーが存在します")

    # オートパイロット指示の確認
    autopilot_path = Path("ORCH/STATE/AUTOPILOT_INSTRUCTIONS.md")
    if autopilot_path.exists():
        print("✓ オートパイロット指示が存在します")

    # スパムフィルターの初期化
    try:
        import sys

        sys.path.insert(0, str(Path.cwd()))
        from src.notification_spam_filter import get_spam_filter, set_silent_mode

        # サイレントモードを有効化
        set_silent_mode(True)

        # 統計情報を表示
        spam_filter = get_spam_filter()
        stats = spam_filter.get_statistics()

        print("✓ スパムフィルターを初期化しました")
        print(f"  - サイレントモード: {stats['silent_mode']}")
        print(f"  - 通知履歴: {stats['total_unique_notifications']}件")
        print(f"  - ブロック済み: {stats['total_blocked']}件")

    except ImportError as e:
        print(f"⚠ スパムフィルターの初期化に失敗: {e}")

    print("\n🤖 サイレントオートパイロットモードが有効になりました")
    print("   - 重要な通知（high/critical）のみ表示されます")
    print("   - todo_write通知は無効化されています")
    print("   - 重複通知は24時間ブロックされます")
    print("   - 1時間あたり最大5件の通知に制限されます")


if __name__ == "__main__":
    enable_silent_autopilot()
