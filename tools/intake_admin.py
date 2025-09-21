"""
学習インテーク・管理CLI
list/approve/reject/edit/delete機能
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intake_service.schema import (
    DomainType,
    IntakeItem,
    IntakeItemUpdate,
    PrivacyLevel,
    SourceType,
    TaskType,
)


class IntakeAdmin:
    """学習インテーク・管理CLI"""
    
    def __init__(self, data_dir: str = "data/intake") -> None:
        """管理CLIの初期化"""
        self.data_dir = Path(data_dir)
        self.inbox_dir = self.data_dir / "inbox"
        self.queue_dir = self.data_dir / "queue"
        self.accepted_dir = self.data_dir / "accepted"
        self.rejected_dir = self.data_dir / "rejected"
        self.index_file = self.data_dir / "index.jsonl"
    
    def _find_item_file(self, item_id: str, directories: List[Path]) -> Optional[Path]:
        """アイテムファイルを検索"""
        for directory in directories:
            for filepath in directory.glob(f"*_{item_id}.json"):
                return filepath
        return None
    
    def _load_item(self, item_id: str, directories: List[Path]) -> tuple[IntakeItem, Path]:
        """アイテムを読み込み"""
        filepath = self._find_item_file(item_id, directories)
        if not filepath:
            raise FileNotFoundError(f"アイテムが見つかりません: {item_id}")
        
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            item = IntakeItem(**data)
        
        return item, filepath
    
    def _save_item(self, item: IntakeItem, filepath: Path) -> None:
        """アイテムを保存"""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(item.dict(), f, ensure_ascii=False, indent=2, default=str)
    
    def _move_item(self, item: IntakeItem, from_dir: Path, to_dir: Path) -> str:
        """アイテムを移動"""
        # ファイルを検索
        source_file = None
        for filepath in from_dir.glob(f"*_{item.id}.json"):
            source_file = filepath
            break
        
        if not source_file:
            raise FileNotFoundError(f"アイテムファイルが見つかりません: {item.id}")
        
        # 移動先ファイル名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_file = to_dir / f"{timestamp}_{item.id}.json"
        
        # ファイル移動
        source_file.rename(dest_file)
        
        return str(dest_file)
    
    def _update_index(self, item: IntakeItem, status: str) -> None:
        """インデックスファイルに追記"""
        index_entry = {
            "id": item.id,
            "ts": item.ts.isoformat(),
            "status": status,
            "domain": item.domain.value,
            "title": item.title,
            "source": item.source.value
        }
        
        with open(self.index_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(index_entry, ensure_ascii=False) + "\n")
    
    def list_items(self, status: Optional[str] = None) -> List[Dict]:
        """アイテム一覧を取得"""
        items = []
        
        # 対象ディレクトリを決定
        if status == "inbox":
            directories = [self.inbox_dir]
        elif status == "queue":
            directories = [self.queue_dir]
        elif status == "accepted":
            directories = [self.accepted_dir]
        elif status == "rejected":
            directories = [self.rejected_dir]
        else:
            directories = [self.inbox_dir, self.queue_dir, self.accepted_dir, self.rejected_dir]
        
        # アイテムを読み込み
        for directory in directories:
            if not directory.exists():
                continue
            
            for filepath in directory.glob("*.json"):
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        item = IntakeItem(**data)
                        
                        # ステータスを決定
                        if directory == self.inbox_dir:
                            item_status = "inbox"
                        elif directory == self.queue_dir:
                            item_status = "queue"
                        elif directory == self.accepted_dir:
                            item_status = "accepted"
                        elif directory == self.rejected_dir:
                            item_status = "rejected"
                        else:
                            item_status = "unknown"
                        
                        items.append({
                            "id": item.id,
                            "ts": item.ts.isoformat(),
                            "status": item_status,
                            "source": item.source.value,
                            "title": item.title,
                            "domain": item.domain.value,
                            "task_type": item.task_type.value,
                            "success": item.success,
                            "privacy": item.privacy.value,
                            "tags": item.tags,
                            "filepath": str(filepath)
                        })
                
                except Exception as e:
                    print(f"Warning: Failed to load {filepath}: {e}")
                    continue
        
        # タイムスタンプでソート（新しい順）
        items.sort(key=lambda x: x["ts"], reverse=True)
        return items
    
    def approve_item(self, item_id: str) -> str:
        """アイテムを承認"""
        # アイテム読み込み
        item, filepath = self._load_item(item_id, [self.queue_dir])
        
        # 移動
        dest_path = self._move_item(item, self.queue_dir, self.accepted_dir)
        
        # インデックス更新
        self._update_index(item, "accepted")
        
        return dest_path
    
    def reject_item(self, item_id: str) -> str:
        """アイテムを拒否"""
        # アイテム読み込み
        item, filepath = self._load_item(item_id, [self.queue_dir])
        
        # 移動
        dest_path = self._move_item(item, self.queue_dir, self.rejected_dir)
        
        # インデックス更新
        self._update_index(item, "rejected")
        
        return dest_path
    
    def edit_item(self, item_id: str, updates: Dict) -> str:
        """アイテムを編集"""
        # アイテム読み込み
        item, filepath = self._load_item(item_id, [self.queue_dir])
        
        # 更新データを適用
        for key, value in updates.items():
            if hasattr(item, key) and value is not None:
                setattr(item, key, value)
        
        # ファイル保存
        self._save_item(item, filepath)
        
        return str(filepath)
    
    def delete_item(self, item_id: str) -> bool:
        """アイテムを削除"""
        # アイテムファイルを検索
        filepath = self._find_item_file(item_id, [self.inbox_dir, self.queue_dir, self.accepted_dir, self.rejected_dir])
        
        if not filepath:
            return False
        
        # ファイル削除
        filepath.unlink()
        
        return True


def main() -> int:
    """メイン関数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="学習インテーク・管理CLI")
    parser.add_argument("--data-dir", default="data/intake", help="データディレクトリ")
    
    subparsers = parser.add_subparsers(dest="command", help="利用可能なコマンド")
    
    # list コマンド
    list_parser = subparsers.add_parser("list", help="アイテム一覧表示")
    list_parser.add_argument("--status", choices=["inbox", "queue", "accepted", "rejected"], help="ステータスでフィルタ")
    list_parser.add_argument("--format", choices=["table", "json"], default="table", help="出力形式")
    
    # approve コマンド
    approve_parser = subparsers.add_parser("approve", help="アイテム承認")
    approve_parser.add_argument("--id", required=True, help="アイテムID")
    
    # reject コマンド
    reject_parser = subparsers.add_parser("reject", help="アイテム拒否")
    reject_parser.add_argument("--id", required=True, help="アイテムID")
    
    # edit コマンド
    edit_parser = subparsers.add_parser("edit", help="アイテム編集")
    edit_parser.add_argument("--id", required=True, help="アイテムID")
    edit_parser.add_argument("--title", help="タイトル")
    edit_parser.add_argument("--domain", choices=[d.value for d in DomainType], help="ドメイン")
    edit_parser.add_argument("--task-type", choices=[t.value for t in TaskType], help="タスク種別")
    edit_parser.add_argument("--success", type=bool, help="成功フラグ")
    edit_parser.add_argument("--privacy", choices=[p.value for p in PrivacyLevel], help="プライバシーレベル")
    
    # delete コマンド
    delete_parser = subparsers.add_parser("delete", help="アイテム削除")
    delete_parser.add_argument("--id", required=True, help="アイテムID")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        admin = IntakeAdmin(args.data_dir)
        
        if args.command == "list":
            items = admin.list_items(args.status)
            
            if args.format == "json":
                print(json.dumps(items, ensure_ascii=False, indent=2))
            else:
                # テーブル形式で表示
                if not items:
                    print("アイテムが見つかりません")
                    return 0
                
                print(f"{'ID':<20} {'Status':<10} {'Source':<8} {'Title':<30} {'Domain':<8} {'Success':<7}")
                print("-" * 100)
                
                for item in items:
                    print(f"{item['id']:<20} {item['status']:<10} {item['source']:<8} {item['title'][:30]:<30} {item['domain']:<8} {item['success']:<7}")
        
        elif args.command == "approve":
            dest_path = admin.approve_item(args.id)
            print(f"アイテムが承認されました: {dest_path}")
        
        elif args.command == "reject":
            dest_path = admin.reject_item(args.id)
            print(f"アイテムが拒否されました: {dest_path}")
        
        elif args.command == "edit":
            updates = {}
            if args.title is not None:
                updates["title"] = args.title
            if args.domain is not None:
                updates["domain"] = DomainType(args.domain)
            if args.task_type is not None:
                updates["task_type"] = TaskType(args.task_type)
            if args.success is not None:
                updates["success"] = args.success
            if args.privacy is not None:
                updates["privacy"] = PrivacyLevel(args.privacy)
            
            if not updates:
                print("更新する項目が指定されていません")
                return 1
            
            filepath = admin.edit_item(args.id, updates)
            print(f"アイテムが更新されました: {filepath}")
        
        elif args.command == "delete":
            success = admin.delete_item(args.id)
            if success:
                print(f"アイテムが削除されました: {args.id}")
            else:
                print(f"アイテムが見つかりません: {args.id}")
                return 1
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

