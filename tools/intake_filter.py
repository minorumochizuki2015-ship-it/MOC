"""
学習インテーク・フィルタ
inbox→queue/accepted/rejected、重複/機微除去、バケット追記
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intake_service.classifier import classify_domain
from app.intake_service.schema import IntakeItem, create_sft_item


def _val(x: Any) -> Any:
    """Enum/str両対応の値取得"""
    return getattr(x, "value", x)

def _norm_enum(x: Any) -> str:
    """Enum/str両対応の正規化"""
    return _val(x)


class IntakeFilter:
    """学習インテーク・フィルタ"""
    
    def __init__(self, data_dir: str = "data/intake") -> None:
        """フィルタの初期化"""
        self.data_dir = Path(data_dir)
        self.inbox_dir = self.data_dir / "inbox"
        self.queue_dir = self.data_dir / "queue"
        self.accepted_dir = self.data_dir / "accepted"
        self.rejected_dir = self.data_dir / "rejected"
        self.buckets_dir = self.data_dir / "buckets"
        self.index_file = self.data_dir / "index.jsonl"
        
        # ディレクトリ作成
        for dir_path in [self.queue_dir, self.accepted_dir, self.rejected_dir, self.buckets_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # 重複チェック用ハッシュセット
        self.duplicate_hashes: Set[str] = set()
        self._load_duplicate_hashes()
        
        # 機微情報パターン
        self.pii_patterns = [
            r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',  # クレジットカード番号
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # メールアドレス
            r'\b\d{3}-\d{3}-\d{4}\b',  # 電話番号
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IPアドレス
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # メールアドレス
        ]
    
    def _load_duplicate_hashes(self) -> None:
        """既存の重複ハッシュを読み込み"""
        if self.index_file.exists():
            with open(self.index_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if "hash" in entry:
                            self.duplicate_hashes.add(entry["hash"])
                    except json.JSONDecodeError:
                        continue
    
    def _calculate_content_hash(self, prompt: str, output: str) -> str:
        """コンテンツのハッシュを計算"""
        content = f"{prompt}|{output}".encode("utf-8")
        return hashlib.sha1(content).hexdigest()
    
    def _check_pii(self, text: str) -> bool:
        """機微情報の検出"""
        for pattern in self.pii_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _validate_item(self, item: IntakeItem) -> Tuple[bool, str]:
        """アイテムの検証"""
        # 必須キー検査
        if not item.prompt or not item.output:
            return False, "プロンプトまたは出力が空です"
        
        # サイズ検査
        if len(item.prompt) > 10000 or len(item.output) > 10000:
            return False, "コンテンツが長すぎます（10KB制限）"
        
        # 機微情報検査
        if _norm_enum(item.privacy) == "no_pii":
            if self._check_pii(item.prompt) or self._check_pii(item.output):
                return False, "機微情報が検出されました"
        
        # 重複検査
        content_hash = self._calculate_content_hash(item.prompt, item.output)
        if content_hash in self.duplicate_hashes:
            return False, "重複するコンテンツです"
        
        return True, "OK"
    
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
    
    def _update_bucket(self, item: IntakeItem) -> None:
        """バケットファイルに追記"""
        bucket_dir = self.buckets_dir / _norm_enum(item.domain)
        bucket_dir.mkdir(exist_ok=True)
        
        # 日付別ファイル
        date_str = item.ts.strftime("%Y%m%d")
        bucket_file = bucket_dir / f"{date_str}.jsonl"
        
        # SFT形式で追記
        sft_item = create_sft_item(item)
        
        with open(bucket_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(sft_item, ensure_ascii=False) + "\n")
    
    def _update_index(self, item: IntakeItem, status: str, reason: str = "") -> None:
        """インデックスファイルに追記"""
        content_hash = self._calculate_content_hash(item.prompt, item.output)
        
        index_entry = {
            "id": item.id,
            "ts": item.ts.isoformat(),
            "status": status,
            "domain": _norm_enum(item.domain),
            "title": item.title,
            "source": _norm_enum(item.source),
            "hash": content_hash,
            "reason": reason
        }
        
        with open(self.index_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(index_entry, ensure_ascii=False) + "\n")
        
        # 重複ハッシュに追加
        self.duplicate_hashes.add(content_hash)
    
    def process_inbox(self, dry_run: bool = False) -> Dict[str, int]:
        """inboxディレクトリを処理"""
        stats = {"processed": 0, "accepted": 0, "rejected": 0, "errors": 0}
        
        if not self.inbox_dir.exists():
            return stats
        
        # inbox内のファイルを処理
        for filepath in self.inbox_dir.glob("*.json"):
            try:
                # アイテム読み込み
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    item = IntakeItem(**data)
                
                # ドメインが未設定の場合は自動推定
                if _norm_enum(item.domain) == "unknown":
                    item.domain = classify_domain(
                        item.title,
                        item.prompt,
                        item.output,
                        item.refs
                    )
                
                # 検証
                is_valid, reason = self._validate_item(item)
                
                if is_valid:
                    if not dry_run:
                        # 承認: queue→accepted
                        self._move_item(item, self.inbox_dir, self.accepted_dir)
                        self._update_bucket(item)
                        self._update_index(item, "accepted")
                    stats["accepted"] += 1
                else:
                    if not dry_run:
                        # 拒否: inbox→rejected
                        self._move_item(item, self.inbox_dir, self.rejected_dir)
                        self._update_index(item, "rejected", reason)
                    stats["rejected"] += 1
                
                stats["processed"] += 1
                
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
                stats["errors"] += 1
                continue
        
        return stats
    
    def process_queue(self, dry_run: bool = False) -> Dict[str, int]:
        """queueディレクトリを処理（手動承認待ち）"""
        stats = {"processed": 0, "accepted": 0, "rejected": 0, "errors": 0}
        
        if not self.queue_dir.exists():
            return stats
        
        # queue内のファイルを処理
        for filepath in self.queue_dir.glob("*.json"):
            try:
                # アイテム読み込み
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    item = IntakeItem(**data)
                
                # 検証
                is_valid, reason = self._validate_item(item)
                
                if is_valid:
                    if not dry_run:
                        # 承認: queue→accepted
                        self._move_item(item, self.queue_dir, self.accepted_dir)
                        self._update_bucket(item)
                        self._update_index(item, "accepted")
                    stats["accepted"] += 1
                else:
                    if not dry_run:
                        # 拒否: queue→rejected
                        self._move_item(item, self.queue_dir, self.rejected_dir)
                        self._update_index(item, "rejected", reason)
                    stats["rejected"] += 1
                
                stats["processed"] += 1
                
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
                stats["errors"] += 1
                continue
        
        return stats


def main() -> int:
    """メイン関数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="学習インテーク・フィルタ")
    parser.add_argument("--data-dir", default="data/intake", help="データディレクトリ")
    parser.add_argument("--dry-run", action="store_true", help="ドライラン（実際の処理は行わない）")
    parser.add_argument("--queue-only", action="store_true", help="queueディレクトリのみ処理")
    args = parser.parse_args()
    
    try:
        filter_obj = IntakeFilter(args.data_dir)
        
        if args.queue_only:
            stats = filter_obj.process_queue(args.dry_run)
            print(f"Queue処理: {stats}")
        else:
            stats = filter_obj.process_inbox(args.dry_run)
            print(f"Inbox処理: {stats}")
        
        # 成功時は0、エラー時は1
        return 0 if stats["errors"] == 0 else 1
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

