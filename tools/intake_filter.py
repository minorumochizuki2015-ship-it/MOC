#!/usr/bin/env python3
"""
SFT Intake Filter - CI Smoke Test Tool
データ取り込み処理のスモークテスト用ツール
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def validate_sft_schema(item: dict) -> bool:
    """SFTスキーマ検証（prompt/output必須、promptは20文字以上）"""
    if not isinstance(item, dict):
        return False
    
    if "prompt" not in item or "output" not in item:
        return False
    
    prompt = str(item["prompt"]).strip()
    output = str(item["output"]).strip()
    
    # promptは20文字以上必須
    if len(prompt) < 20:
        return False
    
    # outputは空でない
    if len(output) == 0:
        return False
    
    return True


def compute_content_hash(prompt: str, output: str) -> str:
    """コンテンツハッシュ計算（prompt + "\n" + output のSHA256）"""
    content = prompt.strip() + "\n" + output.strip()
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def process_intake_directory(data_dir: Path) -> Tuple[int, int, int]:
    """
    データディレクトリを処理し、統計を返す
    Returns: (accepted_count, duplicate_count, error_count)
    """
    accepted_count = 0
    duplicate_count = 0
    error_count = 0
    
    seen_hashes = set()
    
    # JSONファイルを処理
    json_files = list(data_dir.glob("*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # リスト形式の場合は各アイテムを処理
            if isinstance(data, list):
                items = data
            else:
                items = [data]
            
            for item in items:
                if validate_sft_schema(item):
                    # ハッシュ計算
                    content_hash = compute_content_hash(item["prompt"], item["output"])
                    
                    if content_hash in seen_hashes:
                        duplicate_count += 1
                        print(f"DUPLICATE: {json_file.name} (hash: {content_hash[:8]}...)")
                    else:
                        seen_hashes.add(content_hash)
                        accepted_count += 1
                        print(f"ACCEPTED: {json_file.name} (hash: {content_hash[:8]}...)")
                else:
                    error_count += 1
                    print(f"SCHEMA_ERROR: {json_file.name} - invalid prompt/output")
        
        except Exception as e:
            error_count += 1
            print(f"FILE_ERROR: {json_file.name} - {e}")
    
    return accepted_count, duplicate_count, error_count


def main():
    parser = argparse.ArgumentParser(description="SFT Intake Filter - CI Smoke Test")
    parser.add_argument("--data-dir", required=True, help="Data directory to process")
    parser.add_argument("--expect-errors", type=int, default=0, help="Expected error count")
    parser.add_argument("--expect-accepted", type=int, default=1, help="Minimum expected accepted count")
    
    args = parser.parse_args()
    
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"ERROR: Data directory does not exist: {data_dir}")
        sys.exit(1)
    
    print(f"Processing intake directory: {data_dir}")
    
    accepted, duplicates, errors = process_intake_directory(data_dir)
    
    print(f"\n=== RESULTS ===")
    print(f"Accepted: {accepted}")
    print(f"Duplicates: {duplicates}")
    print(f"Errors: {errors}")
    
    # アサーション
    if errors != args.expect_errors:
        print(f"FAIL: Expected {args.expect_errors} errors, got {errors}")
        sys.exit(1)
    
    if accepted < args.expect_accepted:
        print(f"FAIL: Expected at least {args.expect_accepted} accepted, got {accepted}")
        sys.exit(1)
    
    print("PASS: All assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())