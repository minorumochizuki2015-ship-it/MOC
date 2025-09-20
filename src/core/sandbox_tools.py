#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M5: ツールとサンドボックス - 安全なファイル操作と制約
WS外拒否、制御文字除去、4000字上限、タイムアウト
"""

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class SandboxTools:
    """安全なファイル操作ツール（M5）"""
    
    def __init__(self, workspace_root: str = None):
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()
        self.max_file_size = 4000  # 4000字上限
        self.timeout_seconds = 30  # タイムアウト
        self.allowed_extensions = {
            '.py', '.js', '.ts', '.html', '.css', '.json', '.md', '.txt',
            '.yaml', '.yml', '.xml', '.csv', '.sql', '.sh', '.bat', '.ps1'
        }
        
    def list_dir(self, path: str) -> Dict[str, Any]:
        """ディレクトリ一覧取得（WS外拒否）"""
        try:
            # パス検証
            if not self._is_safe_path(path):
                return {"error": "拒否: ワークスペース外のパス", "success": False}
            
            target_path = self.workspace_root / path
            if not target_path.exists():
                return {"error": "パスが存在しません", "success": False}
            
            if not target_path.is_dir():
                return {"error": "ディレクトリではありません", "success": False}
            
            # タイムアウト付きで実行
            start_time = time.time()
            items = []
            
            for item in target_path.iterdir():
                if time.time() - start_time > self.timeout_seconds:
                    return {"error": "タイムアウト", "success": False}
                
                item_info = {
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "extension": item.suffix if item.is_file() else None
                }
                items.append(item_info)
            
            return {
                "success": True,
                "path": str(target_path),
                "items": items,
                "count": len(items)
            }
            
        except Exception as e:
            return {"error": f"エラー: {str(e)}", "success": False}
    
    def read_file(self, path: str) -> Dict[str, Any]:
        """ファイル読み込み（WS外拒否、制御文字除去、4000字上限）"""
        try:
            # パス検証
            if not self._is_safe_path(path):
                return {"error": "拒否: ワークスペース外のパス", "success": False}
            
            target_path = self.workspace_root / path
            if not target_path.exists():
                return {"error": "ファイルが存在しません", "success": False}
            
            if not target_path.is_file():
                return {"error": "ファイルではありません", "success": False}
            
            # ファイルサイズチェック
            file_size = target_path.stat().st_size
            if file_size > self.max_file_size * 4:  # バイト数で概算
                return {"error": f"ファイルが大きすぎます ({file_size} bytes)", "success": False}
            
            # 拡張子チェック
            if target_path.suffix not in self.allowed_extensions:
                return {"error": f"サポートされていないファイル形式: {target_path.suffix}", "success": False}
            
            # タイムアウト付きで読み込み
            start_time = time.time()
            content = target_path.read_text(encoding='utf-8', errors='replace')
            
            if time.time() - start_time > self.timeout_seconds:
                return {"error": "タイムアウト", "success": False}
            
            # 制御文字除去
            content = self._remove_control_chars(content)
            
            # 長さ制限
            if len(content) > self.max_file_size:
                content = content[:self.max_file_size] + "\n... (切り詰められました)"
            
            return {
                "success": True,
                "path": str(target_path),
                "content": content,
                "size": len(content),
                "truncated": len(content) >= self.max_file_size
            }
            
        except Exception as e:
            return {"error": f"エラー: {str(e)}", "success": False}
    
    def _is_safe_path(self, path: str) -> bool:
        """ワークスペース内のパスかチェック"""
        try:
            # パス正規化
            target_path = Path(path).resolve()
            workspace_path = self.workspace_root.resolve()
            
            # ワークスペース内かチェック
            return str(target_path).startswith(str(workspace_path))
        except Exception:
            return False
    
    def _remove_control_chars(self, text: str) -> str:
        """制御文字を除去"""
        # 改行、タブ、復帰以外の制御文字を除去
        control_chars = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
        return control_chars.sub('', text)
    
    def get_workspace_info(self) -> Dict[str, Any]:
        """ワークスペース情報を取得"""
        return {
            "workspace_root": str(self.workspace_root),
            "max_file_size": self.max_file_size,
            "timeout_seconds": self.timeout_seconds,
            "allowed_extensions": list(self.allowed_extensions)
        }


# グローバルインスタンス
sandbox_tools = SandboxTools()
