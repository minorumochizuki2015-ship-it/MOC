# file_manager.py
# 統治核AI - ローカルファイル読み込み・管理システム

import hashlib
import json
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class FileManager:
    """ローカルファイルの読み込み・管理・分析を行うクラス"""

    def __init__(self, workspace_root: str = None):
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()
        self.file_cache: Dict[str, Dict[str, Any]] = {}
        self.file_metadata: Dict[str, Dict[str, Any]] = {}
        self.supported_extensions = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".html",
            ".css",
            ".scss",
            ".json",
            ".xml",
            ".yaml",
            ".yml",
            ".md",
            ".txt",
            ".csv",
            ".sql",
            ".sh",
            ".bat",
            ".ps1",
            ".cpp",
            ".c",
            ".h",
            ".hpp",
            ".java",
            ".go",
            ".rs",
            ".php",
            ".rb",
            ".swift",
            ".kt",
            ".scala",
            ".r",
            ".m",
            ".pl",
            ".lua",
        }

    def read_file(
        self, file_path: Union[str, Path], encoding: str = "utf-8"
    ) -> Dict[str, Any]:
        """ファイルを読み込み、メタデータと共に返す"""
        file_path = Path(file_path)

        # 絶対パスに変換
        if not file_path.is_absolute():
            file_path = self.workspace_root / file_path

        try:
            # ファイル存在確認
            if not file_path.exists():
                return {
                    "success": False,
                    "error": f"File not found: {file_path}",
                    "content": None,
                    "metadata": None,
                }

            # ファイルサイズ確認
            file_size = file_path.stat().st_size
            if file_size > 10 * 1024 * 1024:  # 10MB制限
                return {
                    "success": False,
                    "error": f"File too large: {file_size} bytes",
                    "content": None,
                    "metadata": None,
                }

            # ファイル読み込み
            with open(file_path, "r", encoding=encoding) as f:
                content = f.read()

            # メタデータ生成
            metadata = self._generate_metadata(file_path, content)

            # キャッシュに保存
            cache_key = str(file_path)
            self.file_cache[cache_key] = {
                "content": content,
                "metadata": metadata,
                "timestamp": time.time(),
            }

            return {
                "success": True,
                "content": content,
                "metadata": metadata,
                "file_path": str(file_path),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "content": None,
                "metadata": None,
            }

    def _generate_metadata(self, file_path: Path, content: str) -> Dict[str, Any]:
        """ファイルのメタデータを生成"""
        stat = file_path.stat()

        # ファイルタイプ判定
        mime_type, _ = mimetypes.guess_type(str(file_path))
        file_type = self._determine_file_type(file_path.suffix, content)

        # コード解析
        code_analysis = self._analyze_code(content, file_path.suffix)

        return {
            "name": file_path.name,
            "path": str(file_path),
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "extension": file_path.suffix,
            "mime_type": mime_type,
            "file_type": file_type,
            "line_count": len(content.splitlines()),
            "char_count": len(content),
            "hash": hashlib.md5(content.encode()).hexdigest(),
            "code_analysis": code_analysis,
        }

    def _determine_file_type(self, extension: str, content: str) -> str:
        """ファイルタイプを判定"""
        if extension in [".py"]:
            return "python"
        elif extension in [".js", ".jsx"]:
            return "javascript"
        elif extension in [".ts", ".tsx"]:
            return "typescript"
        elif extension in [".html"]:
            return "html"
        elif extension in [".css", ".scss"]:
            return "css"
        elif extension in [".json"]:
            return "json"
        elif extension in [".md"]:
            return "markdown"
        elif extension in [".yaml", ".yml"]:
            return "yaml"
        else:
            return "text"

    def _analyze_code(self, content: str, extension: str) -> Dict[str, Any]:
        """コードの構造を解析"""
        analysis: Dict[str, Any] = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": [],
            "complexity": 0,
        }

        lines = content.splitlines()

        # 言語別解析
        if extension == ".py":
            analysis = self._analyze_python_code(content)
        elif extension in [".js", ".ts", ".jsx", ".tsx"]:
            analysis = self._analyze_javascript_code(content)
        elif extension == ".json":
            analysis = self._analyze_json_code(content)

        return analysis

    def _analyze_python_code(self, content: str) -> Dict[str, Any]:
        """Pythonコードの解析"""
        import re

        analysis: Dict[str, Any] = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": [],
            "complexity": 0,
        }

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # 関数定義
            func_match = re.match(r"def\s+(\w+)\s*\(", line)
            if func_match:
                analysis["functions"].append(
                    {"name": func_match.group(1), "line": i, "signature": line}
                )

            # クラス定義
            class_match = re.match(r"class\s+(\w+)", line)
            if class_match:
                analysis["classes"].append(
                    {"name": class_match.group(1), "line": i, "signature": line}
                )

            # インポート文
            import_match = re.match(r"(import|from)\s+", line)
            if import_match:
                analysis["imports"].append({"line": i, "statement": line})

            # コメント
            if line.startswith("#"):
                analysis["comments"].append({"line": i, "content": line})

        # 複雑度計算（簡易版）
        analysis["complexity"] = (
            len(analysis["functions"]) + len(analysis["classes"]) * 2
        )

        return analysis

    def _analyze_javascript_code(self, content: str) -> Dict[str, Any]:
        """JavaScript/TypeScriptコードの解析"""
        import re

        analysis: Dict[str, Any] = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": [],
            "complexity": 0,
        }

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # 関数定義
            func_patterns = [
                r"function\s+(\w+)\s*\(",
                r"(\w+)\s*:\s*function",
                r"(\w+)\s*=\s*\([^)]*\)\s*=>",
                r"(\w+)\s*=\s*function",
            ]

            for pattern in func_patterns:
                match = re.search(pattern, line)
                if match:
                    analysis["functions"].append(
                        {"name": match.group(1), "line": i, "signature": line}
                    )
                    break

            # クラス定義
            class_match = re.match(r"class\s+(\w+)", line)
            if class_match:
                analysis["classes"].append(
                    {"name": class_match.group(1), "line": i, "signature": line}
                )

            # インポート文
            import_match = re.match(r"(import|require)\s+", line)
            if import_match:
                analysis["imports"].append({"line": i, "statement": line})

            # コメント
            if line.startswith("//") or line.startswith("/*"):
                analysis["comments"].append({"line": i, "content": line})

        analysis["complexity"] = (
            len(analysis["functions"]) + len(analysis["classes"]) * 2
        )

        return analysis

    def _analyze_json_code(self, content: str) -> Dict[str, Any]:
        """JSONファイルの解析"""
        analysis: Dict[str, Any] = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": [],
            "complexity": 0,
            "structure": {},
        }

        try:
            data = json.loads(content)
            analysis["structure"] = self._analyze_json_structure(data)
            analysis["complexity"] = len(str(data)) // 100  # 簡易複雑度
        except json.JSONDecodeError as e:
            analysis["error"] = str(e)

        return analysis

    def _analyze_json_structure(self, data: Any, depth: int = 0) -> Dict[str, Any]:
        """JSON構造の再帰的解析"""
        if depth > 10:  # 無限再帰防止
            return {"type": "max_depth_reached"}

        if isinstance(data, dict):
            return {
                "type": "object",
                "keys": list(data.keys()),
                "size": len(data),
                "children": {
                    k: self._analyze_json_structure(v, depth + 1)
                    for k, v in list(data.items())[:5]
                },
            }
        elif isinstance(data, list):
            return {
                "type": "array",
                "size": len(data),
                "sample": data[:3] if data else [],
            }
        else:
            return {"type": type(data).__name__, "value": str(data)[:100]}

    def list_files(
        self,
        directory: Union[str, Path] = None,
        extensions: List[str] = None,
        recursive: bool = True,
    ) -> List[Dict[str, Any]]:
        """ディレクトリ内のファイル一覧を取得"""
        if directory is None:
            directory = self.workspace_root
        else:
            directory = Path(directory)
            if not directory.is_absolute():
                directory = self.workspace_root / directory

        if not directory.exists():
            return []

        files = []
        extensions = extensions or list(self.supported_extensions)

        pattern = "**/*" if recursive else "*"

        for file_path in directory.glob(pattern):
            if file_path.is_file() and file_path.suffix in extensions:
                try:
                    metadata = self._generate_metadata(file_path, "")
                    files.append(metadata)
                except Exception:
                    continue

        return sorted(files, key=lambda x: x["name"])

    def search_in_files(
        self,
        query: str,
        directory: Union[str, Path] = None,
        file_extensions: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """ファイル内容を検索"""
        if directory is None:
            directory = self.workspace_root
        else:
            directory = Path(directory)
            if not directory.is_absolute():
                directory = self.workspace_root / directory

        results = []
        file_extensions = file_extensions or list(self.supported_extensions)

        for file_path in directory.rglob("*"):
            if file_path.is_file() and file_path.suffix in file_extensions:
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    if query.lower() in content.lower():
                        lines = content.splitlines()
                        matches = []

                        for i, line in enumerate(lines, 1):
                            if query.lower() in line.lower():
                                matches.append(
                                    {
                                        "line": i,
                                        "content": line.strip(),
                                        "context": lines[max(0, i - 2) : i + 3],
                                    }
                                )

                        if matches:
                            results.append(
                                {
                                    "file_path": str(file_path),
                                    "matches": matches,
                                    "match_count": len(matches),
                                }
                            )

                except Exception:
                    continue

        return results

    def get_file_tree(
        self, directory: Union[str, Path] = None, max_depth: int = 3
    ) -> Dict[str, Any]:
        """ディレクトリツリーを取得"""
        if directory is None:
            directory = self.workspace_root
        else:
            directory = Path(directory)
            if not directory.is_absolute():
                directory = self.workspace_root / directory

        def build_tree(path: Path, current_depth: int = 0) -> Dict[str, Any]:
            if current_depth >= max_depth:
                return {"type": "max_depth", "name": path.name}

            if path.is_file():
                return {
                    "type": "file",
                    "name": path.name,
                    "size": path.stat().st_size,
                    "extension": path.suffix,
                }

            children = []
            try:
                for child in sorted(path.iterdir()):
                    children.append(build_tree(child, current_depth + 1))
            except PermissionError:
                children.append({"type": "permission_denied", "name": "..."})

            return {"type": "directory", "name": path.name, "children": children}

        return build_tree(directory)
