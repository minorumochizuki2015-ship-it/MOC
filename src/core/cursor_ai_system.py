# cursor_ai_system.py
# 統治核AI - Cursor AI同等システム統合

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.core.agent_mode import AgentMode
from src.core.ai_assistant import AIAssistant
from src.core.code_executor import CodeExecutor
from src.core.file_manager import FileManager
from src.core.kernel import Kernel
from src.core.memory import Memory
from src.core.performance_monitor import performance_monitor


class CursorAISystem:
    """Cursor AIと同等以上の機能を提供する統合システム"""

    def __init__(self, workspace_root: str = None):
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()

        # コアコンポーネントの初期化（サーバー接続は遅延）
        self.memory = Memory()
        self.kernel = Kernel(self.memory)
        self.file_manager = FileManager(str(self.workspace_root))
        self.code_executor = CodeExecutor(str(self.workspace_root))
        self.ai_assistant = AIAssistant(
            self.kernel, self.file_manager, self.code_executor
        )
        self.agent_mode = AgentMode(
            self.kernel, self.file_manager, self.code_executor, self.ai_assistant
        )

        # システム状態
        self.is_initialized = True
        self.session_id = f"session_{int(time.time() * 1000)}"
        self.server_ready = False

        print(f"統治核AI Cursor同等システム初期化完了")
        print(f"ワークスペース: {self.workspace_root}")
        print(f"セッションID: {self.session_id}")
        print("注意: サーバーが起動していない場合、AI機能は利用できません")

    def check_server_status(self) -> bool:
        """サーバーの状態をチェック"""
        try:
            import os

            import requests

            # 環境変数からベースURLを取得し、動的にURLを構築
            base = os.environ.get(
                "OPENAI_COMPAT_BASE", "http://127.0.0.1:8080/v1"
            ).rstrip("/")
            url = f"{base}/models"

            response = requests.get(url, timeout=10)  # タイムアウトを10秒に延長
            self.server_ready = response.status_code == 200
            if self.server_ready:
                print("✅ サーバー接続成功")
            return self.server_ready
        except Exception as e:
            print(f"❌ サーバー接続エラー: {e}")
            self.server_ready = False
            return False

    def process_request(
        self, request: str, request_type: str = "auto", context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """ユーザーリクエストを処理"""
        start_time = time.time()

        # サーバー状態をチェック（失敗時も処理を続行）
        server_available = self.check_server_status()
        if not server_available:
            # サーバーが利用できない場合でも、処理時に再確認するため続行
            pass

        try:
            # リクエストタイプを自動判定
            if request_type == "auto":
                request_type = self._detect_request_type(request)

            # リクエストタイプに応じて処理
            if request_type == "agent":
                result = self._handle_agent_request(request, context)
            elif request_type == "code_generation":
                result = self._handle_code_generation(request, context)
            elif request_type == "file_operation":
                result = self._handle_file_operation(request, context)
            elif request_type == "code_execution":
                result = self._handle_code_execution(request, context)
            elif request_type == "analysis":
                result = self._handle_analysis_request(request, context)
            else:
                result = self._handle_generic_request(request, context)

            # 実行時間を記録
            execution_time = time.time() - start_time
            performance_monitor.record_request(
                execution_time, result.get("success", False)
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            performance_monitor.record_request(execution_time, False, error=True)

            return {
                "success": False,
                "error": str(e),
                "request_type": request_type,
                "execution_time": execution_time,
            }

    def _detect_request_type(self, request: str) -> str:
        """リクエストタイプを自動判定"""
        request_lower = request.lower()

        # Agent Modeのキーワード
        agent_keywords = [
            "計画",
            "実行",
            "タスク",
            "プロジェクト",
            "ワークフロー",
            "plan",
            "execute",
            "task",
            "workflow",
        ]
        if any(keyword in request_lower for keyword in agent_keywords):
            return "agent"

        # コード生成のキーワード
        code_gen_keywords = [
            "作成",
            "生成",
            "書いて",
            "コード",
            "関数",
            "クラス",
            "create",
            "generate",
            "write",
            "code",
            "function",
            "class",
        ]
        if any(keyword in request_lower for keyword in code_gen_keywords):
            return "code_generation"

        # ファイル操作のキーワード
        file_keywords = [
            "ファイル",
            "読み込み",
            "保存",
            "検索",
            "file",
            "read",
            "save",
            "search",
            "open",
        ]
        if any(keyword in request_lower for keyword in file_keywords):
            return "file_operation"

        # コード実行のキーワード
        exec_keywords = [
            "実行",
            "動かして",
            "テスト",
            "run",
            "execute",
            "test",
            "debug",
        ]
        if any(keyword in request_lower for keyword in exec_keywords):
            return "code_execution"

        # 分析のキーワード
        analysis_keywords = [
            "分析",
            "説明",
            "デバッグ",
            "改善",
            "analyze",
            "explain",
            "debug",
            "improve",
        ]
        if any(keyword in request_lower for keyword in analysis_keywords):
            return "analysis"

        return "generic"

    def _handle_agent_request(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Agent Modeリクエストを処理"""
        return self.agent_mode.plan_and_execute(request, context)

    def _handle_code_generation(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """コード生成リクエストを処理"""
        # 言語を判定
        language = self._detect_language(request, context)

        # コード生成
        result = self.ai_assistant.generate_code(request, language)

        return {
            "success": result.get("success", False),
            "type": "code_generation",
            "language": language,
            "result": result,
            "error": result.get("error"),
        }

    def _handle_file_operation(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """ファイル操作リクエストを処理"""
        # ファイルパスを抽出
        file_path = self._extract_file_path(request)

        if not file_path:
            return {
                "success": False,
                "error": "ファイルパスが指定されていません",
                "type": "file_operation",
            }

        # ファイル読み込み
        result = self.file_manager.read_file(file_path)

        return {
            "success": result.get("success", False),
            "type": "file_operation",
            "file_path": file_path,
            "result": result,
            "error": result.get("error"),
        }

    def _handle_code_execution(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """コード実行リクエストを処理"""
        # コードを抽出
        code = self._extract_code(request)
        language = self._detect_language(request, context)

        if not code:
            return {
                "success": False,
                "error": "実行するコードが指定されていません",
                "type": "code_execution",
            }

        # コード実行
        result = self.code_executor.execute_code(code, language)

        return {
            "success": result.get("success", False),
            "type": "code_execution",
            "language": language,
            "result": result,
            "error": result.get("error"),
        }

    def _handle_analysis_request(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """分析リクエストを処理"""
        # コードを抽出
        code = self._extract_code(request)
        language = self._detect_language(request, context)

        if not code:
            return {
                "success": False,
                "error": "分析するコードが指定されていません",
                "type": "analysis",
            }

        # コード分析
        result = self.ai_assistant.explain_code(code, language)

        return {
            "success": result.get("success", False),
            "type": "analysis",
            "language": language,
            "result": result,
            "error": result.get("error"),
        }

    def _handle_generic_request(
        self, request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """汎用リクエストを処理"""
        # AIに直接問い合わせ
        response = self.kernel.query_local_api(request)

        return {"success": True, "type": "generic", "result": response, "error": None}

    def _detect_language(self, request: str, context: Dict[str, Any] = None) -> str:
        """プログラミング言語を判定"""
        request_lower = request.lower()

        # 言語キーワード
        language_keywords = {
            "python": ["python", "py", "def ", "import ", "class "],
            "javascript": ["javascript", "js", "function", "const ", "let ", "var "],
            "typescript": ["typescript", "ts", "interface", "type "],
            "html": ["html", "<div", "<span", "<p>"],
            "css": ["css", "style", "{", "}"],
            "bash": ["bash", "shell", "#!/bin/bash"],
            "powershell": ["powershell", "ps1", "Get-"],
        }

        for language, keywords in language_keywords.items():
            if any(keyword in request_lower for keyword in keywords):
                return language

        # コンテキストから判定
        if context and "language" in context:
            return context["language"]

        return "python"  # デフォルト

    def _extract_file_path(self, request: str) -> Optional[str]:
        """リクエストからファイルパスを抽出"""
        import re

        # ファイルパスのパターン
        patterns = [
            r"ファイル[：:]?\s*([^\s]+)",
            r"file[：:]?\s*([^\s]+)",
            r"([^\s]+\.(py|js|ts|html|css|json|txt|md))",
            r"([^\s]+/[^\s]+)",
            r"([^\s]+\\[^\s]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, request, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _extract_code(self, request: str) -> Optional[str]:
        """リクエストからコードを抽出"""
        import re

        # コードブロックのパターン
        code_patterns = [
            r"```(?:python|js|javascript|ts|typescript|html|css|bash|powershell)?\s*\n(.*?)\n```",
            r"```\s*\n(.*?)\n```",
            r"コード[：:]?\s*\n(.*?)(?:\n\n|\n$|$)",
            r"code[：:]?\s*\n(.*?)(?:\n\n|\n$|$)",
        ]

        for pattern in code_patterns:
            match = re.search(pattern, request, re.DOTALL)
            if match:
                return match.group(1).strip()

        return None

    def get_system_status(self) -> Dict[str, Any]:
        """システム状態を取得"""
        return {
            "initialized": self.is_initialized,
            "session_id": self.session_id,
            "workspace_root": str(self.workspace_root),
            "agent_running": self.agent_mode.is_agent_running(),
            "performance_metrics": performance_monitor.get_performance_metrics(),
            "active_tasks": len(self.agent_mode.get_tasks_by_status("in_progress")),
        }

    def get_workspace_info(self) -> Dict[str, Any]:
        """ワークスペース情報を取得"""
        try:
            file_tree = self.file_manager.get_file_tree(max_depth=2)
            file_count = len(self.file_manager.list_files())

            return {
                "workspace_root": str(self.workspace_root),
                "file_count": file_count,
                "file_tree": file_tree,
                "supported_extensions": list(self.file_manager.supported_extensions),
            }
        except Exception as e:
            return {"error": str(e), "workspace_root": str(self.workspace_root)}

    def search_workspace(
        self, query: str, file_types: List[str] = None
    ) -> Dict[str, Any]:
        """ワークスペースを検索"""
        try:
            results = self.file_manager.search_in_files(
                query, file_extensions=file_types
            )

            return {
                "success": True,
                "query": query,
                "results": results,
                "result_count": len(results),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "query": query, "results": []}

    def execute_agent_task(
        self, task_description: str, priority: str = "medium"
    ) -> Dict[str, Any]:
        """エージェントタスクを実行"""
        try:
            # 優先度を変換
            priority_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            priority_value = priority_map.get(priority.lower(), 2)

            # タスクを作成
            task_id = self.agent_mode.create_task(
                title=f"Task: {task_description[:50]}...",
                description=task_description,
                priority=priority_value,
            )

            # タスクを実行
            result = self.agent_mode.plan_and_execute(task_description)

            return {"success": True, "task_id": task_id, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e), "task_id": None}

    def get_available_commands(self) -> List[Dict[str, str]]:
        """利用可能なコマンド一覧を取得"""
        return [
            {
                "command": "code_generation",
                "description": "コード生成",
                "example": "Pythonでデータ分析の関数を作成して",
            },
            {
                "command": "file_operation",
                "description": "ファイル操作",
                "example": "main.pyファイルを読み込んで",
            },
            {
                "command": "code_execution",
                "description": "コード実行",
                "example": "このコードを実行して",
            },
            {
                "command": "analysis",
                "description": "コード分析",
                "example": "このコードを分析して",
            },
            {
                "command": "agent",
                "description": "エージェントタスク",
                "example": "Webアプリケーションのプロジェクトを計画して",
            },
        ]
