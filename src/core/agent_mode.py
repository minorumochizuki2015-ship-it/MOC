# agent_mode.py
# 統治核AI - Agent Mode（計画-実行フロー）システム

import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.core.ai_assistant import AIAssistant
from src.core.code_executor import CodeExecutor
from src.core.file_manager import FileManager
from src.core.kernel import Kernel
from . import code_executor
from .tools_fs import list_dir, read_file, write_file, modify_file, search
from pathlib import Path
import importlib


class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    id: str
    title: str
    description: str
    status: TaskStatus
    priority: TaskPriority
    created_at: float
    updated_at: float
    dependencies: List[str]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class AgentMode:
    """Cursor AIのAgent Modeと同等の計画-実行フローを実装"""

    def __init__(
        self,
        kernel: Kernel = None,
        file_manager: FileManager = None,
        code_executor: CodeExecutor = None,
        ai_assistant: AIAssistant = None,
        # ヘッドレス用の簡易コンストラクタ
        kernel_llm: Callable[[str], str] = None,
        executor = None,
        dry_run: bool = True,
        max_steps: int = 8,
    ):
        # 既存の複雑な初期化
        if kernel is not None:
            self.kernel = kernel
            self.file_manager = file_manager
            self.code_executor = code_executor
            self.ai_assistant = ai_assistant
            self.tasks: Dict[str, Any] = {}
            self.execution_history: List[Dict[str, Any]] = []
            self.current_plan = None
            self.is_running = False
        else:
            # ヘッドレス用の簡易初期化
            # LLMは"kernel経由"のみ許可
            bad = ("openai", "anthropic", "google", "cohere")
            mod = getattr(kernel_llm, "__module__", "") or ""
            name = getattr(kernel_llm, "__name__", "") or ""
            if any(b in mod.lower() or b in name.lower() for b in bad):
                raise RuntimeError("Remote SDK blocked: use kernel.generate_* only")
            
            self.llm = kernel_llm
            self.exec = executor
            self.dry = dry_run
            self.max_steps = max_steps
            self.tasks: Dict[str, Any] = {}
            self.execution_history: List[Dict[str, Any]] = []
            self.current_plan = None
            self.is_running = False

    def plan_and_execute(
        self, user_request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """ユーザーリクエストを分析し、計画を立てて実行"""
        # ヘッドレス用の簡易実装
        if hasattr(self, 'llm'):
            return self._simple_plan_and_execute(user_request)
        
        # 既存の複雑な実装
        try:
            # 1. リクエスト分析
            analysis = self._analyze_request(user_request, context)

            # 2. 計画生成
            plan = self._generate_plan(analysis)

            # 3. 計画実行
            execution_result = self._execute_plan(plan)

            return {
                "success": True,
                "analysis": analysis,
                "plan": plan,
                "execution": execution_result,
                "summary": self._generate_summary(analysis, plan, execution_result),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis": None,
                "plan": None,
                "execution": None,
            }

    def _simple_plan_and_execute(self, goal: str) -> Dict[str, Any]:
        """ヘッドレス用の簡易計画・実行"""
        try:
            # 計画生成
            steps = self.plan(goal)
            
            # 実行トレース
            trace = []
            for i, step in enumerate(steps, 1):
                result = self.step(step)
                trace.append({"step": i, "inst": step, "result": result})
                
                # Dry-runの場合は計画のみ
                if self.dry:
                    continue
                    
            return {
                "goal": goal,
                "steps": steps,
                "trace": trace,
                "dry_run": self.dry,
                "success": True
            }
        except Exception as e:
            return {
                "goal": goal,
                "steps": [],
                "trace": [],
                "dry_run": self.dry,
                "success": False,
                "error": str(e)
            }

    def plan(self, goal: str) -> List[str]:
        """タスクを手順に分解"""
        if not hasattr(self, 'llm'):
            return [f"タスク実行: {goal}"]
            
        prompt = f"次のタスクを最大{self.max_steps}手順に分解して箇条書き:\n{goal}"
        text = self.llm(prompt)
        return [s.strip(" -•\t") for s in text.splitlines() if s.strip()]

    def step(self, instruction: str) -> Dict[str, Any]:
        """1ステップ実行（ローカル専用ツールディスパッチ）"""
        plan = self._llm_plan(instruction)  # {"tool":"...", "args":{...}}
        tool = (plan or {}).get("tool")
        args = (plan or {}).get("args", {})
        try:
            # エイリアス吸収
            if tool == "think":
                return {"success": True, "result": {"ok": True, "note": "reflect-only; no action"}}
            if tool == "list_dir":
                return {"success": True, "result": list_dir(**args)}
            if tool == "read_file":
                return {"success": True, "result": read_file(**args)}
            if tool == "write_file":
                return {"success": True, "result": write_file(**args)}
            if tool == "modify_file":
                return {"success": True, "result": modify_file(**args)}
            if tool == "search":
                return {"success": True, "result": search(**args)}
            if tool == "git_commit":
                mod = importlib.import_module("tools.git_commit")
                return {"success": True, "result": mod.commit(**args)}
            if tool == "run_tests":
                mod = importlib.import_module("tools.run_tests")
                return {"success": True, "result": mod.run(**args)}
            # 不明ツールはプランのみ返す
            return {"success": False, "error": f"unknown tool: {tool}", "plan": plan}
        except Exception as e:
            return {"success": False, "error": str(e)[:200], "plan": plan}

    def _llm_plan(self, instruction: str) -> Dict[str, Any]:
        """LLMにツール選択を依頼"""
        if not hasattr(self, 'llm'):
            return {"tool": "think", "args": {"note": instruction}}
        
        prompt = f"""
以下の指示を適切なツールで実行してください。

指示: {instruction}

利用可能なツール:
- list_dir: ファイル一覧取得 (pattern, limit)
- read_file: ファイル読み取り (path, max_bytes, encoding)
- write_file: ファイル書き込み (path, content, encoding)
- modify_file: ファイル修正 (path, find, replace, encoding, count)
- search: ファイル検索 (pattern, text, limit)
- run_tests: テスト実行
- git_commit: Gitコミット (message)

JSON形式で回答: {{"tool": "ツール名", "args": {{"パラメータ": "値"}}}}
"""
        
        try:
            response = self.llm(prompt)
            import json
            return json.loads(response)
        except Exception:
            return {"tool": "think", "args": {"note": instruction}}

    def integrate_evolution(self) -> None:
        """進化アルゴリズムを統合"""
        try:
            from src.core.evolution import Evolution
            from src.core.simple_bo import SimpleBO
            
            # ベイズ最適化器を初期化
            self.bo = SimpleBO()
            
            # 進化システムを初期化
            self.evolution = Evolution()
            
            # 進化フックを設定
            self._setup_evolution_hooks()
            
        except ImportError as e:
            print(f"進化アルゴリズム統合エラー: {e}")

    def _setup_evolution_hooks(self) -> None:
        """進化フックを設定"""
        if hasattr(self, 'bo') and hasattr(self, 'evolution'):
            # ベイズ最適化の観測フック
            self._original_step = self.step
            self.step = self._evolved_step

    def _evolved_step(self, instruction: str) -> Dict[str, Any]:
        """進化統合されたステップ実行"""
        # 元のステップを実行
        result = self._original_step(instruction)
        
        # ベイズ最適化でパラメータを提案
        if hasattr(self, 'bo'):
            try:
                # 現在のパラメータを観測
                current_params = self._get_current_params()
                performance = self._calculate_performance(result)
                
                # ベイズ最適化に記録
                self.bo.observe(current_params, performance)
                
                # 次のパラメータを提案
                next_params = self.bo.suggest(n_suggestions=1)[0]
                result["evolution"] = {
                    "current_params": current_params,
                    "performance": performance,
                    "next_params": next_params
                }
            except Exception as e:
                result["evolution_error"] = str(e)
        
        return result

    def _get_current_params(self) -> Dict[str, float]:
        """現在のパラメータを取得"""
        return {
            "learning_rate": 0.01,
            "batch_size": 32,
            "temperature": 0.7,
            "max_tokens": 500
        }

    def _calculate_performance(self, result: Dict[str, Any]) -> float:
        """パフォーマンスを計算"""
        # 簡単なスコア計算（実際はより複雑な指標を使用）
        if result.get("success", False):
            return 1.0
        else:
            return 0.0

    def _analyze_request(
        self, user_request: str, context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """ユーザーリクエストを分析"""
        prompt = f"""
以下のユーザーリクエストを分析してください：

リクエスト: {user_request}

コンテキスト: {json.dumps(context or {}, ensure_ascii=False, indent=2)}

以下の観点で分析してください：
1. リクエストの種類（コード生成、デバッグ、リファクタリング、ファイル操作など）
2. 必要な技術スタック
3. 推定される作業時間
4. 必要なリソース
5. 潜在的な課題
6. 推奨されるアプローチ

JSON形式で回答してください。
"""

        response = self.kernel.query_local_api(prompt)
        analysis_text = response.get("response_text", "")

        # JSON解析を試行
        try:
            analysis = json.loads(analysis_text)
        except json.JSONDecodeError:
            # JSON解析に失敗した場合は基本分析を生成
            analysis = {
                "type": "unknown",
                "technologies": [],
                "estimated_time": "unknown",
                "resources": [],
                "challenges": [],
                "approach": "manual",
            }

        return analysis

    def _generate_plan(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """分析結果に基づいて実行計画を生成"""
        prompt = f"""
以下の分析結果に基づいて、詳細な実行計画を立ててください：

分析結果: {json.dumps(analysis, ensure_ascii=False, indent=2)}

以下の形式で計画を立ててください：
1. タスクの分解（具体的なステップ）
2. 各ステップの実行順序
3. 依存関係の特定
4. リソース要件
5. 検証方法
6. リスクと対策

JSON形式で回答してください。
"""

        response = self.kernel.query_local_api(prompt)
        plan_text = response.get("response_text", "")

        try:
            plan = json.loads(plan_text)
        except json.JSONDecodeError:
            # 基本計画を生成
            plan = {
                "steps": [
                    {
                        "id": "step_1",
                        "title": "リクエスト実行",
                        "description": "ユーザーリクエストを実行",
                        "type": "execute",
                        "dependencies": [],
                    }
                ],
                "resources": [],
                "verification": "手動確認",
                "risks": [],
            }

        return plan

    def _execute_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """計画を実行"""
        self.is_running = True
        execution_results = []

        try:
            steps = plan.get("steps", [])

            for step in steps:
                step_result = self._execute_step(step)
                execution_results.append(step_result)

                # ステップが失敗した場合は停止
                if not step_result.get("success", False):
                    break

            return {
                "success": True,
                "steps": execution_results,
                "total_steps": len(steps),
                "completed_steps": len(
                    [r for r in execution_results if r.get("success", False)]
                ),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "steps": execution_results}
        finally:
            self.is_running = False

    def _execute_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """個別のステップを実行"""
        step_type = step.get("type", "unknown")
        step_id = step.get("id", f"step_{int(time.time())}")

        try:
            if step_type == "code_generation":
                return self._execute_code_generation(step)
            elif step_type == "file_operation":
                return self._execute_file_operation(step)
            elif step_type == "code_execution":
                return self._execute_code_execution(step)
            elif step_type == "analysis":
                return self._execute_analysis(step)
            elif step_type == "refactoring":
                return self._execute_refactoring(step)
            else:
                return self._execute_generic(step)

        except Exception as e:
            return {
                "step_id": step_id,
                "success": False,
                "error": str(e),
                "result": None,
            }

    def _execute_code_generation(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """コード生成ステップを実行"""
        description = step.get("description", "")
        language = step.get("language", "python")

        result = self.ai_assistant.generate_code(description, language)

        return {
            "step_id": step.get("id"),
            "success": result.get("success", False),
            "result": result,
            "error": result.get("error"),
        }

    def _execute_file_operation(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """ファイル操作ステップを実行"""
        operation = step.get("operation", "read")
        file_path = step.get("file_path", "")

        result: Any = {}

        if operation == "read":
            result = self.file_manager.read_file(file_path)
        elif operation == "list":
            directory = step.get("directory", ".")
            result = self.file_manager.list_files(directory)
        elif operation == "search":
            query = step.get("query", "")
            result = self.file_manager.search_in_files(query)
        else:
            result = {
                "success": False,
                "error": f"Unknown operation: {operation}",
            }

        return {
            "step_id": step.get("id"),
            "success": result.get("success", False),
            "result": result,
            "error": result.get("error"),
        }

    def _execute_code_execution(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """コード実行ステップを実行"""
        code = step.get("code", "")
        language = step.get("language", "python")

        result = self.code_executor.execute_code(code, language)

        return {
            "step_id": step.get("id"),
            "success": result.get("success", False),
            "result": result,
            "error": result.get("error"),
        }

    def _execute_analysis(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """分析ステップを実行"""
        code = step.get("code", "")
        language = step.get("language", "python")

        result = self.ai_assistant.explain_code(code, language)

        return {
            "step_id": step.get("id"),
            "success": result.get("success", False),
            "result": result,
            "error": result.get("error"),
        }

    def _execute_refactoring(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """リファクタリングステップを実行"""
        code = step.get("code", "")
        language = step.get("language", "python")
        refactor_type = step.get("refactor_type", "optimize")

        result = self.ai_assistant.refactor_code(code, language, refactor_type)

        return {
            "step_id": step.get("id"),
            "success": result.get("success", False),
            "result": result,
            "error": result.get("error"),
        }

    def _execute_generic(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """汎用ステップを実行"""
        description = step.get("description", "")

        # AIに直接実行を依頼
        prompt = f"""
以下のタスクを実行してください：

{description}

実行結果をJSON形式で報告してください。
"""

        response = self.kernel.query_local_api(prompt)
        result_text = response.get("response_text", "")

        try:
            result = json.loads(result_text)
        except json.JSONDecodeError:
            result = {"output": result_text}

        return {
            "step_id": step.get("id"),
            "success": True,
            "result": result,
            "error": None,
        }

    def _generate_summary(
        self, analysis: Dict[str, Any], plan: Dict[str, Any], execution: Dict[str, Any]
    ) -> str:
        """実行結果のサマリーを生成"""
        prompt = f"""
以下の実行結果をサマリーしてください：

分析: {json.dumps(analysis, ensure_ascii=False, indent=2)}
計画: {json.dumps(plan, ensure_ascii=False, indent=2)}
実行結果: {json.dumps(execution, ensure_ascii=False, indent=2)}

以下の点を含めてサマリーしてください：
1. 実行されたタスクの概要
2. 成功したステップ数
3. 発生した問題（あれば）
4. 最終的な成果物
5. 今後の推奨事項

簡潔で分かりやすい日本語で記述してください。
"""

        response = self.kernel.query_local_api(prompt)
        return response.get("response_text", "実行完了")

    def create_task(
        self,
        title: str,
        description: str,
        priority: TaskPriority = TaskPriority.MEDIUM,
        dependencies: List[str] = None,
    ) -> str:
        """新しいタスクを作成"""
        task_id = f"task_{int(time.time() * 1000)}"

        task = Task(
            id=task_id,
            title=title,
            description=description,
            status=TaskStatus.PENDING,
            priority=priority,
            created_at=time.time(),
            updated_at=time.time(),
            dependencies=dependencies or [],
        )

        self.tasks[task_id] = task
        return task_id

    def get_task(self, task_id: str) -> Optional[Task]:
        """タスクを取得"""
        return self.tasks.get(task_id)

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        result: Dict[str, Any] = None,
        error: str = None,
    ) -> bool:
        """タスクのステータスを更新"""
        if task_id not in self.tasks:
            return False

        task = self.tasks[task_id]
        task.status = status
        task.updated_at = time.time()

        if result:
            task.result = result
        if error:
            task.error = error

        return True

    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        """ステータス別にタスクを取得"""
        return [task for task in self.tasks.values() if task.status == status]

    def get_tasks_by_priority(self, priority: TaskPriority) -> List[Task]:
        """優先度別にタスクを取得"""
        return [task for task in self.tasks.values() if task.priority == priority]

    def cancel_task(self, task_id: str) -> bool:
        """タスクをキャンセル"""
        return self.update_task_status(task_id, TaskStatus.CANCELLED)

    def get_execution_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """実行履歴を取得"""
        return self.execution_history[-limit:]

    def is_agent_running(self) -> bool:
        """エージェントが実行中かどうか"""
        return self.is_running

    def stop_agent(self) -> bool:
        """エージェントを停止"""
        if self.is_running:
            self.is_running = False
            return True
        return False
