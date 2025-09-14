# code_executor.py
# 統治核AI - コード実行・インタープリターシステム

import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from subprocess import Popen
from typing import Any, Dict, List, Optional, Union


class CodeExecutor:
    """コードの実行・デバッグ・テストを行うクラス"""

    def __init__(self, workspace_root: str = None):
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()
        self.execution_history: List[Dict[str, Any]] = []
        self.active_processes: Dict[int, Popen[str]] = {}

    def execute_code(
        self,
        code: str,
        language: str = "python",
        timeout: int = 30,
        input_data: str = None,
    ) -> Dict[str, Any]:
        """コードを実行し、結果を返す"""
        execution_id = f"exec_{int(time.time() * 1000)}"

        try:
            if language == "python":
                return self._execute_python(code, execution_id, timeout, input_data)
            elif language == "javascript":
                return self._execute_javascript(code, execution_id, timeout, input_data)
            elif language == "bash":
                return self._execute_bash(code, execution_id, timeout, input_data)
            elif language == "powershell":
                return self._execute_powershell(code, execution_id, timeout, input_data)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported language: {language}",
                    "output": "",
                    "execution_id": execution_id,
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_id": execution_id,
            }

    def _execute_python(
        self, code: str, execution_id: str, timeout: int, input_data: str = None
    ) -> Dict[str, Any]:
        """Pythonコードを実行"""
        try:
            # 一時ファイルを作成
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(code)
                temp_file = f.name

            # 実行
            result = self._run_subprocess(
                [sys.executable, temp_file],
                timeout=timeout,
                input_data=input_data,
                execution_id=execution_id,
            )

            # 一時ファイルを削除
            os.unlink(temp_file)

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_id": execution_id,
            }

    def _execute_javascript(
        self, code: str, execution_id: str, timeout: int, input_data: str = None
    ) -> Dict[str, Any]:
        """JavaScriptコードを実行（Node.js使用）"""
        try:
            # Node.jsの存在確認
            try:
                subprocess.run(["node", "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                return {
                    "success": False,
                    "error": "Node.js is not installed or not in PATH",
                    "output": "",
                    "execution_id": execution_id,
                }

            # 一時ファイルを作成
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(code)
                temp_file = f.name

            # 実行
            result = self._run_subprocess(
                ["node", temp_file],
                timeout=timeout,
                input_data=input_data,
                execution_id=execution_id,
            )

            # 一時ファイルを削除
            os.unlink(temp_file)

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_id": execution_id,
            }

    def _execute_bash(
        self, code: str, execution_id: str, timeout: int, input_data: str = None
    ) -> Dict[str, Any]:
        """Bashスクリプトを実行"""
        try:
            # 一時ファイルを作成
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(code)
                temp_file = f.name

            # 実行権限を付与
            os.chmod(temp_file, 0o755)

            # 実行
            result = self._run_subprocess(
                ["bash", temp_file],
                timeout=timeout,
                input_data=input_data,
                execution_id=execution_id,
            )

            # 一時ファイルを削除
            os.unlink(temp_file)

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_id": execution_id,
            }

    def _execute_powershell(
        self, code: str, execution_id: str, timeout: int, input_data: str = None
    ) -> Dict[str, Any]:
        """PowerShellスクリプトを実行"""
        try:
            # 一時ファイルを作成
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".ps1", delete=False
            ) as f:
                f.write(code)
                temp_file = f.name

            # 実行
            result = self._run_subprocess(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", temp_file],
                timeout=timeout,
                input_data=input_data,
                execution_id=execution_id,
            )

            # 一時ファイルを削除
            os.unlink(temp_file)

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_id": execution_id,
            }

    def _run_subprocess(
        self,
        cmd: List[str],
        timeout: int,
        input_data: str = None,
        execution_id: str = None,
    ) -> Dict[str, Any]:
        """サブプロセスを実行"""
        start_time = time.time()

        try:
            # プロセスを開始
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(self.workspace_root),
            )

            # プロセスを記録
            if execution_id:
                pid = int(execution_id)
                self.active_processes[pid] = process

            # 入力を送信
            if input_data:
                stdout, stderr = process.communicate(input=input_data, timeout=timeout)
            else:
                stdout, stderr = process.communicate(timeout=timeout)

            execution_time = time.time() - start_time

            # 結果を記録
            result = {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "execution_time": execution_time,
                "execution_id": execution_id,
            }

            # 履歴に追加
            self.execution_history.append(
                {"timestamp": time.time(), "command": " ".join(cmd), "result": result}
            )

            return result

        except subprocess.TimeoutExpired:
            # タイムアウト時はプロセスを強制終了
            process.kill()
            return {
                "success": False,
                "error": f"Execution timeout after {timeout} seconds",
                "output": "",
                "execution_time": time.time() - start_time,
                "execution_id": execution_id,
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "output": "",
                "execution_time": time.time() - start_time,
                "execution_id": execution_id,
            }

        finally:
            # プロセスを記録から削除
            if execution_id:
                pid = int(execution_id)
                if pid in self.active_processes:
                    del self.active_processes[pid]

    def execute_file(
        self, file_path: Union[str, Path], args: List[str] = None, timeout: int = 30
    ) -> Dict[str, Any]:
        """ファイルを実行"""
        file_path = Path(file_path)

        if not file_path.is_absolute():
            file_path = self.workspace_root / file_path

        if not file_path.exists():
            return {
                "success": False,
                "error": f"File not found: {file_path}",
                "output": "",
            }

        # ファイル拡張子に基づいて実行方法を決定
        extension = file_path.suffix.lower()

        if extension == ".py":
            cmd = [sys.executable, str(file_path)]
        elif extension == ".js":
            cmd = ["node", str(file_path)]
        elif extension == ".sh":
            cmd = ["bash", str(file_path)]
        elif extension == ".ps1":
            cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(file_path)]
        else:
            return {
                "success": False,
                "error": f"Unsupported file type: {extension}",
                "output": "",
            }

        if args:
            cmd.extend(args)

        return self._run_subprocess(cmd, timeout)

    def run_tests(
        self, test_path: Union[str, Path] = None, framework: str = "pytest"
    ) -> Dict[str, Any]:
        """テストを実行"""
        if test_path is None:
            test_path = self.workspace_root
        else:
            test_path = Path(test_path)
            if not test_path.is_absolute():
                test_path = self.workspace_root / test_path

        if framework == "pytest":
            cmd = [sys.executable, "-m", "pytest", str(test_path), "-v"]
        elif framework == "unittest":
            cmd = [sys.executable, "-m", "unittest", "discover", str(test_path)]
        else:
            return {
                "success": False,
                "error": f"Unsupported test framework: {framework}",
                "output": "",
            }

        return self._run_subprocess(cmd, timeout=60)

    def debug_code(
        self, code: str, language: str = "python", breakpoints: List[int] = None
    ) -> Dict[str, Any]:
        """コードをデバッグ"""
        # 簡易デバッグ実装（実際のデバッガー統合は複雑なため）
        try:
            if language == "python":
                # Pythonのデバッグ情報を生成
                lines = code.splitlines()
                debug_info = []

                for i, line in enumerate(lines, 1):
                    if breakpoints and i in breakpoints:
                        debug_info.append(f"Breakpoint at line {i}: {line.strip()}")

                    # 変数名を抽出
                    import re

                    variables = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", line)
                    if variables:
                        debug_info.append(
                            f"Line {i}: Variables: {', '.join(set(variables))}"
                        )

                return {
                    "success": True,
                    "debug_info": debug_info,
                    "breakpoints": breakpoints or [],
                }
            else:
                return {
                    "success": False,
                    "error": f"Debug not supported for language: {language}",
                    "output": "",
                }

        except Exception as e:
            return {"success": False, "error": str(e), "output": ""}

    def get_execution_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """実行履歴を取得"""
        return self.execution_history[-limit:]

    def stop_execution(self, execution_id: str) -> bool:
        """実行中のプロセスを停止"""
        try:
            pid = int(execution_id)
            if pid in self.active_processes:
                self.active_processes[pid].terminate()
                del self.active_processes[pid]
                return True
        except (ValueError, KeyError):
            pass
        return False

    def get_active_processes(self) -> Dict[int, Popen[str]]:
        """実行中のプロセス一覧を取得"""
        return self.active_processes.copy()
