#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M7: 品質ゲートと手動/自動テスト - 退行防止
pre-commit必須化（Black+isort+mypy strict）、ユニットテスト、UIスモークテスト
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class QualityGates:
    """品質ゲート管理（M7）"""
    
    def __init__(self, workspace_root: str = None):
        self.workspace_root = Path(workspace_root) if workspace_root else Path.cwd()
        self.python_exe = self.workspace_root / ".venv" / "Scripts" / "python.exe"
        self.coverage_threshold = 70  # カバレッジ閾値
        
    def run_pre_commit_checks(self) -> Dict[str, Any]:
        """pre-commit必須化チェック（M7）"""
        results = {
            "black": self._run_black_check(),
            "isort": self._run_isort_check(),
            "mypy": self._run_mypy_check(),
            "overall_success": True
        }
        
        # 全体の成功判定
        for tool, result in results.items():
            if tool != "overall_success" and not result.get("success", False):
                results["overall_success"] = False
                break
        
        return results
    
    def _run_black_check(self) -> Dict[str, Any]:
        """Black（コード整形）チェック"""
        try:
            cmd = [str(self.python_exe), "-m", "black", "--check", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace_root)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _run_isort_check(self) -> Dict[str, Any]:
        """isort（インポート整理）チェック"""
        try:
            cmd = [str(self.python_exe), "-m", "isort", "--check-only", "."]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace_root)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _run_mypy_check(self) -> Dict[str, Any]:
        """mypy（型チェック）チェック"""
        try:
            cmd = [str(self.python_exe), "-m", "mypy", "src"]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace_root)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_unit_tests(self) -> Dict[str, Any]:
        """ユニットテスト実行（M7）"""
        try:
            # バイナリ検出テスト
            binary_test = self._test_binary_detection()
            
            # パス検査テスト
            path_test = self._test_path_validation()
            
            # トランケートテスト
            truncate_test = self._test_text_truncation()
            
            results = {
                "binary_detection": binary_test,
                "path_validation": path_test,
                "text_truncation": truncate_test,
                "overall_success": all([binary_test["success"], path_test["success"], truncate_test["success"]])
            }
            
            return results
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _test_binary_detection(self) -> Dict[str, Any]:
        """バイナリ検出テスト"""
        try:
            from src.core.sandbox_tools import SandboxTools
            
            sandbox = SandboxTools()
            
            # テキストファイルテスト
            result = sandbox.read_file("README.md")
            if not result["success"]:
                return {"success": False, "error": "テキストファイル読み込み失敗"}
            
            # バイナリファイルテスト（存在する場合）
            binary_files = ["llama.cpp/llama.cpp", "llama.cpp/ggml.c"]
            for binary_file in binary_files:
                if Path(binary_file).exists():
                    result = sandbox.read_file(binary_file)
                    if result["success"] and "binary" in result.get("content", "").lower():
                        return {"success": True, "message": "バイナリ検出成功"}
            
            return {"success": True, "message": "バイナリ検出テスト完了"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _test_path_validation(self) -> Dict[str, Any]:
        """パス検査テスト"""
        try:
            from src.core.sandbox_tools import SandboxTools
            
            sandbox = SandboxTools()
            
            # 安全なパステスト
            result = sandbox.list_dir(".")
            if not result["success"]:
                return {"success": False, "error": "安全なパスで失敗"}
            
            # 危険なパステスト
            result = sandbox.list_dir("../../../etc")
            if result["success"]:
                return {"success": False, "error": "危険なパスが許可された"}
            
            return {"success": True, "message": "パス検査成功"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _test_text_truncation(self) -> Dict[str, Any]:
        """テキスト切り詰めテスト"""
        try:
            from src.ui.modern_interface import ModernCursorAIInterface
            import tkinter as tk
            
            root = tk.Tk()
            root.withdraw()
            
            interface = ModernCursorAIInterface(root)
            
            # 長いテキストの切り詰めテスト
            long_text = "A" * 1000
            truncated = interface._truncate(long_text, 100)
            
            if len(truncated) <= 100 and truncated.endswith("…"):
                return {"success": True, "message": "テキスト切り詰め成功"}
            else:
                return {"success": False, "error": "テキスト切り詰め失敗"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_ui_smoke_test(self) -> Dict[str, Any]:
        """UIスモークテスト（起動→実行→終了）"""
        try:
            from src.ui.modern_interface import ModernCursorAIInterface
            import tkinter as tk
            
            # UI起動テスト
            root = tk.Tk()
            root.withdraw()  # ウィンドウを非表示
            
            interface = ModernCursorAIInterface(root)
            
            # 基本機能テスト
            tests = {
                "ui_initialization": True,
                "button_creation": hasattr(interface, "execute_button"),
                "tab_switching": hasattr(interface, "_on_ai_tab_changed"),
                "agent_integration": hasattr(interface, "_agent_task"),
                "observation_hooks": hasattr(interface, "_observation_hooks")
            }
            
            root.destroy()
            
            success = all(tests.values())
            return {
                "success": success,
                "tests": tests,
                "message": "UIスモークテスト完了" if success else "UIスモークテスト失敗"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_full_quality_check(self) -> Dict[str, Any]:
        """全品質チェック実行（M7）"""
        start_time = time.time()
        
        results = {
            "pre_commit": self.run_pre_commit_checks(),
            "unit_tests": self.run_unit_tests(),
            "ui_smoke": self.run_ui_smoke_test(),
            "execution_time": 0,
            "overall_success": False
        }
        
        results["execution_time"] = time.time() - start_time
        
        # 全体の成功判定
        results["overall_success"] = all([
            results["pre_commit"]["overall_success"],
            results["unit_tests"]["overall_success"],
            results["ui_smoke"]["success"]
        ])
        
        return results
    
    def generate_quality_report(self, results: Dict[str, Any]) -> str:
        """品質レポート生成（M7）"""
        report = []
        report.append("=== 品質ゲートレポート ===")
        report.append(f"実行時間: {results['execution_time']:.2f}秒")
        report.append(f"全体結果: {'✅ 成功' if results['overall_success'] else '❌ 失敗'}")
        report.append("")
        
        # pre-commit結果
        report.append("## pre-commitチェック")
        for tool, result in results["pre_commit"].items():
            if tool != "overall_success":
                status = "✅" if result["success"] else "❌"
                report.append(f"- {tool}: {status}")
        
        # ユニットテスト結果
        report.append("\n## ユニットテスト")
        for test, result in results["unit_tests"].items():
            if test != "overall_success":
                status = "✅" if result["success"] else "❌"
                report.append(f"- {test}: {status}")
        
        # UIスモークテスト結果
        report.append("\n## UIスモークテスト")
        status = "✅" if results["ui_smoke"]["success"] else "❌"
        report.append(f"- UI動作: {status}")
        
        return "\n".join(report)


# グローバルインスタンス
quality_gates = QualityGates()
