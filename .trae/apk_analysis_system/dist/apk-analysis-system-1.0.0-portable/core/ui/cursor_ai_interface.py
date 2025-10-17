# cursor_ai_interface.py
# 統治核AI - Cursor AI同等インターフェース

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, Optional

from core.core.cursor_ai_system import CursorAISystem


class CursorAIInterface:
    """Cursor AIと同等のインターフェース"""

    def __init__(self, parent=None):
        self.parent = parent or tk.Tk()
        self.cursor_ai = None
        self.current_file = None
        self.is_processing = False

        self._setup_ui()
        self._initialize_cursor_ai()

    def _setup_ui(self):
        """UIをセットアップ"""
        self.parent.title("統治核AI - Cursor AI同等システム")
        self.parent.geometry("1400x900")

        # メインフレーム
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 左パネル（ファイルエクスプローラー）
        self._setup_file_panel(main_frame)

        # 中央パネル（エディター）
        self._setup_editor_panel(main_frame)

        # 右パネル（AI機能）
        self._setup_ai_panel(main_frame)

        # 下部パネル（実行結果）
        self._setup_output_panel(main_frame)

    def _setup_file_panel(self, parent):
        """ファイルパネルをセットアップ"""
        file_frame = ttk.LabelFrame(parent, text="ファイルエクスプローラー")
        file_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 5))
        file_frame.configure(width=250)

        # ファイルツリー
        self.file_tree = ttk.Treeview(file_frame)
        self.file_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ファイル操作ボタン
        file_buttons = ttk.Frame(file_frame)
        file_buttons.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(file_buttons, text="開く", command=self._open_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(file_buttons, text="保存", command=self._save_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(file_buttons, text="新規", command=self._new_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(file_buttons, text="更新", command=self._refresh_files).pack(
            side=tk.LEFT, padx=2
        )

    def _setup_editor_panel(self, parent):
        """エディターパネルをセットアップ"""
        editor_frame = ttk.LabelFrame(parent, text="エディター")
        editor_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # タブコントロール
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # デフォルトタブ
        self._create_new_tab("新規ファイル")

        # エディター操作ボタン
        editor_buttons = ttk.Frame(editor_frame)
        editor_buttons.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(editor_buttons, text="実行", command=self._run_code).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(editor_buttons, text="デバッグ", command=self._debug_code).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(editor_buttons, text="フォーマット", command=self._format_code).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(editor_buttons, text="分析", command=self._analyze_code).pack(
            side=tk.LEFT, padx=2
        )

    def _setup_ai_panel(self, parent):
        """AIパネルをセットアップ"""
        ai_frame = ttk.LabelFrame(parent, text="AI支援")
        ai_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(5, 0))
        ai_frame.configure(width=350)

        # AI機能ボタン
        ai_buttons = ttk.Frame(ai_frame)
        ai_buttons.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(ai_buttons, text="コード生成", command=self._generate_code).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(ai_buttons, text="コード補完", command=self._complete_code).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(
            ai_buttons, text="リファクタリング", command=self._refactor_code
        ).pack(fill=tk.X, pady=2)
        ttk.Button(
            ai_buttons, text="エージェントタスク", command=self._agent_task
        ).pack(fill=tk.X, pady=2)

        # AI入力エリア
        ai_input_frame = ttk.LabelFrame(ai_frame, text="AI入力")
        ai_input_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.ai_input = scrolledtext.ScrolledText(ai_input_frame, height=8)
        self.ai_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # AI実行ボタン
        ttk.Button(ai_input_frame, text="実行", command=self._execute_ai_request).pack(
            fill=tk.X, padx=5, pady=5
        )

        # システム状態
        status_frame = ttk.LabelFrame(ai_frame, text="システム状態")
        status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.status_text = tk.Text(status_frame, height=4, state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_output_panel(self, parent):
        """出力パネルをセットアップ"""
        output_frame = ttk.LabelFrame(parent, text="実行結果")
        output_frame.pack(fill=tk.X, padx=5, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, height=8)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _initialize_cursor_ai(self):
        """Cursor AIシステムを初期化"""
        try:
            self.cursor_ai = CursorAISystem()
            self._update_status("Cursor AIシステム初期化完了")
            self._refresh_files()
        except Exception as e:
            self._update_status(f"初期化エラー: {e}")
            messagebox.showerror(
                "エラー", f"Cursor AIシステムの初期化に失敗しました: {e}"
            )

    def _create_new_tab(self, title: str, content: str = ""):
        """新しいタブを作成"""
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=title)

        editor = scrolledtext.ScrolledText(tab_frame, wrap=tk.WORD)
        editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        editor.insert(tk.END, content)

        return editor

    def _get_current_editor(self):
        """現在のエディターを取得"""
        current_tab = self.notebook.select()
        if current_tab:
            tab_index = self.notebook.index(current_tab)
            tab_frame = self.notebook.nametowidget(current_tab)
            for widget in tab_frame.winfo_children():
                if isinstance(widget, scrolledtext.ScrolledText):
                    return widget
        return None

    def _open_file(self):
        """ファイルを開く"""
        file_path = filedialog.askopenfilename(
            title="ファイルを開く",
            filetypes=[
                ("Python files", "*.py"),
                ("JavaScript files", "*.js"),
                ("TypeScript files", "*.ts"),
                ("HTML files", "*.html"),
                ("CSS files", "*.css"),
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )

        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                file_name = Path(file_path).name
                editor = self._create_new_tab(file_name, content)
                self.current_file = file_path
                self._update_status(f"ファイルを開きました: {file_name}")

            except Exception as e:
                messagebox.showerror("エラー", f"ファイルの読み込みに失敗しました: {e}")

    def _save_file(self):
        """ファイルを保存"""
        editor = self._get_current_editor()
        if not editor:
            return

        content = editor.get("1.0", tk.END)

        if self.current_file:
            file_path = self.current_file
        else:
            file_path = filedialog.asksaveasfilename(
                title="ファイルを保存",
                defaultextension=".py",
                filetypes=[
                    ("Python files", "*.py"),
                    ("JavaScript files", "*.js"),
                    ("TypeScript files", "*.ts"),
                    ("HTML files", "*.html"),
                    ("CSS files", "*.css"),
                    ("JSON files", "*.json"),
                    ("Text files", "*.txt"),
                    ("All files", "*.*"),
                ],
            )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

                self.current_file = file_path
                self._update_status(f"ファイルを保存しました: {Path(file_path).name}")

            except Exception as e:
                messagebox.showerror("エラー", f"ファイルの保存に失敗しました: {e}")

    def _new_file(self):
        """新規ファイルを作成"""
        editor = self._create_new_tab("新規ファイル")
        self.current_file = None
        self._update_status("新規ファイルを作成しました")

    def _refresh_files(self):
        """ファイル一覧を更新"""
        if not self.cursor_ai:
            return

        try:
            workspace_info = self.cursor_ai.get_workspace_info()
            self._update_file_tree(workspace_info.get("file_tree", {}))
        except Exception as e:
            self._update_status(f"ファイル一覧の更新に失敗しました: {e}")

    def _update_file_tree(self, file_tree: Dict[str, Any]):
        """ファイルツリーを更新"""
        # 既存のアイテムをクリア
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        # ファイルツリーを構築
        self._build_file_tree(file_tree, "")

    def _build_file_tree(self, node: Dict[str, Any], parent_id: str):
        """ファイルツリーを再帰的に構築"""
        if node.get("type") == "directory":
            item_id = self.file_tree.insert(
                parent_id, "end", text=node["name"], open=True
            )
            for child in node.get("children", []):
                self._build_file_tree(child, item_id)
        elif node.get("type") == "file":
            self.file_tree.insert(parent_id, "end", text=node["name"])

    def _run_code(self):
        """コードを実行"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードを実行してください:\n```python\n{code}\n```"
        )

    def _debug_code(self):
        """コードをデバッグ"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをデバッグしてください:\n```python\n{code}\n```"
        )

    def _format_code(self):
        """コードをフォーマット"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをフォーマットしてください:\n```python\n{code}\n```"
        )

    def _analyze_code(self):
        """コードを分析"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードを分析してください:\n```python\n{code}\n```"
        )

    def _generate_code(self):
        """コードを生成"""
        description = self.ai_input.get("1.0", tk.END).strip()
        if not description:
            messagebox.showwarning("警告", "コード生成の説明を入力してください")
            return

        self._execute_ai_request(f"コードを生成してください: {description}")

    def _complete_code(self):
        """コードを補完"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードを補完してください:\n```python\n{code}\n```"
        )

    def _refactor_code(self):
        """コードをリファクタリング"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", tk.END).strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをリファクタリングしてください:\n```python\n{code}\n```"
        )

    def _agent_task(self):
        """エージェントタスクを実行"""
        description = self.ai_input.get("1.0", tk.END).strip()
        if not description:
            messagebox.showwarning("警告", "タスクの説明を入力してください")
            return

        self._execute_ai_request(f"エージェントタスクを実行してください: {description}")

    def _execute_ai_request(self, request: str = None):
        """AIリクエストを実行"""
        if not self.cursor_ai:
            messagebox.showerror("エラー", "Cursor AIシステムが初期化されていません")
            return

        if request is None:
            request = self.ai_input.get("1.0", tk.END).strip()

        if not request:
            return

        if self.is_processing:
            messagebox.showwarning("警告", "既に処理中です")
            return

        self.is_processing = True
        self._update_status("AI処理中...")

        # バックグラウンドで実行
        thread = threading.Thread(target=self._process_ai_request, args=(request,))
        thread.daemon = True
        thread.start()

    def _process_ai_request(self, request: str):
        """AIリクエストを処理（バックグラウンド）"""
        try:
            result = self.cursor_ai.process_request(request)

            # UIスレッドで結果を表示
            self.parent.after(0, self._display_result, result)

        except Exception as e:
            self.parent.after(0, self._display_error, str(e))
        finally:
            self.parent.after(0, self._processing_finished)

    def _display_result(self, result: Dict[str, Any]):
        """結果を表示"""
        self.output_text.delete("1.0", tk.END)

        if result.get("success", False):
            self.output_text.insert(tk.END, "=== 実行結果 ===\n")

            if "result" in result:
                if isinstance(result["result"], dict):
                    self.output_text.insert(
                        tk.END,
                        json.dumps(result["result"], ensure_ascii=False, indent=2),
                    )
                else:
                    self.output_text.insert(tk.END, str(result["result"]))

            if "summary" in result:
                self.output_text.insert(
                    tk.END, f"\n\n=== サマリー ===\n{result['summary']}"
                )

            self._update_status("AI処理完了")
        else:
            error = result.get("error", "不明なエラー")
            self.output_text.insert(tk.END, f"エラー: {error}")
            self._update_status(f"AI処理エラー: {error}")

    def _display_error(self, error: str):
        """エラーを表示"""
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"エラー: {error}")
        self._update_status(f"エラー: {error}")

    def _processing_finished(self):
        """処理完了"""
        self.is_processing = False

    def _update_status(self, message: str):
        """ステータスを更新"""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete("1.0", tk.END)
        self.status_text.insert(tk.END, message)
        self.status_text.config(state=tk.DISABLED)

    def run(self):
        """インターフェースを実行"""
        self.parent.mainloop()


def main():
    """メイン関数"""
    app = CursorAIInterface()
    app.run()


if __name__ == "__main__":
    main()
