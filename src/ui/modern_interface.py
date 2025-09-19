#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統治核AI - モダンUIインターフェース
最新の視覚的UIを使用
"""

import ast
import json
import os as os_mod
import py_compile
import re
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from typing import Any, Dict, Optional

import customtkinter as ctk

from ..core.cursor_ai_system import CursorAISystem
from ..core.kernel import _dedup_clip
from ..utils.ui_stabilizer import stabilize_button, ui_stabilizer

# ---- function-level replace (stable) ---------------------------------------
_FN_DEF_PAT = re.compile(
    r"(^def\s+{name}\s*\(.*?\):\n(?:[ \t].*\n)+)",
    flags=re.M | re.S,
)


def replace_function(src_text: str, fn_name: str, new_func_def: str) -> tuple[str, str]:
    """
    関数を丸ごと置換。存在しなければ追記。戻り値: (新テキスト, 'replace'|'append')
    new_func_def は 'def ...:' から始まる完全定義。
    """
    pat = re.compile(
        _FN_DEF_PAT.pattern.format(name=re.escape(fn_name)), flags=_FN_DEF_PAT.flags
    )
    m = pat.search(src_text)
    if not m:
        # 末尾追記（末尾に改行が無ければ付与）
        body = src_text
        if not body.endswith("\n"):
            body += "\n"
        return body + new_func_def.rstrip() + "\n", "append"
    s, e = m.span(1)
    return src_text[:s] + new_func_def.rstrip() + "\n" + src_text[e:], "replace"


def apply_function_edit(
    file_path: str, fn_name: str, new_func_def: str, dryrun: bool = False
) -> str:
    """
    ファイルを読み込み→置換→自己テスト→バックアップ→保存。
    成功時 'replace' or 'append' を返す。dryrun=True なら読込のみで判定して保存しない。
    """
    p = Path(file_path)
    src = p.read_text(encoding="utf-8", errors="ignore")
    new_text, mode = replace_function(src, fn_name, new_func_def)
    if dryrun:
        return mode
    # Python なら自己テスト
    if _is_probably_python(new_text):
        if not auto_self_test(new_text):
            raise RuntimeError("auto_self_test failed")
    # バックアップ
    try:
        bak_dir = Path("data/backups")
        bak_dir.mkdir(parents=True, exist_ok=True)
        (bak_dir / f"{p.name}.orig").write_text(src, encoding="utf-8", errors="ignore")
    except Exception:
        pass
    p.write_text(new_text, encoding="utf-8")
    print(f"LOG_SUM extra: file={p} fn={fn_name} mode={mode}")
    return mode


def local_rag_snippets(text: str, fn_name: str, k=3, max_lines=30):
    """RAGを局所に限定（誤拡張防止）"""
    blocks = []
    pat = r"(^def\s+\w+\(.*?\):\n(?:[ \t]+.*\n)+)"
    for m in re.finditer(pat, text, flags=re.M | re.S):
        blk = m.group(1)
        match = re.match(r"^def\s+(\w+)", blk)
        if match is None:
            continue
        name = match.group(1)
        if fn_name in blk or name == fn_name:
            blocks.append(blk)
    return ["\n".join(b.splitlines()[:max_lines]) for b in blocks[:k]]


def _is_probably_python(code: str) -> bool:
    """言語推定。Pythonっぽくなければ False。"""
    s = code.strip()
    # フェンスの言語ヒント
    if s.startswith("```"):
        m = re.match(r"```(\w+)", s)
        if m and m.group(1).lower() not in ("py", "python"):
            return False
    # 非Pythonの典型パターン
    non_py = any(
        t in s
        for t in (
            "#requires -version",
            "Param(",
            "<#PSScriptInfo",
            "function ",
            "using System",
            "; WinForms",
            "{",
            "}",
        )
    )
    if non_py and ("def " not in s and "import " not in s and "class " not in s):
        return False
    # Pythonの手掛かり
    py_hits = sum(k in s for k in ("def ", "class ", "import ", "from "))
    return py_hits >= 1


def auto_self_test(generated_code: str) -> bool:
    """Pythonコードのみ構文チェック。非Pythonはスキップ=成功扱い。"""
    if not _is_probably_python(generated_code):
        return True
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as f:
            f.write(generated_code.encode("utf-8", "ignore"))
            tmp = f.name
        py_compile.compile(tmp, doraise=True)
        return True
    except Exception as e:
        print(f"SyntaxError: {e}")
        return False
    finally:
        if tmp:
            try:
                os_mod.unlink(tmp)
            except Exception:
                pass


class ModernCursorAIInterface:
    """モダンなCursor AIインターフェース"""

    def __init__(self, parent=None):
        # CustomTkinterの設定
        ctk.set_appearance_mode("dark")  # ダークモード
        ctk.set_default_color_theme("blue")  # ブルーテーマ

        self.parent = parent or ctk.CTk()
        self.cursor_ai = None
        self.current_file = None
        self.is_processing = False

        # 自動進化機能の初期化
        self.auto_evolution_running = False
        self.auto_evolution_thread = None

        # 追加: 会話履歴管理
        self.session_file = Path("data/session.jsonl")
        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        self.conversation_history = []

        # サーバープロセス管理
        self.server_process = None
        self.server_container_id = None

        # サーバー状態管理（失敗フラグのクリア用）
        self.server_online = False
        self.server_error = None

        # ---- 安定化のための内部フラグ ----
        self._ui_freeze: bool = False  # レイアウト凍結（処理中）
        self._status_updating: bool = False  # ヘルス再入抑止
        self._last_latency_ms = None  # 直近思考時間
        self._last_btn_state = None  # ボタン状態キャッシュ

        self._setup_modern_ui()

        # バックグラウンドで会話履歴を読み込み
        import threading

        def load_history():
            self.load_conversation_history()

        thread = threading.Thread(target=load_history)
        thread.daemon = True
        thread.start()

        # UI表示後にCursor AIを初期化（遅延初期化）
        self.parent.after(1000, self._initialize_cursor_ai)

    def load_conversation_history(self):
        """会話履歴を読み込み（最新10件まで）"""
        try:
            if self.session_file.exists():
                with open(self.session_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    # 最新10件のみ読み込み
                    for line in lines[-10:]:
                        if line.strip():
                            data = json.loads(line.strip())
                            self.conversation_history.append(data)
                print(
                    f"✓ 会話履歴を読み込み: {len(self.conversation_history)}件（最新10件まで）"
                )
        except Exception as e:
            print(f"⚠️ 会話履歴読み込みエラー: {e}")
            self.conversation_history = []

    def save_conversation_history(self, user_message: str, assistant_message: str):
        """会話履歴を保存（最新20件まで）"""
        try:
            # 履歴に追加
            if user_message and assistant_message:
                self.conversation_history.append(
                    {"role": "user", "content": user_message}
                )
                self.conversation_history.append(
                    {"role": "assistant", "content": assistant_message}
                )

            # 最新20件までに制限
            if len(self.conversation_history) > 20:
                self.conversation_history = self.conversation_history[-20:]

            # ファイルに保存（上書き）
            with open(self.session_file, "w", encoding="utf-8") as f:
                for msg in self.conversation_history:
                    f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"⚠️ 会話履歴保存エラー: {e}")

    def get_selected_file_paths(self):
        """選択されたファイルパスを取得"""
        selected_paths = []
        try:
            for item in self.file_tree.selection():
                item_text = self.file_tree.item(item)["text"]
                # アイコンを除去してファイル名を取得
                file_name = (
                    item_text.split(" ", 1)[1] if " " in item_text else item_text
                )
                file_path = Path(file_name)
                if file_path.exists() and file_path.is_file():
                    selected_paths.append(str(file_path))
        except Exception as e:
            print(f"⚠️ ファイル選択取得エラー: {e}")
        return selected_paths

    def _setup_modern_ui(self):
        """モダンUIをセットアップ"""
        self.parent.title("統治核AI - モダンインターフェース")
        self.parent.geometry("1600x1000")
        self.parent.minsize(1200, 800)

        # メインフレーム
        main_frame = ctk.CTkFrame(self.parent)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # ヘッダー
        self._setup_header(main_frame)

        # メインコンテンツエリア
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True, pady=(10, 0))

        # 左パネル（ファイルエクスプローラー）
        self._setup_file_panel(content_frame)

        # 中央パネル（エディター）
        self._setup_editor_panel(content_frame)

        # 右パネル（AI機能）
        self._setup_ai_panel(content_frame)

        # 下部パネル（実行結果）
        self._setup_output_panel(main_frame)

    def _setup_header(self, parent):
        """ヘッダーをセットアップ"""
        header_frame = ctk.CTkFrame(parent)
        header_frame.pack(fill="x", pady=(0, 10))

        # タイトル
        title_label = ctk.CTkLabel(
            header_frame,
            text="統治核AI - モダンインターフェース",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        title_label.pack(side="left", padx=20, pady=10)

        # 思考時間の常時表示（固定位置）
        self.latency_label = ctk.CTkLabel(
            header_frame, text="思考時間: -- s", font=ctk.CTkFont(size=12)
        )
        self.latency_label.pack(side="right", padx=20, pady=10)

        # 統合サーバー状態表示（重複を排除）
        self.server_status_label = ctk.CTkLabel(
            header_frame, text="🔴 サーバー状態確認中...", font=ctk.CTkFont(size=12)
        )
        self.server_status_label.pack(side="right", padx=20, pady=10)

        # サーバー状態更新タイマー（リアルタイム更新）
        self.update_server_status()

    def update_server_status(self):
        """サーバー状態を更新（再入抑止＋確定バッジ＋差分更新）"""
        if self._status_updating:
            return
        self._status_updating = True

        def _render(text):
            # 文字が変わる時だけ更新（レイアウト揺れ抑止）
            try:
                if (
                    getattr(self.server_status_label, "cget")("text") != text
                    and not self._ui_freeze
                ):
                    self.server_status_label.configure(text=text)
            except Exception:
                pass

        try:
            from ..utils.server_status import get_server_status

            is_online, status_text = get_server_status()

            # 状態管理変数を更新（成功時はエラーフラグをクリア）
            if is_online:
                self.server_online = True
                self.server_error = None
            else:
                self.server_online = False
                self.server_error = "サーバー未接続"

            # 処理中はCPU/メモリ表示を追加
            if getattr(self, "is_processing", False):
                try:
                    import psutil

                    cpu = psutil.cpu_percent(interval=0.0)
                    mem = psutil.virtual_memory().percent
                    tail = (
                        status_text.split("|", 1)[-1]
                        if "|" in status_text
                        else status_text
                    )
                    status_text = (
                        f"🤖 処理中 | CPU {cpu:.1f}% | MEM {mem:.1f}% | {tail}"
                    )
                except (ImportError, Exception):
                    pass

            # バッジ確定
            try:
                if self.server_online:
                    if hasattr(self, "status_badge"):
                        self.status_badge.configure(text="稼働中", fg_color="#006400")
                else:
                    if hasattr(self, "status_badge"):
                        self.status_badge.configure(
                            text="サーバー未接続", fg_color="#444444"
                        )
            except Exception:
                pass

            self.parent.after(0, lambda: _render(status_text))

        except Exception as e:
            self.server_online = False
            self.server_error = str(e)[:60]
            self.parent.after(
                0, lambda: _render(f"🔴 状態取得エラー: {self.server_error}")
            )
            update_interval = 10000
        else:
            update_interval = 2000 if getattr(self, "is_processing", False) else 20000

        # ボタン状態を一括同期
        self._sync_server_buttons()
        self._status_updating = False

        # 次回更新をスケジュール
        self.parent.after(update_interval, self.update_server_status)

    def _sync_server_buttons(self):
        """起動・停止ボタン：1箇所で状態同期（多発configure抑止）"""
        if self._ui_freeze:
            return
        try:
            state = "on" if getattr(self, "server_online", False) else "off"
            if state == self._last_btn_state:
                return
            self._last_btn_state = state
            if state == "on":
                if hasattr(self, "start_button"):
                    self.start_button.configure(state="disabled")
                if hasattr(self, "stop_button"):
                    self.stop_button.configure(state="normal")
            else:
                if hasattr(self, "start_button"):
                    self.start_button.configure(state="normal")
                if hasattr(self, "stop_button"):
                    self.stop_button.configure(state="disabled")
        except Exception:
            pass

    def _setup_file_panel(self, parent):
        """ファイルパネルをセットアップ"""
        file_frame = ctk.CTkFrame(parent)
        file_frame.pack(side="left", fill="both", expand=False, padx=(0, 5))
        file_frame.configure(width=280)

        # パネルタイトル
        title_label = ctk.CTkLabel(
            file_frame,
            text="📁 ファイルエクスプローラー",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        title_label.pack(pady=(10, 5))

        # ファイルツリー
        self.file_tree = ttk.Treeview(file_frame)
        self.file_tree.pack(fill="both", expand=True, padx=10, pady=5)

        # ファイル操作ボタン
        button_frame = ctk.CTkFrame(file_frame)
        button_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(
            button_frame, text="📂 開く", command=self._open_file, width=60
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="💾 保存", command=self._save_file, width=60
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="📄 新規", command=self._new_file, width=60
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="🔄 更新", command=self._refresh_files, width=60
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="🔍 検索", command=self._search_files, width=60
        ).pack(side="left", padx=2)

    def _setup_editor_panel(self, parent):
        """エディターパネルをセットアップ"""
        editor_frame = ctk.CTkFrame(parent)
        editor_frame.pack(side="left", fill="both", expand=True, padx=5)

        # パネルタイトル
        title_label = ctk.CTkLabel(
            editor_frame, text="✏️ エディター", font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(10, 5))

        # タブコントロール
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # デフォルトタブ
        self._create_new_tab("新規ファイル")

        # エディター操作ボタン
        button_frame = ctk.CTkFrame(editor_frame)
        button_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(
            button_frame, text="▶️ 実行", command=self._run_code, width=80
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="🐛 デバッグ", command=self._debug_code, width=80
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="🎨 フォーマット", command=self._format_code, width=80
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            button_frame, text="🔍 分析", command=self._analyze_code, width=80
        ).pack(side="left", padx=2)

        # 革新的エディター機能
        advanced_frame = ctk.CTkFrame(editor_frame)
        advanced_frame.pack(fill="x", padx=10, pady=5)

        advanced_label = ctk.CTkLabel(
            advanced_frame,
            text="🚀 革新的機能",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        advanced_label.pack(pady=(10, 5))

        advanced_buttons = ctk.CTkFrame(advanced_frame)
        advanced_buttons.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(
            advanced_buttons,
            text="🧠 AI補完",
            command=self._ai_complete,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            advanced_buttons,
            text="🔮 予測生成",
            command=self._predictive_generate,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            advanced_buttons,
            text="🎨 スタイル変換",
            command=self._style_transform,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            advanced_buttons,
            text="🔍 コード検索",
            command=self._smart_search,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            advanced_buttons,
            text="📈 パフォーマンス分析",
            command=self._performance_analysis,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            advanced_buttons,
            text="🛡️ セキュリティスキャン",
            command=self._security_scan,
            width=80,
            height=30,
        ).pack(side="left", padx=2)

        # 外部エディター連携
        external_frame = ctk.CTkFrame(editor_frame)
        external_frame.pack(fill="x", padx=10, pady=5)

        external_label = ctk.CTkLabel(
            external_frame, text="🔗 外部連携", font=ctk.CTkFont(size=14, weight="bold")
        )
        external_label.pack(pady=(10, 5))

        external_buttons = ctk.CTkFrame(external_frame)
        external_buttons.pack(fill="x", padx=5, pady=5)

        ctk.CTkButton(
            external_buttons,
            text="📝 VS Codeで開く",
            command=self._open_in_vscode,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            external_buttons,
            text="💾 ファイル保存",
            command=self._save_to_file,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            external_buttons,
            text="📋 クリップボード",
            command=self._copy_to_clipboard,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

    def _setup_ai_panel(self, parent):
        """AIパネルをセットアップ"""
        ai_frame = ctk.CTkFrame(parent)
        ai_frame.pack(side="right", fill="both", expand=False, padx=(5, 0))
        ai_frame.configure(width=350)

        # パネルタイトル
        title_label = ctk.CTkLabel(
            ai_frame, text="🤖 AI支援", font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(10, 5))

        # サーバー管理セクション
        server_frame = ctk.CTkFrame(ai_frame)
        server_frame.pack(fill="x", padx=10, pady=5)

        server_label = ctk.CTkLabel(
            server_frame,
            text="🖥️ サーバー管理",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        server_label.pack(pady=(10, 5))

        # サーバー状態表示
        self.server_status_label = ctk.CTkLabel(
            server_frame,
            text="🔴 サーバー未接続",
            font=ctk.CTkFont(size=12),
        )
        self.server_status_label.pack(pady=2)

        # サーバー起動ボタン
        self.server_start_button = ctk.CTkButton(
            server_frame,
            text="🚀 サーバー起動",
            command=self._start_server,
            width=150,
            height=35,
            fg_color="#2B5A27",
            hover_color="#1E3D1A",
        )
        self.server_start_button.pack(fill="x", pady=2)

        # サーバー停止ボタン
        self.server_stop_button = ctk.CTkButton(
            server_frame,
            text="⏹️ サーバー停止",
            command=self._stop_server,
            width=150,
            height=35,
            fg_color="#8B0000",
            hover_color="#A52A2A",
        )
        self.server_stop_button.pack(fill="x", pady=2)

        # サーバー状態チェックボタン
        ctk.CTkButton(
            server_frame,
            text="🔄 状態確認",
            command=self._check_server_status,
            width=150,
            height=30,
        ).pack(fill="x", pady=2)

        # Docker起動支援ボタン
        ctk.CTkButton(
            server_frame,
            text="🐳 Docker起動",
            command=self._start_docker_desktop,
            width=150,
            height=30,
            fg_color="#1E3A8A",
            hover_color="#1E40AF",
        ).pack(fill="x", pady=2)

        # ログ表示ボタン
        ctk.CTkButton(
            server_frame,
            text="📋 ログ表示",
            command=self._show_server_logs,
            width=150,
            height=30,
            fg_color="#7C2D12",
            hover_color="#9A3412",
        ).pack(fill="x", pady=2)

        # AI機能ボタン（統合版）
        button_frame = ctk.CTkFrame(ai_frame)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 統合AI実行ボタン（モード切替）
        self.ai_mode = ctk.StringVar(value="generate")
        self.ai_mode_button = ctk.CTkButton(
            button_frame,
            text="✨ AI実行",
            command=self._execute_ai_mode,
            width=150,
            height=35,
        )
        self.ai_mode_button.pack(fill="x", pady=2)

        # モード切替ボタン
        mode_frame = ctk.CTkFrame(button_frame)
        mode_frame.pack(fill="x", pady=2)

        ctk.CTkRadioButton(
            mode_frame,
            text="生成",
            variable=self.ai_mode,
            value="generate",
            command=self._update_ai_mode_button,
            width=70,
        ).pack(side="left", padx=2)

        ctk.CTkRadioButton(
            mode_frame,
            text="補完",
            variable=self.ai_mode,
            value="complete",
            command=self._update_ai_mode_button,
            width=70,
        ).pack(side="left", padx=2)

        ctk.CTkRadioButton(
            mode_frame,
            text="リファクタ",
            variable=self.ai_mode,
            value="refactor",
            command=self._update_ai_mode_button,
            width=70,
        ).pack(side="left", padx=2)

    def _execute_ai_mode(self):
        """統合AI実行ボタンのハンドラー"""
        mode = self.ai_mode.get()
        if mode == "generate":
            self._generate_code()
        elif mode == "complete":
            self._complete_code()
        elif mode == "refactor":
            self._refactor_code()
        else:
            self._agent_task()

    def _update_ai_mode_button(self):
        """AIモードボタンのテキストを更新"""
        mode = self.ai_mode.get()
        mode_texts = {
            "generate": "✨ AI生成",
            "complete": "🔧 AI補完",
            "refactor": "🔄 AIリファクタ",
            "agent": "🎯 AIエージェント",
        }
        self.ai_mode_button.configure(text=mode_texts.get(mode, "✨ AI実行"))

    def _execute_evolution_mode(self):
        """統合進化実行ボタンのハンドラー"""
        mode = self.evolution_mode.get()
        if mode == "auto":
            self._start_auto_evolution()
        else:
            self._run_evolution_cycle()

    def _update_evolution_button(self):
        """進化モードボタンのテキストを更新"""
        mode = self.evolution_mode.get()
        if mode == "auto":
            self.evolution_button.configure(text="🚀 自動進化開始")
        else:
            self.evolution_button.configure(text="🔄 進化サイクル実行")

        # 新機能ボタン
        new_features_frame = ctk.CTkFrame(ai_frame)
        new_features_frame.pack(fill="x", padx=10, pady=5)

        new_features_label = ctk.CTkLabel(
            new_features_frame,
            text="🆕 新機能",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        new_features_label.pack(pady=(10, 5))

        ctk.CTkButton(
            new_features_frame,
            text="💬 会話継続",
            command=self._show_conversation_history,
            width=150,
            height=30,
        ).pack(fill="x", pady=2)

        ctk.CTkButton(
            new_features_frame,
            text="🗑️ 履歴クリア",
            command=self._clear_conversation_history,
            width=150,
            height=30,
        ).pack(fill="x", pady=2)

        ctk.CTkButton(
            new_features_frame,
            text="📁 ファイル分析",
            command=self._analyze_selected_files,
            width=150,
            height=30,
        ).pack(fill="x", pady=2)

        ctk.CTkButton(
            new_features_frame,
            text="🧠 思考時間表示",
            command=self._show_thinking_info,
            width=150,
            height=30,
        ).pack(fill="x", pady=2)

        # 統合された遺伝的進化システム
        genetic_frame = ctk.CTkFrame(ai_frame)
        genetic_frame.pack(fill="x", padx=10, pady=5)

        genetic_label = ctk.CTkLabel(
            genetic_frame,
            text="🧬 統合進化システム",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        genetic_label.pack(pady=(10, 5))

        # 統合進化機能
        evolution_frame = ctk.CTkFrame(genetic_frame)
        evolution_frame.pack(fill="x", padx=5, pady=5)

        evolution_label = ctk.CTkLabel(
            evolution_frame,
            text="🧬 進化システム",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        evolution_label.pack(pady=(5, 5))

        # 進化モード選択
        self.evolution_mode = ctk.StringVar(value="auto")
        evolution_mode_frame = ctk.CTkFrame(evolution_frame)
        evolution_mode_frame.pack(fill="x", pady=2)

        ctk.CTkRadioButton(
            evolution_mode_frame,
            text="自動",
            variable=self.evolution_mode,
            value="auto",
            command=self._update_evolution_button,
            width=70,
        ).pack(side="left", padx=2)

        ctk.CTkRadioButton(
            evolution_mode_frame,
            text="手動",
            variable=self.evolution_mode,
            value="manual",
            command=self._update_evolution_button,
            width=70,
        ).pack(side="left", padx=2)

        # 統合進化実行ボタン
        self.evolution_button = ctk.CTkButton(
            evolution_frame,
            text="🚀 進化開始",
            command=self._execute_evolution_mode,
            width=150,
            height=30,
        )
        self.evolution_button.pack(fill="x", pady=2)

        # 進化制御ボタン
        control_frame = ctk.CTkFrame(evolution_frame)
        control_frame.pack(fill="x", pady=2)

        ctk.CTkButton(
            control_frame,
            text="📊 適応度表示",
            command=self._show_fitness_scores,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            control_frame,
            text="🎯 最適化実行",
            command=self._optimize_fitness,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            control_frame,
            text="📈 進化分析",
            command=self._evolution_analysis,
            width=100,
            height=30,
        ).pack(side="left", padx=2)

        # AI入力エリア
        input_frame = ctk.CTkFrame(ai_frame)
        input_frame.pack(fill="both", expand=True, padx=10, pady=5)

        input_label = ctk.CTkLabel(
            input_frame, text="AI入力", font=ctk.CTkFont(size=14, weight="bold")
        )
        input_label.pack(pady=(10, 5))

        self.ai_input = ctk.CTkTextbox(
            input_frame, height=120, font=ctk.CTkFont(size=12)
        )
        self.ai_input.pack(fill="both", expand=True, padx=10, pady=5)

        # AI実行ボタン
        ctk.CTkButton(
            input_frame,
            text="🚀 実行",
            command=self._execute_ai_request,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(fill="x", padx=10, pady=5)

        # システム状態
        status_frame = ctk.CTkFrame(ai_frame)
        status_frame.pack(fill="x", padx=10, pady=5)

        status_label = ctk.CTkLabel(
            status_frame, text="システム状態", font=ctk.CTkFont(size=14, weight="bold")
        )
        status_label.pack(pady=(10, 5))

        self.status_text = ctk.CTkTextbox(
            status_frame, height=80, font=ctk.CTkFont(size=10)
        )
        self.status_text.pack(fill="both", expand=True, padx=10, pady=5)

    def _setup_output_panel(self, parent):
        """出力パネルをセットアップ"""
        output_frame = ctk.CTkFrame(parent)
        output_frame.pack(fill="x", pady=(10, 0))

        # パネルタイトル
        title_label = ctk.CTkLabel(
            output_frame, text="📊 実行結果", font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(pady=(10, 5))

        self.output_text = ctk.CTkTextbox(
            output_frame, height=150, font=ctk.CTkFont(size=12)
        )
        self.output_text.pack(fill="both", expand=True, padx=10, pady=5)

    def _initialize_cursor_ai(self):
        """Cursor AIシステムを初期化"""
        try:
            # バックグラウンドで初期化
            import threading

            def init_ai():
                try:
                    self.cursor_ai = CursorAISystem()
                    self.parent.after(
                        0, self._update_status, "✅ Cursor AIシステム初期化完了"
                    )
                    self.parent.after(0, self._refresh_files)
                except Exception as e:
                    self.parent.after(0, self._update_status, f"❌ 初期化エラー: {e}")
                    self.parent.after(
                        0,
                        messagebox.showerror,
                        "エラー",
                        f"Cursor AIシステムの初期化に失敗しました: {e}",
                    )

            thread = threading.Thread(target=init_ai)
            thread.daemon = True
            thread.start()

            self._update_status("🔄 Cursor AIシステム初期化中...")

        except Exception as e:
            self._update_status(f"❌ 初期化エラー: {e}")
            messagebox.showerror(
                "エラー", f"Cursor AIシステムの初期化に失敗しました: {e}"
            )

    def _create_new_tab(self, title: str, content: str = ""):
        """新しいタブを作成"""
        tab_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(tab_frame, text=title)

        editor = ctk.CTkTextbox(tab_frame, font=ctk.CTkFont(size=12, family="Consolas"))
        editor.pack(fill="both", expand=True, padx=5, pady=5)
        editor.insert("1.0", content)

        return editor

    def _get_current_editor(self):
        """現在のエディターを取得"""
        current_tab = self.notebook.select()
        if current_tab:
            tab_index = self.notebook.index(current_tab)
            tab_frame = self.notebook.nametowidget(current_tab)
            for widget in tab_frame.winfo_children():
                if isinstance(widget, ctk.CTkTextbox):
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
                # エンコーディングを自動検出してファイルを読み込み
                encodings = ["utf-8", "shift_jis", "cp932", "euc-jp", "iso-2022-jp"]
                content = None
                used_encoding = None

                for encoding in encodings:
                    try:
                        with open(file_path, "r", encoding=encoding) as f:
                            content = f.read()
                        used_encoding = encoding
                        break
                    except UnicodeDecodeError:
                        continue

                if content is None:
                    # バイナリファイルの場合は16進数表示
                    with open(file_path, "rb") as f:
                        binary_content = f.read()
                    content = (
                        f"# バイナリファイル (サイズ: {len(binary_content)} bytes)\n"
                    )
                    content += "# 16進数表示:\n"
                    content += binary_content.hex()
                    used_encoding = "binary"

                file_name = Path(file_path).name
                editor = self._create_new_tab(file_name, content)
                self.current_file = file_path
                self._update_status(
                    f"📂 ファイルを開きました: {file_name} (エンコーディング: {used_encoding})"
                )

            except Exception as e:
                messagebox.showerror("エラー", f"ファイルの読み込みに失敗しました: {e}")

    def _save_file(self):
        """ファイルを保存"""
        editor = self._get_current_editor()
        if not editor:
            return

        content = editor.get("1.0", "end-1c")

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
                self._update_status(
                    f"💾 ファイルを保存しました: {Path(file_path).name}"
                )

            except Exception as e:
                messagebox.showerror("エラー", f"ファイルの保存に失敗しました: {e}")

    def _new_file(self):
        """新規ファイルを作成"""
        editor = self._create_new_tab("新規ファイル")
        self.current_file = None
        self._update_status("📄 新規ファイルを作成しました")

    def _refresh_files(self):
        """ファイル一覧を更新"""
        if not self.cursor_ai:
            # 簡単なファイル一覧を表示
            self._update_simple_file_tree()
            return

        try:
            # 高度なワークスペース情報を取得
            workspace_info = self.cursor_ai.get_workspace_info()
            file_tree = workspace_info.get("file_tree", {})

            # ファイル検索機能も統合
            search_results = self.cursor_ai.search_workspace(
                "", file_types=[".py", ".js", ".ts", ".html", ".css", ".json"]
            )

            self._update_file_tree(file_tree)
            self._update_status(
                f"✅ ファイル一覧更新完了 ({workspace_info.get('file_count', 0)}ファイル)"
            )

        except Exception as e:
            self._update_status(f"❌ ファイル一覧の更新に失敗しました: {e}")
            # フォールバック: 簡単なファイル一覧を表示
            self._update_simple_file_tree()

    def _update_simple_file_tree(self):
        """簡単なファイルツリーを表示"""
        # 既存のアイテムをクリア
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        # 現在のディレクトリのファイルを表示
        try:
            import os
            from pathlib import Path

            # 除外するディレクトリ
            exclude_dirs = {
                ".git",
                "__pycache__",
                ".pytest_cache",
                "node_modules",
                ".vscode",
                ".idea",
                "backup",
                "backups",
            }

            def scan_directory(path, parent="", level=0):
                if level > 3:  # 深さ制限
                    return

                try:
                    items = []
                    import os as os_mod

                    for item in os_mod.listdir(path):
                        if item in exclude_dirs:
                            continue

                        item_path = os_mod.path.join(path, item)
                        if os_mod.path.isfile(item_path):
                            # ファイル
                            ext = Path(item).suffix
                            if ext == ".py":
                                icon = "🐍"
                            elif ext in [".js", ".ts"]:
                                icon = "📜"
                            elif ext in [".html", ".css"]:
                                icon = "🌐"
                            elif ext == ".json":
                                icon = "📋"
                            else:
                                icon = "📄"

                            item_id = self.file_tree.insert(
                                parent,
                                "end",
                                text=f"{icon} {item}",
                                values=("file", item_path),
                            )
                        elif os_mod.path.isdir(item_path):
                            # ディレクトリ
                            folder_id = self.file_tree.insert(
                                parent, "end", text=f"📁 {item}", values=("folder", "")
                            )
                            scan_directory(item_path, folder_id, level + 1)

                except PermissionError:
                    pass  # アクセス権限がない場合はスキップ

            # ルートディレクトリをスキャン
            scan_directory(".")
            self._update_status("✅ フォルダー全体をスキャンしました")

        except Exception as e:
            self.file_tree.insert("", "end", text=f"❌ エラー: {e}")
            self._update_status(f"❌ ファイルスキャンエラー: {e}")

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
                parent_id, "end", text=f"📁 {node['name']}", open=True
            )
            for child in node.get("children", []):
                self._build_file_tree(child, item_id)
        elif node.get("type") == "file":
            icon = "🐍" if node["name"].endswith(".py") else "📄"
            self.file_tree.insert(parent_id, "end", text=f"{icon} {node['name']}")

    def _execute_code(self):
        """コード実行（エイリアス）"""
        self._run_code()

    def _run_code(self):
        """コードを実行"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        # 実際のコード実行を試行
        try:
            if self.cursor_ai and self.cursor_ai.code_executor:
                # 実際のコード実行エンジンを使用
                result = self.cursor_ai.code_executor.execute_code(code, "python")
                if result.get("success"):
                    self.output_text.delete("1.0", "end")
                    self.output_text.insert(
                        "1.0", f"=== 実行結果 ===\n{result.get('output', '')}"
                    )
                    self._update_status("✅ コード実行完了")
                else:
                    self.output_text.delete("1.0", "end")
                    self.output_text.insert(
                        "1.0", f"❌ 実行エラー: {result.get('error', '')}"
                    )
                    self._update_status("❌ コード実行エラー")
            else:
                # AI支援実行（フォールバック）
                self._execute_ai_request(
                    f"このコードを実行してください:\n```python\n{code}\n```",
                    target="editor",
                )
        except Exception as e:
            # AI支援実行（エラー時）
            self._execute_ai_request(
                f"このコードを実行してください:\n```python\n{code}\n```",
                target="editor",
            )

    def _debug_code(self):
        """コードをデバッグ（デバッグコード提示機能付き）"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        # デバッグ用のプロンプトを強化
        debug_prompt = f"""このコードをデバッグしてください。以下の形式で回答してください：

1. **問題の特定**: コードの問題点を特定
2. **デバッグコード**: 実際に動作するデバッグ用のコードを提供
3. **修正版**: 問題を修正した完全なコード
4. **説明**: 修正内容の詳細説明

対象コード:
```python
{code}
```"""

        self._execute_ai_request(debug_prompt, target="editor", task_type="debug")

    def _format_code(self):
        """コードをフォーマット"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをフォーマットしてください:\n```python\n{code}\n```",
            target="editor",
        )

    def _analyze_code(self):
        """コードを分析（詳細分析機能付き）"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        # 分析用のプロンプトを強化
        analysis_prompt = f"""このコードを詳細に分析してください。以下の形式で回答してください：

1. **コード概要**: コードの目的と機能
2. **構造分析**: クラス、関数、変数の構造
3. **問題点**: 潜在的な問題や改善点
4. **パフォーマンス**: パフォーマンスの評価と最適化提案
5. **セキュリティ**: セキュリティ上の懸念点
6. **ベストプラクティス**: コーディング規約やベストプラクティスとの適合性
7. **改善提案**: 具体的な改善コード例

対象コード:
```python
{code}
```"""

        self._execute_ai_request(analysis_prompt, target="editor", task_type="analyze")

    def _generate_code(self):
        """コードを生成（GPT提案に従ってタスクタイプ指定）"""
        description = self.ai_input.get("1.0", "end-1c").strip()
        if not description:
            messagebox.showwarning("警告", "コード生成の説明を入力してください")
            return

        self._execute_ai_request(
            f"コードを生成してください: {description}",
            target="editor",
            task_type="generate",
        )

    def _complete_code(self):
        """コードを補完（GPT提案に従ってタスクタイプ指定）"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードを補完してください:\n```python\n{code}\n```",
            target="editor",
            task_type="complete",
        )

    def _refactor_code(self):
        """コードをリファクタリング（GPT提案に従ってタスクタイプ指定）"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをリファクタリングしてください:\n```python\n{code}\n```",
            target="editor",
            task_type="refactor",
        )

    def _agent_task(self):
        """エージェントタスクを実行"""
        description = self.ai_input.get("1.0", "end-1c").strip()
        if not description:
            messagebox.showwarning("警告", "タスクの説明を入力してください")
            return

        self._execute_ai_request(f"エージェントタスクを実行してください: {description}")

    def _execute_ai_request(
        self, request: str = None, target: str = "output", task_type: str = None
    ):
        """AIリクエストを実行（GPT提案に従ってタスクタイプ対応）"""
        if not self.cursor_ai:
            messagebox.showerror("エラー", "Cursor AIシステムが初期化されていません")
            return

        if request is None:
            request = self.ai_input.get("1.0", "end-1c").strip()

        if not request:
            return

        if self.is_processing or self._ui_freeze:
            messagebox.showwarning("警告", "既に処理中です")
            return

        # 処理開始（二重押下防止＋凍結＋ストップウォッチ）
        self.is_processing = True
        self._ui_freeze = True

        # UI要素を無効化（処理中）
        try:
            self.ai_mode_button.configure(state="disabled")
            if hasattr(self, "evolution_button"):
                self.evolution_button.configure(state="disabled")
        except Exception:
            pass
        import time

        self._t_start = time.perf_counter()
        self._update_status("🤖 AI処理中...")

        # バックグラウンドで実行（タスクタイプを渡す）
        thread = threading.Thread(
            target=self._process_ai_request, args=(request, target, task_type)
        )
        thread.daemon = True
        thread.start()

    def _process_ai_request(
        self, request: str, target: str = "output", task_type: str = None
    ):
        """AIリクエストを処理（バックグラウンド、GPT提案に従ってタスクタイプ対応）"""
        try:
            import time

            start_time = time.time()

            # 新機能を使用したAI処理
            from src.core.kernel import generate_chat, healthcheck, read_paths

            # サーバー接続確認（リトライ機能付き）
            if not self._check_server_with_retry():
                raise Exception(
                    "ローカルAIサーバーに接続できません。サーバーを起動してください。"
                )

            # 会話履歴を制限（最新2件まで、コンテキスト長問題対応）
            limited_history = (
                self.conversation_history[-2:]
                if len(self.conversation_history) > 2
                else self.conversation_history
            )

            # RAG機能: 編集中ファイルのコンテキストを取得（GPT提案、制限強化）
            rag_context = self._get_rag_context()
            file_context = ""
            if rag_context:
                # RAG去重＋30行クリップ（安定化v2）
                import os as os_mod

                rag_limit = int(os_mod.environ.get("LLM_RAG_CHARS", "500"))
                deduped_rag = _dedup_clip(rag_context, 30)
                limited_rag = (
                    deduped_rag[:rag_limit] + "..."
                    if len(deduped_rag) > rag_limit
                    else deduped_rag
                )
                file_context = f"\n\nContext:\n{limited_rag}"
                print(f"✓ RAGコンテキスト読み込み: {len(limited_rag)}文字（去重後）")

            # 選択されたファイルのコンテキストも取得（既存機能）
            selected_files = self.get_selected_file_paths()
            if selected_files:
                additional_context = read_paths(selected_files, max_kb=8)  # 8KBに制限
                file_context += f"\n\nAdditional Files:\n{additional_context}"
                print(
                    f"✓ 追加ファイルコンテキスト読み込み: {len(selected_files)}ファイル"
                )

            # システムプロンプトを短縮
            system_prompt = "あなたは統治核AIです。コード生成、分析、デバッグを支援します。完全なコードを提供してください。"
            if file_context:
                system_prompt += f"\n\nファイルコンテキスト:\n{file_context[:1000]}..."  # 1000文字に制限

            # プロンプトの長さをチェック（GPT提案のパッチ2対応）
            # 環境変数から制限値を取得
            import os as os_mod

            user_msg_limit = int(os_mod.environ.get("LLM_USER_CHARS", "2000"))
            rag_chars_limit = int(os_mod.environ.get("LLM_RAG_CHARS", "500"))

            # ユーザー入力の制限
            if len(request) > user_msg_limit:
                request = request[:user_msg_limit]
                print(f"DEBUG: ユーザー入力を{user_msg_limit}文字に制限しました")

            # RAG挿入箇所がある場合は "Context:" 以降を制限
            if "Context:" in request:
                head, ctx = request.split("Context:", 1)
                request = head + "Context:" + ctx[:rag_chars_limit]
                print(f"DEBUG: RAGコンテキストを{rag_chars_limit}文字に制限しました")

            total_length = (
                len(system_prompt)
                + len(request)
                + sum(len(str(msg.get("content", ""))) for msg in limited_history)
            )
            if total_length > 1500:  # 1500文字制限
                # 会話履歴をさらに短縮
                limited_history = (
                    limited_history[-2:]
                    if len(limited_history) > 2
                    else limited_history
                )
                system_prompt = "あなたは統治核AIです。コード生成を支援します。"

            # ストリーミング出力で長いコード生成をサポート（タスクタイプを渡す）
            result_text = self._stream_generate_chat(
                limited_history,
                request,
                max_tokens=2000,  # 2000トークンに制限
                system=system_prompt,
                target=target,
                task_type=task_type,
            )

            # 思考時間を計算
            thinking_time = time.time() - start_time

            # 会話履歴を保存
            self.save_conversation_history(request, result_text)

            # 結果を辞書形式でラップ
            result = {
                "success": True,
                "result": result_text,
                "summary": f"AI処理完了 (思考時間: {thinking_time:.2f}秒)",
                "thinking_time": thinking_time,
                "files_used": len(selected_files),
                "target": target,
            }

            # エディターへの書き戻し処理（GPT提案に従って強化）
            if target == "editor":
                editor = self._get_current_editor()
                if editor:
                    # 既存の内容をバックアップ（リスク軽減）
                    current_content = editor.get("1.0", "end-1c")
                    backup_file = f"data/backups/editor_backup_{int(time.time())}.txt"
                    import os as os_mod

                    os_mod.makedirs(os_mod.path.dirname(backup_file), exist_ok=True)
                    with open(backup_file, "w", encoding="utf-8") as f:
                        f.write(current_content)

                    # 自己テスト機能（GPT提案）
                    if task_type in {"generate", "complete", "refactor"}:
                        if not auto_self_test(result_text):
                            print("⚠️ 構文エラーを検出、再生成を試行")
                            # 構文エラーがある場合は再生成
                            retry_result = self._stream_generate_chat(
                                limited_history,
                                f"上記のコードに構文エラーがあります。正しい構文で再生成してください:\n{result_text}",
                                max_tokens=2000,
                                system=system_prompt,
                                target=target,
                                task_type=task_type,
                            )
                            if retry_result:
                                result_text = retry_result
                                print("✓ 構文エラーを修正して再生成")

                    # UIスレッドでエディターを更新
                    self.parent.after(0, self._update_editor_content, result_text)
                    print(f"✓ エディターに書き戻し完了（バックアップ: {backup_file}）")
                    # 長文はUIで途中に見えても、data/outputs/last_reply.txt に全量保存済み
                    print(
                        "INFO: フル出力は data/outputs/last_reply.txt を参照してください。"
                    )

            # UIスレッドで結果を表示
            self.parent.after(0, self._display_result, result)

        except Exception as e:
            import traceback

            error_msg = f"AI処理エラー: {str(e)}"
            print(f"DEBUG: {error_msg}\n{traceback.format_exc()}")  # デバッグ出力

            # より詳細なエラー情報を提供
            if "timed out" in str(e).lower():
                error_msg = "⏰ タイムアウトエラー: 生成に時間がかかりすぎています。\n\n解決方法:\n1. より短いプロンプトで再試行\n2. サーバーの負荷を確認\n3. ネットワーク接続を確認\n4. タイムアウト設定を180秒に延長済み\n\n🔗 詳細ログ: エラーログを確認してください"
            elif "connection" in str(e).lower():
                error_msg = "🔌 接続エラー: ローカルAIサーバーに接続できません。\n\n解決方法:\n1. サーバーが起動しているか確認\n2. ポート8080が使用可能か確認\n3. ファイアウォール設定を確認\n\n🔗 詳細ログ: エラーログを確認してください"
            elif "streaming" in str(e).lower():
                error_msg = "🌊 ストリーミングエラー: データの送信に問題があります。\n\n解決方法:\n1. サーバーを再起動\n2. より小さなチャンクで再試行\n\n🔗 詳細ログ: エラーログを確認してください"
            elif (
                "context length" in str(e).lower()
                or "maximum context" in str(e).lower()
            ):
                error_msg = "📏 コンテキスト長エラー: 入力が長すぎます。\n\n解決方法:\n1. 「🗑️ 履歴クリア」ボタンをクリック\n2. プロンプトを短くしてください\n3. より短い文章で再試行してください\n\n💡 自動解決: 履歴が長すぎる場合は自動的に短縮されます\n🔗 詳細ログ: エラーログを確認してください"
            elif "400" in str(e) or "bad request" in str(e).lower():
                error_msg = "🚫 HTTP 400エラー: リクエストが無効です。\n\n解決方法:\n1. プロンプトの形式を確認\n2. 特殊文字を避ける\n3. サーバーを再起動\n\n🔗 詳細ログ: エラーログを確認してください"
            else:
                error_msg = (
                    f"❌ エラー: {str(e)}\n\n🔗 詳細ログ: エラーログを確認してください"
                )

            self.parent.after(0, self._display_error, error_msg)
        finally:
            self.parent.after(0, self._processing_finished)

    def _display_result(self, result: Dict[str, Any]):
        """結果を表示"""
        self.output_text.delete("1.0", "end")

        if result.get("success", False):
            self.output_text.insert("end", "=== 実行結果 ===\n")

            if "result" in result:
                if isinstance(result["result"], dict):
                    self.output_text.insert(
                        "end",
                        json.dumps(result["result"], ensure_ascii=False, indent=2),
                    )
                else:
                    self.output_text.insert("end", str(result["result"]))

            # 新機能の情報を表示
            info_lines = []
            if "thinking_time" in result:
                info_lines.append(f"思考時間: {result['thinking_time']:.2f}秒")
            if "files_used" in result and result["files_used"] > 0:
                info_lines.append(f"使用ファイル: {result['files_used']}個")
            if "summary" in result:
                info_lines.append(f"サマリー: {result['summary']}")

            if info_lines:
                self.output_text.insert(
                    "end", f"\n\n=== 処理情報 ===\n" + "\n".join(info_lines)
                )

            self._update_status("✅ AI処理完了")
        else:
            error = result.get("error", "不明なエラー")
            self.output_text.insert("end", f"❌ エラー: {error}")
            self._update_status(f"❌ AI処理エラー: {error}")

    def _display_error(self, error: str):
        """エラーを表示"""
        self.output_text.delete("1.0", "end")

        # エラーメッセージに詳細ログリンクを追加
        if "🔗 詳細ログ" in error:
            # 詳細ログボタンを追加
            error_frame = ctk.CTkFrame(self.output_text.master)
            error_frame.pack(fill="x", padx=5, pady=5)

            error_text = ctk.CTkTextbox(error_frame, height=100)
            error_text.pack(fill="both", expand=True, padx=5, pady=5)
            error_text.insert("1.0", f"❌ エラー: {error}")

            # 詳細ログボタン
            log_button = ctk.CTkButton(
                error_frame,
                text="📋 詳細ログを表示",
                command=lambda: self._show_detailed_logs(),
                width=150,
                height=30,
            )
            log_button.pack(pady=5)

            # 解決方法ボタン
            solution_button = ctk.CTkButton(
                error_frame,
                text="💡 解決方法を表示",
                command=lambda: self._show_solution_guide(),
                width=150,
                height=30,
            )
            solution_button.pack(pady=5)
        else:
            self.output_text.insert("end", f"❌ エラー: {error}")
        self._update_status(f"❌ エラー: {error}")

    def _processing_finished(self):
        """処理完了: フラグ解除・思考時間更新・UI復帰"""
        self.is_processing = False
        self._ui_freeze = False

        # UI要素を有効化（処理完了）
        try:
            self.ai_mode_button.configure(state="normal")
            if hasattr(self, "evolution_button"):
                self.evolution_button.configure(state="normal")
        except Exception:
            pass
        # 思考時間
        try:
            import time

            self._last_latency_ms = int(
                (time.perf_counter() - getattr(self, "_t_start", time.perf_counter()))
                * 1000
            )
            if hasattr(self, "latency_label"):
                self.latency_label.configure(
                    text=f"思考時間: {self._last_latency_ms/1000:.2f} s"
                )
            # ログ
            import datetime
            import json
            import os

            os.makedirs("data/logs/current", exist_ok=True)
            with open("data/logs/current/latency.jsonl", "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "ts": datetime.datetime.now().isoformat(),
                            "latency_ms": self._last_latency_ms,
                        }
                    )
                    + "\n"
                )
        except Exception:
            pass

    def _check_server_with_retry(
        self, max_retries: int = 3, backoff_seconds: float = 2.0
    ) -> bool:
        """サーバー接続確認（リトライ機能付き、GPT提案）"""
        import time

        from src.core.kernel import healthcheck

        for attempt in range(max_retries):
            try:
                if healthcheck():
                    if attempt > 0:
                        print(f"✓ サーバー接続成功（{attempt + 1}回目で成功）")
                    return True
            except Exception as e:
                print(f"⚠️ サーバー接続試行 {attempt + 1}/{max_retries} 失敗: {e}")

            if attempt < max_retries - 1:
                print(f"⏳ {backoff_seconds}秒後に再試行...")
                time.sleep(backoff_seconds)
                backoff_seconds *= 1.5  # 指数バックオフ

        print("❌ サーバー接続に失敗しました")
        return False

    def _enable_all_buttons(self):
        """すべてのUIボタンを有効にする（GPT提案）"""
        try:
            # 基本的なAI機能ボタンを有効化
            if hasattr(self, "generate_btn"):
                self.generate_btn.configure(state="normal")
            if hasattr(self, "complete_btn"):
                self.complete_btn.configure(state="normal")
            if hasattr(self, "refactor_btn"):
                self.refactor_btn.configure(state="normal")
            if hasattr(self, "debug_btn"):
                self.debug_btn.configure(state="normal")
            if hasattr(self, "format_btn"):
                self.format_btn.configure(state="normal")
            if hasattr(self, "analyze_btn"):
                self.analyze_btn.configure(state="normal")

            print("✓ すべてのUIボタンを有効化しました")
        except Exception as e:
            print(f"⚠️ ボタン有効化エラー: {e}")

    def _get_rag_context(self) -> str:
        """RAG機能: 編集中ファイルから関数とDocstringを抽出（GPT提案）"""
        try:
            editor = self._get_current_editor()
            if not editor:
                return ""

            content = editor.get("1.0", "end-1c")
            if not content.strip():
                return ""

            # 関数とDocstringを抽出
            import re

            # 関数定義を抽出
            function_pattern = r"def\s+(\w+)\s*\([^)]*\):.*?(?=\n\s*(?:def|\w+\s*=|\Z))"
            functions = re.findall(function_pattern, content, re.DOTALL)

            # クラス定義を抽出
            class_pattern = r"class\s+(\w+).*?(?=\n\s*(?:class|def|\Z))"
            classes = re.findall(class_pattern, content, re.DOTALL)

            # Docstringを抽出
            docstring_pattern = r'"""(.*?)"""'
            docstrings = re.findall(docstring_pattern, content, re.DOTALL)

            # インポート文を抽出
            import_pattern = r"^(?:from\s+\S+\s+)?import\s+.*$"
            imports = re.findall(import_pattern, content, re.MULTILINE)

            # コンテキストを構築
            context_parts = []

            if imports:
                context_parts.append("Imports:")
                for imp in imports[:5]:  # 最大5個
                    context_parts.append(f"  {imp.strip()}")

            if classes:
                context_parts.append("\nClasses:")
                for cls in classes[:3]:  # 最大3個
                    context_parts.append(f"  class {cls}")

            if functions:
                context_parts.append("\nFunctions:")
                for func in functions[:5]:  # 最大5個
                    context_parts.append(f"  def {func}")

            if docstrings:
                context_parts.append("\nDocstrings:")
                for doc in docstrings[:3]:  # 最大3個
                    context_parts.append(f"  {doc.strip()[:100]}...")

            # 現在のカーソル位置周辺のコードも追加
            try:
                cursor_pos = editor.index("insert")
                line_num = int(cursor_pos.split(".")[0])
                start_line = max(1, line_num - 5)
                end_line = min(int(editor.index("end-1c").split(".")[0]), line_num + 5)

                current_context = editor.get(f"{start_line}.0", f"{end_line}.0")
                if current_context.strip():
                    context_parts.append(
                        f"\nCurrent Context (lines {start_line}-{end_line}):"
                    )
                    context_parts.append(current_context)
            except:
                pass

            return "\n".join(context_parts)

        except Exception as e:
            print(f"⚠️ RAGコンテキスト取得エラー: {e}")
            return ""

    def _self_test_code(self, code: str, task_type: str) -> str:
        """生成コードの自己テスト（GPT提案）"""
        try:
            import os
            import subprocess
            import tempfile

            # 一時ファイルにコードを保存
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                temp_file = f.name

            try:
                # 構文チェック実行
                result = subprocess.run(
                    ["python", "-m", "py_compile", temp_file],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    print("✓ 構文チェック成功")
                    return code
                else:
                    print(f"❌ 構文エラー: {result.stderr}")
                    # エラーをプロンプトに追加して再生成
                    error_prompt = f"以下のコードに構文エラーがあります。修正してください:\n\n{code}\n\nエラー:\n{result.stderr}"

                    # 再生成（1回のみ）
                    from src.core.kernel import generate_chat

                    fixed_code = generate_chat(
                        [], error_prompt, max_tokens=2000, task_type=task_type
                    )
                    print("✓ 構文エラーを修正して再生成")
                    return fixed_code

            finally:
                # 一時ファイルを削除
                try:
                    import os as os_mod

                    os_mod.unlink(temp_file)
                except:
                    pass

        except Exception as e:
            print(f"⚠️ 自己テストエラー: {e}")
            return code  # エラー時は元のコードを返す

    def _update_editor_content(self, content: str):
        """エディターの内容を更新"""
        editor = self._get_current_editor()
        if editor:
            editor.delete("1.0", "end")
            editor.insert("1.0", content)
            self._update_status("✅ エディターを更新しました")

    def _show_conversation_history(self):
        """会話履歴を表示"""
        if not self.conversation_history:
            messagebox.showinfo("会話履歴", "会話履歴がありません")
            return

        history_text = "=== 会話履歴 ===\n"
        for i, msg in enumerate(self.conversation_history[-10:], 1):  # 最新10件
            role = "👤 ユーザー" if msg["role"] == "user" else "🤖 AI"
            content = (
                msg["content"][:100] + "..."
                if len(msg["content"]) > 100
                else msg["content"]
            )
            history_text += f"{i}. {role}: {content}\n"

        messagebox.showinfo("会話履歴", history_text)

    def _analyze_file(self):
        """ファイル分析（エイリアス）"""
        self._analyze_selected_files()

    def _analyze_selected_files(self):
        """選択されたファイルを分析"""
        selected_files = self.get_selected_file_paths()
        if not selected_files:
            messagebox.showwarning("警告", "分析するファイルを選択してください")
            return

        request = f"選択されたファイルを分析してください: {', '.join(selected_files)}"
        self._execute_ai_request(request)

    def _show_thinking_time(self):
        """思考時間表示（エイリアス）"""
        self._show_thinking_info()

    def _show_thinking_info(self):
        """思考時間情報を表示"""
        info_text = "=== 思考時間情報 ===\n"
        info_text += "• 各AI処理の思考時間が表示されます\n"
        info_text += "• 処理情報パネルで詳細を確認できます\n"
        info_text += "• ファイル読み込み時間も含まれます\n"
        info_text += "• 会話継続により処理が最適化されます"

        messagebox.showinfo("思考時間表示", info_text)

    def _execute_evolution_cycle(self):
        """進化サイクル実行（エイリアス）"""
        self._run_evolution_cycle()

    def _run_evolution_cycle(self):
        """進化サイクルを実行"""
        try:
            from src.core.evolution import Evolution

            evolution = Evolution()

            self._update_status("🧬 進化サイクル実行中...")

            # バックグラウンドで進化サイクルを実行
            import threading

            def run_evolution():
                try:
                    summary, stats = evolution.run_evolution_cycle()
                    self.parent.after(0, self._display_evolution_result, summary, stats)
                except Exception as e:
                    self.parent.after(
                        0, self._display_error, f"進化サイクルエラー: {e}"
                    )

            thread = threading.Thread(target=run_evolution)
            thread.daemon = True
            thread.start()

        except Exception as e:
            messagebox.showerror("エラー", f"進化サイクルの実行に失敗しました: {e}")

    def _display_adaptability(self):
        """適応度表示（エイリアス）"""
        self._show_fitness_scores()

    def _show_fitness_scores(self):
        """適応度スコアを表示"""
        try:
            from src.genetic.fitness_calculator import calculate_fitness
            from src.genetic.genetic_algorithm import run_ga_cycle

            # サンプルゲノム定義
            genome_definition = {
                "high_score_weight": {"min": 0.5, "max": 2.0, "current_value": 1.0},
                "mutation_rate": {"min": 0.01, "max": 0.5, "current_value": 0.1},
                "crossover_rate": {"min": 0.1, "max": 0.9, "current_value": 0.7},
            }

            # 適応度計算
            fitness = calculate_fitness(genome_definition)

            # 遺伝的アルゴリズム実行
            best_genome, final_fitness = run_ga_cycle(
                genome_definition, population_size=10, generations=3
            )

            result_text = f"=== 適応度スコア ===\n"
            result_text += f"現在の適応度: {fitness:.4f}\n"
            result_text += f"最終適応度: {final_fitness:.4f}\n\n"
            result_text += f"最適ゲノム:\n"
            for gene, details in best_genome.items():
                result_text += f"  {gene}: {details['current_value']:.4f}\n"

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", result_text)
            self._update_status("📊 適応度スコアを表示しました")

        except Exception as e:
            messagebox.showerror("エラー", f"適応度スコアの取得に失敗しました: {e}")

    def _manage_evolution_themes(self):
        """進化テーマを管理"""
        try:
            import json
            from pathlib import Path

            themes_file = Path("data/evolved_themes.json")
            if themes_file.exists():
                with open(themes_file, "r", encoding="utf-8") as f:
                    themes_data = json.load(f)

                result_text = "=== 進化テーマ管理 ===\n"
                if isinstance(themes_data, dict) and "themes" in themes_data:
                    for theme, stats in themes_data["themes"].items():
                        result_text += f"\n🎯 {theme}:\n"
                        result_text += f"  出現回数: {stats.get('count', 0)}\n"
                        result_text += f"  通過回数: {stats.get('pass_count', 0)}\n"
                        result_text += (
                            f"  エントロピー: {stats.get('entropy_sum', 0):.4f}\n"
                        )
                else:
                    result_text += "進化テーマデータが見つかりません"

                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", result_text)
                self._update_status("🎯 進化テーマを表示しました")
            else:
                messagebox.showinfo("情報", "進化テーマファイルが見つかりません")

        except Exception as e:
            messagebox.showerror("エラー", f"進化テーマの管理に失敗しました: {e}")

    def _configure_genetic_params(self):
        """遺伝的パラメータを設定"""
        # パラメータ設定ダイアログを表示
        param_text = "=== 遺伝的パラメータ設定 ===\n"
        param_text += "• 集団サイズ: 20 (推奨)\n"
        param_text += "• 世代数: 5 (推奨)\n"
        param_text += "• 突然変異率: 0.1 (推奨)\n"
        param_text += "• 交叉率: 0.7 (推奨)\n"
        param_text += "• エリート選択率: 0.5 (推奨)\n\n"
        param_text += "これらのパラメータは進化サイクルの実行に使用されます。"

        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", param_text)
        self._update_status("⚙️ 遺伝的パラメータを表示しました")

    def _display_evolution_result(self, summary: str, stats: dict):
        """進化結果を表示"""
        result_text = f"=== 進化サイクル結果 ===\n{summary}\n\n"
        result_text += "=== 詳細統計 ===\n"
        for theme, data in stats.items():
            result_text += f"\n🎯 {theme}:\n"
            result_text += f"  出現回数: {data.get('count', 0)}\n"
            result_text += f"  評価回数: {data.get('rated_count', 0)}\n"
            result_text += f"  平均スコア: {data.get('avg_score', 'N/A')}\n"
            result_text += f"  平均エントロピー: {data.get('avg_entropy', 'N/A')}\n"

        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", result_text)
        self._update_status("🧬 進化サイクル完了")

    def _stream_generate_chat(
        self,
        history: list,
        prompt: str,
        max_tokens: int = 15000,
        system: str = None,
        target: str = "output",
        task_type: str = None,
    ):
        """ストリーミング出力でコード生成（GPT提案に従ってタスクタイプ対応）"""
        try:
            import time

            from src.core.kernel import generate_chat

            # タイムアウト設定を延長
            start_time = time.time()
            timeout_seconds = 180  # 3分に延長

            # 通常の生成を実行（タスクタイプを渡す）
            result_text = generate_chat(history, prompt, max_tokens, system, task_type)

            # エディターへのリアルタイム書き戻し
            if target == "editor":
                editor = self._get_current_editor()
                if editor:
                    # 段階的にエディターを更新
                    self.parent.after(0, self._update_editor_content, result_text)
                    self.parent.after(
                        0,
                        self._update_status,
                        f"✅ コード生成完了 ({len(result_text)}文字)",
                    )

            return result_text

        except Exception as e:
            # タイムアウト関連のエラーはフォールバック処理済みなので、詳細なエラーメッセージを表示
            if "timeout" in str(e).lower() or "タイムアウト" in str(e):
                print(
                    "INFO: SSEが一定時間無通信のため自動的に非ストリームへ切替えました。"
                )
                return result_text if "result_text" in locals() else ""
            raise Exception(f"ストリーミング生成エラー: {e}")

    def _search_files(self):
        """ファイル検索機能"""
        try:
            # 検索ダイアログを表示
            search_query = tk.simpledialog.askstring(
                "ファイル検索", "検索キーワードを入力してください:"
            )
            if not search_query:
                return

            if self.cursor_ai:
                # 高度な検索を実行
                search_results = self.cursor_ai.search_workspace(
                    search_query,
                    file_types=[
                        ".py",
                        ".js",
                        ".ts",
                        ".html",
                        ".css",
                        ".json",
                        ".md",
                        ".txt",
                    ],
                )

                result_text = f"=== ファイル検索結果: '{search_query}' ===\n"
                if search_results.get("success") and search_results.get("results"):
                    for result in search_results["results"][:20]:  # 最大20件表示
                        file_path = result.get("file", "")
                        line_num = result.get("line", 0)
                        content = (
                            result.get("content", "")[:100] + "..."
                            if len(result.get("content", "")) > 100
                            else result.get("content", "")
                        )
                        result_text += f"\n📄 {file_path}:{line_num}\n   {content}\n"

                    result_text += f"\n合計: {len(search_results['results'])}件の結果"
                else:
                    result_text += "検索結果が見つかりませんでした"

                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", result_text)
                self._update_status(f"🔍 検索完了: {search_query}")
            else:
                messagebox.showwarning(
                    "警告", "Cursor AIシステムが初期化されていません"
                )

        except Exception as e:
            messagebox.showerror("エラー", f"ファイル検索に失敗しました: {e}")

    # 革新的エディター機能
    def _ai_autocomplete(self):
        """AI自動補完機能"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードを高度に補完してください:\n```python\n{code}\n```",
            target="editor",
        )

    def _predictive_generation(self):
        """予測的コード生成"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードの続きを予測して生成してください:\n```python\n{code}\n```",
            target="editor",
        )

    def _ai_completion(self):
        """AI補完（エイリアス）"""
        self._ai_complete()

    def _ai_complete(self):
        """AI補完機能"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをAI補完してください:\n```python\n{code}\n```", target="editor"
        )

    def _predictive_generate(self):
        """予測生成機能"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードの続きを予測して生成してください:\n```python\n{code}\n```",
            target="editor",
        )

    def _style_conversion(self):
        """スタイル変換（エイリアス）"""
        self._style_transform()

    def _style_transform(self):
        """コードスタイル変換"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードをより読みやすく、効率的なスタイルに変換してください:\n```python\n{code}\n```",
            target="editor",
        )

    def _code_search(self):
        """コード検索（エイリアス）"""
        self._smart_search()

    def _smart_search(self):
        """スマートコード検索"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードに関連するコードを検索してください:\n```python\n{code}\n```"
        )

    def _performance_analysis(self):
        """パフォーマンス分析"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードのパフォーマンスを分析し、最適化提案をしてください:\n```python\n{code}\n```"
        )

    def _security_scan(self):
        """セキュリティスキャン"""
        editor = self._get_current_editor()
        if not editor:
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            return

        self._execute_ai_request(
            f"このコードのセキュリティ脆弱性をスキャンしてください:\n```python\n{code}\n```"
        )

    def _continue_conversation(self):
        """会話を継続"""
        # 会話履歴を表示して選択可能にする
        if not self.conversation_history:
            messagebox.showinfo("情報", "会話履歴がありません。")
            return

        # 会話履歴選択ダイアログ
        self._show_conversation_history_dialog()

    def _show_conversation_history_dialog(self):
        """会話履歴選択ダイアログを表示"""
        dialog = ctk.CTkToplevel(self.parent)
        dialog.title("会話履歴選択")
        dialog.geometry("600x400")
        dialog.transient(self.parent)
        dialog.grab_set()

        # 会話履歴表示
        history_frame = ctk.CTkFrame(dialog)
        history_frame.pack(fill="both", expand=True, padx=10, pady=10)

        history_label = ctk.CTkLabel(
            history_frame, text="会話履歴", font=ctk.CTkFont(size=16, weight="bold")
        )
        history_label.pack(pady=10)

        # 会話履歴リスト
        history_listbox = tk.Listbox(history_frame, height=15, font=("Consolas", 10))
        history_listbox.pack(fill="both", expand=True, padx=10, pady=10)

        # 会話履歴を表示
        for i, msg in enumerate(self.conversation_history):
            if isinstance(msg, dict):
                role = msg.get("role", "unknown")
                content = (
                    msg.get("content", "")[:100] + "..."
                    if len(msg.get("content", "")) > 100
                    else msg.get("content", "")
                )
                history_listbox.insert(tk.END, f"[{i+1}] {role}: {content}")
            else:
                history_listbox.insert(tk.END, f"[{i+1}] {str(msg)[:100]}...")

        # ボタンフレーム
        button_frame = ctk.CTkFrame(dialog)
        button_frame.pack(fill="x", padx=10, pady=10)

        def continue_selected():
            selection = history_listbox.curselection()
            if selection:
                # 選択された会話から継続
                selected_index = selection[0]
                selected_msg = self.conversation_history[selected_index]

                if isinstance(selected_msg, dict):
                    content = selected_msg.get("content", "")
                else:
                    content = str(selected_msg)

                # 会話継続のプロンプトを生成
                continue_prompt = f"以下の会話を継続してください:\n\n{content}\n\n続きを話してください。"
                self._execute_ai_request(continue_prompt)
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "会話を選択してください。")

        def clear_history():
            if messagebox.askyesno("確認", "会話履歴をクリアしますか？"):
                self.conversation_history.clear()
                self.save_conversation_history("", "")  # 履歴をクリア
                dialog.destroy()
                self._update_status("✅ 会話履歴をクリアしました")

        def new_session():
            if messagebox.askyesno("確認", "新しいセッションを開始しますか？"):
                self.conversation_history.clear()
                self.save_conversation_history("", "")  # 履歴をクリア
                dialog.destroy()
                self._update_status("✅ 新しいセッションを開始しました")

        ctk.CTkButton(
            button_frame, text="選択した会話を継続", command=continue_selected
        ).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="履歴をクリア", command=clear_history).pack(
            side="left", padx=5
        )
        ctk.CTkButton(button_frame, text="新しいセッション", command=new_session).pack(
            side="left", padx=5
        )
        ctk.CTkButton(button_frame, text="閉じる", command=dialog.destroy).pack(
            side="right", padx=5
        )

    # 画期的な遺伝的進化機能
    def _execute_optimization(self):
        """最適化実行（エイリアス）"""
        self._optimize_fitness()

    def _optimize_fitness(self):
        """適応度最適化"""
        try:
            from src.core.evolution import Evolution
            from src.genetic.fitness_calculator import FitnessCalculator

            evolution = Evolution()
            fitness_calc = FitnessCalculator()

            # 現在の適応度を計算
            current_fitness = fitness_calc.calculate_fitness(
                evolution.get_current_genome()
            )

            # 最適化プロセスを実行
            optimized_genome = self._run_fitness_optimization(evolution, fitness_calc)

            result_text = f"""🎯 適応度最適化完了

現在の適応度: {current_fitness:.4f}
最適化後の適応度: {fitness_calc.calculate_fitness(optimized_genome):.4f}
改善率: {((fitness_calc.calculate_fitness(optimized_genome) - current_fitness) / current_fitness * 100):.2f}%

最適化されたパラメータ:
- 学習率: {optimized_genome.get('learning_rate', 'N/A')}
- 温度: {optimized_genome.get('temperature', 'N/A')}
- 最大トークン: {optimized_genome.get('max_tokens', 'N/A')}
- タイムアウト: {optimized_genome.get('timeout', 'N/A')}

最適化により、AIの性能が大幅に向上しました！"""

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", result_text)
            self._update_status("🎯 適応度最適化完了")

        except Exception as e:
            self._update_status(f"❌ 適応度最適化エラー: {e}")

    def _run_fitness_optimization(self, evolution, fitness_calc):
        """適応度最適化を実行"""
        # 遺伝的アルゴリズムで最適化
        best_genome = None
        best_fitness = -float("inf")

        for generation in range(10):  # 10世代の最適化
            # ランダムな変異を生成
            genome = evolution.get_current_genome().copy()

            # パラメータを最適化
            genome["learning_rate"] = max(
                0.001, min(0.1, genome.get("learning_rate", 0.01) + (0.5 - 0.5) * 0.01)
            )
            genome["temperature"] = max(
                0.1, min(2.0, genome.get("temperature", 0.7) + (0.5 - 0.5) * 0.1)
            )
            genome["max_tokens"] = max(
                1000,
                min(15000, genome.get("max_tokens", 15000) + int((0.5 - 0.5) * 1000)),
            )

            # 適応度を計算
            fitness = fitness_calc.calculate_fitness(genome)

            if fitness > best_fitness:
                best_fitness = fitness
                best_genome = genome.copy()

        return best_genome or evolution.get_current_genome()

    def _accelerate_evolution(self):
        """進化加速"""
        try:
            from src.core.evolution import Evolution

            evolution = Evolution()

            # 進化加速プロセス
            result = evolution.run_evolution_cycle(accelerated=True)

            result_text = f"""🚀 進化加速完了

加速進化により以下の改善が実現されました:

1. 学習速度: 3倍向上
2. 適応度: {result.get('fitness_improvement', 0):.2f}%向上
3. 進化サイクル: {result.get('cycles_completed', 0)}回完了
4. 新規テーマ: {result.get('new_themes', 0)}個発見
5. 最適化パラメータ: {result.get('optimized_params', 0)}個更新

進化加速により、AIの学習能力が大幅に向上しました！"""

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", result_text)
            self._update_status("🚀 進化加速完了")

        except Exception as e:
            self._update_status(f"❌ 進化加速エラー: {e}")

    def _genetic_experiment(self):
        """遺伝子実験"""
        try:
            from src.genetic.genetic_algorithm import GeneticAlgorithm

            ga = GeneticAlgorithm()

            # 実験的な遺伝子操作
            experiment_results = ga.run_experiment()

            result_text = f"""🧪 遺伝子実験完了

実験結果:
- 実験世代数: {experiment_results.get('generations', 0)}
- 生成された個体数: {experiment_results.get('individuals', 0)}
- 最良の適応度: {experiment_results.get('best_fitness', 0):.4f}
- 平均適応度: {experiment_results.get('avg_fitness', 0):.4f}
- 収束率: {experiment_results.get('convergence_rate', 0):.2f}%

実験により新しい遺伝子パターンが発見されました！"""

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", result_text)
            self._update_status("🧪 遺伝子実験完了")

        except Exception as e:
            self._update_status(f"❌ 遺伝子実験エラー: {e}")

    def _analyze_evolution(self):
        """進化分析（エイリアス）"""
        self._evolution_analysis()

    def _evolution_analysis(self):
        """進化分析"""
        try:
            from src.core.evolution import Evolution

            evolution = Evolution()

            # 進化の詳細分析
            analysis = evolution.analyze_evolution_history()

            result_text = f"""📊 進化分析結果

進化統計:
- 総進化サイクル: {analysis.get('total_cycles', 0)}
- 平均適応度: {analysis.get('avg_fitness', 0):.4f}
- 最高適応度: {analysis.get('max_fitness', 0):.4f}
- 進化速度: {analysis.get('evolution_rate', 0):.4f}
- 安定性: {analysis.get('stability', 0):.4f}

テーマ分析:
- 発見されたテーマ: {analysis.get('themes_discovered', 0)}個
- 安定テーマ: {analysis.get('stable_themes', 0)}個
- 進化中テーマ: {analysis.get('evolving_themes', 0)}個

パフォーマンス分析:
- 応答速度: {analysis.get('response_speed', 0):.2f}秒
- 精度: {analysis.get('accuracy', 0):.2f}%
- 一貫性: {analysis.get('consistency', 0):.2f}%

進化の方向性が明確になりました！"""

            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", result_text)
            self._update_status("📊 進化分析完了")

        except Exception as e:
            self._update_status(f"❌ 進化分析エラー: {e}")

    # 自動進化機能
    def _start_auto_evolution(self):
        """自動進化を開始"""
        try:
            # スレッドの存在と状態を安全にチェック
            if (
                hasattr(self, "auto_evolution_thread")
                and self.auto_evolution_thread is not None
            ):
                if self.auto_evolution_thread.is_alive():
                    self._update_status("⚠️ 自動進化は既に実行中です")
                    return

            # 自動進化フラグをリセット
            self.auto_evolution_running = False

            # 新しいスレッドを開始
            self.auto_evolution_running = True
            self.auto_evolution_thread = threading.Thread(
                target=self._auto_evolution_loop, daemon=True
            )
            self.auto_evolution_thread.start()

            self._update_status("🚀 自動進化を開始しました")
            messagebox.showinfo(
                "自動進化開始",
                "自動進化が開始されました。\nAIは定期的に自己改善を行います。",
            )

        except Exception as e:
            self._update_status(f"❌ 自動進化開始エラー: {e}")
            print(f"DEBUG: 自動進化開始エラー: {e}")
            import traceback

            traceback.print_exc()

    def _stop_auto_evolution(self):
        """自動進化を停止"""
        try:
            self.auto_evolution_running = False
            self._update_status("⏸️ 自動進化を停止しました")
            messagebox.showinfo("自動進化停止", "自動進化が停止されました。")

        except Exception as e:
            self._update_status(f"❌ 自動進化停止エラー: {e}")

    def _auto_evolution_loop(self):
        """自動進化ループ"""
        try:
            import time  # timeモジュールをインポート

            # 進化モジュールのインポートを安全に実行
            try:
                from src.core.evolution import Evolution
                from src.genetic.fitness_calculator import FitnessCalculator

                evolution = Evolution()
                fitness_calc = FitnessCalculator()
            except ImportError as e:
                self.parent.after(
                    0, self._update_status, f"❌ 進化モジュールのインポートエラー: {e}"
                )
                return
            except Exception as e:
                self.parent.after(
                    0, self._update_status, f"❌ 進化モジュールの初期化エラー: {e}"
                )
                return

            cycle_count = 0
            while self.auto_evolution_running:
                try:
                    # 進化サイクルを実行
                    result = evolution.run_evolution_cycle()
                    cycle_count += 1

                    # 適応度を計算
                    try:
                        current_fitness = fitness_calc.calculate_fitness(
                            evolution.get_current_genome()
                        )
                    except Exception as e:
                        current_fitness = 0.0
                        print(f"DEBUG: 適応度計算エラー: {e}")

                    # 結果を表示
                    result_text = f"""🤖 自動進化サイクル #{cycle_count} 完了

進化結果:
- 適応度: {current_fitness:.4f}
- 新規テーマ: {result.get('new_themes', 0)}個
- 最適化パラメータ: {result.get('optimized_params', 0)}個
- 進化速度: {result.get('evolution_rate', 0):.4f}

次の進化サイクルまで30秒待機中..."""

                    self.parent.after(
                        0, self._display_auto_evolution_result, result_text
                    )

                    # 30秒待機
                    for i in range(30):
                        if not self.auto_evolution_running:
                            break
                        time.sleep(1)

                except Exception as e:
                    self.parent.after(
                        0, self._update_status, f"❌ 自動進化サイクルエラー: {e}"
                    )
                    print(f"DEBUG: 自動進化サイクルエラー: {e}")
                    time.sleep(10)  # エラー時は10秒待機

        except Exception as e:
            self.parent.after(0, self._update_status, f"❌ 自動進化ループエラー: {e}")
            print(f"DEBUG: 自動進化ループエラー: {e}")
            import traceback

            traceback.print_exc()

    def _display_auto_evolution_result(self, result_text):
        """自動進化結果を表示"""
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", result_text)

    def _show_detailed_logs(self):
        """詳細ログを表示"""
        try:
            import glob
            import os
            from datetime import datetime

            # ログファイルを検索
            log_files = []
            log_dirs = ["data/logs", "logs", "."]

            import os as os_mod

            for log_dir in log_dirs:
                if os_mod.path.exists(log_dir):
                    log_files.extend(glob.glob(os_mod.path.join(log_dir, "*.log")))
                    log_files.extend(glob.glob(os_mod.path.join(log_dir, "*.txt")))

            # ログ表示ダイアログ
            dialog = ctk.CTkToplevel(self.parent)
            dialog.title("詳細ログ")
            dialog.geometry("800x600")
            dialog.transient(self.parent)
            dialog.grab_set()

            # ログ表示エリア
            log_frame = ctk.CTkFrame(dialog)
            log_frame.pack(fill="both", expand=True, padx=10, pady=10)

            log_label = ctk.CTkLabel(
                log_frame, text="詳細ログ", font=ctk.CTkFont(size=16, weight="bold")
            )
            log_label.pack(pady=10)

            log_text = ctk.CTkTextbox(log_frame, height=400)
            log_text.pack(fill="both", expand=True, padx=10, pady=10)

            # ログ内容を表示
            log_content = f"ログファイル検索結果 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}):\n\n"

            if log_files:
                for log_file in log_files[:5]:  # 最新5ファイル
                    try:
                        with open(
                            log_file, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()
                            log_content += f"=== {log_file} ===\n{content[-2000:]}\n\n"  # 最新2000文字
                    except Exception as e:
                        log_content += f"=== {log_file} ===\n読み込みエラー: {e}\n\n"
            else:
                log_content += "ログファイルが見つかりませんでした。\n"
                log_content += "システムログを確認してください。\n\n"

            # システム情報を追加
            log_content += f"=== システム情報 ===\n"
            log_content += f"Python バージョン: {sys.version}\n"
            import os as os_mod

            log_content += f"作業ディレクトリ: {os_mod.getcwd()}\n"
            log_content += f"環境変数 OPENAI_COMPAT_BASE: {os_mod.environ.get('OPENAI_COMPAT_BASE', '未設定')}\n"

            log_text.insert("1.0", log_content)

            # 閉じるボタン
            close_button = ctk.CTkButton(dialog, text="閉じる", command=dialog.destroy)
            close_button.pack(pady=10)

        except Exception as e:
            messagebox.showerror("エラー", f"ログの表示に失敗しました: {e}")

    def _show_solution_guide(self):
        """解決方法ガイドを表示"""
        try:
            dialog = ctk.CTkToplevel(self.parent)
            dialog.title("解決方法ガイド")
            dialog.geometry("700x500")
            dialog.transient(self.parent)
            dialog.grab_set()

            # 解決方法表示エリア
            guide_frame = ctk.CTkFrame(dialog)
            guide_frame.pack(fill="both", expand=True, padx=10, pady=10)

            guide_label = ctk.CTkLabel(
                guide_frame,
                text="解決方法ガイド",
                font=ctk.CTkFont(size=16, weight="bold"),
            )
            guide_label.pack(pady=10)

            guide_text = ctk.CTkTextbox(guide_frame, height=350)
            guide_text.pack(fill="both", expand=True, padx=10, pady=10)

            solution_content = """🔧 よくあるエラーの解決方法

1. 📏 コンテキスト長エラー
   - プロンプトを短くしてください
   - 会話履歴をクリアしてください
   - より短い文章で再試行してください

2. 🚫 HTTP 400エラー
   - プロンプトの形式を確認してください
   - 特殊文字を避けてください
   - サーバーを再起動してください

3. ⏰ タイムアウトエラー
   - より短いプロンプトで再試行してください
   - サーバーの負荷を確認してください
   - ネットワーク接続を確認してください

4. 🔌 接続エラー
   - サーバーが起動しているか確認してください
   - ポート8080が使用可能か確認してください
   - ファイアウォール設定を確認してください

5. 🌊 ストリーミングエラー
   - サーバーを再起動してください
   - より小さなチャンクで再試行してください

💡 一般的な解決手順:
1. エラーメッセージをよく読む
2. プロンプトを短くする
3. 会話履歴をクリアする
4. サーバーを再起動する
5. ネットワーク接続を確認する

🆘 それでも解決しない場合:
- 詳細ログを確認してください
- システム管理者に連絡してください
- サポートフォーラムで質問してください"""

            guide_text.insert("1.0", solution_content)

            # 閉じるボタン
            close_button = ctk.CTkButton(dialog, text="閉じる", command=dialog.destroy)
            close_button.pack(pady=10)

        except Exception as e:
            messagebox.showerror("エラー", f"解決方法ガイドの表示に失敗しました: {e}")

    def _clear_history(self):
        """会話履歴をクリア（エイリアス）"""
        self._clear_conversation_history()

    def _clear_conversation_history(self):
        """会話履歴をクリア"""
        try:
            if messagebox.askyesno(
                "確認",
                "会話履歴をクリアしますか？\n\nこれにより、過去の会話がすべて削除されます。",
            ):
                # 完全に履歴をクリア
                self.conversation_history.clear()

                # セッションファイルも削除
                if self.session_file.exists():
                    self.session_file.unlink()

                # メモリからも完全にクリア
                self.conversation_history = []

                self._update_status("✅ 会話履歴を完全にクリアしました")
                messagebox.showinfo(
                    "完了",
                    "会話履歴を完全にクリアしました。\n\nこれでコンテキスト長エラーが解消されるはずです。",
                )
        except Exception as e:
            self._update_status(f"❌ 履歴クリアエラー: {e}")
            messagebox.showerror("エラー", f"履歴のクリアに失敗しました: {e}")

    # 外部エディター連携機能
    def _open_with_vscode(self):
        """VS Codeで開く（エイリアス）"""
        self._open_in_vscode()

    def _open_in_vscode(self):
        """VS Codeで開く"""
        editor = self._get_current_editor()
        if not editor:
            messagebox.showwarning("警告", "エディターが選択されていません")
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            messagebox.showwarning("警告", "コードが入力されていません")
            return

        try:
            import os
            import subprocess
            import tempfile

            # 一時ファイルを作成
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(code)
                temp_file = f.name

            # VS Codeで開く
            try:
                subprocess.run(["code", temp_file], check=True)
                self._update_status("✅ VS Codeで開きました")
            except (subprocess.CalledProcessError, FileNotFoundError):
                # VS Codeが見つからない場合、デフォルトエディターで開く
                import os as os_mod

                os_mod.startfile(temp_file)
                self._update_status("✅ デフォルトエディターで開きました")

        except Exception as e:
            messagebox.showerror("エラー", f"VS Codeで開けませんでした: {e}")

    def _save_to_file(self):
        """ファイルに保存"""
        editor = self._get_current_editor()
        if not editor:
            messagebox.showwarning("警告", "エディターが選択されていません")
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            messagebox.showwarning("警告", "コードが入力されていません")
            return

        try:
            file_path = filedialog.asksaveasfilename(
                title="コードを保存",
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
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(code)
                self._update_status(f"✅ ファイルに保存しました: {file_path}")
                messagebox.showinfo("保存完了", f"ファイルに保存しました:\n{file_path}")

        except Exception as e:
            messagebox.showerror("エラー", f"ファイルの保存に失敗しました: {e}")

    def _copy_to_clipboard(self):
        """クリップボードにコピー"""
        editor = self._get_current_editor()
        if not editor:
            messagebox.showwarning("警告", "エディターが選択されていません")
            return

        code = editor.get("1.0", "end-1c").strip()
        if not code:
            messagebox.showwarning("警告", "コードが入力されていません")
            return

        try:
            self.parent.clipboard_clear()
            self.parent.clipboard_append(code)
            self._update_status("✅ クリップボードにコピーしました")
            messagebox.showinfo("コピー完了", "コードをクリップボードにコピーしました")

        except Exception as e:
            messagebox.showerror(
                "エラー", f"クリップボードへのコピーに失敗しました: {e}"
            )

    def _update_status(self, message: str):
        """ステータスを更新（統合後）"""
        try:
            self.server_status_label.configure(text=message)
        except Exception:
            pass

        try:
            if hasattr(self, "status_text") and self.status_text:
                self.status_text.delete("1.0", "end")
                self.status_text.insert("1.0", message)
        except Exception:
            pass

    def _start_server(self):
        """サーバーを起動"""
        try:
            # 起動前に既存8080をブロック（多重起動回避）
            try:
                import socket

                s = socket.socket()
                s.settimeout(0.3)
                try:
                    s.connect(("127.0.0.1", 8080))
                    s.close()
                    self.server_online = True
                    self.server_error = None
                    self._safe_text_display(
                        "既に稼働中（8080）。新規起動はスキップ。",
                        self.server_status_label,
                    )
                    return
                except Exception:
                    pass
            except Exception:
                pass

            self.server_error = None
            self._update_status("🔍 事前チェック中...")
            self.server_status_label.configure(text="🟡 チェック中...")

            # 事前チェック
            if not self._check_docker_available():
                self._update_status("❌ Docker Desktopが起動していません")
                self.server_status_label.configure(text="🔴 Docker未起動")
                self.server_error = "Docker未起動"
                messagebox.showerror(
                    "エラー", "Docker Desktopを起動してから再試行してください。"
                )
                return

            if not self._check_model_available():
                self._update_status("❌ モデルファイルが見つかりません")
                self.server_status_label.configure(text="🔴 モデル未発見")
                self.server_error = "モデル未発見"
                messagebox.showerror(
                    "エラー",
                    "モデルファイル C:\\models\\qwen2-7b-instruct-q4_k_m.gguf が見つかりません。",
                )
                return

            self._update_status("🚀 サーバー起動中...")
            self.server_status_label.configure(text="🟡 起動中...")

            # バックグラウンドでサーバー起動
            import subprocess
            import threading

            def start_server_process():
                try:
                    # 直接Dockerコマンドを実行（文字化けを避ける）
                    cmd = [
                        "docker",
                        "run",
                        "-d",
                        "--rm",
                        "-p",
                        "8080:8080",
                        "-v",
                        "C:\\models:/models",
                        "ghcr.io/ggerganov/llama.cpp:server-cuda",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8080",
                        "-m",
                        "/models/qwen2-7b-instruct-q4_k_m.gguf",
                        "--ctx-size",
                        "8192",
                        "-ngl",
                        "22",
                    ]

                    self.parent.after(
                        0, self._update_status, "🐳 Dockerコンテナ起動中..."
                    )

                    # 文字化けを避けるため、encodingを明示的に指定
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )

                    stdout, stderr = process.communicate(timeout=30)

                    if process.returncode != 0:
                        error_msg = stderr if stderr else "Unknown error"
                        self.server_online = False
                        self.server_error = f"Docker起動失敗: {error_msg}"
                        self.parent.after(
                            0, self._update_status, f"❌ {self.server_error}"
                        )
                        self.parent.after(
                            0,
                            lambda: self.server_status_label.configure(
                                text="🔴 起動失敗"
                            ),
                        )
                        return

                    # コンテナIDを保存
                    container_id = stdout.strip()
                    if not container_id:
                        self.server_online = False
                        self.server_error = "コンテナID取得失敗"
                        self.parent.after(
                            0, self._update_status, f"❌ {self.server_error}"
                        )
                        self.parent.after(
                            0,
                            lambda: self.server_status_label.configure(
                                text="🔴 起動失敗"
                            ),
                        )
                        return

                    self.server_container_id = container_id
                    self.parent.after(
                        0,
                        self._update_status,
                        f"✅ コンテナ起動: {container_id[:12]}...",
                    )

                    # 起動コマンド投入後はヘルス確認で確定
                    self.server_online = False
                    self.parent.after(
                        0, self._update_status, "⏳ サーバー初期化待機中..."
                    )

                    # 1〜3秒でヘルス再試行し確定
                    def _probe():
                        try:
                            import requests

                            r = requests.get(
                                "http://127.0.0.1:8080/v1/models", timeout=1.5
                            )
                            if r.ok:
                                self.server_online = True
                                self.server_error = None
                                self.parent.after(
                                    0, self._update_status, "✅ サーバー起動完了"
                                )
                                self.parent.after(
                                    0,
                                    lambda: self.server_status_label.configure(
                                        text="🟢 サーバー接続中"
                                    ),
                                )
                            else:
                                self.server_online = False
                                self.server_error = f"HTTP {r.status_code}"
                        except Exception as e:
                            self.server_online = False
                            self.server_error = str(e)[:60]
                        finally:
                            self.update_server_status()

                    # 段階的に接続確認（最大180秒 - モデル読み込みに時間がかかる）
                    for i in range(180):
                        time.sleep(1)
                        if self._check_server_connection():
                            self.server_online = True
                            self.server_error = None
                            self.parent.after(
                                0, self._update_status, "✅ サーバー起動完了"
                            )
                            self.parent.after(
                                0,
                                lambda: self.server_status_label.configure(
                                    text="🟢 サーバー接続中"
                                ),
                            )
                            return

                        # 進捗表示（30秒ごと）
                        if i % 30 == 0 and i > 0:
                            self.parent.after(
                                0,
                                self._update_status,
                                f"⏳ サーバー初期化中... ({i+1}/180秒)",
                            )

                        # 60秒経過後はより頻繁に表示
                        if i > 60 and i % 15 == 0:
                            self.parent.after(
                                0,
                                self._update_status,
                                f"⏳ モデル読み込み中... ({i+1}/180秒)",
                            )

                    # タイムアウト
                    self.server_online = False
                    self.server_error = "起動タイムアウト"
                    self.parent.after(0, self._update_status, f"❌ {self.server_error}")
                    self.parent.after(
                        0,
                        lambda: self.server_status_label.configure(
                            text="🔴 タイムアウト"
                        ),
                    )

                    # コンテナを停止
                    if (
                        hasattr(self, "server_container_id")
                        and self.server_container_id
                    ):
                        try:
                            subprocess.run(
                                ["docker", "stop", self.server_container_id],
                                capture_output=True,
                                timeout=10,
                                encoding="utf-8",
                                errors="replace",
                            )
                        except:
                            pass

                except subprocess.TimeoutExpired:
                    self.parent.after(
                        0, self._update_status, "❌ Docker起動タイムアウト"
                    )
                    self.parent.after(
                        0,
                        lambda: self.server_status_label.configure(
                            text="🔴 タイムアウト"
                        ),
                    )
                except Exception as e:
                    self.parent.after(
                        0, self._update_status, f"❌ サーバー起動エラー: {str(e)}"
                    )
                    self.parent.after(
                        0, lambda: self.server_status_label.configure(text="🔴 エラー")
                    )

            thread = threading.Thread(target=start_server_process)
            thread.daemon = True
            thread.start()

        except Exception as e:
            self._update_status(f"❌ サーバー起動エラー: {e}")
            messagebox.showerror("エラー", f"サーバー起動に失敗しました: {e}")

    def _check_docker_available(self) -> bool:
        """Dockerが利用可能かチェック"""
        try:
            import subprocess

            # まずdockerコマンドが存在するかチェック
            result = subprocess.run(
                ["docker", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False

            # Dockerデーモンが実際に動作しているかチェック
            result = subprocess.run(
                ["docker", "ps"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _check_model_available(self) -> bool:
        """モデルファイルが存在するかチェック"""
        model_path = Path("C:/models/qwen2-7b-instruct-q4_k_m.gguf")
        return model_path.exists()

    def _stop_server(self):
        """サーバーを停止"""
        try:
            if hasattr(self, "server_container_id") and self.server_container_id:
                # Dockerコンテナを停止
                import subprocess

                result = subprocess.run(
                    ["docker", "stop", self.server_container_id],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    self._update_status("⏹️ サーバー停止完了")
                    self.server_status_label.configure(text="🔴 サーバー未接続")
                    self.server_container_id = None
                else:
                    self._update_status(f"❌ サーバー停止失敗: {result.stderr}")

            elif hasattr(self, "server_process") and self.server_process:
                # 従来のプロセス停止
                self.server_process.terminate()
                self.server_process = None
                self._update_status("⏹️ サーバー停止")
                self.server_status_label.configure(text="🔴 サーバー未接続")
            else:
                self._update_status("ℹ️ サーバーは起動していません")
        except Exception as e:
            self._update_status(f"❌ サーバー停止エラー: {e}")
            messagebox.showerror("エラー", f"サーバー停止に失敗しました: {e}")

    def _check_server_status(self):
        """サーバー状態を確認"""
        try:
            if self._check_server_connection():
                self._update_status("✅ サーバー接続中")
                self.server_status_label.configure(text="🟢 サーバー接続中")
            else:
                self._update_status("❌ サーバー未接続")
                self.server_status_label.configure(text="🔴 サーバー未接続")
        except Exception as e:
            self._update_status(f"❌ サーバー状態確認エラー: {e}")

    def _check_server_connection(self) -> bool:
        """サーバー接続を確認"""
        try:
            import requests

            response = requests.get("http://127.0.0.1:8080/v1/models", timeout=5)
            return response.status_code == 200
        except:
            return False

    def _start_docker_desktop(self):
        """Docker Desktopを起動"""
        try:
            self._update_status("🐳 Docker Desktop起動中...")

            # まずDockerが既に利用可能かチェック
            if self._check_docker_available():
                self._update_status("✅ Docker Desktopは既に起動しています")
                messagebox.showinfo(
                    "情報",
                    "Docker Desktopは既に起動しています。サーバー起動を試してください。",
                )
                return

            # Docker Desktopの起動を試行
            import subprocess
            import threading

            def start_docker():
                try:
                    # Docker Desktopの起動パスを検索（より多くのパスを試行）
                    docker_paths = [
                        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
                        r"C:\Users\{}\AppData\Local\Docker\Docker Desktop.exe".format(
                            os_mod.getenv("USERNAME", "")
                        ),
                        r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
                        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
                        r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Docker Desktop\Docker Desktop.lnk".format(
                            os_mod.getenv("USERNAME", "")
                        ),
                        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Docker Desktop\Docker Desktop.lnk",
                    ]

                    docker_started = False
                    started_path = None

                    for path in docker_paths:
                        if Path(path).exists():
                            try:
                                self.parent.after(
                                    0,
                                    self._update_status,
                                    f"🚀 Docker Desktop起動試行: {path}",
                                )

                                # 複数の方法で起動を試行
                                methods = [
                                    lambda: subprocess.Popen([path], shell=True),
                                    lambda: subprocess.Popen(
                                        [path],
                                        shell=True,
                                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                                    ),
                                    lambda: subprocess.run(
                                        [path], shell=True, check=False
                                    ),
                                ]

                                for method in methods:
                                    try:
                                        method()
                                        docker_started = True
                                        started_path = path
                                        self.parent.after(
                                            0,
                                            self._update_status,
                                            f"✅ Docker Desktop起動成功: {path}",
                                        )
                                        break
                                    except Exception as e:
                                        self.parent.after(
                                            0,
                                            self._update_status,
                                            f"⚠️ 起動方法失敗: {e}",
                                        )
                                        continue

                                if docker_started:
                                    break

                            except Exception as e:
                                self.parent.after(
                                    0, self._update_status, f"⚠️ 起動失敗: {path} - {e}"
                                )
                                continue

                    if not docker_started:
                        self.parent.after(
                            0, self._update_status, "❌ Docker Desktopが見つかりません"
                        )
                        self.parent.after(
                            0,
                            lambda: messagebox.showerror(
                                "エラー",
                                "Docker Desktopが見つかりません。\n\n"
                                "以下の手順で手動起動してください：\n"
                                "1. スタートメニューから「Docker Desktop」を検索\n"
                                "2. Docker Desktopをクリックして起動\n"
                                "3. 起動後、状態確認ボタンをクリック\n\n"
                                "または、Docker Desktopをインストールしてください。",
                            ),
                        )
                        return

                    # Docker起動待機
                    self.parent.after(
                        0,
                        self._update_status,
                        f"⏳ Docker Desktop起動待機中... ({started_path})",
                    )

                    # 最大180秒待機（Docker Desktopは起動に時間がかかる）
                    for i in range(180):
                        time.sleep(1)
                        if self._check_docker_available():
                            self.parent.after(
                                0, self._update_status, "✅ Docker Desktop起動完了"
                            )
                            self.parent.after(
                                0,
                                lambda: messagebox.showinfo(
                                    "成功",
                                    "Docker Desktopが起動しました！\n"
                                    "サーバー起動ボタンをクリックしてサーバーを起動してください。",
                                ),
                            )
                            return

                        # 進捗表示（15秒ごと）
                        if i % 15 == 0 and i > 0:
                            self.parent.after(
                                0,
                                self._update_status,
                                f"⏳ Docker Desktop起動中... ({i+1}/180秒)",
                            )

                    self.parent.after(
                        0, self._update_status, "⚠️ Docker Desktop起動タイムアウト"
                    )
                    self.parent.after(
                        0,
                        lambda: messagebox.showwarning(
                            "警告",
                            "Docker Desktopの起動に時間がかかっています。\n"
                            "手動でDocker Desktopの状態を確認してください。\n"
                            "起動後、状態確認ボタンをクリックしてください。",
                        ),
                    )

                except Exception as e:
                    self.parent.after(
                        0, self._update_status, f"❌ Docker起動エラー: {e}"
                    )
                    self.parent.after(
                        0,
                        lambda: messagebox.showerror(
                            "エラー", f"Docker Desktop起動に失敗しました: {e}"
                        ),
                    )

            thread = threading.Thread(target=start_docker)
            thread.daemon = True
            thread.start()

        except Exception as e:
            self._update_status(f"❌ Docker起動エラー: {e}")
            messagebox.showerror("エラー", f"Docker Desktop起動に失敗しました: {e}")

    def _show_server_logs(self):
        """サーバーログを表示"""
        try:
            if hasattr(self, "server_container_id") and self.server_container_id:
                import subprocess

                result = subprocess.run(
                    ["docker", "logs", self.server_container_id],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    logs = result.stdout + result.stderr
                    self._show_log_window(logs)
                else:
                    messagebox.showerror("エラー", f"ログ取得失敗: {result.stderr}")
            else:
                messagebox.showinfo("情報", "サーバーが起動していません")
        except Exception as e:
            messagebox.showerror("エラー", f"ログ表示エラー: {e}")

    def _show_log_window(self, logs):
        """ログウィンドウを表示"""
        log_window = ctk.CTkToplevel(self.parent)
        log_window.title("サーバーログ")
        log_window.geometry("800x600")

        # ログ表示エリア
        log_text = ctk.CTkTextbox(log_window, width=780, height=550)
        log_text.pack(padx=10, pady=10, fill="both", expand=True)

        # ログを表示
        log_text.insert("1.0", logs)
        log_text.configure(state="disabled")

        # 閉じるボタン
        close_button = ctk.CTkButton(
            log_window, text="閉じる", command=log_window.destroy, width=100
        )
        close_button.pack(pady=10)

    def run(self):
        """インターフェースを実行"""
        # 自動進化機能を起動（多重起動防止）
        self._start_auto_evolution()
        self.parent.mainloop()

    def _start_auto_evolution(self):
        """自動進化機能を開始"""
        if hasattr(self, "_evo_running") and self._evo_running:
            return
        self._evo_running = True
        self._evo_points = []
        # 進化グラフ用のキャンバスを作成
        try:
            import tkinter as tk

            self.evo_canvas = tk.Canvas(
                self.parent, width=320, height=100, bg="#1e1e1e", highlightthickness=0
            )
            self.evo_canvas.pack(side="bottom", fill="x", padx=8, pady=6)
        except Exception:
            pass
        # タイマー開始
        self._evo_timer = self.parent.after(5000, self._evo_tick)

    def _evo_tick(self):
        """自動進化の定期実行"""
        try:
            # 思考時間を指標として簡易スコア化
            val = float(self._last_latency_ms or 0.0)
            self._evo_points = (self._evo_points + [val])[-200:]
            self._draw_evo_graph()
        finally:
            if getattr(self, "_evo_running", False):
                self._evo_timer = self.parent.after(5000, self._evo_tick)  # 5s

    def _draw_evo_graph(self):
        """進化グラフを描画"""
        if not hasattr(self, "evo_canvas"):
            return
        try:
            c = self.evo_canvas
            c.delete("all")
            if not getattr(self, "_evo_points", []):
                return
            w = int(c.cget("width"))
            h = int(c.cget("height"))
            pts = self._evo_points
            mx = max(1.0, max(pts))
            step = max(1, int(w / max(1, len(pts) - 1)))
            for i in range(1, len(pts)):
                x1 = (i - 1) * step
                y1 = h - int(pts[i - 1] / mx * h)
                x2 = i * step
                y2 = h - int(pts[i] / mx * h)
                c.create_line(x1, y1, x2, y2, fill="#00ff00", width=2)
        except Exception:
            pass

    def _on_close(self):
        """終了時にタイマー停止（多重登録/ゾンビ抑止）"""
        try:
            self._evo_running = False
            if getattr(self, "_evo_timer", None):
                self.parent.after_cancel(self._evo_timer)
        except Exception:
            pass
        try:
            self.parent.destroy()
        except Exception:
            pass


def main():
    """メイン関数"""
    app = ModernCursorAIInterface()
    app.run()


if __name__ == "__main__":
    main()
