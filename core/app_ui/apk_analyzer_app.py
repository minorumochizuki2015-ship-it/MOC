#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK解析アプリケーション - GUI版APK解析ツール
"""

import json
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Dict, List, Optional

import customtkinter as ctk

from ..utils.apk_analyzer import APKAnalyzer


class APKAnalyzerApp:
    """APK解析GUIアプリケーション"""

    def __init__(self):
        """アプリケーションの初期化"""
        # CustomTkinter設定
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # メインウィンドウ
        self.root = ctk.CTk()
        self.root.title("APK解析ツール")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)

        # 変数
        self.apk_path = tk.StringVar()
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "data" / "apk_analysis"))
        self.analysis_running = False
        
        # 解析オプション変数を追加
        self.unity_analysis_var = tk.BooleanVar(value=True)
        self.detailed_analysis_var = tk.BooleanVar(value=False)

        # ファイル選択関連の属性を追加
        self.selected_file = None
        self.output_directory = None

        # UI構築
        self.setup_ui()

        # 解析履歴
        self.analysis_history: List[Dict] = []
        self.load_history()

    def setup_ui(self):
        """UIコンポーネントの設定"""
        # メインフレーム
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # タイトル
        title_label = ctk.CTkLabel(
            self.main_frame, 
            text="APK解析ツール", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=(20, 30))
        
        # ファイル選択セクション
        self.setup_file_selection(self.main_frame)
        
        # 出力先選択セクション
        self.setup_output_selection(self.main_frame)
        
        # 解析実行セクション
        self.setup_analysis_section(self.main_frame)
        
        # 結果表示セクション
        self.setup_results_section(self.main_frame)
        
        # 履歴セクション
        self.setup_history_section(self.main_frame)

    def setup_file_selection(self, parent):
        """ファイル選択セクションの設定"""
        file_frame = ctk.CTkFrame(parent)
        file_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # ファイル選択ラベル
        file_label = ctk.CTkLabel(
            file_frame, 
            text="APKファイル選択", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        file_label.pack(pady=(20, 10))
        
        # ファイルパス表示
        self.file_path_label = ctk.CTkLabel(
            file_frame,
            text="ファイルが選択されていません",
            font=ctk.CTkFont(size=12)
        )
        self.file_path_label.pack(pady=(0, 10))
        
        # ファイル選択ボタン
        select_button = ctk.CTkButton(
            file_frame,
            text="APKファイルを選択",
            command=self.select_apk_file
        )
        select_button.pack(pady=(0, 20))

    def setup_output_selection(self, parent):
        """出力先選択セクションの設定"""
        output_frame = ctk.CTkFrame(parent)
        output_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # 出力先ラベル
        output_label = ctk.CTkLabel(
            output_frame, 
            text="出力先設定", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        output_label.pack(pady=(20, 10))
        
        # 出力先パス表示
        self.output_path_label = ctk.CTkLabel(
            output_frame,
            text=self.output_dir.get(),
            font=ctk.CTkFont(size=12)
        )
        self.output_path_label.pack(pady=(0, 10))
        
        # 出力先選択ボタン
        output_button = ctk.CTkButton(
            output_frame,
            text="出力先を選択",
            command=self.select_output_dir
        )
        output_button.pack(pady=(0, 20))

    def setup_analysis_section(self, parent):
        """解析実行セクションの設定"""
        analysis_frame = ctk.CTkFrame(parent)
        analysis_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # 解析オプションラベル
        options_label = ctk.CTkLabel(
            analysis_frame, 
            text="解析オプション", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        options_label.pack(pady=(20, 10))
        
        # Unity解析チェックボックス
        self.unity_checkbox = ctk.CTkCheckBox(
            analysis_frame,
            text="Unity DLL解析を含める",
            variable=self.unity_analysis_var
        )
        self.unity_checkbox.pack(pady=(0, 10))
        
        # 詳細解析チェックボックス
        self.detailed_checkbox = ctk.CTkCheckBox(
            analysis_frame,
            text="詳細解析を実行",
            variable=self.detailed_analysis_var
        )
        self.detailed_checkbox.pack(pady=(0, 20))
        
        # 解析実行ボタン
        self.analyze_button = ctk.CTkButton(
            analysis_frame,
            text="解析実行",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            command=self.run_analysis
        )
        self.analyze_button.pack(pady=(0, 20))
        
        # プログレスバー
        self.progress_bar = ctk.CTkProgressBar(analysis_frame)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 10))
        self.progress_bar.set(0)
        
        # ステータスラベル
        self.status_label = ctk.CTkLabel(
            analysis_frame,
            text="解析待機中...",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(pady=(0, 20))

    def setup_results_section(self, parent):
        """結果表示セクションの設定"""
        results_frame = ctk.CTkFrame(parent)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # 結果ラベル
        results_label = ctk.CTkLabel(
            results_frame, 
            text="解析結果", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        results_label.pack(pady=(20, 10))
        
        # 結果表示テキストボックス
        self.results_text = ctk.CTkTextbox(
            results_frame,
            height=200,
            font=ctk.CTkFont(size=11)
        )
        self.results_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    def setup_history_section(self, parent):
        """履歴セクションの設定"""
        history_frame = ctk.CTkFrame(parent)
        history_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # 履歴ラベル
        history_label = ctk.CTkLabel(
            history_frame, 
            text="解析履歴", 
            font=ctk.CTkFont(size=16, weight="bold")
        )
        history_label.pack(pady=(20, 10))
        
        # 履歴リスト
        self.history_listbox = ctk.CTkScrollableFrame(history_frame, height=100)
        self.history_listbox.pack(fill="x", padx=20, pady=(0, 20))

    def select_apk_file(self):
        """APKファイルの選択"""
        file_path = filedialog.askopenfilename(
            title="APKファイルを選択",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        
        if file_path:
            self.apk_path.set(file_path)
            self.file_path_label.configure(text=f"選択済み: {Path(file_path).name}")

    def select_output_dir(self):
        """出力ディレクトリの選択"""
        dir_path = filedialog.askdirectory(title="出力先フォルダを選択")
        
        if dir_path:
            self.output_dir.set(dir_path)
            self.output_path_label.configure(text=dir_path)

    def run_analysis(self):
        """解析の実行"""
        if not self.apk_path.get():
            messagebox.showerror("エラー", "APKファイルを選択してください")
            return
        
        if self.analysis_running:
            messagebox.showwarning("警告", "解析が既に実行中です")
            return
        
        # UI状態の更新
        self.analysis_running = True
        self.analyze_button.configure(state="disabled", text="解析中...")
        self.progress_bar.set(0)
        self.status_label.configure(text="解析を開始しています...")
        
        # バックグラウンドで解析実行
        analysis_thread = threading.Thread(target=self._perform_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()

    def reset_analysis_ui(self):
        """解析UI状態のリセット"""
        self.analyze_button.configure(state="normal", text="解析実行")
        self.analysis_running = False

    def display_results(self, result: Dict, output_file: Path):
        """解析結果の表示"""
        apk_info = result.get("apk_info", {})
        manifest = result.get("manifest", {})
        resources = result.get("resources", {})
        unity_analysis = result.get("unity_analysis", {})
        
        # Unity解析結果の表示部分を追加
        unity_summary = ""
        if unity_analysis:
            unity_summary = f"""
🎮 Unity解析:
  Unity検出: {'はい' if unity_analysis.get('unity_detected') else 'いいえ'}
  IL2CPP使用: {'はい' if unity_analysis.get('il2cpp_detected') else 'いいえ'}
  DLLファイル数: {len(unity_analysis.get('dll_files', []))}
"""
        
        summary = f"""解析完了！

📁 APK情報:
  ファイル名: {apk_info.get('file_name', 'N/A')}
  ファイルサイズ: {apk_info.get('file_size_mb', 0):.2f} MB
  解析時刻: {apk_info.get('analysis_time', 'N/A')}

📋 マニフェスト:
  発見: {'はい' if manifest.get('found') else 'いいえ'}
  サイズ: {manifest.get('size', 0)} bytes

📦 リソース:
  総リソース数: {resources.get('total_resources', 0)}
  画像ファイル: {len(resources.get('images', []))}
  レイアウトファイル: {len(resources.get('layouts', []))}
{unity_summary}
詳細結果: {output_file}
"""
        
        messagebox.showinfo("解析完了", summary)

    def add_to_history(self, item):
        """履歴に項目を追加"""
        self.analysis_history.append(item)
        self.save_history()

    def load_history(self):
        """履歴の読み込み"""
        history_file = Path("data/apk_analysis_history.json")
        if history_file.exists():
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    self.analysis_history = json.load(f)
            except Exception as e:
                print(f"履歴読み込みエラー: {e}")
                self.analysis_history = []
        else:
            self.analysis_history = []

    def save_history(self):
        """履歴の保存"""
        history_file = Path("data/apk_analysis_history.json")
        history_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"履歴保存エラー: {e}")

    def update_history_display(self):
        """履歴表示の更新"""
        # 既存の履歴項目をクリア
        for widget in self.history_listbox.winfo_children():
            widget.destroy()
        
        # 最新の履歴項目を表示（最大5件）
        for item in self.analysis_history[-5:]:
            history_item = ctk.CTkLabel(
                self.history_listbox,
                text=f"{item.get('timestamp', 'N/A')}: {Path(item.get('apk_file', 'N/A')).name}",
                font=ctk.CTkFont(size=10)
            )
            history_item.pack(pady=2)

    def _perform_analysis(self):
        """実際の解析処理（バックグラウンド）"""
        try:
            # ファイルパスを取得
            apk_file = self.apk_path.get()
            output_dir = self.output_dir.get()
            
            # プログレスバーの更新
            self.root.after(0, lambda: self.progress_bar.set(0.1))
            self.root.after(0, lambda: self.status_label.configure(text="APKファイルを読み込み中..."))
            
            # APK解析器初期化
            analyzer = APKAnalyzer(apk_file, output_dir)
            
            # プログレス更新
            self.root.after(0, lambda: self.progress_bar.set(0.3))
            self.root.after(0, lambda: self.status_label.configure(text="ファイル構造を解析中..."))
            
            # Unity DLL解析オプションを取得
            include_unity = self.unity_analysis_var.get()
            
            # 解析実行
            result = analyzer.analyze(include_unity_analysis=include_unity)
            
            # プログレス更新
            self.root.after(0, lambda: self.progress_bar.set(0.8))
            self.root.after(0, lambda: self.status_label.configure(text="結果を保存中..."))
            
            # 結果保存
            output_file = analyzer.save_analysis()
            
            # プログレス完了
            self.root.after(0, lambda: self.progress_bar.set(1.0))
            self.root.after(0, lambda: self.status_label.configure(text="解析完了"))
            
            # 結果表示
            self.root.after(0, lambda: self.display_results(result, output_file))
            
            # 履歴に追加
            history_item = {
                "apk_file": apk_file,
                "output_file": str(output_file),
                "timestamp": result.get("apk_info", {}).get("analysis_time", ""),
                "file_size_mb": result.get("apk_info", {}).get("file_size_mb", 0)
            }
            self.root.after(0, lambda: self.add_to_history(history_item))
            
        except Exception as e:
            error_msg = f"解析エラー: {str(e)}"
            self.root.after(0, lambda: messagebox.showerror("エラー", error_msg))
            self.root.after(0, lambda: self.status_label.configure(text="解析エラー"))
        
        finally:
            # UI状態をリセット
            self.root.after(0, self.reset_analysis_ui)

    def run(self):
        """アプリケーションの実行"""
        self.root.mainloop()


if __name__ == "__main__":
    app = APKAnalyzerApp()
    app.run()