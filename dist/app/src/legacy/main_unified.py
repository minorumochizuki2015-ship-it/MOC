# C:\Users\User\PhoenixCodex\main_unified.py
# encoding: utf-8
# PhoenixCodex 最終統合実行スクリプト v5.0-FINAL (進化的統治機構)

import json
import os
import random
import threading
import tkinter as tk
import urllib.request
from datetime import datetime
from tkinter import messagebox, ttk

# --- 依存モジュールのインポート ---
# これらのファイルが C:\Users\User\PhoenixCodex\modules に存在することを確認
from modules import fitness_calculator, genetic_algorithm

# --- グローバル設定 ---
TARGET_MODEL = "gemma3:4b"
OLLAMA_ENDPOINT = "http://localhost:11434/api/chat"
try:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
except NameError:
    PROJECT_ROOT = os.getcwd()
LOG_FILE_PATH = os.path.join(PROJECT_ROOT, "interaction_log.json")
PERSONA_FILE_PATH = os.path.join(PROJECT_ROOT, "persona_context.json")
CONCEPTUAL_DICTIONARY_PATH = os.path.join(PROJECT_ROOT, "conceptual_dictionary.json")
EVOLUTIONARY_GENOME_PATH = os.path.join(PROJECT_ROOT, "evolutionary_genome.json")

# --- バックエンド機能 ---


def load_json_file(path, default_value):
    if not os.path.exists(path):
        return default_value
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            if not content:
                return default_value
            return json.loads(content)
    except (json.JSONDecodeError, TypeError, FileNotFoundError):
        return default_value


def save_json_file(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"JSON保存エラー ({path}): {e}")
        return False


def query_ollama(prompt_text):
    """Ollama APIと通信する。進化したゲノムに基づいて思考を補助する。"""
    system_prompt = load_json_file(PERSONA_FILE_PATH, {}).get(
        "dynamic_system_prompt", ""
    )
    genome = load_json_file(EVOLUTIONARY_GENOME_PATH, {})

    # --- 進化したゲノムをリアルタイムで思考に反映 ---
    retrieval_scope = int(
        genome.get("knowledge_retrieval_scope", {}).get("current_value", 2)
    )
    # ------------------------------------------

    relevant_knowledge = ""
    if os.path.exists(LOG_FILE_PATH):
        relevant_logs = []
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    log = json.loads(line)
                    if log.get("feedback_score", 0) >= 4:
                        relevant_logs.append(
                            f"Q: {log['prompt']}\nA: {log['response']}\n"
                        )
                except json.JSONDecodeError:
                    continue
        if relevant_logs:
            relevant_knowledge = (
                "\n\n思考の参考にすべき、過去の高く評価された対話:\n"
                + "".join(relevant_logs[-retrieval_scope:])
            )

    final_prompt = f"{system_prompt}\n{relevant_knowledge}\n\n上記はあなたの役割定義と、思考の参考となる情報です。これらに基づき、以下のユーザーの命令に、より深く、洞察に満ちた回答を生成してください。\n\n命令: '{prompt_text}'"

    data = {
        "model": TARGET_MODEL,
        "messages": [{"role": "user", "content": final_prompt}],
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(
        OLLAMA_ENDPOINT,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req) as response:
        response_body = response.read().decode("utf-8")
        response_json = json.loads(response_body)
        return response_json.get("message", {}).get(
            "content", f"エラー: 予期せぬ応答形式です。\n{response_body}"
        )


def log_interaction(prompt, response):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt,
        "response": response,
        "feedback_score": None,
    }
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


def add_feedback_to_last_log(score):
    if not os.path.exists(LOG_FILE_PATH):
        return False, "ログファイルが存在しません。"
    with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if not lines:
        return False, "ログが空です。"
    last_log = json.loads(lines[-1])
    last_log["feedback_score"] = score
    lines[-1] = json.dumps(last_log, ensure_ascii=False) + "\n"
    with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return True, "評価を保存しました。"


# --- フロントエンド (GUIアプリケーションクラス) ---
class PhoenixApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhoenixCodex 統治核インターフェース (進化的統治版 v5.0-FINAL)")
        self.root.geometry("1200x800")
        self.create_widgets()
        self.update_dashboard()  # 初期表示

    def create_widgets(self):
        main_paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_paned_window.pack(fill="both", expand=True, padx=10, pady=10)
        top_pane = ttk.Frame(main_paned_window)
        main_paned_window.add(top_pane, weight=3)
        top_paned_window = ttk.PanedWindow(top_pane, orient=tk.HORIZONTAL)
        top_paned_window.pack(fill="both", expand=True)
        dialog_frame = ttk.Frame(top_paned_window, padding="10")
        top_paned_window.add(dialog_frame, weight=3)
        ttk.Label(dialog_frame, text="命令入力:", font=("Meiryo UI", 10)).pack(
            anchor="w"
        )
        self.input_widget = tk.Text(dialog_frame, height=8, font=("Meiryo UI", 10))
        self.input_widget.pack(pady=5, fill="both", expand=True)
        button_frame = ttk.Frame(dialog_frame)
        button_frame.pack(pady=10)
        self.execute_button = ttk.Button(
            button_frame, text="思考実行", command=self.on_execute_button_click
        )
        self.execute_button.pack(side="left", padx=10)
        self.evolve_button = ttk.Button(
            button_frame, text="進化サイクル実行", command=self.on_evolve_button_click
        )
        self.evolve_button.pack(side="left", padx=10)
        governance_pane = ttk.Frame(top_paned_window)
        top_paned_window.add(governance_pane, weight=1)
        dict_frame = ttk.Labelframe(governance_pane, text="概念辞書管理", padding="10")
        dict_frame.pack(fill="both", expand=True)
        self.keyword_listbox = tk.Listbox(dict_frame, font=("Meiryo UI", 10))
        self.keyword_listbox.pack(fill="both", expand=True)
        entry_frame = ttk.Frame(dict_frame)
        entry_frame.pack(fill="x", pady=5)
        self.keyword_entry = ttk.Entry(entry_frame, font=("Meiryo UI", 10))
        self.keyword_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(entry_frame, text="追加", command=self.add_keyword).pack(
            side="left", padx=5
        )
        ttk.Button(
            dict_frame, text="選択したキーワードを削除", command=self.remove_keyword
        ).pack(fill="x", pady=5)
        self.refresh_keyword_list()
        bottom_pane = ttk.Frame(main_paned_window)
        main_paned_window.add(bottom_pane, weight=2)
        response_frame = ttk.Labelframe(
            bottom_pane, text="統治核からの応答", padding="10"
        )
        response_frame.pack(fill="both", expand=True, side="left", padx=(0, 10))
        self.output_widget = tk.Text(
            response_frame, font=("Meiryo UI", 10), state=tk.DISABLED, bg="#f0f0f0"
        )
        self.output_widget.pack(fill="both", expand=True)
        feedback_frame = ttk.Labelframe(response_frame, text="応答評価", padding="5")
        feedback_frame.pack(fill="x", pady=(10, 0))
        ttk.Label(feedback_frame, text="評価:").pack(side="left", padx=5)
        self.feedback_var = tk.StringVar()
        self.feedback_combo = ttk.Combobox(
            feedback_frame,
            textvariable=self.feedback_var,
            values=["1 (不満)", "2", "3 (普通)", "4", "5 (満足)"],
            state="readonly",
            width=10,
        )
        self.feedback_combo.pack(side="left", padx=5)
        self.save_feedback_button = ttk.Button(
            feedback_frame,
            text="評価を保存",
            command=self.on_save_feedback_click,
            state=tk.DISABLED,
        )
        self.save_feedback_button.pack(side="left", padx=5)

        # --- 進化的統治ダッシュボード ---
        dashboard_frame = ttk.Labelframe(
            bottom_pane, text="進化的統治ダッシュボード", padding="10"
        )
        dashboard_frame.pack(fill="both", expand=True, side="left")
        columns = ("parameter", "value")
        self.dashboard_tree = ttk.Treeview(
            dashboard_frame, columns=columns, show="headings"
        )
        self.dashboard_tree.heading("parameter", text="進化パラメータ")
        self.dashboard_tree.heading("value", text="現在値")
        self.dashboard_tree.column("parameter", width=150)
        self.dashboard_tree.column("value", width=100, anchor="center")
        self.dashboard_tree.pack(fill="both", expand=True)

    def refresh_keyword_list(self):
        self.keyword_listbox.delete(0, tk.END)
        for keyword in sorted(list(load_json_file(CONCEPTUAL_DICTIONARY_PATH, []))):
            self.keyword_listbox.insert(tk.END, keyword)

    def add_keyword(self):
        new_keyword = self.keyword_entry.get().strip().lower()
        if not new_keyword:
            return
        keywords = set(load_json_file(CONCEPTUAL_DICTIONARY_PATH, []))
        if new_keyword in keywords:
            messagebox.showwarning("警告", "そのキーワードは既に存在します。")
            return
        keywords.add(new_keyword)
        if save_json_file(CONCEPTUAL_DICTIONARY_PATH, list(keywords)):
            self.refresh_keyword_list()
            self.keyword_entry.delete(0, tk.END)
            messagebox.showinfo("成功", f"キーワード「{new_keyword}」を追加しました。")
        else:
            messagebox.showerror("エラー", "キーワードの保存に失敗しました。")

    def remove_keyword(self):
        selected_indices = self.keyword_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("警告", "削除するキーワードを選択してください。")
            return
        selected_keyword = self.keyword_listbox.get(selected_indices[0])
        if messagebox.askyesno(
            "確認", f"キーワード「{selected_keyword}」を本当に削除しますか？"
        ):
            keywords = set(load_json_file(CONCEPTUAL_DICTIONARY_PATH, []))
            keywords.discard(selected_keyword)
            if save_json_file(CONCEPTUAL_DICTIONARY_PATH, list(keywords)):
                self.refresh_keyword_list()
                messagebox.showinfo(
                    "成功", f"キーワード「{selected_keyword}」を削除しました。"
                )
            else:
                messagebox.showerror("エラー", "キーワードの削除に失敗しました。")

    def update_output_area(self, text):
        self.output_widget.config(state=tk.NORMAL)
        self.output_widget.delete("1.0", tk.END)
        self.output_widget.insert(tk.END, text)
        self.output_widget.config(state=tk.DISABLED)

    def on_execute_button_click(self):
        prompt = self.input_widget.get("1.0", tk.END).strip()
        if not prompt:
            self.update_output_area("命令を入力してください。")
            return
        self.execute_button.config(state=tk.DISABLED)
        self.evolve_button.config(state=tk.DISABLED)
        self.save_feedback_button.config(state=tk.DISABLED)
        self.feedback_combo.set("")
        self.update_output_area("思考中...")
        threading.Thread(
            target=self.thinking_thread, args=(prompt,), daemon=True
        ).start()

    def thinking_thread(self, prompt):
        try:
            response = query_ollama(prompt)
            if not response.startswith("エラー:"):
                log_interaction(prompt, response)
        except Exception as e:
            response = (
                f"思考プロセス中に致命的なエラーが発生しました。\nエラー詳細: {e}"
            )
        self.root.after(0, self.finalize_response, response)

    def finalize_response(self, response):
        self.update_output_area(response)
        self.execute_button.config(state=tk.NORMAL)
        self.evolve_button.config(state=tk.NORMAL)
        if not response.startswith("エラー:"):
            self.save_feedback_button.config(state=tk.NORMAL)

    def on_evolve_button_click(self):
        """進化サイクルを実行し、ゲノムを更新し、結果を表示する。"""
        self.execute_button.config(state=tk.DISABLED)
        self.evolve_button.config(state=tk.DISABLED)
        self.update_output_area(
            "進化サイクル実行中... 世代交代をシミュレートしています。"
        )
        threading.Thread(target=self.evolution_thread, daemon=True).start()

    def evolution_thread(self):
        genome_def = load_json_file(EVOLUTIONARY_GENOME_PATH, {})
        if not genome_def:
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "エラー",
                    "ゲノム定義ファイル `evolutionary_genome.json` が見つかりません。",
                ),
            )
            self.root.after(0, self.finalize_evolution, None, 0)
            return

        best_genome, final_fitness = genetic_algorithm.run_ga_cycle(genome_def)

        # 最も優れたゲノムを保存
        save_json_file(EVOLUTIONARY_GENOME_PATH, best_genome)

        self.root.after(0, self.finalize_evolution, best_genome, final_fitness)

    def finalize_evolution(self, best_genome, final_fitness):
        self.update_output_area("進化サイクル完了。")
        self.execute_button.config(state=tk.NORMAL)
        self.evolve_button.config(state=tk.NORMAL)
        if best_genome:
            self.update_dashboard(best_genome, final_fitness)
            messagebox.showinfo(
                "進化完了",
                f"新しいパラメータセットへの進化が完了しました。\n最終適応度: {final_fitness:.4f}",
            )

    def on_save_feedback_click(self):
        selection = self.feedback_var.get()
        if not selection:
            messagebox.showwarning("警告", "評価を選択してください。")
            return
        score = int(selection.split(" ")[0])
        success, message = add_feedback_to_last_log(score)
        if success:
            messagebox.showinfo("成功", message)
            self.save_feedback_button.config(state=tk.DISABLED)
        else:
            messagebox.showerror("エラー", message)

    def update_dashboard(self, genome=None, fitness=None):
        """ダッシュボードを進化パラメータで更新する。"""
        for item in self.dashboard_tree.get_children():
            self.dashboard_tree.delete(item)

        if genome is None:
            genome = load_json_file(EVOLUTIONARY_GENOME_PATH, {})

        if fitness is not None:
            self.dashboard_tree.insert(
                "", "end", values=("最終適応度", f"{fitness:.4f}")
            )
            self.dashboard_tree.insert("", "end", values=("---", "---"))

        for gene, details in sorted(genome.items()):
            self.dashboard_tree.insert(
                "",
                "end",
                values=(
                    details.get("description", gene),
                    f"{details.get('current_value', 0):.4f}",
                ),
            )


# --- アプリケーションの起動 ---
if __name__ == "__main__":
    main_root = tk.Tk()
    app = PhoenixApp(main_root)
    main_root.mainloop()
