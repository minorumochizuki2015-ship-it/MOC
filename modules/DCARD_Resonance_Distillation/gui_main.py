import tkinter as tk
from tkinter import filedialog, messagebox

from distillation_engine import load_config, run_distillation


def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml")])
    if file_path:
        config_path.set(file_path)


def start_distillation():
    yaml_path = config_path.get()
    print(f"[DEBUG] 入力されたYAML構成ファイルパス: {yaml_path}")

    try:
        config = load_config(yaml_path)  # ← ここで辞書に変換
        if not isinstance(config, dict):
            raise ValueError("設定ファイルの形式が不正です（辞書でない）")

        result = run_distillation(config)  # ← 辞書を渡す
        messagebox.showinfo("完了", "ディスティレーションが完了しました。")
    except Exception as e:
        messagebox.showerror("エラー", f"処理中にエラーが発生しました:\n{e}")
        print(f"[ERROR] {e}")


# GUI構築
root = tk.Tk()
root.title("ディスティレーション設定")

config_path = tk.StringVar()

tk.Label(root, text="YAML構成ファイルのパス:").pack(pady=5)
tk.Entry(root, textvariable=config_path, width=50).pack(pady=5)
tk.Button(root, text="参照", command=browse_file).pack(pady=5)
tk.Button(root, text="開始", command=start_distillation).pack(pady=20)

print("[DEBUG] GUI起動開始")
root.mainloop()
