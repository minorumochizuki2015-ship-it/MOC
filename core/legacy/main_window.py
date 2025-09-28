# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import messagebox, ttk

import yaml
from gui.gui_elements import build_gui


def load_config():
    try:
        with open("config/settings.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        messagebox.showerror("エラー", f"設定ファイル読み込み失敗: {e}")
        return {}


def main():
    root = tk.Tk()
    root.title("PhoenixCodex GUI")
    root.geometry("500x400")

    config = load_config()
    build_gui(root, config)

    root.mainloop()


if __name__ == "__main__":
    main()
