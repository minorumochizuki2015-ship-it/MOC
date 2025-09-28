from __future__ import annotations

import csv
import importlib
import json
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.core.memory import Memory
from src.core.performance_monitor import performance_monitor
from src.utils import config as _cfg
from src.utils.config import EVOLVED_THEMES_PATH, LOG_FILE_PATH

_WORD_RE = re.compile(r"(?:[一-龥]{2,6}|[ァ-ヴー]{2,}|[A-Za-z][A-Za-z0-9_\-]{2,})")
_STOP = {
    "こと",
    "もの",
    "よう",
    "ため",
    "これ",
    "それ",
    "どれ",
    "ところ",
    "ので",
    "から",
    "です",
    "ます",
    "する",
    "した",
    "して",
    "そして",
    "について",
    "など",
    "また",
    "ます。",
    "です。",
    "いる",
    "ある",
    "今回",
    "今回の",
    "本日",
    "今日",
    "まず",
    "例",
    "例として",
    "例えば",
    "注意",
    "ポイント",
    "重要",
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
}


def _extract_themes(
    text: str,
    top_k: int = 5,
    window: int = 4,
    alpha: float = 0.8,
    use_poor_pagerank: bool = False,
) -> List[str]:
    if not text:
        return []
    words: List[str] = []
    for m in _WORD_RE.finditer(text):
        w = m.group(0).strip("・、。.,!?:;（）()[]「」『』“”\"'")
        if len(w) < 2 or w in _STOP:
            continue
        words.append(w)
    if not words:
        return []

    freq: Dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1

    deg: Dict[str, float] = {w: 0.0 for w in freq}
    neighbors: Dict[str, Set[str]] = {w: set() for w in freq}
    L, W = len(words), max(1, int(window))
    for i, a in enumerate(words):
        for j in range(i + 1, min(L, i + W + 1)):
            b = words[j]
            if a == b:
                continue
            deg[a] += 1.0
            deg[b] += 1.0
            neighbors[a].add(b)
            neighbors[b].add(a)

    if use_poor_pagerank:
        deg_inv = {w: 1.0 / (1.0 + deg[w]) for w in deg}
        cen = {w: sum(deg_inv[v] for v in neighbors[w]) for w in neighbors}
    else:
        cen = deg

    maxf = float(max(freq.values()))
    maxc = float(max(cen.values())) if cen else 1.0
    score = {}
    for w in freq:
        f = freq[w] / maxf
        c = (cen[w] / maxc) if maxc > 0 else 0.0
        score[w] = alpha * f + (1.0 - alpha) * c

    return [w for w, _ in sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]]


def _parse_governance_summary(gov_text: str | None) -> Tuple[bool, Optional[float]]:
    if not gov_text:
        return (True, None)
    passed = "Phase Break: PASSED" in gov_text
    m = re.search(r"Entanglement Entropy:\s*([0-9]+(?:\.[0-9]+)?)", gov_text)
    entropy = float(m.group(1)) if m else None
    return (passed, entropy)


class PhoenixApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.memory = Memory()

        self.var_extractor = tk.StringVar(value="degree")
        self.var_alpha = tk.DoubleVar(value=0.8)
        self.var_window = tk.IntVar(value=4)

        self.title("PhoenixCodex 統治核 v9.3.1 (High Performance)")
        self.geometry("1200x800")
        self._load_state()

        self._running = False
        self._run_start = 0.0
        self._worker = None
        self._q: "queue.Queue[dict]" = queue.Queue()

        # 性能監視用の変数
        self._performance_update_interval = 2.0  # 2秒ごとに更新
        self._last_performance_update = 0.0

        self._build_widgets()
        self._refresh_dashboard()
        self._tick()

    def _build_widgets(self) -> None:
        # Menu（Ctrl+E でもCSV出力）
        menubar = tk.Menu(self)
        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="CSVエクスポート\tCtrl+E", command=self._on_export_csv)
        menubar.add_cascade(label="ファイル", menu=m_file)
        self.config(menu=menubar)
        self.bind("<Control-e>", lambda e: self._on_export_csv())

        frm_in = ttk.LabelFrame(self, text="命令入力")
        frm_in.place(x=8, y=8, width=560, height=250)
        self.txt_in = tk.Text(frm_in, wrap="word")
        self.txt_in.place(x=8, y=8, width=536, height=210)
        self.txt_in.focus_set()
        self.bind("<Control-Return>", lambda e: self._on_run())

        frm_ctrl = ttk.LabelFrame(self, text="実行制御")
        frm_ctrl.place(x=580, y=8, width=510, height=150)
        ttk.Label(frm_ctrl, text="プロバイダ").place(x=10, y=10)
        self.cmb_provider = ttk.Combobox(
            frm_ctrl, values=["openai_compat", "ollama", "google_ai"], state="readonly"
        )
        self.cmb_provider.set(getattr(_cfg, "PROVIDER", "openai_compat"))
        self.cmb_provider.place(x=70, y=8, width=160)
        self.btn_run = ttk.Button(frm_ctrl, text="思考実行", command=self._on_run)
        self.btn_run.place(x=250, y=8, width=90)
        self.btn_cycle = ttk.Button(
            frm_ctrl, text="進化サイクル実行", command=self._on_cycle
        )
        self.btn_cycle.place(x=350, y=8, width=140)

        ttk.Label(frm_ctrl, text="評価メモ").place(x=10, y=40)
        self.ent_note = ttk.Entry(frm_ctrl)
        self.ent_note.place(x=70, y=38, width=270)
        self.btn_save = ttk.Button(frm_ctrl, text="評価保存", command=self._on_save)
        self.btn_save.place(x=350, y=36, width=140)

        ttk.Label(frm_ctrl, text="抽出器").place(x=10, y=72)
        self.cbo_ext = ttk.Combobox(
            frm_ctrl,
            state="readonly",
            values=["degree", "poorpr", "auto"],
            textvariable=self.var_extractor,
        )
        self.cbo_ext.place(x=60, y=70, width=100)
        ttk.Label(frm_ctrl, text="α").place(x=170, y=72)
        self.spn_alpha = ttk.Spinbox(
            frm_ctrl,
            from_=0.1,
            to=1.0,
            increment=0.05,
            textvariable=self.var_alpha,
            width=6,
            format="%.2f",
        )
        self.spn_alpha.place(x=190, y=70, width=56)
        ttk.Label(frm_ctrl, text="window").place(x=260, y=72)
        self.spn_win = ttk.Spinbox(
            frm_ctrl, from_=1, to=8, increment=1, textvariable=self.var_window, width=6
        )
        self.spn_win.place(x=320, y=70, width=56)

        frm_gov = ttk.LabelFrame(self, text="統治監査レポート")
        frm_gov.place(x=580, y=168, width=510, height=208)
        self.txt_gov = tk.Text(frm_gov, wrap="word", font=("Consolas", 10))
        self.txt_gov.place(x=8, y=8, width=486, height=172)

        frm_out = ttk.LabelFrame(self, text="統治核からの応答")
        frm_out.place(x=8, y=268, width=560, height=420)
        self.txt_out = tk.Text(frm_out, wrap="word")
        self.txt_out.place(x=8, y=8, width=536, height=380)

        frm_dash = ttk.LabelFrame(self, text="学習傾向ダッシュボード")
        frm_dash.place(x=580, y=384, width=510, height=304)
        self.tree = ttk.Treeview(
            frm_dash, columns=("c1", "c2", "c3", "c4", "c5"), show="headings", height=11
        )
        for i, h in enumerate(
            ["テーマ", "出現", "評価数", "平均スコア", "平均エントロピー"], 1
        ):
            self.tree.heading(f"c{i}", text=h)
            self.tree.column(f"c{i}", width=95, anchor="center")
        self.tree.place(x=8, y=8, width=486, height=260)

        # ★ 左下に固定（必ず見える）
        self.btn_export = ttk.Button(
            frm_dash, text="CSVエクスポート", command=self._on_export_csv
        )
        self.btn_export.place(x=8, y=270, width=120)

        self.var_status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.var_status, anchor="w").place(
            x=8, y=676, width=1080, height=24
        )

    def _on_run(self) -> None:
        if self._running:
            return
        prompt = self.txt_in.get("1.0", "end").strip()
        if not prompt:
            messagebox.showinfo("情報", "命令を入力してください。")
            return
        self._start_worker(prompt, self.cmb_provider.get().strip())

    def _on_cycle(self) -> None:
        if self._running:
            return
        prev_prompt = self.txt_in.get("1.0", "end").strip()
        prev_resp = self.txt_out.get("1.0", "end").strip()
        base = (
            "以下の前回入出力の不足点を3点以内で列挙し、改善した回答を1段落で提示してください。\n"
            "制約: 箇条書きは最大3点、改善回答は200字以内、専門用語は控えめ。\n\n"
            f"[Prompt]\n{prev_prompt}\n\n[Response]\n{prev_resp}\n"
        )
        self._start_worker(base, self.cmb_provider.get().strip())

    def _on_save(self) -> None:
        record = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "provider": self.cmb_provider.get(),
            "prompt": self.txt_in.get("1.0", "end").strip(),
            "response": self.txt_out.get("1.0", "end").strip(),
            "governance": self.txt_gov.get("1.0", "end").strip(),
            "note": self.ent_note.get().strip(),
        }
        data = self.memory.load_json_file(LOG_FILE_PATH, default_value=[])
        if not isinstance(data, list):
            data = []
        data.append(record)
        ok = self.memory.save_json_file(LOG_FILE_PATH, data)
        self._update_evolved_themes(record, counted_as_note=True)
        self._refresh_dashboard()
        messagebox.showinfo("保存", "保存しました。" if ok else "保存に失敗しました。")

    def _start_worker(self, prompt: str, provider: str) -> None:
        if self._running:
            return
        self._running = True
        self._run_start = time.time()
        for b in (self.btn_run, self.btn_cycle, self.btn_save):
            b.configure(state="disabled")
        self.var_status.set(f"Running ({provider}) …")
        self.txt_out.delete("1.0", "end")
        self.txt_gov.delete("1.0", "end")

        def _job():
            try:
                os.environ["PROVIDER"] = provider
                from src.core import kernel as kern
                from src.utils import config as cfg

                importlib.reload(cfg)
                importlib.reload(kern)
                from src.core.kernel import Kernel

                k = Kernel(self.memory)
                t0 = time.time()
                res = k.query_local_api(prompt)
                el = time.time() - t0
                self._q.put(
                    {
                        "ok": True,
                        "res": res,
                        "elapsed": el,
                        "provider": provider,
                        "prompt": prompt,
                    }
                )
            except Exception as e:
                self._q.put({"ok": False, "err": str(e), "provider": provider})

        threading.Thread(target=_job, daemon=True).start()

    def _tick(self) -> None:
        try:
            item = self._q.get_nowait()
        except queue.Empty:
            item = None

        if item is not None:
            self._running = False
            for b in (self.btn_run, self.btn_cycle, self.btn_save):
                b.configure(state="normal")
            if item.get("ok"):
                res = item.get("res", {}) or {}
                elapsed = float(item.get("elapsed", 0.0))
                provider = item.get("provider", "-")
                prompt_sent = item.get("prompt", "")

                def _clean(s: str) -> str:
                    if not s:
                        return ""
                    t = s.strip()
                    return re.sub(
                        r"^(assistant|system|user)\s*[:：]\s*", "", t, 1, flags=re.I
                    )

                txt = _clean(res.get("response_text") or res.get("error_message") or "")
                self.txt_out.insert("end", txt)
                gov = res.get("governance_analysis")
                gov_s = (
                    "None"
                    if gov is None
                    else (
                        gov
                        if isinstance(gov, str)
                        else json.dumps(gov, ensure_ascii=False, indent=2)
                    )
                )
                self.txt_gov.insert("end", gov_s)

                record = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "provider": provider,
                    "prompt": prompt_sent,
                    "response": txt,
                    "governance": gov_s,
                    "note": "",
                }
                self._update_evolved_themes(record, counted_as_note=False)
                self._refresh_dashboard()
                self.var_status.set(f"Done ({provider})  elapsed={elapsed:.2f}s")
            else:
                self.var_status.set("Error")
                messagebox.showerror("実行エラー", item.get("err", "Unknown error"))

        if self._running:
            self.var_status.set(f"Running … {time.time()-self._run_start:.1f}s")
        self.after(120, self._tick)

    def _update_evolved_themes(
        self, record: Dict[str, Any], counted_as_note: bool
    ) -> None:
        db = self.memory.load_json_file(
            EVOLVED_THEMES_PATH, default_value={"themes": {}}
        )
        if not isinstance(db, dict) or "themes" not in db:
            db = {"themes": {}}
        response = record.get("response", "")
        gov = record.get("governance", "") or ""
        passed, entropy = _parse_governance_summary(gov)
        # 抽出器の安全な処理（auto抽出の例外フォールバック）
        try:
            ex = self.var_extractor.get().lower()
            if ex == "auto":
                # auto抽出の簡易実装（エントロピーに基づく自動選択）
                if entropy is not None and entropy > 0.5:
                    ex, use_pr, alpha_v, win_v = "poorpr", True, 0.6, 3
                else:
                    ex, use_pr, alpha_v, win_v = "degree", False, 0.8, 4
            else:
                use_pr = ex == "poorpr"
                alpha_v = float(self.var_alpha.get())
                win_v = int(self.var_window.get())
        except Exception:
            # 例外時はdegreeにフォールバック
            ex, use_pr, alpha_v, win_v = (
                "degree",
                False,
                float(self.var_alpha.get()),
                int(self.var_window.get()),
            )

        themes = _extract_themes(
            response, top_k=5, window=win_v, alpha=alpha_v, use_poor_pagerank=use_pr
        )
        for t in themes:
            slot = db["themes"].get(t) or {
                "count": 0,
                "note_count": 0,
                "pass_count": 0,
                "entropy_sum": 0.0,
                "entropy_n": 0,
            }
            slot["count"] += 1
            if counted_as_note and (record.get("note") or ""):
                slot["note_count"] += 1
            if passed:
                slot["pass_count"] += 1
            if isinstance(entropy, float):
                slot["entropy_sum"] += entropy
                slot["entropy_n"] += 1
            db["themes"][t] = slot
        self.memory.save_json_file(EVOLVED_THEMES_PATH, db)

    def _collect_theme_rows(self) -> List[Tuple[str, int, int, str, str, int, int]]:
        db = self.memory.load_json_file(
            EVOLVED_THEMES_PATH, default_value={"themes": {}}
        )
        if not isinstance(db, dict):
            db = {"themes": {}}
        rows = []
        for name, s in db.get("themes", {}).items():
            c = int(s.get("count", 0))
            n = int(s.get("note_count", 0))
            p = int(s.get("pass_count", 0))
            en = int(s.get("entropy_n", 0))
            ent = (float(s.get("entropy_sum", 0.0)) / en) if en > 0 else 0.0
            score = (p / c) if c > 0 else 0.0
            rows.append(
                (name, c, n, f"{score:.2f}", f"{ent:.4f}" if en > 0 else "N/A", p, en)
            )
        rows.sort(key=lambda r: (-r[1], r[0]))
        return rows

    def _refresh_dashboard(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in self._collect_theme_rows()[:100]:
            self.tree.insert("", "end", values=r[:5])

    def _on_export_csv(self) -> None:
        rows = self._collect_theme_rows()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"themes_{ts}.csv"
        initial_dir = os.path.dirname(EVOLVED_THEMES_PATH) or os.getcwd()
        path = filedialog.asksaveasfilename(
            parent=self,
            title="ダッシュボードをCSVに保存",
            initialdir=initial_dir,
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        "テーマ",
                        "出現",
                        "評価数",
                        "平均スコア",
                        "平均エントロピー",
                        "pass_count",
                        "entropy_n",
                    ]
                )
                for name, c, n, score, ent, p, en in rows:
                    w.writerow([name, c, n, score, ent, p, en])
            messagebox.showinfo("CSVエクスポート", f"保存しました:\n{path}")
        except Exception as e:
            messagebox.showerror("CSVエクスポート失敗", str(e))

    def _load_state(self) -> Optional[str]:
        try:
            st = self.memory.load_json_file("ui_state.json", {})
            if "extractor" in st:
                self.var_extractor.set(st["extractor"])
            if "alpha" in st:
                self.var_alpha.set(float(st["alpha"]))
            if "window" in st:
                self.var_window.set(int(st["window"]))
            geom = st.get("geometry")
            if isinstance(geom, str) and geom:
                self.geometry(geom)
            return geom
        except Exception:
            return None

    def _save_state(self) -> None:
        try:
            st = self.memory.load_json_file("ui_state.json", {})
            st["geometry"] = self.geometry()
            st["extractor"] = self.var_extractor.get()
            st["alpha"] = float(self.var_alpha.get())
            st["window"] = int(self.var_window.get())
            self.memory.save_json_file("ui_state.json", st)
        except Exception:
            pass

    def destroy(self) -> None:
        self._save_state()
        super().destroy()


def main() -> None:
    app = PhoenixApp()
    app.mainloop()


if __name__ == "__main__":
    main()
