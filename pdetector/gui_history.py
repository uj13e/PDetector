"""スキャン履歴ウィンドウ。"""
from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, List

from . import gui_logic as L
from . import gui_theme as T
from . import scanlog
from .i18n import tr


def open_folder(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    if sys.platform.startswith("win"):
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def targets_label(targets: List[str]) -> str:
    if not targets:
        return "-"
    first = L.short_name(targets[0], 40)
    return first + (tr(' ほか {0} 件').format(len(targets) - 1) if len(targets) > 1 else "")


def state_label(s: Dict) -> str:
    if s.get("error"):
        return tr("エラー終了")
    if not s.get("finished"):
        return tr("未完了(途中で終了)")
    return tr("キャンセル") if s.get("cancelled") else tr("完了")


class HistoryWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title(tr("スキャン履歴(ログ)"))
        self.configure(bg=app.pal["bg"])
        self.transient(app.root)
        sc = max(1.0, app.fonts.scale)
        self.geometry(f"{int(min(app.root.winfo_screenwidth() * 0.9, 1040 * sc))}x{int(min(app.root.winfo_screenheight() * 0.85, 560 * sc))}")
        self.minsize(640, 360)
        self.sessions: Dict[str, Dict] = {}

        # 下の段から先に pack する。後だと小さい窓で切れる
        opt = ttk.Frame(self, padding=(14, 8, 14, 12))
        opt.pack(side="bottom", fill="x")
        self.v_enabled = tk.BooleanVar(value=bool(app.ui.get("log_enabled", True)))
        ttk.Checkbutton(opt, text=tr("スキャンのたびにログを保存する"), variable=self.v_enabled,
                        command=self._save_opts).pack(side="left")
        ttk.Label(opt, text=tr("保存期間(日・0で無期限):")).pack(side="left", padx=(18, 4))
        self.v_days = tk.StringVar(value=str(int(app.ui.get("log_keep_days", 90))))
        sp = ttk.Spinbox(opt, from_=0, to=3650, width=6, textvariable=self.v_days, command=self._save_opts)
        sp.pack(side="left")
        sp.bind("<FocusOut>", lambda e: self._save_opts())
        sp.bind("<Return>", lambda e: self._save_opts())
        self.lbl_dir = ttk.Label(opt, text="", style="Muted.TLabel")
        self.lbl_dir.pack(side="right")

        bar = ttk.Frame(self, padding=(14, 12, 14, 6))
        bar.pack(side="bottom", fill="x")
        ttk.Button(bar, text=tr("結果を開く"), style="Accent.TButton", command=self.open_selected).pack(side="left")
        ttk.Button(bar, text=tr("更新"), command=self.reload).pack(side="left", padx=8)
        ttk.Button(bar, text=tr("ログフォルダを開く"), command=self.open_dir).pack(side="left")
        ttk.Button(bar, text=tr("すべて削除"), command=lambda: self.delete(all_=True)).pack(side="right")
        ttk.Button(bar, text=tr("選択を削除"), command=self.delete).pack(side="right", padx=8)

        ttk.Label(self, text=tr("過去のスキャンの記録です。ダブルクリックで、そのときの結果をメイン画面に表示します"
                             "(本文のプレビューは保存されないため表示されません)。"),
                  padding=(14, 12, 14, 4)).pack(side="top", anchor="w")
        body = ttk.Frame(self)
        body.pack(side="top", fill="both", expand=True, padx=14)
        cols = (("when", tr("日時"), 185), ("targets", tr("対象"), 240), ("count", tr("件数"), 70), ("worst", tr("総合判定"), 120),
                ("detail", tr("内訳"), 240), ("state", tr("状態"), 130))
        self.tv = ttk.Treeview(body, columns=[c[0] for c in cols], show="headings", selectmode="extended")
        for c, t, w in cols:
            self.tv.heading(c, text=t, anchor="center" if c in ("count", "worst") else "w")
            self.tv.column(c, width=w, minwidth=50, stretch=(c in ("targets", "detail")), anchor="center" if c in ("count", "worst") else "w")
        sb = ttk.Scrollbar(body, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tv.pack(side="left", fill="both", expand=True)
        lc = T.level_text_colors(app.theme)
        for lv, col in lc.items():
            self.tv.tag_configure("lv_" + lv, foreground=col, font=app.fonts.bold if lv not in ("clean",) else app.fonts.ui)
        self.tv.tag_configure("muted", foreground=app.pal["mut"])
        self.tv.bind("<Double-1>", lambda e: self.open_selected())
        self.tv.bind("<Return>", lambda e: self.open_selected())
        self.tv.bind("<Delete>", lambda e: self.delete())
        self.bind("<Escape>", lambda e: self.destroy())
        self.reload()
        self.tv.focus_set()

    def _dir(self) -> str:
        return scanlog.default_log_dir()

    def reload(self) -> None:
        self.tv.delete(*self.tv.get_children())
        self.sessions = {}
        self.lbl_dir.config(text=tr('保存先: {0}').format(self._dir()))
        items = scanlog.list_sessions(self._dir())
        if not items:
            self.tv.insert("", "end", iid="none", values=("", tr("(ログはまだありません)"), "", "", "", ""), tags=("muted",))
            return
        for s in items:
            iid = s["path"]
            self.sessions[iid] = s
            counts = s.get("counts") or {}
            detail = " / ".join(f"{L.LEVEL_NAME.get(k, k)} {v}" for k, v in
                                sorted(counts.items(), key=lambda kv: -L.LEVEL_ORDER.index(kv[0]) if kv[0] in L.LEVEL_ORDER else 0)
                                if k != "clean") or (tr("問題なし") if s["count"] else "-")
            worst = s["worst"] if s["count"] else "clean"
            self.tv.insert("", "end", iid=iid, tags=("lv_" + worst,),
                           values=(s["started"], targets_label(s["targets"]), s["count"],
                                   L.LEVEL_NAME.get(worst, worst) if s["count"] else "-", detail, state_label(s)))

    def _selected(self) -> List[str]:
        return [i for i in self.tv.selection() if i in self.sessions]

    def open_selected(self) -> None:
        sel = self._selected()
        if not sel:
            return
        if self.app.scanning:
            messagebox.showinfo(tr("スキャン中です"), tr("スキャンが終わってから開いてください。"), parent=self)
            return
        try:
            self.app.show_logged(sel[0])
        except OSError as e:
            messagebox.showerror(tr("ログを開けません"), str(e), parent=self)
            return
        self.destroy()

    def open_dir(self) -> None:
        try:
            open_folder(self._dir())
        except Exception as e:  # noqa
            messagebox.showerror(tr("フォルダを開けません"), str(e), parent=self)

    def delete(self, all_: bool = False) -> None:
        paths = list(self.sessions) if all_ else self._selected()
        if not paths:
            return
        msg = tr('ログ {0} 件を削除します。元に戻せません。よろしいですか?').format(len(paths))
        if not messagebox.askyesno(tr("ログの削除"), msg, parent=self):
            return
        n = scanlog.delete_logs(paths)
        self.app.set_status(tr('ログを {0} 件削除しました').format(n))
        self.reload()

    def _save_opts(self) -> None:
        self.app.ui["log_enabled"] = bool(self.v_enabled.get())
        try:
            self.app.ui["log_keep_days"] = max(0, min(3650, int(float(self.v_days.get()))))
        except ValueError:
            self.v_days.set(str(self.app.ui.get("log_keep_days", 90)))
        L.save_ui_state(self.app.ui)
