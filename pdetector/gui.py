"""PDetector の Tkinter GUI。ファイル・フォルダ・URL・貼り付けテキストをスキャンして、
結果を対象 > 検知のツリーと本文プレビューで見せる。Tk 非依存の処理は gui_logic.py。
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

from . import deps, gui_logic as L, gui_theme as T, icon, neutralize, patterns, report, scanlog
from .config import DetectorConfig
from .detector import Detector, TOOL_VERSION
from .model import Finding, ScanResult, SEV_ORDER
from .scan import scan_text
from . import i18n
from .i18n import tr

PASTE_SRC = "(貼り付けテキスト)"
PREVIEW_LIMIT = 200_000
APP_TITLE = "PDetector — 間接プロンプトインジェクション検知"


class App:
    def __init__(self, root: tk.Misc, dnd: bool = False):
        self.root = root
        self.dnd = dnd
        self.ui = L.load_ui_state()
        i18n.set_lang(i18n.resolve_lang(self.ui.get("lang", "auto")))
        self.cfg, self.cfg_note = L.load_user_config()
        self.cfg.keep_text = True
        self.detector = Detector(self.cfg)
        self.theme = T.resolve_theme(self.ui["theme"])
        self.pal = T.palette(self.theme)
        self.fonts = T.Fonts(root, self.ui["font_scale"])
        self.style = T.apply_theme(root, self.pal, self.fonts)

        self.results: List[ScanResult] = []
        self.last_targets: List[str] = []
        self.node_map: Dict[str, tuple] = {}
        self.cancel = threading.Event()
        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.scanning = False
        self.t_start = 0.0
        self._refresh_after = None
        self._open_pref: Dict[str, bool] = {}
        self.logger: Optional[scanlog.ScanLogger] = None
        self._pasted_text = ""
        self.busy_bg = False
        self._prune_logs()
        self._cur_finding: Optional[Finding] = None
        self._cur_result: Optional[ScanResult] = None
        self._tk_widgets: List[tuple] = []        # (widget, {option: palette_key})

        icon.apply_icon(root)
        geo = self.ui.get("geometry") or "1180x780"
        try:
            root.geometry(geo)
        except tk.TclError:
            root.geometry("1180x780")
        root.minsize(900, 620)

        self.v_sev = {s: tk.BooleanVar(value=(s in self.ui["sev_filter"])) for s in L.SEV_LIST}
        self.v_query = tk.StringVar()
        self.v_target = tk.StringVar()
        self.v_only_problem = tk.BooleanVar(value=False)

        self.v_lang = tk.StringVar(value=self.ui.get("lang", "auto"))
        self._build_all()
        self.show_welcome(True)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_id = root.after(80, self._poll)
        self.set_status(tr("準備完了"))

    def _build_all(self):
        root = self.root
        root.title(tr(APP_TITLE))
        self._tk_widgets = []
        self._build_menu()
        body = ttk.Frame(root, padding=(12, 10, 12, 6))
        body.pack(fill="both", expand=True)
        self._build_input(body)
        self._build_banner(body)
        self._build_progress(body)
        self._build_filter(body)
        self._build_main(body)
        self._build_status()
        self._bind_keys()
        self._init_dnd()
        self._apply_tk_palette()

    def change_lang(self):
        """言語切り替え。画面は作り直すが、結果・フィルタ・進捗は引き継ぐ。"""
        self.ui["lang"] = self.v_lang.get()
        i18n.set_lang(i18n.resolve_lang(self.ui["lang"]))
        for w in list(self.root.winfo_children()):
            if isinstance(w, tk.Toplevel):
                w.destroy()                       # 設定や履歴の窓は閉じる。開き直せば新しい言語で出る
            else:
                w.destroy()
        self._banner_visible = False
        self._cur_result = self._cur_finding = None
        self._build_all()
        if self.scanning:
            self.prog.pack(fill="x", pady=(10, 0), before=self.filter_bar)
            self.pbar.configure(mode="indeterminate")
            self.pbar.start(12)
            self.btn_scan.state(["disabled"])
        self.refresh_tree(select_first=bool(self.results))
        self._update_banner()
        self.show_welcome(not self.results and not self.scanning)
        self.set_status(tr("表示言語を切り替えました"))

    # 構築
    def _build_menu(self):
        m = tk.Menu(self.root)
        self.root.config(menu=m)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label=tr("ファイルを選んでスキャン…"), accelerator="Ctrl+O", command=self.choose_files)
        fm.add_command(label=tr("フォルダをスキャン…"), accelerator="Ctrl+Shift+O", command=self.choose_folder)
        fm.add_command(label=tr("URLを入力…"), accelerator="Ctrl+L", command=self.focus_target)
        fm.add_command(label=tr("テキストを貼り付けてスキャン…"), accelerator="Ctrl+Shift+V", command=self.paste_dialog)
        self.recent_menu = tk.Menu(fm, tearoff=0, postcommand=self._fill_recent)
        fm.add_cascade(label=tr("最近のスキャン"), menu=self.recent_menu)
        fm.add_separator()
        fm.add_command(label=tr("再スキャン"), accelerator="F5", command=self.rescan)
        fm.add_command(label=tr("結果をクリア"), command=self.clear_results)
        fm.add_separator()
        sm = tk.Menu(fm, tearoff=0)
        for lab, kind in (("JSON(.json)", "json"), (tr("HTMLレポート(.html)"), "html"), ("Markdown(.md)", "markdown"), ("CSV(.csv)", "csv"), (tr("テキスト(.txt)"), "text")):
            sm.add_command(label=lab, command=lambda k=kind: self.save_report(k))
        fm.add_cascade(label=tr("結果を保存"), menu=sm)
        fm.add_command(label=tr("HTMLレポートをブラウザで開く"), command=self.open_html_report)
        fm.add_separator()
        fm.add_command(label=tr("選択中の対象を無害化して保存…"), command=self.sanitize_current)
        fm.add_command(label=tr("表示中のすべてを無害化して保存…"), command=self.sanitize_all)
        fm.add_command(label=tr("結果をクリップボードにコピー"), command=self.copy_all)
        fm.add_separator()
        fm.add_command(label=tr("スキャン履歴(ログ)…"), accelerator="Ctrl+H", command=self.open_history)
        fm.add_separator()
        fm.add_command(label=tr("終了"), command=self.on_close)
        m.add_cascade(label=tr("ファイル"), menu=fm)

        vm = tk.Menu(m, tearoff=0)
        self.v_theme = tk.StringVar(value=self.ui["theme"])
        for lab, val in ((tr("システムに合わせる"), "auto"), (tr("ライト"), "light"), (tr("ダーク"), "dark")):
            vm.add_radiobutton(label=lab, value=val, variable=self.v_theme, command=self.change_theme)
        vm.add_separator()
        vm.add_command(label=tr("文字を大きく"), accelerator="Ctrl++", command=lambda: self.change_scale(+0.1))
        vm.add_command(label=tr("文字を小さく"), accelerator="Ctrl+-", command=lambda: self.change_scale(-0.1))
        vm.add_command(label=tr("文字サイズを戻す"), accelerator="Ctrl+0", command=lambda: self.change_scale(0))
        vm.add_separator()
        vm.add_checkbutton(label=tr("問題のある対象だけ表示"), variable=self.v_only_problem, command=self.refresh_tree)
        m.add_cascade(label=tr("表示"), menu=vm)

        sm2 = tk.Menu(m, tearoff=0)
        sm2.add_command(label=tr("検知設定…"), accelerator="Ctrl+,", command=self.open_settings)
        sm2.add_command(label=tr("環境 / 依存ライブラリ…"), command=self.open_deps_window)
        lm = tk.Menu(sm2, tearoff=0)
        for lab, val in ((tr("システムに合わせる"), "auto"), ("日本語", "ja"), ("English", "en")):
            lm.add_radiobutton(label=lab, value=val, variable=self.v_lang, command=self.change_lang)
        sm2.add_cascade(label=tr("言語 / Language"), menu=lm)
        m.add_cascade(label=tr("設定"), menu=sm2)

        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label=tr("使い方と判定の見方"), accelerator="F1", command=self.open_help)
        hm.add_command(label=tr("ルール一覧…"), command=self.open_rules_window)
        hm.add_separator()
        hm.add_command(label=tr("バージョン情報"), command=self.about)
        m.add_cascade(label=tr("ヘルプ"), menu=hm)

    def _build_input(self, parent):
        box = ttk.Frame(parent)
        box.pack(fill="x")
        row = ttk.Frame(box)
        row.pack(fill="x")
        self.ent = ttk.Entry(row, textvariable=self.v_target)
        self.ent.pack(side="left", fill="x", expand=True)
        self.ent.bind("<Return>", lambda e: self.scan_entry())
        self.ph = tk.Label(self.ent, text=tr("ファイル/フォルダのパス、または URL(複数可)"), fg=self.pal["mut"],
                           bg=self.pal["input"], font=self.fonts.ui, cursor="xterm")
        self.ph.place(x=10, rely=0.5, anchor="w")
        self.ph.bind("<Button-1>", lambda e: self.ent.focus_set())
        self.v_target.trace_add("write", lambda *a: self._sync_placeholder())
        self.ent.bind("<FocusIn>", lambda e: self.ph.place_forget())
        self.ent.bind("<FocusOut>", lambda e: self._sync_placeholder())
        self.btn_scan = ttk.Button(row, text=tr("スキャン"), style="Accent.TButton", command=self.scan_entry)
        self.btn_scan.pack(side="left", padx=(8, 0))
        row2 = ttk.Frame(box)
        row2.pack(fill="x", pady=(6, 0))
        for text, cmd in ((tr("ファイルを選択…"), self.choose_files), (tr("フォルダを選択…"), self.choose_folder),
                          (tr("テキストを貼り付け…"), self.paste_dialog)):
            ttk.Button(row2, text=text, command=cmd).pack(side="left", padx=(0, 6))
        self.hint = ttk.Label(row2, style="Muted.TLabel", text=(tr("ドラッグ&ドロップでも指定できます") if self.dnd else ""))
        self.hint.pack(side="left", padx=(6, 0))

    def _sync_placeholder(self):
        if self.v_target.get() or self.root.focus_get() is self.ent:
            self.ph.place_forget()
        else:
            self.ph.place(x=10, rely=0.5, anchor="w")

    def _build_banner(self, parent):
        self.banner = tk.Frame(parent, bg=T.LEVEL_TINT_LIGHT["clean"])
        self.banner_stripe = tk.Frame(self.banner, width=5, bg=T.LEVEL_FILL["clean"])
        self.banner_stripe.pack(side="left", fill="y")
        inner = tk.Frame(self.banner, bg=T.LEVEL_TINT_LIGHT["clean"], padx=12, pady=7)
        inner.pack(side="left", fill="both", expand=True)
        self.banner_inner = inner
        self.banner_title = tk.Label(inner, text="", font=self.fonts.big, anchor="w")
        self.banner_title.pack(anchor="w")
        self.banner_sub = tk.Label(inner, text="", font=self.fonts.ui, anchor="w", justify="left")
        self.banner_sub.pack(anchor="w")
        self.chips = tk.Label(self.banner, text="", font=self.fonts.ui, padx=14)
        self.chips.pack(side="right")
        self._banner_visible = False

    def _build_progress(self, parent):
        self.prog = ttk.Frame(parent)
        self.pbar = ttk.Progressbar(self.prog, mode="determinate")
        self.pbar.pack(side="left", fill="x", expand=True)
        self.lbl_prog = ttk.Label(self.prog, text="", style="Muted.TLabel")
        self.lbl_prog.pack(side="left", padx=10)
        self.btn_cancel = ttk.Button(self.prog, text=tr("キャンセル"), command=self.cancel_scan)
        self.btn_cancel.pack(side="left")

    def _build_filter(self, parent):
        self.filter_bar = ttk.Frame(parent)
        self.filter_bar.pack(fill="x", pady=(10, 6))
        ttk.Label(self.filter_bar, text=tr("表示する重大度:"), style="Muted.TLabel").pack(side="left")
        for s in L.SEV_LIST:
            ttk.Checkbutton(self.filter_bar, text=L.SEV_NAME[s], variable=self.v_sev[s], style="Chip.TCheckbutton",
                            command=self.refresh_tree).pack(side="left", padx=(6, 0))
        self.ent_q = ttk.Entry(self.filter_bar, textvariable=self.v_query, width=26)
        self.ent_q.pack(side="right", padx=(0, 12))
        ttk.Label(self.filter_bar, text=tr("絞り込み:"), style="Muted.TLabel").pack(side="right", padx=(0, 6))
        self.v_query.trace_add("write", lambda *a: self._schedule_refresh())

    def _build_main(self, parent):
        self.main = ttk.Frame(parent)
        self.main.pack(fill="both", expand=True)
        pw = ttk.PanedWindow(self.main, orient="horizontal")
        pw.pack(fill="both", expand=True)
        self.pw = pw
        # 左: ツリー
        left = ttk.Frame(pw, style="Card.TFrame")
        cols = ("sev", "cat")
        self.tree = ttk.Treeview(left, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text=tr("対象 / 検知内容"))
        self.tree.heading("sev", text=tr("判定"))
        self.tree.heading("cat", text=tr("分類"))
        self.tree.column("#0", width=360, minwidth=180, stretch=True)
        self.tree.column("sev", width=86, minwidth=60, anchor="center", stretch=False)
        self.tree.column("cat", width=104, minwidth=70, stretch=False)
        vs = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        vs.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<<TreeviewOpen>>", lambda e: self._remember_open(True))
        self.tree.bind("<<TreeviewClose>>", lambda e: self._remember_open(False))
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Button-2>", self._context_menu)
        self.tree.bind("<Double-1>", lambda e: self.goto_preview())
        self.tree.bind("<Delete>", lambda e: None)
        pw.add(left, weight=1)
        # 右: 詳細とプレビュー
        right = ttk.Frame(pw, style="Card.TFrame")
        self.nb = ttk.Notebook(right)
        self.nb.pack(fill="both", expand=True, padx=1, pady=1)
        tab_d = ttk.Frame(self.nb, style="Plain.TFrame")
        self.nb.add(tab_d, text=tr("  詳細  "))
        self.detail = tk.Text(tab_d, wrap="word", state="disabled", relief="flat", padx=16, pady=12, cursor="arrow",
                              spacing1=2, spacing3=4, font=self.fonts.ui, borderwidth=0, highlightthickness=0)
        dvs = ttk.Scrollbar(tab_d, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dvs.set)
        self.act_bar = ttk.Frame(tab_d, style="Plain.TFrame", padding=(12, 6))
        self.act_bar.pack(side="bottom", fill="x")
        dvs.pack(side="right", fill="y")
        self.detail.pack(side="left", fill="both", expand=True)
        row1 = ttk.Frame(self.act_bar, style="Plain.TFrame")
        row2 = ttk.Frame(self.act_bar, style="Plain.TFrame")
        row1.pack(side="top", fill="x")
        row2.pack(side="top", fill="x", pady=(6, 0))
        self.btn_goto = ttk.Button(row1, text=tr("本文の該当箇所を見る"), command=self.goto_preview)
        self.btn_allow = ttk.Button(row1, text=tr("この文言を無視する(許可)"), command=self.allow_current)
        self.btn_disable = ttk.Button(row1, text=tr("このルールを無効化"), command=self.disable_current_rule)
        self.btn_goto.pack(side="left")
        self.btn_allow.pack(side="left", padx=8)
        self.btn_disable.pack(side="left")
        self.btn_sanitize = ttk.Button(row2, text=tr("無害化して保存…"), command=self.sanitize_current)
        self.btn_sanitize.pack(side="left")
        tab_p = ttk.Frame(self.nb, style="Plain.TFrame")
        self.nb.add(tab_p, text=tr("  本文プレビュー  "))
        self.pv_head = ttk.Label(tab_p, text="", style="CardMuted.TLabel", padding=(14, 8, 14, 0), wraplength=520, justify="left")
        self.pv_head.pack(fill="x")
        pvw = ttk.Frame(tab_p, style="Plain.TFrame")
        pvw.pack(fill="both", expand=True)
        self.preview = tk.Text(pvw, wrap="char", state="disabled", relief="flat", padx=14, pady=10,
                               font=self.fonts.mono, borderwidth=0, highlightthickness=0)
        pvs = ttk.Scrollbar(pvw, orient="vertical", command=self.preview.yview)
        self.preview.configure(yscrollcommand=pvs.set)
        pvs.pack(side="right", fill="y")
        self.preview.pack(side="left", fill="both", expand=True)
        pw.add(right, weight=1)
        self.root.after(50, self._set_sash)
        # 結果が空のときの案内
        self.welcome = ttk.Frame(self.main, style="Plain.TFrame", padding=(24, 22))
        ttk.Label(self.welcome, text=tr("ファイルまたは URL を指定してスキャンします"), style="Card.TLabel", font=self.fonts.bold).pack(anchor="w")
        txt = (tr("PDF / Word / Excel / PowerPoint / HTML / メール / 画像 / zip など。拡張子ではなく中身で形式を判定します。\n"
               "一覧で検知を選ぶと、見つかった文字列と対処を確認できます。\n"
               "「解析不可」は安全という意味ではありません(暗号化・破損などで中身を調べられなかった対象です)。"))
        ttk.Label(self.welcome, text=txt, style="Card.TLabel", justify="left").pack(anchor="w", pady=(10, 0))
        ttk.Label(self.welcome, text=tr('ルール {0}({1} 件)/ 設定: {2}').format(patterns.RULES_VERSION, len(patterns.ALL_PATTERNS), self.cfg_note),
                  style="CardMuted.TLabel").pack(anchor="w", pady=(14, 0))

    def _set_sash(self):
        try:
            w = self.pw.winfo_width()
            if w > 100:
                self.pw.sashpos(0, int(w * float(self.ui.get("pane_ratio", 0.46))))
        except tk.TclError:
            pass

    def _build_status(self):
        self.status = ttk.Label(self.root, text="", style="Status.TLabel", anchor="w")
        self.status.pack(fill="x", side="bottom")

    def _bind_keys(self):
        r = self.root
        r.bind("<Control-o>", lambda e: self.choose_files())
        r.bind("<Control-O>", lambda e: self.choose_folder())
        r.bind("<Control-l>", lambda e: self.focus_target())
        r.bind("<Control-f>", lambda e: (self.ent_q.focus_set(), self.ent_q.select_range(0, "end")))
        r.bind("<Control-V>", lambda e: self.paste_dialog())
        r.bind("<Control-h>", lambda e: self.open_history())
        r.bind("<F5>", lambda e: self.rescan())
        r.bind("<F1>", lambda e: self.open_help())
        r.bind("<Escape>", lambda e: self.cancel_scan() if self.scanning else None)
        r.bind("<Control-s>", lambda e: self.save_report("json"))
        r.bind("<Control-comma>", lambda e: self.open_settings())
        r.bind("<Control-equal>", lambda e: self.change_scale(+0.1))
        r.bind("<Control-plus>", lambda e: self.change_scale(+0.1))
        r.bind("<Control-minus>", lambda e: self.change_scale(-0.1))
        r.bind("<Control-0>", lambda e: self.change_scale(0))

    def _init_dnd(self):
        if not self.dnd:
            return
        try:
            from tkinterdnd2 import DND_FILES  # type: ignore
            for w in (self.root, self.ent):
                w.drop_target_register(DND_FILES)  # type: ignore
                w.dnd_bind("<<Drop>>", self._on_drop)  # type: ignore
        except Exception:
            self.dnd = False

    def _on_drop(self, event):
        self.start_scan(L.split_targets(event.data))

    def _reg(self, widget, **opts):
        self._tk_widgets.append((widget, opts))

    def _apply_tk_palette(self):
        p = self.pal
        for w, opts in self._tk_widgets:
            try:
                w.configure(**{k: p[v] for k, v in opts.items()})
            except tk.TclError:
                pass
        self.ph.configure(fg=p["mut"], bg=p["input"])
        for t in (self.detail, self.preview):
            t.configure(bg=p["card"], fg=p["fg"], selectbackground=p["sel"], selectforeground=p["sel_fg"], insertbackground=p["fg"])
        self.preview.configure(bg=p["code_bg"])
        lc = T.level_text_colors(self.theme)
        # ツリーのタグ色
        for lv in ("critical", "high", "medium", "low", "unscanned", "clean", "info"):
            self.tree.tag_configure("lv_" + lv, foreground=lc[lv], font=self.fonts.bold)
            self.tree.tag_configure("sv_" + lv, foreground=lc[lv])
        self.tree.tag_configure("muted", foreground=p["mut"])
        # 詳細テキストのタグ
        d = self.detail
        d.tag_configure("h1", font=self.fonts.big, spacing1=4, spacing3=6)
        d.tag_configure("key", foreground=p["mut"], font=self.fonts.small)
        d.tag_configure("val", font=self.fonts.ui)
        d.tag_configure("code", font=self.fonts.mono, background=p["code_bg"], lmargin1=10, lmargin2=10, rmargin=10,
                        spacing1=6, spacing3=6)
        d.tag_configure("advice", background=p["code_bg"], lmargin1=10, lmargin2=10, rmargin=10, spacing1=6, spacing3=6)
        d.tag_configure("sec", font=self.fonts.bold, spacing1=14)
        d.tag_configure("mut", foreground=p["mut"])
        for lv, col in T.LEVEL_FILL.items():
            d.tag_configure("badge_" + lv, background=col, foreground="#ffffff", font=self.fonts.bold)
            self.preview.tag_configure("hit_" + lv, background=col, foreground="#ffffff")
        self.preview.tag_configure("cur", underline=True)
        self._relayout_banner()

    def change_theme(self):
        self.ui["theme"] = self.v_theme.get()
        self.theme = T.resolve_theme(self.ui["theme"])
        self.pal = T.palette(self.theme)
        self.style = T.apply_theme(self.root, self.pal, self.fonts)
        self._apply_tk_palette()
        self.refresh_tree()
        self.root.update_idletasks()

    def change_scale(self, delta: float):
        s = 1.0 if delta == 0 else round(min(1.8, max(0.8, self.fonts.scale + delta)), 2)
        self.fonts.set_scale(s)
        self.ui["font_scale"] = s
        self.style.configure("Treeview", rowheight=self.fonts.row_height)
        self.ph.configure(font=self.fonts.ui)
        self._apply_tk_palette()
        self.set_status(tr('文字サイズ: {0}%').format(int(s * 100)))

    def focus_target(self):
        self.ent.focus_set()
        self.ent.select_range(0, "end")

    def scan_entry(self):
        targets = L.split_targets(self.v_target.get())
        targets = [L.normalize_url(t) for t in targets]
        if not targets:
            self.set_status(tr("対象を入力してください(ファイル/フォルダのパス、または URL)"))
            self.focus_target()
            return
        missing = [t for t in targets if not L.is_url(t) and not os.path.exists(t)]
        if missing:
            messagebox.showwarning(tr("見つかりません"), tr("次のパスが見つかりません:\n\n") + "\n".join(missing[:8]), parent=self.root)
            return
        self.start_scan(targets)

    def choose_files(self):
        ps = filedialog.askopenfilenames(title=tr("スキャンするファイルを選択"), initialdir=self.ui.get("last_dir") or None, parent=self.root)
        if ps:
            self.ui["last_dir"] = os.path.dirname(ps[0])
            self.start_scan(list(ps))

    def choose_folder(self):
        d = filedialog.askdirectory(title=tr("スキャンするフォルダを選択(サブフォルダも対象)"), initialdir=self.ui.get("last_dir") or None, parent=self.root)
        if d:
            self.ui["last_dir"] = d
            self.start_scan([d])

    def paste_dialog(self):
        win = tk.Toplevel(self.root)
        win.title(tr("テキストを貼り付けてスキャン"))
        win.configure(bg=self.pal["bg"])
        win.transient(self.root)
        # ボタン列を先に下端へ pack しておく。後だと小さい画面で切れる
        sc = max(1.0, self.fonts.scale)
        w = int(min(self.root.winfo_screenwidth() * 0.8, 760 * sc))
        h = int(min(self.root.winfo_screenheight() * 0.8, 480 * sc))
        win.geometry(f"{w}x{h}")
        win.minsize(420, 260)

        bar = ttk.Frame(win, padding=(14, 10, 14, 14))
        bar.pack(side="bottom", fill="x")
        ttk.Label(win, text=tr("AI に渡そうとしているテキストを貼り付けてください(Ctrl+V)。"),
                  padding=(14, 12, 14, 4)).pack(side="top", anchor="w")
        body = ttk.Frame(win)
        body.pack(side="top", fill="both", expand=True, padx=14)
        tx = tk.Text(body, wrap="word", bg=self.pal["input"], fg=self.pal["fg"], insertbackground=self.pal["fg"],
                     relief="flat", highlightthickness=1, highlightbackground=self.pal["border"],
                     font=self.fonts.ui, padx=10, pady=8, undo=True)
        sb = ttk.Scrollbar(body, orient="vertical", command=tx.yview)
        tx.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tx.pack(side="left", fill="both", expand=True)

        def go():
            s = tx.get("1.0", "end").strip()
            if not s:
                return
            win.destroy()
            self.start_text(s)

        ttk.Button(bar, text=tr("スキャン"), style="Accent.TButton", command=go).pack(side="right")
        ttk.Button(bar, text=tr("キャンセル"), command=win.destroy).pack(side="right", padx=8)
        ttk.Label(bar, text=tr("Ctrl+Enter でスキャン / Esc で閉じる"), style="Muted.TLabel").pack(side="left")
        try:
            clip = self.root.clipboard_get()
            tx.insert("1.0", clip)
        except tk.TclError:
            pass
        tx.focus_set()
        win.bind("<Control-Return>", lambda e: go())
        win.bind("<Escape>", lambda e: win.destroy())
        self.paste_win = win

    def _fill_recent(self):
        m = self.recent_menu
        m.delete(0, "end")
        rec = self.ui.get("recent", [])
        if not rec:
            m.add_command(label=tr("(なし)"), state="disabled")
            return
        for t in rec:
            m.add_command(label=L.short_name(t, 70) if not L.is_url(t) else t[:70], command=lambda t=t: self.start_scan([t]))
        m.add_separator()
        m.add_command(label=tr("履歴を消去"), command=lambda: self.ui.update(recent=[]))

    # スキャン実行
    def start_scan(self, targets: List[str]):
        targets = [t for t in targets if t]
        if not targets:
            return
        if self.scanning:
            self.set_status(tr("別のスキャンが実行中です。完了またはキャンセルしてから実行してください。"))
            return
        self.last_targets = list(targets)
        for t in targets[:3]:
            L.add_recent(self.ui, t)
        det = self.detector

        def job(cancel, on_prog, on_res):
            return L.run_scan(targets, det, cancel, on_prog, on_res)

        self._begin(job, tr('{0} 件の対象をスキャン中…').format(len(targets)), targets)

    def start_text(self, text: str):
        self.last_targets = []
        self._pasted_text = text
        det = self.detector

        def job(cancel, on_prog, on_res):
            on_prog(L.Progress(0, 1, PASTE_SRC))
            on_res(scan_text(text, source=PASTE_SRC, detector=det))
            on_prog(L.Progress(1, 1, ""))
            return 1, False

        self._begin(job, tr("テキストをスキャン中…"), [PASTE_SRC])

    def rescan(self):
        if self.last_targets:
            self.start_scan(self.last_targets)
        else:
            self.set_status(tr("再スキャンする対象がありません"))

    def _begin(self, job, label, targets=()):
        self.results = []
        self._open_pref = {}
        self.logger = None
        if self.ui.get("log_enabled", True):
            self.logger = scanlog.ScanLogger(targets=targets, mode="gui").start()
            if self.logger.error:
                self.set_status(tr("ログを保存できません: ") + self.logger.error)
        self.cancel.clear()
        self.scanning = True
        self.t_start = time.monotonic()
        self.btn_scan.state(["disabled"])
        self.btn_cancel.state(["!disabled"])
        self.lbl_prog.config(text=label)
        self.pbar.configure(mode="indeterminate")
        self.pbar.start(12)
        self.prog.pack(fill="x", pady=(10, 0), before=self.filter_bar)
        self.show_welcome(False)
        self.refresh_tree()
        self._update_banner()
        self.set_status(label)

        def worker():
            try:
                done, cancelled = job(self.cancel, lambda p: self.q.put(("progress", p)), lambda r: self.q.put(("result", r)))
                self.q.put(("done", (done, cancelled)))
            except Exception as e:  # noqa
                self.q.put(("error", f"{type(e).__name__}: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def cancel_scan(self):
        if self.scanning:
            self.cancel.set()
            self.btn_cancel.state(["disabled"])
            self.lbl_prog.config(text=tr("キャンセル中…(実行中の1件が終わるまでお待ちください)"))

    def _poll(self):
        changed = False
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    self._on_progress(payload)
                elif kind == "result":
                    self.results.append(payload)
                    if self.logger:
                        self.logger.write(payload)
                    changed = True
                elif kind == "done":
                    self._on_done(*payload)
                    changed = False
                elif kind == "error":
                    self._on_error(payload)
                elif kind == "status":
                    self.set_status(payload)
                elif kind == "bg":
                    self.busy_bg = False
                    cb, res = payload
                    cb(res)
                    if self._cur_result is not None:
                        self._set_actions(self._cur_finding)
        except queue.Empty:
            pass
        if changed:
            self._schedule_refresh()
            self._update_banner()
        self._poll_id = self.root.after(80, self._poll)

    def _on_progress(self, p: "L.Progress"):
        if p.total:
            if str(self.pbar.cget("mode")) != "determinate":
                self.pbar.stop()
                self.pbar.configure(mode="determinate", maximum=p.total)
            self.pbar.configure(maximum=p.total, value=p.done)
        txt = tr('{0}/{1} 件').format(p.done, p.total)
        if p.current:
            txt += f" — {L.short_name(p.current, 50)}"
        if p.truncated:
            txt += tr("(件数が多いため先頭のみ)")
        if not self.cancel.is_set():
            self.lbl_prog.config(text=txt)

    def _on_done(self, done: int, cancelled: bool):
        self.scanning = False
        self.pbar.stop()
        self.prog.pack_forget()
        self.btn_scan.state(["!disabled"])
        self.results = L.sort_results(self.results)
        self.refresh_tree(select_first=True)
        self._update_banner()
        el = time.monotonic() - self.t_start
        msg = tr('{0} 件を解析しました({1:.1f} 秒)').format(len(self.results), el)
        if cancelled:
            msg = tr('キャンセルしました。{0} 件までの結果を表示しています').format(len(self.results))
        msg += tr(' — ルール {0}').format(patterns.RULES_VERSION)
        if self.logger:
            self.logger.end(done, cancelled)
            if self.logger.error:
                msg += tr(' / ログ保存に失敗: {0}').format(self.logger.error)
            elif self.logger.path:
                msg += tr(' / ログ: {0}').format(os.path.basename(self.logger.path))
        self.set_status(msg)
        if not self.results:
            self.show_welcome(True)
            self.set_status(tr("スキャン対象が見つかりませんでした"))

    def _on_error(self, msg: str):
        self.scanning = False
        self.pbar.stop()
        self.prog.pack_forget()
        self.btn_scan.state(["!disabled"])
        if self.logger:
            self.logger.end(len(self.results), False, msg)
        self.set_status(tr("エラー: ") + msg)
        messagebox.showerror(tr("スキャン中にエラーが発生しました"), msg, parent=self.root)

    def show_welcome(self, on: bool):
        if on:
            self.welcome.place(in_=self.main, x=0, y=0, relwidth=1, relheight=1)
            self.welcome.lift()
        else:
            self.welcome.place_forget()

    def clear_results(self):
        if self.scanning:
            return
        self.results = []
        self._open_pref = {}
        self.refresh_tree()
        self._update_banner()
        self.show_welcome(True)
        self._show_detail_empty()

    def _relayout_banner(self):
        if hasattr(self, "banner") and self._banner_visible:
            self._update_banner()

    def _update_banner(self):
        if not self.results and not self.scanning:
            self.banner.pack_forget()
            self._banner_visible = False
            return
        if not self._banner_visible:
            self.banner.pack(fill="x", pady=(8, 0), before=self.filter_bar)
            self._banner_visible = True
        worst = L.worst_level(self.results) if self.results else "clean"
        tint = T.level_tint(self.theme)[worst]
        col = T.level_text_colors(self.theme)[worst]
        n = len(self.results)
        nf = sum(len(r.findings) for r in self.results)
        title = L.LEVEL_NAME[worst] if self.results else tr("スキャン中")
        if self.scanning:
            title += tr("(スキャン中…)")
        sub = tr('{0} 件の対象 / {1} 件の検知').format(n, nf)
        n_un = sum(1 for r in self.results if r.status != "scanned")
        if worst == "clean" and n_un:
            sub += tr(' — ただし {0} 件は一部のみ解析').format(n_un)
        elif worst == "unscanned":
            sub += tr(" — 解析できなかった対象があります。安全とは判断できません")
        elif worst in ("high", "critical"):
            sub += tr(" — このまま AI に読ませないでください")
        for w in (self.banner, self.banner_inner, self.banner_title, self.banner_sub, self.chips):
            w.configure(bg=tint)
        self.banner_stripe.configure(bg=col)
        self.banner_title.configure(text=title, fg=col)
        self.banner_sub.configure(text=sub, fg=self.pal["fg"])
        cnt = L.count_levels(self.results)
        self.chips.configure(fg=self.pal["mut"], text="   ".join(f"{L.LEVEL_NAME[lv]} {cnt[lv]}" for lv in L.LEVEL_ORDER if cnt.get(lv)))

    def _schedule_refresh(self):
        if self._refresh_after is None:
            self._refresh_after = self.root.after(150, self._do_refresh)

    def _do_refresh(self):
        self._refresh_after = None
        self.refresh_tree()

    def _remember_open(self, on: bool):
        """手で開閉した対象だけ覚えておく。再描画しても維持するため。"""
        iid = self.tree.focus()
        key = self.node_map.get(iid)
        if key is not None and key[1] is None and key[0] < len(self.results):
            self._open_pref[self.results[key[0]].source] = on

    def refresh_tree(self, select_first: bool = False):
        sevs = {s for s, v in self.v_sev.items() if v.get()}
        self.ui["sev_filter"] = sorted(sevs)
        q = self.v_query.get()
        prev = self.tree.selection()
        prev_key = self.node_map.get(prev[0]) if prev else None
        # 基本は折りたたみ。1件だけで完了済みなら開く
        default_open = (not self.scanning) and len(self.results) == 1
        self.tree.delete(*self.tree.get_children())
        self.node_map = {}
        shown = 0
        for idx, r in enumerate(self.results):
            if not L.result_visible(r, sevs, q, self.v_only_problem.get()):
                continue
            fs = L.visible_findings(r, sevs, q)
            pid = f"r{idx}"
            lv = r.risk_level
            lab = L.LEVEL_NAME[lv] + (tr("(一部のみ)") if r.status == "partial" and lv in ("clean", "low") else "")
            cnt = tr('  ({0}件)').format(len(r.findings)) if r.findings else ""
            self.tree.insert("", "end", iid=pid, text=" " + L.short_name(r.source, 70) + cnt, open=self._open_pref.get(r.source, default_open),
                             values=(lab, r.kind or "-"), tags=("lv_" + lv,))
            self.node_map[pid] = (idx, None)
            for j, f in enumerate(fs):
                cid = f"{pid}.{j}"
                self.tree.insert(pid, "end", iid=cid, text="   " + L.tree_label(f),
                                 values=(L.SEV_NAME[f.severity], L.CATEGORY_NAME.get(f.category, f.category)),
                                 tags=("sv_" + f.severity,))
                self.node_map[cid] = (idx, f)
            shown += 1
        if not shown and self.results:
            self.tree.insert("", "end", iid="empty", text=tr("  表示条件に一致する項目がありません(重大度/絞り込みを確認)"), tags=("muted",))
        if select_first:
            kids = self.tree.get_children()
            if kids and kids[0] != "empty":
                self.tree.selection_set(kids[0])
                self.tree.see(kids[0])
        elif prev_key:
            for iid, key in self.node_map.items():
                if key[0] == prev_key[0] and key[1] is prev_key[1]:
                    self.tree.selection_set(iid)
                    break

    # 詳細とプレビュー
    def _on_select(self, _e=None):
        sel = self.tree.selection()
        if not sel or sel[0] not in self.node_map:
            self._show_detail_empty()
            return
        idx, f = self.node_map[sel[0]]
        r = self.results[idx]
        self._cur_result, self._cur_finding = r, f
        self._render_detail(r, f)
        self._render_preview(r, f)

    def _set_actions(self, f: Optional[Finding]):
        for b in (self.btn_goto, self.btn_allow, self.btn_disable):
            b.state(["!disabled"] if f is not None else ["disabled"])
        if f is not None and (f.offset < 0 or not (self._cur_result and self._cur_result.text)):
            self.btn_goto.state(["disabled"])
        self.btn_sanitize.state(["!disabled"] if self._cur_result is not None and not self.busy_bg else ["disabled"])

    def _show_detail_empty(self):
        self._cur_result = self._cur_finding = None
        d = self.detail
        d.config(state="normal")
        d.delete("1.0", "end")
        d.insert("end", tr("左の一覧から対象または検知を選ぶと、ここに詳しい内容が表示されます。"), "mut")
        d.config(state="disabled")
        self._set_actions(None)
        self._set_preview_text("", [])
        self.pv_head.config(text="")

    def _ins(self, *parts):
        for text, tag in parts:
            self.detail.insert("end", text, tag)

    def _render_detail(self, r: ScanResult, f: Optional[Finding]):
        d = self.detail
        d.config(state="normal")
        d.delete("1.0", "end")
        if f is None:
            self._ins((f" {L.LEVEL_NAME[r.risk_level]} ", "badge_" + r.risk_level), ("  ", ""), (L.short_name(r.source, 80) + "\n", "h1"))
            rows = [(tr("対象"), r.source), (tr("形式"), r.kind or "-"), (tr("解析の状態"), L.STATUS_TEXT.get(r.status, r.status)),
                    (tr("文字数"), f"{r.text_length:,}"), (tr("リスクスコア"), f"{r.risk_score} / 100")]
            if r.size:
                rows.insert(2, (tr("サイズ"), L.human_size(r.size)))
            if r.encoding:
                rows.append((tr("文字コード"), r.encoding))
            if r.sha256:
                rows.append(("SHA-256", r.sha256))
            for k, v in rows:
                self._ins((k + "  ", "key"), (v + "\n", "val"))
            sv = L.count_severities([r])
            if sv:
                self._ins((tr("検知の内訳\n"), "sec"))
                self._ins(("  ".join(f"{L.SEV_NAME[s]} {sv[s]}" for s in L.SEV_LIST if sv.get(s)) + "\n", "val"))
            if r.status == "unscanned":
                self._ins((tr("この対象は解析できませんでした\n"), "sec"),
                          (tr("「問題なし」ではありません。暗号化されている・壊れている・対応していない形式・取得できなかった、などの理由で中身を調べられていません。"
                           "パスワードを解除する、別の形式に変換する、内容を目視で確認するなどしてから AI に渡してください。\n"), "advice"))
            elif r.status == "partial":
                self._ins((tr("一部のみ解析しました\n"), "sec"),
                          (tr("全体は調べられていません。理由は下の注記を確認してください。\n"), "advice"))
            if r.notes:
                self._ins((tr("注記\n"), "sec"))
                for n in r.notes:
                    self._ins(("・" + tr(n) + "\n", "val"))
            if not r.findings and r.status == "scanned":
                self._ins((tr("\n間接プロンプトインジェクションの兆候は検出されませんでした。\n"), "val"))
        else:
            self._ins((f" {L.SEV_NAME[f.severity]} ", "badge_" + f.severity), ("  ", ""), (tr(f.description) + "\n", "h1"))
            self._ins((tr("対象  "), "key"), (L.short_name(r.source, 90) + "\n", "val"))
            if f.location:
                self._ins((tr("位置  "), "key"), (tr(f.location) + (tr('  (行 {0})').format(f.line) if f.line else "") + "\n", "val"))
            self._ins((tr("分類  "), "key"), (L.CATEGORY_NAME.get(f.category, f.category) + "\n", "val"))
            self._ins((tr("ルール  "), "key"), (f.rule_id + "\n", "val"))
            if f.snippet:
                self._ins((tr("見つかった文字列\n"), "sec"), (f.snippet + "\n", "code"))
            if f.detail:
                self._ins((tr("補足\n"), "sec"), (tr(f.detail) + "\n", "val"))
            adv = L.advice_for(f)
            if adv:
                self._ins((tr("なぜ危険か・対処\n"), "sec"), (adv + "\n", "advice"))
        d.config(state="disabled")
        d.yview_moveto(0)
        self._set_actions(f)

    def _set_preview_text(self, text: str, spans):
        pv = self.preview
        pv.config(state="normal")
        pv.delete("1.0", "end")
        pv.insert("end", text)
        for a, b, sev in spans:
            pv.tag_add("hit_" + sev, f"1.0+{a}c", f"1.0+{b}c")
        pv.config(state="disabled")

    def _render_preview(self, r: ScanResult, f: Optional[Finding]):
        text = r.text or ""
        if not text:
            self._set_preview_text(tr("(本文プレビューはありません。解析できなかった対象や空の文書です)"), [])
            self.pv_head.config(text="")
            return
        shown = text[:PREVIEW_LIMIT]
        spans = L.highlight_spans(r, len(shown))
        self._set_preview_text(shown, spans)
        more = tr('(長いため先頭 {0:,} 文字のみ表示)').format(PREVIEW_LIMIT) if len(text) > PREVIEW_LIMIT else ""
        self.pv_head.config(text=tr('{0} — 照合用に正規化した本文(不可視文字は除去済み)。黄/色付きが検知箇所です。{1}').format(L.short_name(r.source, 70), more))
        if f is not None and f.offset < 0:
            self.pv_head.config(text=self.pv_head.cget("text") + tr('\n※ 選択中の検知は本文ではなく「{0}」にあるため、ここには表示されません(詳細タブの抜粋を参照)。').format(tr(f.location) if f.location else tr('本文以外')))
        if f is not None and f.offset >= 0 and f.offset < len(shown):
            idx = f"1.0+{f.offset}c"
            self.preview.tag_remove("cur", "1.0", "end")
            self.preview.tag_add("cur", idx, f"1.0+{min(len(shown), f.offset + max(1, f.length))}c")
            self.preview.see(idx)
        else:
            self.preview.yview_moveto(0)

    def goto_preview(self):
        f = self._cur_finding
        if f is None or f.offset < 0 or not (self._cur_result and self._cur_result.text):
            return
        self.nb.select(1)
        self.preview.see(f"1.0+{f.offset}c")

    def _context_menu(self, ev):
        iid = self.tree.identify_row(ev.y)
        if not iid or iid not in self.node_map:
            return
        self.tree.selection_set(iid)
        idx, f = self.node_map[iid]
        r = self.results[idx]
        m = tk.Menu(self.root, tearoff=0)
        if f is not None:
            m.add_command(label=tr("検知内容をコピー"), command=lambda: self._copy(f"{tr(f.description)}\n{f.snippet}"))
            m.add_command(label=tr("この文言を無視する(許可)"), command=self.allow_current)
            m.add_command(label=tr("このルールを無効化"), command=self.disable_current_rule)
            m.add_separator()
        m.add_command(label=tr("パスをコピー"), command=lambda: self._copy(r.source))
        if not L.is_url(r.source) and os.path.exists(r.source):
            m.add_command(label=tr("ファイルの場所を開く"), command=lambda: self.reveal(r.source))
        m.add_command(label=tr("この対象だけ再スキャン"), command=lambda: self.start_scan([r.source]))
        m.add_command(label=tr("無害化して保存…"), command=self.sanitize_current)
        m.tk_popup(ev.x_root, ev.y_root)

    def _copy(self, s: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(s)
        self.set_status(tr("クリップボードにコピーしました"))

    def copy_all(self):
        if not self.results:
            return
        self._copy("\n".join(report.format_text(r) for r in self.results))

    def reveal(self, path: str):
        try:
            if sys.platform.startswith("win"):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
        except Exception as e:  # noqa
            self.set_status(tr('開けませんでした: {0}').format(e))

    def _save_cfg(self, note: str):
        try:
            p = L.save_user_config(self.cfg)
        except OSError as e:
            messagebox.showerror(tr("設定を保存できません"), str(e), parent=self.root)
            return
        self.detector = Detector(self.cfg)
        self.cfg_note = p
        self.set_status(tr('{0}(設定を保存しました: {1})。「再スキャン」で反映できます').format(note, p))

    def allow_current(self):
        f = self._cur_finding
        if f is None:
            return
        pat = L.allow_pattern_for(f)
        if not pat:
            return
        if not messagebox.askyesno(tr("この文言を無視しますか?"),
                                   tr('今後、次の文言を含む検知を無視します(許可パターンに追加):\n\n{0}\n\n安全な文言であることを確認してから追加してください。').format(f.snippet[:160]), parent=self.root):
            return
        if pat not in self.cfg.allow_patterns:
            self.cfg.allow_patterns.append(pat)
        self._save_cfg(tr("許可パターンを追加しました"))

    def disable_current_rule(self):
        f = self._cur_finding
        if f is None:
            return
        rid = f.rule_id.rsplit(":", 1)[-1]
        if not messagebox.askyesno(tr("このルールを無効化しますか?"),
                                   tr('ルール「{0}」を無効にします。\n{1}\n\n無効にすると同種の攻撃を見逃します。誤検知が多い場合は、重大度を下げる方が安全です(検知設定 → ルール)。').format(rid, tr(f.description)), parent=self.root):
            return
        if rid not in self.cfg.disabled_rules:
            self.cfg.disabled_rules.append(rid)
        self._save_cfg(tr('ルール {0} を無効化しました').format(rid))

    def _need_results(self) -> bool:
        if not self.results:
            messagebox.showinfo(tr("保存する結果がありません"), tr("先にスキャンしてください。"), parent=self.root)
            return False
        return True

    def save_report(self, kind: str):
        if not self._need_results():
            return
        ext = {"json": ".json", "html": ".html", "markdown": ".md", "csv": ".csv", "text": ".txt"}[kind]
        stamp = time.strftime("%Y%m%d_%H%M%S")
        p = filedialog.asksaveasfilename(parent=self.root, defaultextension=ext, initialfile=f"pdetector_{stamp}{ext}",
                                         initialdir=self.ui.get("last_dir") or None, filetypes=[(kind.upper(), "*" + ext)])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8-sig" if kind == "csv" else "utf-8", newline="") as fh:
                fh.write(self._format(kind))
        except OSError as e:
            messagebox.showerror(tr("保存できません"), str(e), parent=self.root)
            return
        self.set_status(tr('保存しました: {0}').format(p))

    def _format(self, kind: str) -> str:
        rs = self.results
        if kind == "json":
            return report.format_json(rs)
        if kind == "html":
            return report.format_html(rs)
        if kind == "markdown":
            return report.format_markdown(rs)
        if kind == "csv":
            return report.format_csv(rs)
        return "\n".join(report.format_text(r) for r in rs)

    def open_html_report(self):
        if not self._need_results():
            return
        try:
            fd, p = tempfile.mkstemp(suffix=".html", prefix="pdetector_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(report.format_html(self.results))
            webbrowser.open("file://" + p.replace("\\", "/") if not p.startswith("/") else "file://" + p)
        except Exception as e:  # noqa
            messagebox.showerror(tr("開けません"), str(e), parent=self.root)

    # 無害化
    def _run_bg(self, work, done, label: str):
        """work を別スレッドで走らせ、done は UI スレッドで呼ぶ。"""
        if self.busy_bg:
            self.set_status(tr("別の処理が実行中です。完了までお待ちください。"))
            return
        self.busy_bg = True
        self.set_status(label)
        self.btn_sanitize.state(["disabled"])

        def run():
            try:
                res = work()
            except Exception as e:  # noqa
                res = neutralize.SanitizeOutcome(source="", state="skipped", notes=[f"{type(e).__name__}: {e}"])
            self.q.put(("bg", (done, res)))

        threading.Thread(target=run, daemon=True).start()

    def _sanitize_one(self, src: str, fmt: str = "auto") -> "neutralize.SanitizeOutcome":
        if src == PASTE_SRC:
            return neutralize.sanitize_string(self._pasted_text, src, self.detector)
        return neutralize.sanitize_source(src, self.detector, fmt=fmt)

    def sanitize_current(self):
        r = self._cur_result
        if r is None:
            messagebox.showinfo(tr("無害化"), tr("一覧から対象を選んでください。"), parent=self.root)
            return
        src = r.source
        if src == PASTE_SRC and not self._pasted_text:
            messagebox.showinfo(tr("無害化"), tr("貼り付けテキストが残っていないため、無害化できません。"), parent=self.root)
            return
        init_dir = os.path.dirname(src) if (not L.is_url(src) and os.path.isfile(src)) else (self.ui.get("last_dir") or "")
        native = neutralize.native_format(r.kind or "") if src != PASTE_SRC else ""
        types = [(tr("テキスト"), "*.txt"), (tr("すべて"), "*.*")]
        if native:
            nm = {"pptx": "PowerPoint", "docx": "Word", "xlsx": "Excel"}[native]
            types = [(f"{nm} (*.{native})", f"*.{native}")] + types
        path = filedialog.asksaveasfilename(parent=self.root, title=tr("無害化したファイルの保存先"),
                                            initialdir=init_dir or None, initialfile=neutralize.default_name(src, native or "txt"),
                                            defaultextension="." + (native or "txt"), filetypes=types)
        if not path:
            return
        self.ui["last_dir"] = os.path.dirname(path)
        as_text = path.lower().endswith(".txt")

        def work():
            o = self._sanitize_one(src, "txt" if as_text else "auto")
            if o.state in ("ok", "partial"):
                try:
                    neutralize.write_outcome(o, neutralize.fix_ext(path, o), overwrite=True)
                except (OSError, ValueError) as e:
                    o.state = "skipped"
                    o.notes.append(str(e))
            return o

        self._run_bg(work, lambda o: self._show_sanitize_result([o]), tr("無害化中…"))

    def sanitize_all(self):
        srcs = [r.source for r in self.results if r.source != PASTE_SRC or self._pasted_text]
        if not srcs:
            messagebox.showinfo(tr("無害化"), tr("無害化できる対象がありません。先にスキャンしてください。"), parent=self.root)
            return
        d = filedialog.askdirectory(parent=self.root, title=tr("無害化したファイルを保存するフォルダ"),
                                    initialdir=self.ui.get("last_dir") or None)
        if not d:
            return
        self.ui["last_dir"] = d
        n = len(srcs)

        def work():
            outs = []
            for i, s in enumerate(srcs, start=1):
                self.q.put(("status", tr('無害化中… {0}/{1}: {2}').format(i, n, L.short_name(s, 50))))
                o = self._sanitize_one(s)
                if o.state in ("ok", "partial"):
                    try:
                        name = neutralize.default_name(s if s != PASTE_SRC else "pasted-text", o.fmt)
                        neutralize.write_outcome(o, neutralize.unique_path(d, name))
                    except (OSError, ValueError) as e:
                        o.state = "skipped"
                        o.notes.append(str(e))
                outs.append(o)
            try:
                with open(os.path.join(d, "sanitize_report.csv"), "w", encoding="utf-8-sig", newline="") as fh:
                    fh.write(neutralize.report_csv(outs))
            except OSError:
                pass
            return outs

        self._run_bg(work, lambda outs: self._show_sanitize_result(outs, d), tr('{0} 件を無害化中…').format(n))

    def _show_sanitize_result(self, outs, folder: str = ""):
        self.set_status(tr("無害化が完了しました"))
        if len(outs) == 1:
            o = outs[0]
            lines = [f"{L.short_name(o.source, 60)}", ""]
            lines.append(tr("結果: ") + neutralize.STATE_JA.get(o.state, o.state))
            if o.state in ("ok", "partial"):
                lines.append(tr('除去した隠し要素: {0} 件 / 不可視文字: {1} 文字 / 伏せ字にした文: {2} 件').format(o.hidden_dropped, o.invisible_removed, o.redacted))
                lines.append(tr('保存先: {0}').format(o.out_path))
                if o.state == "partial":
                    lines += ["", tr("元ファイルを一部しか解析できなかったため、取りこぼしがある可能性があります。内容を確認してから使ってください。")]
                lines += ["", (tr("見えている本文だけで作り直した、素のファイルです(元のレイアウト・画像・書式は残りません)。保存先の場所を開きますか?")
                               if o.fmt != "txt" else tr("出力はプレーンテキストです(書式・画像は残りません)。保存先の場所を開きますか?"))]
                if messagebox.askyesno(tr("無害化が完了しました"), "\n".join(lines), parent=self.root):
                    self.reveal(o.out_path)
                return
            if o.state == "unsafe":
                lines += ["", tr("命令文を取り除ききれなかったため、出力しませんでした(安全と確認できないものは渡さない方針です)。")]
            else:
                lines += ["", tr("内容を読み取れなかったため、無害化できません。") + (" " + tr(o.notes[0]) if o.notes else "")]
            messagebox.showwarning(tr("無害化できませんでした"), "\n".join(lines), parent=self.root)
            return
        cnt = {k: sum(1 for o in outs if o.state == k) for k in ("ok", "partial", "unsafe", "skipped")}
        lines = [tr('{0} 件を処理しました。').format(len(outs)), "",
                 tr('無害化・確認済み: {0} 件').format(cnt['ok']), tr('一部のみ(要確認): {0} 件').format(cnt['partial']),
                 tr('無害化できず(出力なし): {0} 件').format(cnt['unsafe']), tr('スキップ(読めない): {0} 件').format(cnt['skipped']), "",
                 tr('保存先: {0}').format(folder), tr("一覧は sanitize_report.csv に書き出しました。"), "", tr("保存先のフォルダを開きますか?")]
        if messagebox.askyesno(tr("無害化が完了しました"), "\n".join(lines), parent=self.root):
            from .gui_history import open_folder
            try:
                open_folder(folder)
            except Exception:  # noqa
                pass

    def _prune_logs(self):
        try:
            scanlog.prune(keep_days=int(self.ui.get("log_keep_days", 90)))
        except Exception:  # noqa  ログの掃除に失敗しても無視
            pass

    def open_history(self):
        from .gui_history import HistoryWindow
        HistoryWindow(self)

    def show_logged(self, path: str):
        """ログの結果をメイン画面に出す。本文は保存していないのでプレビューは空。"""
        head, results, foot = scanlog.read_session(path)
        self.results = L.sort_results(results)
        self._open_pref = {}
        self.last_targets = [t for t in head.get("targets", []) if t and not t.startswith("(")]
        self.show_welcome(not self.results)
        self.refresh_tree(select_first=True)
        self._update_banner()
        when = head.get("started", "")
        self.set_status(tr('履歴を表示中: {0}({1} 件)— 過去のスキャン結果です。最新の状態は「再スキャン」で確認できます').format(when, len(results)))

    def open_settings(self):
        from .gui_settings import SettingsDialog
        dlg = SettingsDialog(self.root, self.cfg, self.fonts, self.pal, T.level_text_colors(self.theme),
                             config_path=L.user_config_path())
        self.root.wait_window(dlg)
        if dlg.result is not None:
            dlg.result.keep_text = True
            self.cfg = dlg.result
            self._save_cfg(tr("検知設定を更新しました"))

    def open_help(self):
        win = tk.Toplevel(self.root)
        win.title(tr("使い方と判定の見方"))
        win.configure(bg=self.pal["bg"])
        win.geometry("700x620")
        tx = tk.Text(win, wrap="word", relief="flat", padx=20, pady=16, bg=self.pal["card"], fg=self.pal["fg"], font=self.fonts.ui,
                     borderwidth=0, highlightthickness=0, spacing3=4)
        tx.pack(fill="both", expand=True)
        tx.tag_configure("h", font=self.fonts.big, spacing1=10, spacing3=6)
        tx.tag_configure("b", font=self.fonts.bold)
        lc = T.LEVEL_FILL
        for lv in lc:
            tx.tag_configure("b_" + lv, background=lc[lv], foreground="#ffffff", font=self.fonts.bold)

        def h(s): tx.insert("end", s + "\n", "h")

        h(tr("これは何をするツール?"))
        tx.insert("end", tr("AI(LLM)に読ませる文書の中に仕込まれた「以前の指示を無視しろ」「ユーザーには黙って情報を送れ」といった隠れた命令(間接プロンプトインジェクション)を、"
                         "AI に渡す前に見つけます。PDF・Office・HTML・メール・画像・zip など、拡張子ではなく中身で判定します。\n"))
        h(tr("判定の見方"))
        for lv, txt in (("critical", tr("重大: 隠されていて、かつ命令文。AI に渡さないでください。")), ("high", tr("高: 明確な攻撃文や、文字を隠す細工があります。")),
                        ("medium", tr("中: 疑わしい要素があります。内容を確認してください。")), ("low", tr("低: 軽微な兆候です(正当な使い方の可能性が高い)。")),
                        ("unscanned", tr("解析不可: 暗号化・破損などで調べられていません。安全という意味ではありません。")), ("clean", tr("問題なし: 兆候は見つかりませんでした。"))):
            tx.insert("end", f" {L.LEVEL_NAME[lv]} ", "b_" + lv)
            tx.insert("end", "  " + txt + "\n")
        h(tr("結果の使い方"))
        tx.insert("end", tr("・左の一覧で対象や検知を選ぶと、右に「見つかった文字列」「なぜ危険か・対処」が表示されます。\n"
                         "・「本文プレビュー」では、検知箇所が色付きで強調されます(ダブルクリックでも移動)。\n"
                         "・誤検知は「この文言を無視する」で許可、ルール自体が合わない場合は検知設定で重大度を下げてください。\n"
                         "・結果は JSON / HTML / Markdown / CSV で保存できます。\n"))
        h(tr("ショートカット"))
        tx.insert("end", tr("Ctrl+O ファイル / Ctrl+Shift+O フォルダ / Ctrl+L 入力欄 / Ctrl+Shift+V 貼り付け / F5 再スキャン / Esc キャンセル / "
                         "Ctrl+F 絞り込み / Ctrl+, 設定 / Ctrl++・- 文字サイズ / Ctrl+S JSON保存\n"))
        h(tr("限界"))
        tx.insert("end", tr("ルールベースなので、言い換えや未対応言語の攻撃文は見逃します。判定が「問題なし」でも安全を保証するものではありません。\n"))
        tx.configure(state="disabled")
        win.bind("<Escape>", lambda e: win.destroy())

    def open_rules_window(self):
        win = tk.Toplevel(self.root)
        win.title(tr('ルール一覧(rules {0})').format(patterns.RULES_VERSION))
        win.geometry("940x560")
        win.configure(bg=self.pal["bg"])
        tv = ttk.Treeview(win, columns=("sev", "cat", "id", "desc"), show="headings")
        for c, t, w in (("sev", tr("重大度"), 70), ("cat", tr("分類"), 120), ("id", "ID", 210), ("desc", tr("説明"), 500)):
            tv.heading(c, text=t)
            tv.column(c, width=w, anchor="center" if c == "sev" else "w")
        lc = T.level_text_colors(self.theme)
        for s, col in lc.items():
            tv.tag_configure(s, foreground=col)
        from .gui_settings import all_rules
        for rid, desc, sev, cat in all_rules():
            tv.insert("", "end", values=(L.SEV_NAME[sev], L.CATEGORY_NAME.get(cat, cat), rid, desc), tags=(sev,))
        tv.pack(fill="both", expand=True, padx=10, pady=10)

    def about(self):
        messagebox.showinfo(tr("バージョン情報"), tr('PDetector {0}\nルール {1}\n\n間接プロンプトインジェクション検知ツール\n設定: ').format(TOOL_VERSION, patterns.RULES_VERSION) + self.cfg_note, parent=self.root)

    def open_deps_window(self):
        win = tk.Toplevel(self.root)
        win.title(tr("環境 / 依存ライブラリ"))
        win.geometry("780x560")
        win.configure(bg=self.pal["bg"])
        info = deps.python_info()
        top = ttk.Frame(win, padding=14)
        top.pack(fill="x")
        ttk.Label(top, text=tr("このアプリを動かしている Python(ここに入れないと反映されません)"), font=self.fonts.bold).pack(anchor="w")
        pe = ttk.Entry(top)
        pe.insert(0, info["executable"])
        pe.state(["readonly"])
        pe.pack(fill="x", pady=(4, 2))
        ttk.Label(top, text=tr('バージョン: {0}').format(info['version']), style="Muted.TLabel").pack(anchor="w")
        rep = tk.Text(win, height=16, wrap="word", bg=self.pal["card"], fg=self.pal["fg"], relief="flat", font=self.fonts.mono,
                      padx=12, pady=10, highlightthickness=1, highlightbackground=self.pal["border"])
        rep.pack(fill="both", expand=True, padx=14)
        btns = ttk.Frame(win, padding=14)
        btns.pack(fill="x")
        install_btn = ttk.Button(btns, text=tr("不足しているライブラリをインストール"), style="Accent.TButton")
        install_btn.pack(side="left")
        copy_btn = ttk.Button(btns, text=tr("インストールコマンドをコピー"))
        copy_btn.pack(side="left", padx=8)
        ttk.Button(btns, text=tr("再チェック"), command=lambda: refresh()).pack(side="left")

        def refresh(append=False):
            text = deps.format_report()
            rep.config(state="normal")
            if append:
                rep.insert("end", "\n" + "-" * 50 + tr("\n再チェック結果:\n") + text + "\n")
            else:
                rep.delete("1.0", "end")
                rep.insert("end", text)
            rep.config(state="disabled")
            rep.see("end")
            miss = deps.missing_pip_names()
            install_btn.state(["!disabled"] if miss else ["disabled"])
            install_btn.config(text=tr('不足 {0} 件をインストール').format(len(miss)) if miss else tr("すべて導入済み"))

        def do_copy():
            miss = deps.missing_pip_names()
            self._copy(f'"{deps.python_exe()}" -m pip install ' + " ".join(miss or [tr("(不足なし)")]))

        def do_install():
            miss = deps.missing_pip_names()
            if not miss:
                return
            install_btn.state(["disabled"])
            install_btn.config(text=tr("インストール中…"))
            rep.config(state="normal")
            rep.insert("end", tr('\n\n>>> インストール開始: {0}\n').format(' '.join(miss)))
            rep.config(state="disabled")
            q2: "queue.Queue[tuple]" = queue.Queue()

            def worker():
                q2.put(deps.install(miss))

            def check():
                try:
                    code, out = q2.get_nowait()
                except queue.Empty:
                    win.after(300, check)
                    return
                rep.config(state="normal")
                rep.insert("end", out[-4000:] + "\n" + (tr("完了。\n") if code == 0 else tr('pip がエラーを返しました (code={0})。\n').format(code)))
                rep.config(state="disabled")
                refresh(append=True)

            threading.Thread(target=worker, daemon=True).start()
            win.after(300, check)

        copy_btn.config(command=do_copy)
        install_btn.config(command=do_install)
        refresh()

    def set_status(self, text: str):
        self.status.config(text=text)

    def on_close(self):
        try:
            self.ui["geometry"] = self.root.winfo_geometry()
            w = self.pw.winfo_width()
            if w > 100:
                self.ui["pane_ratio"] = round(self.pw.sashpos(0) / w, 3)
        except tk.TclError:
            pass
        self.cancel.set()
        if self.logger and self.scanning:
            self.logger.end(len(self.results), True)
        L.save_ui_state(self.ui)
        self.shutdown()
        self.root.destroy()

    def shutdown(self):
        """after を全部キャンセルする。残すと破棄後に 'invalid command name' が出る。"""
        for name in ("_poll_id", "_refresh_after"):
            aid = getattr(self, name, None)
            if aid:
                try:
                    self.root.after_cancel(aid)
                except tk.TclError:
                    pass
                setattr(self, name, None)


def launch():
    from . import crashlog
    crashlog.ensure_std_streams()
    T.enable_dpi_awareness()
    dnd = False
    try:
        from tkinterdnd2 import TkinterDnD  # type: ignore
        root = TkinterDnD.Tk()
        dnd = True
    except Exception:
        root = tk.Tk()

    def on_error(exc, val, tb):          # コンソールが無いのでログに残す
        import traceback
        text = "".join(traceback.format_exception(exc, val, tb))
        crashlog.write(tr("操作中のエラー"), text)
        try:
            messagebox.showerror(tr("エラーが発生しました"), tr('{0}: {1}\n\n詳細: {2}').format(exc.__name__, val, crashlog.log_path()), parent=root)
        except Exception:  # noqa
            pass

    root.report_callback_exception = on_error
    try:
        App(root, dnd=dnd)
        root.mainloop()
    except Exception:  # noqa
        import traceback
        crashlog.report(tr("起動中にエラーが発生しました"), traceback.format_exc(), parent=root)


if __name__ == "__main__":
    launch()
