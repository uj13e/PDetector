"""テーマ(ライト/ダーク)、フォント、ttk スタイル。"""
from __future__ import annotations

import sys
from typing import Dict, Iterable

LIGHT: Dict[str, str] = {
    "bg": "#f3f3f3", "card": "#ffffff", "fg": "#1f1f1f", "mut": "#5f5f5f", "border": "#cfcfcf",
    "accent": "#0f6cbd", "accent_fg": "#ffffff", "accent_hover": "#115ea3",
    "sel": "#cce4f7", "sel_fg": "#1f1f1f", "hover": "#e6e6e6", "input": "#ffffff",
    "header": "#f3f3f3", "header_fg": "#1f1f1f", "header_mut": "#5f5f5f",
    "code_bg": "#f5f5f5", "hit_bg": "#fde68a", "warn_bg": "#f1f1f1",
    "disabled": "#9a9a9a",
}
DARK: Dict[str, str] = {
    "bg": "#202020", "card": "#2b2b2b", "fg": "#e8e8e8", "mut": "#a3a3a3", "border": "#474747",
    "accent": "#2b7fd0", "accent_fg": "#ffffff", "accent_hover": "#3a8fe0",
    "sel": "#0f4c81", "sel_fg": "#ffffff", "hover": "#383838", "input": "#2b2b2b",
    "header": "#202020", "header_fg": "#e8e8e8", "header_mut": "#a3a3a3",
    "code_bg": "#252525", "hit_bg": "#854d0e", "warn_bg": "#333333",
    "disabled": "#6b6b6b",
}
# レベル/重大度の色。FILL は白文字を載せる塗り、TEXT は文字色、TINT はバナーの薄い背景
LEVEL_FILL = {
    "clean": "#2e7d32", "low": "#8a6d00", "medium": "#b45309", "high": "#b3261e",
    "critical": "#8b1a1a", "unscanned": "#5b3fa0", "info": "#5f6b7a",
}
LEVEL_TEXT_LIGHT = dict(LEVEL_FILL)
LEVEL_TEXT_DARK = {
    "clean": "#6fcf73", "low": "#e0c050", "medium": "#f0a060", "high": "#f28b82",
    "critical": "#ff9e9e", "unscanned": "#b9a7f0", "info": "#9aa5b1",
}
LEVEL_TINT_LIGHT = {
    "clean": "#e8f3e9", "low": "#f6f0d9", "medium": "#f8e9d8", "high": "#f8e0de",
    "critical": "#f3d6d6", "unscanned": "#e9e3f5", "info": "#e8ebef",
}
LEVEL_TINT_DARK = {
    "clean": "#243626", "low": "#3a3418", "medium": "#40301c", "high": "#432625",
    "critical": "#4a2020", "unscanned": "#322a48", "info": "#2f3338",
}


def level_tint(theme: str) -> Dict[str, str]:
    return LEVEL_TINT_DARK if theme == "dark" else LEVEL_TINT_LIGHT


UI_FONT_CANDIDATES = ["Yu Gothic UI", "Meiryo UI", "Segoe UI", "Hiragino Sans", "Noto Sans CJK JP", "Noto Sans JP",
                      "IPAexGothic", "IPAPGothic", "IPAGothic", "TkDefaultFont"]
MONO_FONT_CANDIDATES = ["Consolas", "BIZ UDGothic", "MS Gothic", "Menlo", "DejaVu Sans Mono", "Courier New", "IPAGothic", "TkFixedFont"]


def palette(theme: str) -> Dict[str, str]:
    return dict(DARK if theme == "dark" else LIGHT)


def level_text_colors(theme: str) -> Dict[str, str]:
    return LEVEL_TEXT_DARK if theme == "dark" else LEVEL_TEXT_LIGHT


def system_prefers_dark() -> bool:
    """Windows のアプリ側ダークモード設定。読めなければ False。"""
    if not sys.platform.startswith("win"):
        return False
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except Exception:
        return False


def resolve_theme(pref: str) -> str:
    if pref in ("light", "dark"):
        return pref
    return "dark" if system_prefers_dark() else "light"


def pick_font(root, candidates: Iterable[str]) -> str:
    from tkinter import font as tkfont
    have = {f.lower(): f for f in tkfont.families(root)}
    for c in candidates:
        if c.lower() in have:
            return have[c.lower()]
        if c.startswith("Tk"):
            return c
    return "TkDefaultFont"


def enable_dpi_awareness() -> None:
    """高DPI でぼやけないようにする。Tk を作る前に呼ぶこと。"""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


class Fonts:
    """名前付きフォント。サイズは configure し直すだけで全体に効く。"""

    def __init__(self, root, scale: float = 1.0):
        from tkinter import font as tkfont
        self.ui_family = pick_font(root, UI_FONT_CANDIDATES)
        self.mono_family = pick_font(root, MONO_FONT_CANDIDATES)
        mk = lambda name, **kw: tkfont.Font(root=root, name=name, exists=False, **kw)
        self.base = 10
        self.ui = mk("pid_ui", family=self.ui_family, size=self.base)
        self.bold = mk("pid_bold", family=self.ui_family, size=self.base, weight="bold")
        self.small = mk("pid_small", family=self.ui_family, size=self.base - 1)
        self.title = mk("pid_title", family=self.ui_family, size=self.base + 4, weight="bold")
        self.big = mk("pid_big", family=self.ui_family, size=self.base + 2, weight="bold")
        self.mono = mk("pid_mono", family=self.mono_family, size=self.base)
        self.set_scale(scale)
        # ダイアログやメニューは既定フォントを使うので、そっちも差し替える
        for n in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont", "TkTooltipFont"):
            try:
                tkfont.nametofont(n).configure(family=self.ui_family, size=self.base)
            except Exception:
                pass
        self.scale = scale

    def set_scale(self, scale: float):
        self.scale = scale
        b = max(8, round(self.base * scale))
        self.ui.configure(size=b)
        self.bold.configure(size=b)
        self.small.configure(size=max(7, b - 1))
        self.title.configure(size=b + 4)
        self.big.configure(size=b + 2)
        self.mono.configure(size=b)
        from tkinter import font as tkfont
        for n in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(n).configure(size=b)
            except Exception:
                pass

    @property
    def row_height(self) -> int:
        return int(round(self.ui.metrics("linespace") * 1.7))


def apply_theme(root, pal: Dict[str, str], fonts: Fonts) -> "object":
    """ttk スタイルを設定して返す。clam を土台にするのは OS 間で見た目が揃うから。"""
    from tkinter import ttk
    st = ttk.Style(root)
    try:
        st.theme_use("clam")
    except Exception:
        pass
    bg, card, fg, mut, bd = pal["bg"], pal["card"], pal["fg"], pal["mut"], pal["border"]
    root.configure(bg=bg)
    st.configure(".", background=bg, foreground=fg, fieldbackground=pal["input"], bordercolor=bd,
                 lightcolor=bd, darkcolor=bd, troughcolor=pal["border"], focuscolor=pal["accent"], font=fonts.ui)
    st.configure("TFrame", background=bg)
    st.configure("Card.TFrame", background=card, bordercolor=bd, relief="solid", borderwidth=1)
    st.configure("Plain.TFrame", background=card)
    st.configure("TLabel", background=bg, foreground=fg)
    st.configure("Card.TLabel", background=card, foreground=fg)
    st.configure("Muted.TLabel", background=bg, foreground=mut, font=fonts.small)
    st.configure("CardMuted.TLabel", background=card, foreground=mut, font=fonts.small)
    st.configure("Title.TLabel", background=pal["header"], foreground=pal["header_fg"], font=fonts.title)
    st.configure("HeaderMuted.TLabel", background=pal["header"], foreground=pal["header_mut"], font=fonts.small)
    st.configure("Header.TFrame", background=pal["header"])
    st.configure("TButton", background=card, foreground=fg, bordercolor=bd, padding=(10, 4), relief="flat", borderwidth=1)
    st.map("TButton", background=[("active", pal["hover"]), ("disabled", bg)],
           foreground=[("disabled", pal["disabled"])], bordercolor=[("focus", pal["accent"])])
    st.configure("Accent.TButton", background=pal["accent"], foreground=pal["accent_fg"], bordercolor=pal["accent"],
                 padding=(16, 4), font=fonts.bold)
    st.map("Accent.TButton", background=[("active", pal["accent_hover"]), ("disabled", pal["disabled"])],
           foreground=[("disabled", "#ffffff")])
    st.configure("Header.TButton", background=pal["header"], foreground=pal["header_fg"], bordercolor=pal["header"],
                 padding=(10, 4))
    st.map("Header.TButton", background=[("active", "#374151")])
    st.configure("Link.TButton", background=bg, foreground=pal["accent"], bordercolor=bg, padding=(6, 2), relief="flat")
    st.map("Link.TButton", background=[("active", pal["hover"])])
    st.configure("TEntry", padding=(8, 6), fieldbackground=pal["input"], foreground=fg, bordercolor=bd, insertcolor=fg)
    st.map("TEntry", bordercolor=[("focus", pal["accent"])])
    st.configure("TCombobox", padding=(6, 4), fieldbackground=pal["input"], foreground=fg, arrowcolor=fg, bordercolor=bd)
    st.map("TCombobox", fieldbackground=[("readonly", pal["input"])], bordercolor=[("focus", pal["accent"])],
           foreground=[("readonly", fg)])
    root.option_add("*TCombobox*Listbox.background", pal["input"])
    root.option_add("*TCombobox*Listbox.foreground", fg)
    root.option_add("*TCombobox*Listbox.selectBackground", pal["sel"])
    root.option_add("*TCombobox*Listbox.selectForeground", pal["sel_fg"])
    st.configure("TCheckbutton", background=bg, foreground=fg)
    st.map("TCheckbutton", background=[("active", bg)])
    st.configure("Card.TCheckbutton", background=card, foreground=fg)
    st.map("Card.TCheckbutton", background=[("active", card)])
    st.configure("Chip.TCheckbutton", background=bg, foreground=fg, padding=(6, 2))
    st.configure("TNotebook", background=bg, bordercolor=bd, tabmargins=(0, 0, 0, 0))
    st.configure("TNotebook.Tab", background=bg, foreground=mut, padding=(14, 7), bordercolor=bd)
    st.map("TNotebook.Tab", background=[("selected", card), ("active", pal["hover"])],
           foreground=[("selected", fg)])
    st.configure("Treeview", background=card, fieldbackground=card, foreground=fg, bordercolor=bd,
                 rowheight=fonts.row_height, borderwidth=0)
    st.map("Treeview", background=[("selected", pal["sel"])], foreground=[("selected", pal["sel_fg"])])
    st.configure("Treeview.Heading", background=bg, foreground=mut, bordercolor=bd, relief="flat",
                 padding=(8, 5), font=fonts.bold)
    st.map("Treeview.Heading", background=[("active", pal["hover"])])
    st.configure("Horizontal.TProgressbar", background=pal["accent"], troughcolor=bd, bordercolor=bd,
                 lightcolor=pal["accent"], darkcolor=pal["accent"], thickness=8)
    st.configure("TScrollbar", background=bg, troughcolor=bg, bordercolor=bg, arrowcolor=mut, relief="flat")
    st.map("TScrollbar", background=[("active", pal["border"])])
    st.configure("TPanedwindow", background=bg)
    st.configure("Sash", sashthickness=5, background=bg)
    st.configure("TSeparator", background=bd)
    st.configure("Status.TLabel", background=bd, foreground=fg, padding=(10, 3), font=fonts.small)
    st.configure("TSpinbox", fieldbackground=pal["input"], foreground=fg, arrowcolor=fg, padding=(6, 4))
    st.configure("TLabelframe", background=bg, bordercolor=bd)
    st.configure("TLabelframe.Label", background=bg, foreground=mut, font=fonts.small)
    return st
