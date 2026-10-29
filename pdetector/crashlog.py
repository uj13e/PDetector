"""pythonw だとエラーが見えないので、ファイルに残してダイアログでも出す。"""
from __future__ import annotations

import os
import sys
import time

from .i18n import tr


def log_path() -> str:
    from .gui_logic import state_dir
    return os.path.join(state_dir(), "error.log")


def ensure_std_streams() -> None:
    """pythonw は stdout/stderr が None で、print すると落ちる。"""
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def write(title: str, tb_text: str) -> str:
    """error.log に追記してパスを返す。書けなければ空文字。"""
    try:
        path = log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"==== {time.strftime('%Y-%m-%d %H:%M:%S')} {title}\n{tb_text}\n")
        return path
    except OSError:
        return ""


def report(title: str, tb_text: str, parent=None) -> None:
    """ログに書いてからエラーダイアログを出す。"""
    path = write(title, tb_text)
    last = (tb_text.strip().splitlines() or [""])[-1]
    msg = f"{title}\n\n{last}" + (tr('\n\n詳細は次のファイルに記録しました:\n{0}').format(path) if path else "")
    try:
        import tkinter as tk
        from tkinter import messagebox
        own = None
        if parent is None:
            own = tk.Tk()
            own.withdraw()
            parent = own
        messagebox.showerror("PDetector", msg, parent=parent)
        if own is not None:
            own.destroy()
    except Exception:  # noqa
        try:
            print(msg, file=sys.stderr)
        except Exception:  # noqa
            pass
