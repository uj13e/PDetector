#!/usr/bin/env python3
"""GUI の起動口。Windows ではコンソールなしで開く。
run_gui.pyw / pdetector.vbs のダブルクリックでも同じ。エラーを見たいときは --console を付ける。
"""
import os
import subprocess
import sys


def _relaunch_without_console() -> bool:
    """python.exe 経由だったら pythonw.exe で起動し直す。起動し直したら True。"""
    if not sys.platform.startswith("win"):
        return False
    if os.environ.get("PDETECTOR_CONSOLE") or "--console" in sys.argv:
        return False
    exe = sys.executable or ""
    if os.path.basename(exe).lower() != "python.exe":
        return False                                   # すでに pythonw など
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if not os.path.exists(pyw):
        return False
    flags = 0x00000008 | 0x00000200                    # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    try:
        subprocess.Popen([pyw, os.path.abspath(__file__)] + [a for a in sys.argv[1:] if a != "--console"],
                         creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def main(relaunch: bool = True) -> None:
    if relaunch and _relaunch_without_console():
        return
    try:
        from pdetector.gui import launch
    except Exception:  # noqa  コンソールが無いので、ログに残してダイアログで出す
        import traceback
        from pdetector import crashlog
        crashlog.report("起動できませんでした", traceback.format_exc())
        return
    launch()


if __name__ == "__main__":
    main()
