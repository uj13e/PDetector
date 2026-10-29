"""ダブルクリック用。run_gui.py の main を呼ぶだけ。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_gui import main  # noqa: E402

main(relaunch=False)
