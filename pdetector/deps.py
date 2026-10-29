"""依存ライブラリの確認と pip インストール。

pip は必ず実行中の Python(sys.executable)経由で呼ぶ。別の pip だと「入れたのに未導入」になる。
"""
from __future__ import annotations

import importlib
import importlib.util
import shutil
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

from .i18n import tr


@dataclass
class Dep:
    import_name: str
    pip_name: str
    purpose: str
    installed: bool = False
    version: str = ""


# (import名, pip名, 用途)
# HTML・Office・メール・URL取得は標準ライブラリだけで動く。ここは PDF/画像/GUI の強化用。
# 無ければ unscanned として出るので、黙って見逃すことはない。
OPTIONAL_DEPS = [
    ("pdfplumber", "pdfplumber", "PDFの白文字/極小文字/ページ外文字の検出(推奨)"),
    ("pypdf", "pypdf", "PDFの構造解析(メタデータ/注釈/フォーム)"),
    ("pypdfium2", "pypdfium2", "画像のみPDFのレンダリング(OCR用)"),
    ("PIL", "pillow", "画像の読み込み(メタデータ/OCR)"),
    ("pytesseract", "pytesseract", "画像OCR(Tesseract本体も必要)"),
    ("numpy", "numpy", "低コントラスト文字の強調(任意)"),
    ("cv2", "opencv-python-headless", "画像の前処理(任意)"),
    ("tkinterdnd2", "tkinterdnd2", "GUIのドラッグ&ドロップ(任意)"),
]


def python_info() -> dict:
    return {
        "executable": sys.executable,
        "version": sys.version.split()[0],
        "full_version": sys.version.replace("\n", " "),
    }


def _get_version(mod_name: str) -> str:
    try:
        mod = importlib.import_module(mod_name)
        for attr in ("__version__", "version", "VERSION"):
            v = getattr(mod, attr, None)
            if isinstance(v, str):
                return v
    except Exception:
        pass
    return ""


def check() -> List[Dep]:
    out: List[Dep] = []
    for imp, pip_name, purpose in OPTIONAL_DEPS:
        spec = None
        try:
            spec = importlib.util.find_spec(imp)
        except Exception:
            spec = None
        installed = spec is not None
        ver = _get_version(imp) if installed else ""
        out.append(Dep(imp, pip_name, purpose, installed=installed, version=ver))
    return out


def tesseract_available() -> Optional[str]:
    """tesseract 本体のパス。無ければ None。"""
    return shutil.which("tesseract")


def missing_pip_names(deps: Optional[List[Dep]] = None) -> List[str]:
    deps = deps or check()
    # pdfplumber があれば pypdf は要らない
    names = []
    have = {d.import_name: d.installed for d in deps}
    for d in deps:
        if d.installed:
            continue
        if d.import_name == "pypdf" and have.get("pdfplumber"):
            continue
        if d.import_name in ("numpy", "cv2") and not have.get("PIL"):
            continue        # Pillow が無ければ画像系は使わない
        if d.import_name == "pypdfium2" and not have.get("pytesseract"):
            continue        # OCR 用
        names.append(d.pip_name)
    return names


def python_exe() -> str:
    """pythonw.exe で動いているときは隣の python.exe を返す。"""
    exe = sys.executable or "python"
    base = os.path.basename(exe).lower()
    if base == "pythonw.exe":
        cand = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _quiet_kwargs() -> dict:
    """Windows でコンソール窓を出さない。pythonw は stdin が無効なので DEVNULL を渡す。"""
    kw: dict = {"stdin": subprocess.DEVNULL}
    if sys.platform.startswith("win"):
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return kw


def install(pip_names: List[str]):
    """(returncode, 出力) を返す。"""
    if not pip_names:
        return 0, tr("インストール対象はありません。")
    cmd = [python_exe(), "-m", "pip", "install", "--upgrade", *pip_names]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, **_quiet_kwargs())
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return proc.returncode, out.strip()
    except Exception as e:  # noqa
        return 1, tr('pip 実行に失敗: {0}\nコマンド: {1}').format(e, ' '.join(cmd))


def format_report() -> str:
    info = python_info()
    lines = [
        tr("=== 実行中の Python ==="),
        tr('  パス  : {0}').format(info['executable']),
        tr('  バージョン: {0}').format(info['version']),
        "",
        tr("=== 依存ライブラリ ==="),
    ]
    for d in check():
        mark = "✓" if d.installed else "×"
        v = f" ({d.version})" if d.version else ""
        lines.append(f"  [{mark}] {d.pip_name}{v} — {tr(d.purpose)}")
    tz = tesseract_available()
    lines.append("")
    lines.append(tr("  ※ HTML/Office/OpenDocument/EPUB/RTF/メール/URL取得は標準ライブラリのみで動作します。"))
    lines.append("")
    lines.append(tr("=== OCRエンジン(Tesseract本体) ==="))
    lines.append(f"  {'✓ ' + tz if tz else tr('× 未検出(画像OCRには別途インストールが必要)')}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_report())
    miss = missing_pip_names()
    if miss:
        print("\n不足:", " ".join(miss))
        print(f"導入コマンド: {sys.executable} -m pip install " + " ".join(miss))
