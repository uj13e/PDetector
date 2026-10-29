"""表示言語の切り替え。文字列は日本語のまま tr("...") で包み、English のときだけ i18n_en.EN を引く。
訳がなければ日本語のまま返す。プレースホルダは tr("{0} 件").format(n) の形で、訳側も同じ番号にする。
動的に組み立てた注記は、{0} 入りの訳をテンプレートにして正規表現で当てて訳す。
"""
from __future__ import annotations

import os
import re
import sys
from typing import Dict, List, Optional, Pattern, Tuple

LANGS = ("ja", "en")
LANG_NAMES = {"ja": "日本語", "en": "English"}
_lang = "ja"
_templates: Optional[List[Tuple[Pattern[str], str]]] = None
_PH = re.compile(r"\{(\d+)(?:![sra])?(?::[^{}]*)?\}")


def get_lang() -> str:
    return _lang


def set_lang(code: str) -> str:
    global _lang
    _lang = code if code in LANGS else "ja"
    return _lang


def detect_system_lang() -> str:
    env = (os.environ.get("PDETECTOR_LANG") or "").lower()
    if env in LANGS:
        return env
    if sys.platform.startswith("win"):
        try:
            import ctypes
            langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return "ja" if (langid & 0x3FF) == 0x11 else "en"
        except Exception:
            pass
    for k in ("LC_ALL", "LC_MESSAGES", "LANG"):
        v = os.environ.get(k, "")
        if v:
            return "ja" if v.lower().startswith("ja") else "en"
    try:
        import locale
        v = locale.getlocale()[0] or ""
        return "ja" if v.lower().startswith("ja") else "en"
    except Exception:
        return "ja"


def resolve_lang(pref: str) -> str:
    if pref in LANGS:
        return pref
    return detect_system_lang()


def _en() -> Dict[str, str]:
    from .i18n_en import EN
    return EN


_SPEC = re.compile(r"\{(\d+)(?:![sra])?(?::[^{}]*)?\}")


def _plain(tmpl: str) -> str:
    """値はもう文字列なので {0:,} の書式指定は外す。"""
    return _SPEC.sub(r"{\1}", tmpl)


def _build_templates() -> List[Tuple[Pattern[str], str]]:
    out: List[Tuple[Pattern[str], str]] = []
    for ja, en in _en().items():
        if not _PH.search(ja):
            continue
        rx, pos = "", 0
        for m in _PH.finditer(ja):
            rx += re.escape(ja[pos:m.start()]).replace(r"\{\{", "{").replace(r"\}\}", "}")
            rx += "(?P<g%s>.*?)" % m.group(1) if f"(?P<g{m.group(1)}>" not in rx else "(?P=g%s)" % m.group(1)
            pos = m.end()
        rx += re.escape(ja[pos:])
        try:
            out.append((re.compile("^" + rx + "$", re.S), _plain(en)))
        except re.error:
            continue
    out.sort(key=lambda t: -len(t[0].pattern))
    return out


_JP = re.compile(r"[\u3041-\u3096\u30a1-\u30fa\u4e00-\u9fff]")
_partial_keys: Optional[List[str]] = None
_partial_templates: Optional[List[Tuple[Pattern[str], str]]] = None


def _partial(s: str) -> str:
    """全体一致しない文でも、中に含まれる既知の文言だけは訳す。"""
    global _partial_keys, _partial_templates
    if _partial_keys is None:
        en = _en()
        _partial_keys = sorted((k for k in en if not _PH.search(k) and len(k.strip()) >= 4), key=len, reverse=True)
        pt = []
        for ja, e in en.items():
            if not _PH.search(ja) or len(_PH.sub("", ja).strip()) < 6:
                continue
            rx, pos = "", 0
            for m in _PH.finditer(ja):
                rx += re.escape(ja[pos:m.start()]) + "(?P<g%s>.+?)" % m.group(1) if f"(?P<g{m.group(1)}>" not in rx else re.escape(ja[pos:m.start()]) + "(?P=g%s)" % m.group(1)
                pos = m.end()
            rx += re.escape(ja[pos:])
            try:
                pt.append((re.compile(rx, re.S), _plain(e)))
            except re.error:
                continue
        pt.sort(key=lambda t: -len(t[0].pattern))
        _partial_templates = pt
    en = _en()
    for rx, tmpl in _partial_templates or []:
        def fill(m, tmpl=tmpl):
            vals = {int(k[1:]): (tr(x) if _JP.search(x) else x) for k, x in m.groupdict().items()}
            try:
                return tmpl.format(*[vals.get(i, "") for i in range(max(vals) + 1)]) if vals else tmpl
            except (IndexError, KeyError, ValueError):
                return m.group(0)
        s = rx.sub(fill, s)
        if not _JP.search(s):
            return s
    for k in _partial_keys or []:
        if k in s:
            s = s.replace(k, en[k])
            if not _JP.search(s):
                break
    return s


_HIDDEN = re.compile(r"^【隠し要素内: ([^】]*)】(.*)$", re.S)


def _special(s: str) -> Optional[str]:
    m = _HIDDEN.match(s)
    if m:
        return f"[In hidden element: {tr(m.group(1))}] {tr(m.group(2))}"
    return None


def tr(s: str) -> str:
    """ja ならそのまま、en なら訳を返す。"""
    if _lang == "ja" or not s:
        return s
    en = _en()
    v = en.get(s)
    if v is not None:
        return v
    v = _special(s)
    if v is not None:
        return v
    global _templates
    if _templates is None:
        _templates = _build_templates()
    for rx, tmpl in _templates:
        m = rx.match(s)
        if m:
            vals = {int(k[1:]): tr(x) if re.search(r"[ぁ-鿿]", x) else x for k, x in m.groupdict().items()}
            try:
                return tmpl.format(*[vals.get(i, "") for i in range(max(vals) + 1)]) if vals else tmpl
            except (IndexError, KeyError, ValueError):
                break
    return _partial(s) if _JP.search(s) else s


class TMap(dict):
    """取り出すときに tr() を通す dict。言語切り替えに定数表を追従させる用。"""

    def __getitem__(self, k):
        return tr(dict.__getitem__(self, k))

    def get(self, k, default=None):
        if k in self:
            return tr(dict.__getitem__(self, k))
        return default

    def values(self):
        return [tr(v) for v in dict.values(self)]

    def items(self):
        return [(k, tr(v)) for k, v in dict.items(self)]


def placeholders(s: str) -> List[str]:
    """プレースホルダ番号の一覧。翻訳表のテスト用。"""
    return sorted(set(m.group(1) for m in _PH.finditer(s)))
