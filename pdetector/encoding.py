"""バイト列の文字コード判定。外部依存なし。

cp932 / EUC-JP / ISO-2022-JP / UTF-16 が普通にあるので、UTF-8 決め打ちだと日本語の攻撃文が化けて素通りする。
"""
from __future__ import annotations

import codecs
import re
import unicodedata
from typing import List, Optional, Tuple

_META_CHARSET = re.compile(rb"""(?:charset|encoding)\s*=\s*["']?\s*([A-Za-z0-9_\-:.]+)""", re.I)

_CANDIDATES = ("cp932", "euc_jp", "gb18030", "big5", "cp949")
# 最良の推定が外れたときの見逃し対策。非 UTF-8 なら他の候補でも読み直す
EXTRA_CANDIDATES = ("cp932", "euc_jp", "gb18030", "big5", "cp949", "koi8_r", "cp1251", "cp1252", "iso8859_2", "cp1250", "iso8859_7", "cp1253", "iso8859_9", "cp1256", "cp874")


def sniff_declared_charset(data: bytes) -> Optional[str]:
    """<meta charset> か XML 宣言から拾う。先頭 4KB だけ見る。"""
    m = _META_CHARSET.search(data[:4096])
    if not m:
        return None
    name = m.group(1).decode("ascii", "ignore").strip().lower()
    return _normalize_codec_name(name)


def _normalize_codec_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = name.strip().strip("\"'").lower()
    aliases = {
        "shift_jis": "cp932", "shift-jis": "cp932", "sjis": "cp932", "x-sjis": "cp932",
        "windows-31j": "cp932", "ms932": "cp932", "ms_kanji": "cp932",
        "euc-jp": "euc_jp", "eucjp": "euc_jp", "x-euc-jp": "euc_jp",
        "iso-2022-jp": "iso2022_jp", "utf8": "utf-8",
        "gbk": "gb18030", "gb2312": "gb18030", "x-gbk": "gb18030",
        "euc-kr": "cp949", "ks_c_5601-1987": "cp949",
    }
    name = aliases.get(name, name)
    try:
        codecs.lookup(name)
    except LookupError:
        return None
    return name


def _weirdness(s: str) -> float:
    """文字化けらしさ。小さいほど自然。"""
    if not s:
        return 1.0
    bad = 0
    for ch in s:
        o = ord(ch)
        if ch in "\r\n\t " or 0x20 <= o < 0x7F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Co", "Cn", "Cs") or (cat == "Cc"):
            bad += 3
        elif 0xFF61 <= o <= 0xFF9F:       # 半角カナは化けると増える
            bad += 2
        elif 0x3040 <= o <= 0x30FF or 0x4E00 <= o <= 0x9FFF or 0x3000 <= o <= 0x303F or 0xFF00 <= o <= 0xFF60:
            continue                        # かな・漢字・全角記号
        elif 0xAC00 <= o <= 0xD7A3:         # ハングル。韓国語かもしれないので軽め
            bad += 0.3
        elif 0x0400 <= o <= 0x04FF or 0x0370 <= o <= 0x03FF or 0x2500 <= o <= 0x257F or 0x00A0 <= o <= 0x00FF:
            bad += 1.5                      # キリル、ギリシャ、罫線、Latin-1。誤判定すると出やすい
        else:
            bad += 0.5
    return bad / len(s)


def alternative_decodings(data: bytes, used: str, limit: int = 200_000) -> List[Tuple[str, str]]:
    """used 以外で厳密に読めるものを (文字コード, テキスト) で返す。誤判定で見逃さないよう別解釈でも走査する。"""
    out: List[Tuple[str, str]] = []
    seen = set()
    chunk = data[:limit]
    for enc in EXTRA_CANDIDATES:
        if enc == used:
            continue
        try:
            s = chunk.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append((enc, s))
    return out


def decode_bytes(data: bytes, charset_hint: Optional[str] = None) -> Tuple[str, str, List[str]]:
    """(text, 文字コード, 注記)。失敗しても何かしらテキストは返す。"""
    notes: List[str] = []
    if not data:
        return "", "utf-8", notes

    # BOM
    if data.startswith(codecs.BOM_UTF32_LE) or data.startswith(codecs.BOM_UTF32_BE):
        try:
            return data.decode("utf-32"), "utf-32", notes
        except UnicodeDecodeError:
            pass
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace"), "utf-8-sig", notes
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        try:
            return data.decode("utf-16"), "utf-16", notes
        except UnicodeDecodeError:
            return data.decode("utf-16", errors="replace"), "utf-16", ["UTF-16 を一部置換して読み込みました。"]

    # 宣言があればまずそれ
    hint = _normalize_codec_name(charset_hint)
    if hint:
        try:
            return data.decode(hint), hint, notes
        except (UnicodeDecodeError, LookupError):
            notes.append(f"宣言された文字コード({hint})で読めないため自動判定に切替。")

    # BOMなし UTF-16。NUL が交互に並ぶ
    head = data[:4000]
    if len(head) >= 4:
        even_nul = head[0::2].count(0) / max(1, len(head[0::2]))
        odd_nul = head[1::2].count(0) / max(1, len(head[1::2]))
        if odd_nul > 0.1 and even_nul < 0.05:
            try:
                return data.decode("utf-16-le"), "utf-16-le", ["BOMなし UTF-16LE と推定。"]
            except UnicodeDecodeError:
                pass
        if even_nul > 0.1 and odd_nul < 0.05:
            try:
                return data.decode("utf-16-be"), "utf-16-be", ["BOMなし UTF-16BE と推定。"]
            except UnicodeDecodeError:
                pass

    # ISO-2022-JP は 7bit で UTF-8 として読めてしまうので先に判定
    if b"\x1b$B" in data or b"\x1b$@" in data or b"\x1b(J" in data:
        try:
            return data.decode("iso2022_jp"), "iso2022_jp", ["ISO-2022-JP と推定。"]
        except UnicodeDecodeError:
            pass

    # UTF-8
    try:
        return data.decode("utf-8"), "utf-8", notes
    except UnicodeDecodeError:
        pass

    # レガシー文字コードは一番化けていないものを採る
    best: Optional[Tuple[float, str, str]] = None
    for enc in _CANDIDATES:
        try:
            s = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        w = _weirdness(s[:20000])
        if best is None or w < best[0] - 1e-9:
            best = (w, enc, s)
    if best is not None:
        notes.append(f"文字コードを {best[1]} と推定しました(UTF-8 ではありません)。")
        return best[2], best[1], notes

    notes.append("文字コードを特定できませんでした(UTF-8 として置換読込み)。検知精度が下がる可能性があります。")
    return data.decode("utf-8", errors="replace"), "utf-8(replace)", notes
