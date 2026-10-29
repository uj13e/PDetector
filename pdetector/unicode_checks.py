"""Unicode での隠蔽(不可視文字・双方向制御・Tags・異体字セレクタ・PUA・ホモグリフ)の検査。

BOM、絵文字の ZWJ/VS16、国旗の Tags、ソフトハイフン、RTL文書の方向マークは誤検知が多いので、正当な使い方は数えない。
"""
from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

from .model import Finding
from . import normalize as nz

_SUSP = re.compile(
    "[" + "".join(re.escape(c) for c in list(nz.INVISIBLE_CHARS) + list(nz.BIDI_MARKS) + list(nz.BIDI_CHARS))
    + "\U000E0000-\U000E007F︀-️\U000E0100-\U000E01EF-\U000F0000-\U000FFFFD\U00100000-\U0010FFFD]"
)
_VS_RUN = re.compile("[︀-️\U000E0100-\U000E01EF]+")
_TAG_FLAG = re.compile("\U0001F3F4[\U000E0020-\U000E007E]+\U000E007F")      # 🏴󠁧󠁢󠁥󠁮󠁧󠁿 など
_TAG_ANY = re.compile("[\U000E0000-\U000E007F]+")

_JOINER_SCRIPTS = ("ARABIC", "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL", "TELUGU", "KANNADA",
                   "MALAYALAM", "SINHALA", "THAI", "KHMER", "MYANMAR", "HEBREW", "SYRIAC", "THAANA", "TIBETAN", "LAO",
                   "NKO", "MONGOLIAN")
_RTL_RE = re.compile("[֐-ࣿיִ-﷿ﹰ-﻿]")


def _emoji_like(ch: str) -> bool:
    cp = ord(ch)
    return (cp >= 0x1F000 or 0x2190 <= cp <= 0x2BFF or 0x2600 <= cp <= 0x27BF or cp in (0x200D, 0xFE0F, 0x20E3, 0x00A9, 0x00AE, 0x203C, 0x2049)
            or 0x1F3FB <= cp <= 0x1F3FF or 0x3030 == cp or 0x303D == cp or 0x3297 == cp or 0x3299 == cp)


def _joiner_legit(text: str, i: int) -> bool:
    prev = text[i - 1] if i > 0 else ""
    nxt = text[i + 1] if i + 1 < len(text) else ""
    for ch in (prev, nxt):
        if not ch:
            continue
        if _emoji_like(ch):
            return True
        if not ch.isascii():
            try:
                nm = unicodedata.name(ch)
            except ValueError:
                continue
            if nm.split(" ", 1)[0] in _JOINER_SCRIPTS:
                return True
    return False


def _vs_run_legit(text: str, start: int, end: int) -> bool:
    """絵文字のVS16かCJK異体字なら正当。"""
    run_len = end - start
    if run_len >= 3:
        return False
    prev = text[start - 1] if start > 0 else ""
    if not prev:
        return False
    cp = ord(prev)
    if prev.isascii():
        # keycap(数字/#/* + FE0F)だけ正当
        return prev in "0123456789#*" and run_len == 1
    if _emoji_like(prev) or 0x2000 <= cp <= 0x2BFF:
        return True
    if 0x3400 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF or 0x20000 <= cp <= 0x3FFFF or 0x3000 <= cp <= 0x30FF:
        return True     # CJK 異体字(IVS: 葛󠄀 など)
    return False


def decode_vs(run: str) -> str:
    """FE00-FE0F を 0..15、E0100-E01EF を 16..255 のバイトとして復元する。"""
    bs = bytearray()
    for ch in run:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            bs.append(cp - 0xFE00)
        else:
            bs.append(cp - 0xE0100 + 16)
    try:
        s = bytes(bs).decode("utf-8")
    except UnicodeDecodeError:
        s = bytes(bs).decode("latin-1", errors="replace")
    return s if sum(c.isprintable() or c in "\n\t " for c in s) >= max(4, len(s) * 0.8) else ""


def decode_tags(run: str) -> str:
    out = []
    for ch in run:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
        elif cp == 0xE0001 or cp == 0xE007F:
            continue
    return "".join(out)


def check_unicode(text: str, invisible_ratio_threshold: float = 0.02) -> Tuple[List[Finding], List[Tuple[str, str]]]:
    """(findings, hidden_payloads)。payloads は (理由, 復元テキスト) でルール照合に回す。"""
    findings: List[Finding] = []
    payloads: List[Tuple[str, str]] = []
    n = len(text)
    if n == 0 or text.isascii():
        return findings, payloads

    inv_hits = {}
    shy = 0
    marks = 0
    bidi_hits = {}
    pua = 0
    vs_illegit = 0
    vs_runs_bad: List[str] = []

    # 国旗の Tags 列は先に除く
    tag_text = _TAG_FLAG.sub("", text) if "\U0001F3F4" in text else text
    tag_runs = _TAG_ANY.findall(tag_text)
    tag_count = sum(len(r) for r in tag_runs)

    for m in _VS_RUN.finditer(text):
        if not _vs_run_legit(text, m.start(), m.end()):
            vs_illegit += len(m.group(0))
            vs_runs_bad.append(m.group(0))

    for m in _SUSP.finditer(text):
        ch = m.group(0)
        i = m.start()
        if ch in nz.INVISIBLE_CHARS:
            if i == 0 and ch == "﻿":
                continue                                   # 先頭のBOMは正常
            if ch in ("‍", "‌") and _joiner_legit(text, i):
                continue
            if ch == "­":
                shy += 1
                continue
            inv_hits[ch] = inv_hits.get(ch, 0) + 1
        elif ch in nz.BIDI_MARKS:
            marks += 1
        elif ch in nz.BIDI_CHARS:
            bidi_hits[ch] = bidi_hits.get(ch, 0) + 1
        elif nz.is_private_use(ch):
            pua += 1

    total_inv = sum(inv_hits.values())
    if total_inv > 0:
        names = ", ".join(f"{nz.INVISIBLE_CHARS[c]}×{cnt}" for c, cnt in inv_hits.items())
        ratio = total_inv / n
        if total_inv >= 8 or (total_inv >= 3 and ratio > invisible_ratio_threshold):
            sev = "high"
        elif total_inv >= 3:
            sev = "medium"
        else:
            sev = "low"
        findings.append(Finding(
            rule_id="invisible_chars", category="obfuscation", severity=sev,
            description="不可視文字/ゼロ幅文字が埋め込まれている(隠しテキストの可能性)",
            detail=f"{names} (全体比 {ratio:.3%})", location="text"))

    if shy >= 8:
        findings.append(Finding(
            rule_id="soft_hyphen_many", category="obfuscation", severity="low" if shy < 40 else "medium",
            description="ソフトハイフン(U+00AD)が多数あります(ハイフネーション由来の可能性が高い)",
            detail=f"{shy}文字", location="text"))

    if marks >= 6:
        rtl = len(_RTL_RE.findall(text[:200000])) / max(1, min(n, 200000))
        if rtl < 0.2:
            findings.append(Finding(
                rule_id="bidi_marks", category="obfuscation", severity="medium",
                description="方向マーク(LRM/RLM/ALM)が多数あります(RTL文字がほとんど無い文書では不自然)",
                detail=f"{marks}文字", location="text"))

    if bidi_hits:
        names = ", ".join(f"{nz.BIDI_CHARS[c]}×{cnt}" for c, cnt in bidi_hits.items())
        rtl = len(_RTL_RE.findall(text[:200000])) / max(1, min(n, 200000))
        has_override = any(c in nz.BIDI_OVERRIDES for c in bidi_hits)
        if has_override:
            sev = "high"
        elif rtl >= 0.2:
            sev = "low"          # RTL文書では埋め込み/分離が普通に出る
        else:
            sev = "medium"
        findings.append(Finding(
            rule_id="bidi_control", category="obfuscation", severity=sev,
            description="双方向制御文字(文字並べ替えで見た目を偽装:Trojan Source)",
            detail=names, location="text"))

    if tag_count > 0:
        hidden = "".join(decode_tags(r) for r in tag_runs)
        findings.append(Finding(
            rule_id="unicode_tag_smuggling", category="obfuscation", severity="critical",
            description="Unicode Tags ブロックの不可視文字(ASCIIスマグリングで隠し命令を密輸)",
            detail=(f"{tag_count}文字。復元内容: {hidden[:160]!r}" if hidden else f"{tag_count}文字"),
            snippet=hidden[:160], location="text"))
        if hidden:
            payloads.append(("Unicode Tags に埋め込まれた文字列", hidden))

    if vs_illegit:
        decoded = [decode_vs(r) for r in vs_runs_bad]
        decoded = [d for d in decoded if d]
        long_run = any(len(r) >= 3 for r in vs_runs_bad)
        findings.append(Finding(
            rule_id="variation_selector_smuggling", category="obfuscation",
            severity="high" if (long_run or vs_illegit >= 4) else "medium",
            description="異体字セレクタの不自然な使用(不可視データ埋め込みの疑い)",
            detail=f"{vs_illegit}文字" + (f"。復元内容: {decoded[0][:120]!r}" if decoded else ""),
            snippet=(decoded[0][:160] if decoded else ""), location="text"))
        for d in decoded:
            payloads.append(("異体字セレクタに埋め込まれた文字列", d))

    if pua >= 4:
        findings.append(Finding(
            rule_id="private_use_chars", category="obfuscation", severity="low" if pua < 16 else "medium",
            description="私用領域(PUA)文字の使用(外字/アイコンフォントの可能性もあるが、独自エンコードでの隠蔽の疑いも)",
            detail=f"{pua}文字", location="text"))

    mixed = nz.mixed_script_tokens(text)
    if mixed:
        findings.append(Finding(
            rule_id="homoglyph_mixed_script", category="obfuscation",
            severity="high" if len(mixed) >= 3 else "medium",
            description="ラテン文字とキリル/ギリシャ文字が混在した単語(見た目が似た別文字でのフィルタ回避の疑い)",
            detail="例: " + ", ".join(repr(t) for t in mixed[:5]), location="text"))
    return findings, payloads
