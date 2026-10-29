"""照合用の正規化と難読化(不可視文字・ホモグリフ・分断)対策。元テキストは別に持つ。"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Dict, List, Tuple

# ゼロ幅・結合・不可視系。正規化で除去する
INVISIBLE_CHARS: Dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "ᅟ": "HANGUL CHOSEONG FILLER",
    "ᅠ": "HANGUL JUNGSEONG FILLER",
    "ㅤ": "HANGUL FILLER",
    "ﾠ": "HALFWIDTH HANGUL FILLER",
    "͏": "COMBINING GRAPHEME JOINER",
    "⠀": "BRAILLE PATTERN BLANK",
    "឴": "KHMER VOWEL INHERENT AQ",
    "឵": "KHMER VOWEL INHERENT AA",
    "᠋": "MONGOLIAN FREE VARIATION SELECTOR ONE",
    "᠌": "MONGOLIAN FREE VARIATION SELECTOR TWO",
    "᠍": "MONGOLIAN FREE VARIATION SELECTOR THREE",
    "᠏": "MONGOLIAN FREE VARIATION SELECTOR FOUR",
    "⁪": "INHIBIT SYMMETRIC SWAPPING",
    "⁫": "ACTIVATE SYMMETRIC SWAPPING",
    "⁬": "INHIBIT ARABIC FORM SHAPING",
    "⁭": "ACTIVATE ARABIC FORM SHAPING",
    "⁮": "NATIONAL DIGIT SHAPES",
    "⁯": "NOMINAL DIGIT SHAPES",
    "￹": "INTERLINEAR ANNOTATION ANCHOR",
    "￺": "INTERLINEAR ANNOTATION SEPARATOR",
    "￻": "INTERLINEAR ANNOTATION TERMINATOR",
    "⁥": "UNASSIGNED FORMAT CHARACTER",
}

# 方向マーク。RTL文書では普通に使われるので別枠
BIDI_MARKS: Dict[str, str] = {
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
    "؜": "ARABIC LETTER MARK",
}

# 双方向制御(Trojan Source 等)
BIDI_CHARS: Dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}
BIDI_OVERRIDES = {"‭", "‮"}

# 後方互換
ALL_NAMES: Dict[str, str] = {**INVISIBLE_CHARS, **BIDI_MARKS, **BIDI_CHARS}


def is_tag_char(ch: str) -> bool:
    """Tags ブロック。ASCII スマグリングに使われる。"""
    return 0xE0000 <= ord(ch) <= 0xE007F


def is_variation_selector(ch: str) -> bool:
    cp = ord(ch)
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF)


def is_private_use(ch: str) -> bool:
    cp = ord(ch)
    return (0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD) or (0x100000 <= cp <= 0x10FFFD)


def _build_strip_table() -> Dict[int, None]:
    t: Dict[int, None] = {}
    for c in list(INVISIBLE_CHARS) + list(BIDI_MARKS) + list(BIDI_CHARS):
        t[ord(c)] = None
    for cp in range(0xE0000, 0xE0080):
        t[cp] = None
    for cp in range(0xFE00, 0xFE10):
        t[cp] = None
    for cp in range(0xE0100, 0xE01F0):
        t[cp] = None
    return t


_STRIP_TABLE = _build_strip_table()

# IPA小型大文字など見た目だけの文字。正規の用途がないので常に畳む
ALWAYS_FOLD: Dict[str, str] = {
    "ı": "i", "ɪ": "i", "ɢ": "g", "ʜ": "h", "ʙ": "b", "ᴄ": "c",
    "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ᴊ": "j", "ᴋ": "k", "ʟ": "l",
    "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s",
    "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
    "ᴀ": "a", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ℓ": "l",
}
_ALWAYS_FOLD_TABLE = {ord(k): v for k, v in ALWAYS_FOLD.items()}

# ホモグリフ。ロシア語などの正規テキストを壊さないよう、
# ラテン文字と混在した単語があるときだけ使う別バリアント。
CONFUSABLES: Dict[str, str] = {}
for _src, _dst in {
    # Cyrillic 小文字
    "а": "a", "в": "b", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ԁ": "d", "ԛ": "q",
    "ԝ": "w", "ѵ": "v", "ӏ": "l", "ё": "e", "ї": "i", "ґ": "r", "ь": "b", "ѡ": "w",
    # Cyrillic 大文字
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "Ү": "Y", "Ԍ": "G", "Ё": "E",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x",
    "ϲ": "c", "ϳ": "j", "ε": "e", "β": "b", "γ": "y", "η": "n", "ω": "w",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # その他
    "ɡ": "g", "ɩ": "i", "ǀ": "l", "Ι": "I", "ⅼ": "l", "ⅰ": "i", "ꓲ": "I", "０": "0",
}.items():
    CONFUSABLES[_src] = _dst
_CONFUSABLE_TABLE = {ord(k): v for k, v in CONFUSABLES.items()}
_CONFUSABLE_RE = re.compile("[" + "".join(re.escape(c) for c in CONFUSABLES) + "]")

_DIACRITIC_HINT = re.compile("[À-ɏ̀-ͯḀ-ỿ]")
_COMBINING_RE = re.compile("[̀-ͯ᪰-᫿᷀-᷿⃐-⃿︠-︯]")


def _deaccent_latin(s: str) -> str:
    """ASCII ラテン文字の結合記号だけ落とす。ロシア語の й などを壊さないため。"""
    if s.isascii() or not _DIACRITIC_HINT.search(s):
        return s
    d = unicodedata.normalize("NFKD", s)
    out: List[str] = []
    prev_ascii_letter = False
    for ch in d:
        if _COMBINING_RE.match(ch):
            if prev_ascii_letter:
                continue
        else:
            prev_ascii_letter = ch.isascii() and ch.isalpha()
        out.append(ch)
    return unicodedata.normalize("NFC", "".join(out))


def strip_hidden_chars(text: str) -> str:
    return text.translate(_STRIP_TABLE)


def normalize_for_match(text: str) -> str:
    """不可視文字除去、NFKC、結合記号除去、見た目だけの文字の畳み込み。"""
    s = text.translate(_STRIP_TABLE)
    if not s.isascii():
        s = unicodedata.normalize("NFKC", s)
        s = s.translate(_ALWAYS_FOLD_TABLE)
        s = _deaccent_latin(s)
    return s


def fold_confusables(s: str) -> str:
    return s.translate(_CONFUSABLE_TABLE)


@lru_cache(maxsize=8192)
def _script(ch: str) -> str:
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return "?"


_WORD_RE = re.compile(r"[^\W\d_]{3,}")


def mixed_script_tokens(text: str, limit: int = 20, scan_limit: int = 400_000) -> List[str]:
    """ラテンとキリル/ギリシャが混ざった単語(ホモグリフ偽装)を返す。"""
    if text.isascii():
        return []
    sample = text[:scan_limit]
    if not _CONFUSABLE_RE.search(sample):
        return []
    found: List[str] = []
    for m in _WORD_RE.finditer(sample):
        tok = m.group(0)
        if tok.isascii():
            continue
        scripts = {_script(c) for c in tok}
        if "LATIN" in scripts and (scripts & {"CYRILLIC", "GREEK"}):
            found.append(tok)
            if len(found) >= limit:
                break
    return found


# 分断対策の照合用バリアント
_CJK = "　-鿿＀-￯㐀-䶿豈-﫿"
_CJK_NL = re.compile(f"(?<=[{_CJK}])[ \\t]*\\r?\\n[ \\t]*(?=[{_CJK}])")
_WS = re.compile(r"\s+")
_PUNCT_BETWEEN_LETTERS = re.compile(r"(?<=[A-Za-z])[.,;:!?\-_*|/\\~^`'\"()\[\]{}<>]+\s*(?=[A-Za-z])")
_SPACED_LETTERS = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ \t.\-_*]){2,}[A-Za-z](?![A-Za-z])")
_CJK_SPACE = re.compile(f"(?<=[{_CJK}])[ \\t\\u00a0]+(?=[{_CJK}])")


def flat_variant(norm: str) -> str:
    """改行・連続空白を1つの空白にする。PDF/Word の折り返しで割れた文を戻す。
    日本語/中国語は文字間の改行を除去。"""
    s = _CJK_NL.sub("", norm)
    return _WS.sub(" ", s)


def squashed_variant(norm: str) -> str:
    """1文字ずつの空白/句読点区切り、文字間の記号、日本語文字間の空白を除去する。
    単語間が2つ以上の空白の「i g n o r e  a l l」も拾えるよう、flat 化する前のテキストを渡すこと。"""
    s = _CJK_NL.sub("", norm)
    s = _SPACED_LETTERS.sub(lambda m: re.sub(r"[ \t.\-_*]", "", m.group(0)), s)
    s = _PUNCT_BETWEEN_LETTERS.sub(" ", s)
    s = _CJK_SPACE.sub("", s)
    return _WS.sub(" ", s)


_NON_WORD = re.compile(r"[\W_]+")


def compact_variant(norm: str) -> str:
    """空白・記号を全部消して小文字化する。単語境界まで潰された分断への最後の手段で、短い定型句の照合専用。"""
    return _NON_WORD.sub("", norm).lower()
