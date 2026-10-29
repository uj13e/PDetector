"""各種エンコード/簡易暗号をデコードして候補テキストを作る。

base64 のほか hex・base32・URL/HTML エンティティ・Unicode エスケープ・文字コード列・ROT13/47・Atbash・反転・leet・zlib/gzip などで隠されうる。
候補を作るところまでがここの仕事で、ルール照合は detector 側。全文変換(rot13 等)は whole=True で返し、
detector は元テキストで当たらなかったルールだけ採用する(普通の英文が別変換でたまたま意味を持つのを誤検知しないため)。
多段デコードは深さ上限あり。時間予算(Budget)と候補数の上限で暴走を止める。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html as _html
import re
import urllib.parse
import zlib
from typing import Iterator, List, NamedTuple, Optional

from .safeio import Budget


class Decoded(NamedTuple):
    scheme: str        # 例: "base64", "base64+hex"
    text: str
    whole: bool        # 全文変換なら True。元テキストとの差分だけ有効


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}")
# MIME 風に折り返された base64
_B64_WRAP_RE = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,}[ \t]*\r?\n[ \t]*){1,400}[A-Za-z0-9+/]{4,}={0,2}")
# 空白区切りの base64。英文を拾わないよう、同じ長さのグループが続くものだけ
_B64_SPACED_RE = re.compile("|".join(
    rf"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{{{n}}}[ ]){{4,}}[A-Za-z0-9+/]{{1,{n}}}={{0,2}}" for n in (4, 5, 6, 8, 10, 12, 16, 20, 24, 32, 64)))
_B85_RE = re.compile(r"(?<![0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~])[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{24,}")
_A85_RE = re.compile(r"<~[!-u\s]{12,}~>")
_QP_RE = re.compile(r"(?:=[0-9A-F]{2}(?:\r?\n)?){8,}")
_B32_RE = re.compile(r"(?<![A-Za-z2-7])[A-Za-z2-7]{24,}={0,6}")
_HEX_RE = re.compile(r"(?:(?:0x|\\x)?[0-9A-Fa-f]{2}[\s,:;_-]*){10,}")
_BIN_RE = re.compile(r"(?:[01]{8}[\s,]*){5,}")
_DECSEQ_RE = re.compile(r"(?:\d{1,7}[\s,;]+){5,}\d{1,7}")
_OCT_RE = re.compile(r"(?:\\[0-7]{3}[ \t,;]*){6,}")
_A85_RAW_RE = re.compile(r"(?<![!-u])[!-u]{20,}")
_QPX_RE = re.compile(r"=[0-9A-F]{2}")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_ENTITY_RE = re.compile(r"&#x?[0-9A-Fa-f]+;|&[a-zA-Z]{2,10};")
_UESC_RE = re.compile(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}|\\u\{[0-9A-Fa-f]{1,6}\}")

_MAX_BLOBS = 40           # 1方式あたり、デコードに成功したブロブの上限
_MAX_ATTEMPTS = 4000      # 試行の上限。ハッシュ等の長い英数字列で枠を食われないように
_MAX_BLOB_LEN = 400_000
_MAX_TOTAL = 400          # iter_decodings 1回で返す候補の上限
_MIN_READABLE = 0.85      # 印字可能率がこれ以上なら読めるテキスト扱い
_MAX_INFLATE = 2_000_000
_CHARMAP_MAX = 200_000    # ROT13等をかける最大文字数。超えたら先頭と末尾だけ


_UNPRINTABLE_RE = re.compile(r"[^\x20-\x7e\n\r\t\u00a0-\U0010ffff]")
_ODD_RE = re.compile(r"[^\w\s.,;:!?'\"()\-_/@#%&*+=<>\[\]{}$\\|~^`]")
_SAMPLE = 20000


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    smp = s[:_SAMPLE]
    bad = len(_UNPRINTABLE_RE.findall(smp)) + sum(1 for c in smp if c >= "\u0080" and not c.isprintable())
    return 1.0 - bad / len(smp)


def _wordish_ratio(s: str) -> float:
    """文字・空白・一般的な記号の割合。記号だらけのゴミを落とす。"""
    if not s:
        return 0.0
    smp = s[:_SAMPLE]
    return 1.0 - len(_ODD_RE.findall(smp)) / len(smp)


def _is_useful(s: str, min_len: int = 8) -> bool:
    return bool(s) and len(s) >= min_len and _printable_ratio(s) >= _MIN_READABLE and _wordish_ratio(s) >= 0.8


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


_ROT47 = {o: chr(33 + ((o - 33 + 47) % 94)) for o in range(33, 127)}


def _rot47(text: str) -> str:
    return text.translate(_ROT47)


_ATBASH = {}
for _i in range(26):
    _ATBASH[ord("a") + _i] = chr(ord("z") - _i)
    _ATBASH[ord("A") + _i] = chr(ord("Z") - _i)


def _atbash(text: str) -> str:
    return text.translate(_ATBASH)


_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "|": "l", "€": "e", "£": "l", "+": "t",
})


def _deleet(text: str) -> str:
    return text.translate(_LEET)


_WORD_REV_RE = re.compile(r"\S+")


def _reverse_words(text: str) -> str:
    """単語ごとの反転(「erongi lla suoiverp」)。語順はそのまま。"""
    return _WORD_REV_RE.sub(lambda m: m.group(0)[::-1], text)


def _bytes_to_text(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if raw[:2] == b"\x1f\x8b" or (raw[:1] == b"\x78" and raw[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda")):
        try:
            d = zlib.decompressobj(47)           # 47 で gzip/zlib 自動判別
            out = d.decompress(raw, _MAX_INFLATE)
            if out:
                raw = out
        except Exception:
            pass
    # UTF-16(NUL混じり)
    if len(raw) >= 8 and raw.count(b"\x00") >= len(raw) // 4:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                s = raw.decode(enc, errors="strict")
                if _printable_ratio(s) >= _MIN_READABLE:
                    return s
            except Exception:
                continue
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except Exception:
        pass
    # cp932 で隠された日本語
    try:
        s = raw.decode("cp932", errors="strict")
        if _printable_ratio(s) >= 0.95 and any("぀" <= c <= "ヿ" or "一" <= c <= "鿿" for c in s):
            return s
    except Exception:
        pass
    return None


def _b64_bytes(blob: str) -> Optional[bytes]:
    blob = re.sub(r"\s+", "", blob).replace("-", "+").replace("_", "/")
    blob = blob.rstrip("=")
    if len(blob) < 12 or len(blob) % 4 == 1:
        return None
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except Exception:
        return None


def _try_base64(blob: str):
    # 直前の語とくっついていることがあるので、先頭を 0〜3 文字ずらして試す
    for skip in (0, 1, 2, 3):
        raw = _b64_bytes(blob[skip:]) if skip else _b64_bytes(blob)
        if raw:
            t = _bytes_to_text(raw)
            if t and _is_useful(t):
                return t
    return None


def _try_base85(blob: str):
    try:
        raw = base64.b85decode(blob)
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_ascii85(blob: str):
    try:
        raw = base64.a85decode(blob, adobe=True)
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_ascii85_raw(blob: str):
    """区切り(<~ ~>)なしの Ascii85。"""
    try:
        raw = base64.a85decode(blob)
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_qp(blob: str):
    import quopri
    try:
        raw = quopri.decodestring(blob.encode("ascii", "ignore"))
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_base32(blob: str):
    blob = blob.rstrip("=").upper()
    if len(blob) < 16:
        return None
    try:
        raw = base64.b32decode(blob + "=" * (-len(blob) % 8), casefold=True)
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_hex(blob: str):
    cleaned = re.sub(r"(0x|\\x|[\s,:;_-])", "", blob)
    if len(cleaned) % 2 or len(cleaned) < 16:
        return None
    try:
        raw = binascii.unhexlify(cleaned)
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_binary(blob: str):
    bits = re.sub(r"[^01]", "", blob)
    if len(bits) % 8 or len(bits) < 40:
        return None
    try:
        raw = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    except Exception:
        return None
    return _bytes_to_text(raw)


def _try_decimal_codes(blob: str):
    nums = [int(x) for x in re.findall(r"\d{1,7}", blob)]
    if len(nums) < 5:
        return None
    if not all(0 < n <= 0x10FFFF for n in nums):
        return None
    try:
        s = "".join(chr(n) for n in nums)
    except Exception:
        return None
    return s if _printable_ratio(s) >= _MIN_READABLE else None


def _try_octal(blob: str):
    try:
        raw = bytes(int(x, 8) & 0xFF for x in re.findall(r"\\([0-7]{3})", blob))
    except Exception:
        return None
    return _bytes_to_text(raw)


def _unescape(text: str) -> str:
    def rep(m: "re.Match") -> str:
        s = m.group(0)
        try:
            if s.startswith("\\u{"):
                return chr(int(s[3:-1], 16))
            if s[1] in "uUx":
                return chr(int(s[2:], 16))
        except (ValueError, OverflowError):
            pass
        return s
    return _UESC_RE.sub(rep, text)


_BLOB_SPECS = (
    ("base64", _B64_RE, _try_base64),
    ("base64", _B64_WRAP_RE, _try_base64),
    ("base64", _B64_SPACED_RE, _try_base64),
    ("base85", _B85_RE, _try_base85),
    ("ascii85", _A85_RE, _try_ascii85),
    ("ascii85", _A85_RAW_RE, _try_ascii85_raw),
    ("quoted_printable", _QP_RE, _try_qp),
    ("base32", _B32_RE, _try_base32),
    ("hex", _HEX_RE, _try_hex),
    ("binary", _BIN_RE, _try_binary),
    ("decimal_codes", _DECSEQ_RE, _try_decimal_codes),
    ("octal", _OCT_RE, _try_octal),
)


def _letters(s: str) -> int:
    return sum(1 for c in s if c.isalpha())


def _whole_transforms(text: str) -> Iterator[Decoded]:
    """全文変換の候補。元と同じになるものは出さない。"""
    # 大きい文書は先頭と末尾だけ。全文に何回もルールを回すと遅い
    sample = text if len(text) <= _CHARMAP_MAX else text[:_CHARMAP_MAX // 2] + "\n" + text[-_CHARMAP_MAX // 2:]
    for scheme, fn in (("rot13", _rot13), ("rot47", _rot47), ("atbash", _atbash),
                       ("reversed", lambda t: t[::-1]), ("reversed_words", _reverse_words)):
        try:
            d = fn(sample)
        except Exception:
            continue
        if d and d != sample:
            yield Decoded(scheme, d, True)

    # leet は該当する数字/記号が1つでもあるときだけ
    if any(c in text for c in "0134578@$!|"):
        d = _deleet(sample)
        if d != sample:
            yield Decoded("leet", d, True)

    # =20 のように記号だけ符号化されたものも含めて全文を戻す
    if len(_QPX_RE.findall(text)) >= 3:
        try:
            import quopri
            d = quopri.decodestring(text.encode("utf-8", "ignore")).decode("utf-8", "replace")
            if d != text and _is_useful(d):
                yield Decoded("quoted_printable", d, True)
        except Exception:
            pass
    if len(_PCT_RE.findall(text)) >= 3:
        try:
            d = urllib.parse.unquote(text, errors="strict")
            if d != text and _is_useful(d):
                yield Decoded("url_encoding", d, True)
        except Exception:
            pass
    if _ENTITY_RE.search(text):
        try:
            d = _html.unescape(text)
            if d != text and _is_useful(d):
                yield Decoded("html_entity", d, True)
        except Exception:
            pass
    if len(_UESC_RE.findall(text)) >= 4:
        d = _unescape(text)
        if d != text and _is_useful(d):
            yield Decoded("unicode_escape", d, True)


def _blob_candidates(text: str, budget: Optional[Budget]) -> Iterator[Decoded]:
    seen = set()
    for scheme, regex, fn in _BLOB_SPECS:
        n = 0
        tries = 0
        for m in regex.finditer(text):
            if budget:
                budget.check()
            blob = m.group(0)
            if len(blob) > _MAX_BLOB_LEN:
                blob = blob[:_MAX_BLOB_LEN]
            tries += 1
            if tries > _MAX_ATTEMPTS:
                break
            try:
                d = fn(blob)
            except Exception:
                d = None
            if d and d not in seen and _is_useful(d):
                seen.add(d)
                n += 1
                yield Decoded(scheme, d, False)
                if n >= _MAX_BLOBS:
                    break


def iter_decodings(text: str, budget: Optional[Budget] = None, depth: int = 2) -> Iterator[Decoded]:
    """デコード候補を返す。depth>1 なら結果をさらにデコードする。"""
    if not text:
        return
    count = 0
    level: List[Decoded] = []
    for dec in _whole_transforms(text):
        level.append(dec)
        count += 1
        yield dec
        if count >= _MAX_TOTAL:
            return
    for dec in _blob_candidates(text, budget):
        level.append(dec)
        count += 1
        yield dec
        if count >= _MAX_TOTAL:
            return

    # 2段目以降はブロブ系だけ。全文変換の結果をさらに変換しても意味が薄い
    cur = [d for d in level if not d.whole]
    for _ in range(max(0, depth - 1)):
        nxt: List[Decoded] = []
        for parent in cur:
            if budget:
                budget.check()
            kids = list(_blob_candidates(parent.text, budget))
            for k in kids:
                dec = Decoded(f"{parent.scheme}+{k.scheme}", k.text, False)
                nxt.append(dec)
                count += 1
                yield dec
                if count >= _MAX_TOTAL:
                    return
            # 中身がさらに rot13/escape 等で隠されている場合
            for k in _whole_transforms(parent.text):
                if k.scheme in ("rot13", "reversed", "url_encoding", "html_entity", "unicode_escape"):
                    dec = Decoded(f"{parent.scheme}+{k.scheme}", k.text, False)
                    count += 1
                    yield dec
                    if count >= _MAX_TOTAL:
                        return
        cur = nxt
        if not cur:
            break


SCHEME_LABEL = {
    "base64": "base64", "base85": "base85", "ascii85": "ascii85", "quoted_printable": "quoted-printable", "base32": "base32", "hex": "16進(hex)", "binary": "2進",
    "decimal_codes": "10進文字コード", "octal": "8進エスケープ",
    "url_encoding": "URLエンコード", "html_entity": "HTMLエンティティ",
    "unicode_escape": "\\uエスケープ", "rot13": "ROT13", "rot47": "ROT47",
    "atbash": "Atbash暗号", "reversed": "文字列反転", "reversed_words": "単語ごとの反転",
    "leet": "leet(文字置換)",
}


def label(scheme: str) -> str:
    return "→".join(SCHEME_LABEL.get(s, s) for s in scheme.split("+"))
