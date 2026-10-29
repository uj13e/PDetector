"""画像の抽出(OCR + メタデータ + QRコード)。

普通に OCR で読めた文字は doc.text へ。コントラストを強調したときだけ読めた文字(白地にほぼ白など)と
EXIF/PNG text/XMP 等のメタデータは HiddenRegion に入れる。OCR が使えないときは clean にせず partial。
どの関数も例外は投げない。
"""
from __future__ import annotations

import hashlib
import io
import re
import shutil
import unicodedata
import warnings
from dataclasses import dataclass, field
from typing import List, Set, Tuple

from .model import ExtractedDoc, HiddenRegion
from .safeio import Budget, BudgetExceeded, Limits, UnsafeInput

MAX_PIXELS = 50_000_000          # 超えたら decompression bomb 扱いで拒否
MAX_FRAMES = 10                  # GIF/TIFF/APNG は先頭これだけ
MAX_OCR_SIDE = 4000              # OCR 前に長辺をここまで縮小。巨大画像で時間が溶ける
MIN_OCR_SIDE = 12

_LOW_CONTRAST_REASON = "低コントラストの隠し文字(強調時のみ検出)"


# OCR
@dataclass
class OcrOutcome:
    text: str = ""                                   # 通常の OCR で読めた分
    hidden: List[str] = field(default_factory=list)  # 強調後にだけ読めた行
    available: bool = True
    partial: bool = False                            # 言語データ不足など
    notes: List[str] = field(default_factory=list)
    lang: str = ""


_ENGINE_CACHE: dict = {}


def _engine():
    """(pytesseract, 言語, 注記, partial)。使えないときは (None, "", 注記, True)。"""
    if "v" in _ENGINE_CACHE:
        return _ENGINE_CACHE["v"]
    notes: List[str] = []
    result = (None, "", notes, True)
    try:
        import pytesseract  # type: ignore
    except Exception:
        notes.append("pytesseract が未導入のため OCR は未実施です(`pip install pytesseract pillow`)。")
        _ENGINE_CACHE["v"] = result
        return result
    if not shutil.which("tesseract"):
        try:
            cmd = getattr(pytesseract.pytesseract, "tesseract_cmd", "tesseract")
            if not shutil.which(cmd):
                raise FileNotFoundError(cmd)
        except Exception:
            notes.append("Tesseract OCR 本体が見つからないため OCR は未実施です。")
            _ENGINE_CACHE["v"] = result
            return result
    try:
        langs = set(pytesseract.get_languages(config=""))
    except Exception as e:  # noqa
        notes.append(f"Tesseract の言語一覧を取得できませんでした({e})。")
        _ENGINE_CACHE["v"] = result
        return result
    partial = False
    if "jpn" in langs and "eng" in langs:
        lang = "jpn+eng"
    elif "eng" in langs:
        lang = "eng"
        partial = True
        notes.append("Tesseract に日本語データ(jpn)が無いため英語のみで OCR しました。"
                     "画像内の日本語テキストは検出できません。")
    else:
        usable = sorted(l for l in langs if l != "osd")
        if not usable:
            notes.append("Tesseract に使える言語データがありません。OCR は未実施です。")
            _ENGINE_CACHE["v"] = result
            return result
        lang = usable[0]
        partial = True
        notes.append(f"Tesseract の言語データが {lang} のみのため、画像内の他言語テキストは検出できません。")
    result = (pytesseract, lang, notes, partial)
    _ENGINE_CACHE["v"] = result
    return result


def ocr_available() -> Tuple[bool, str]:
    """(使えるか, 使えない理由 or 使う言語)。"""
    pt, lang, notes, _ = _engine()
    if pt is None:
        return False, " ".join(notes)
    return True, lang


def _bg_stretch(gray, width: int = 12):
    """背景色(最頻値)のすぐ近くの階調だけを 0〜255 に引き伸ばす。

    背景255/文字248 みたいなのは autocontrast だと黒文字に引っ張られて見えないままになる。
    出力は白地黒文字に揃える。
    """
    hist = gray.histogram()
    bg = max(range(256), key=lambda v: hist[v])
    lut = []
    if bg >= 128:       # 明るい背景
        for v in range(256):
            if v >= bg:
                lut.append(255)
            else:
                lut.append(max(0, int(255 - (bg - v) * 255 / width)))
    else:               # 暗い背景は反転して白地黒文字にする
        for v in range(256):
            if v <= bg:
                lut.append(255)
            else:
                lut.append(max(0, int(255 - (v - bg) * 255 / width)))
    return gray.point(lut)


def _variants(img, budget: Budget):
    """(名前, PIL画像)。最初は必ず元画像(グレースケール化だけ)。"""
    from PIL import Image, ImageOps  # type: ignore

    # 透明部分は白で合成
    base = img
    if base.mode in ("RGBA", "LA", "PA") or (base.mode == "P" and "transparency" in base.info):
        rgba = base.convert("RGBA")
        bgw = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        base = Image.alpha_composite(bgw, rgba).convert("RGB")
    gray = base.convert("L")
    w, h = gray.size
    long_side = max(w, h)
    if long_side > MAX_OCR_SIDE:
        scale = MAX_OCR_SIDE / long_side
        gray = gray.resize((max(1, int(w * scale)), max(1, int(h * scale))))
        w, h = gray.size
    yield "original", gray
    budget.check()
    try:
        yield "autocontrast", ImageOps.autocontrast(gray, cutoff=1)
        yield "equalize", ImageOps.equalize(gray)
        yield "bg_stretch", _bg_stretch(gray)
        yield "invert", ImageOps.invert(gray)
        if long_side * 2 <= MAX_OCR_SIDE:
            yield "upscale2x", ImageOps.autocontrast(gray, cutoff=1).resize((w * 2, h * 2))
        # 傾いた文字は読み順が崩れて失敗するので、少し回した版も試す
        bgv = gray.getpixel((0, 0))
        for deg in (3, -3, 6, -6):
            yield f"rot{deg:+d}", gray.rotate(deg, expand=True, fillcolor=bgv)
    except BudgetExceeded:
        raise
    except Exception:
        return


def _norm_line(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _words(s: str) -> Set[str]:
    return {w for w in re.findall(r"\w{3,}", s.lower())}


def _is_texty(line: str) -> bool:
    """OCR ノイズ(記号の羅列)を弾く簡易判定。"""
    compact = line.replace(" ", "")
    if not compact:
        return False
    letters = sum(1 for c in compact if unicodedata.category(c)[0] in ("L", "N"))
    ratio = letters / len(compact)
    has_cjk = any(0x3040 <= ord(c) <= 0x9FFF for c in compact)
    if has_cjk:
        return len(compact) >= 4 and ratio >= 0.7
    return len(line) >= 6 and ratio >= 0.7 and len(_words(line)) >= 2


def ocr_pil_image(img, budget: Budget, max_variants: int = 10) -> OcrOutcome:
    """前処理違いで何度か OCR する。例外は投げない。"""
    out = OcrOutcome()
    pt, lang, notes, partial = _engine()
    out.notes.extend(notes)
    if pt is None:
        out.available = False
        out.partial = True
        return out
    out.lang = lang
    out.partial = partial
    try:
        gw, gh = img.size
        if min(gw, gh) < MIN_OCR_SIDE:
            out.notes.append("画像が小さすぎるため OCR をスキップしました。")
            return out
        orig_words: Set[str] = set()
        hidden_seen: Set[str] = set()
        for i, (name, v) in enumerate(_variants(img, budget)):
            if i >= max_variants:
                break
            budget.check()
            rem = budget.remaining
            timeout = 20 if rem is None else max(1, min(20, int(rem)))
            try:
                txt = pt.image_to_string(v, lang=lang, timeout=timeout)
            except RuntimeError:
                out.notes.append("OCR がタイムアウトしました。")
                out.partial = True
                break
            except Exception as e:  # noqa
                out.notes.append(f"OCR 失敗({name}): {e}")
                out.partial = True
                break
            lines = [_norm_line(l) for l in txt.splitlines()]
            lines = [l for l in lines if l]
            if name == "original":
                orig_words = _words("\n".join(lines))
                out.text = "\n".join(lines)
                continue
            if name.startswith("rot"):
                # 回転で読めたのは普通に見えてる文字。原版に無い行だけ本文へ足す
                extra = [l for l in lines if _is_texty(l) and l not in out.text]
                if extra:
                    out.text = (out.text + "\n" + "\n".join(extra)).strip()
                continue
            for l in lines:
                if not _is_texty(l):
                    continue
                lw = _words(l)
                if not lw:
                    # CJK だけの行は単語で比べられないので行ごと比べる
                    if l not in out.text and l not in hidden_seen:
                        hidden_seen.add(l)
                        out.hidden.append(l)
                    continue
                new_ratio = len(lw - orig_words) / len(lw)
                if new_ratio >= 0.5 and l not in hidden_seen:
                    hidden_seen.add(l)
                    out.hidden.append(l)
    except BudgetExceeded:
        out.partial = True
        out.notes.append("OCR が時間予算を超過したため途中で打ち切りました。")
    except Exception as e:  # noqa
        out.partial = True
        out.notes.append(f"OCR 処理で例外: {e}")
    return out


# メタデータ
_SKIP_INFO_KEYS = {
    "dpi", "gamma", "interlace", "transparency", "background", "aspect", "chromaticity",
    "srgb", "icc_profile", "exif", "photoshop", "duration", "loop", "version", "progressive",
    "progression", "jfif", "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform",
    "compression", "extension", "default_image", "timestamp", "dpi_unit", "mpoffset", "mp",
}
_SKIP_EXIF_TAGS = {37500, 59932, 34665, 34853, 40965}   # MakerNote や IFD ポインタ。UserComment(37510)は見る


def _bytes_to_text(b: bytes) -> str:
    if not b:
        return ""
    # UserComment の文字コード接頭辞
    for prefix, enc in ((b"ASCII\x00\x00\x00", "ascii"), (b"UNICODE\x00", "utf-16"), (b"JIS\x00\x00\x00\x00\x00", "iso2022_jp")):
        if b.startswith(prefix):
            try:
                return b[len(prefix):].decode(enc, errors="replace").strip("\x00 ")
            except Exception:
                return ""
    if b.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return b.decode("utf-16", errors="replace").strip("\x00 ")
        except Exception:
            return ""
    # XP* タグは BOM なしの UTF-16LE
    if len(b) >= 4 and b[1:2] == b"\x00" and b[3:4] == b"\x00":
        try:
            return b.decode("utf-16-le", errors="replace").strip("\x00 ")
        except Exception:
            pass
    try:
        from .encoding import decode_bytes
        t, _enc, _n = decode_bytes(b)
        return t.strip("\x00 ")
    except Exception:
        return b.decode("latin-1", errors="replace").strip("\x00 ")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _xmp_text(xml: str) -> str:
    parts = [p.strip() for p in re.findall(r">([^<>]+)<", xml)]
    parts = [p for p in parts if len(p) >= 4 and not re.fullmatch(r"[\d\-:T.+Z/ ]+", p)
             and not re.fullmatch(r"(?:uuid|xmp\.[a-z]+):[\w\-.]+", p, re.I) and p != "application/pdf"]
    return "\n".join(dict.fromkeys(parts))


def _collect_metadata(img, doc: ExtractedDoc, budget: Budget):
    seen: Set[str] = set()
    lines: List[str] = []

    def add(text: str, label: str):
        t = (text or "").strip()
        if len(t) < 4 or _printable_ratio(t) < 0.85:
            return
        key = t.lower()
        if key in seen:
            return
        seen.add(key)
        lines.append(f"{label}: {t[:8000]}")

    # img.info: PNG の tEXt/iTXt/zTXt、JPEG/GIF コメント、XMP など
    try:
        for k, v in list(getattr(img, "info", {}).items()):
            ks = str(k)
            if ks.lower() in _SKIP_INFO_KEYS and ks not in ("comment",):
                continue
            if isinstance(v, bytes):
                if ks.lower() in ("xmp", "xml:com.adobe.xmp"):
                    add(_xmp_text(_bytes_to_text(v)), "XMP")
                elif ks.lower() in ("icc_profile", "exif", "photoshop"):
                    continue
                else:
                    add(_bytes_to_text(v), ks)
            elif isinstance(v, str):
                if "<x:xmpmeta" in v or "<?xpacket" in v or ks.lower() in ("xmp", "xml:com.adobe.xmp"):
                    add(_xmp_text(v), "XMP")
                else:
                    add(v, ks)
            elif isinstance(v, (tuple, list)):
                for item in v:
                    if isinstance(item, str):
                        add(item, ks)
    except Exception:
        pass
    try:   # PNG text。info と被るが add() で弾かれる
        for k, v in dict(getattr(img, "text", {}) or {}).items():
            add(str(v), f"PNG text:{k}")
    except Exception:
        pass

    try:
        from PIL import ExifTags  # type: ignore
        exif = img.getexif()
        tags = dict(exif.items()) if exif is not None else {}
        sub = {}
        for ifd_tag in (0x8769,):
            try:
                sub.update(dict(exif.get_ifd(ifd_tag)))
            except Exception:
                pass
        tags.update(sub)
        for tag, val in tags.items():
            budget.check()
            if tag in _SKIP_EXIF_TAGS:
                continue
            name = ExifTags.TAGS.get(tag, f"0x{tag:04x}")
            if isinstance(val, bytes):
                add(_bytes_to_text(val), f"EXIF {name}")
            elif isinstance(val, str):
                add(val, f"EXIF {name}")
    except BudgetExceeded:
        raise
    except Exception:
        pass
    if lines:
        # 項目ごとに出すと低レベルの指摘が並ぶので1領域にまとめる
        doc.hidden_regions.append(HiddenRegion(text="\n".join(lines), reason="画像メタデータ(EXIF/PNGテキスト/XMP/コメント)",
                                               location="メタデータ", kind="metadata"))


# QR
_QR_LIBS: dict = {}


def _qr_libs():
    """(cv2, numpy) か None。import は1回しか試さない。"""
    if "v" not in _QR_LIBS:
        try:
            import cv2  # type: ignore
            import numpy as np  # type: ignore
            _QR_LIBS["v"] = (cv2, np)
        except Exception:
            _QR_LIBS["v"] = None
    return _QR_LIBS["v"]


def _decode_qr(img) -> List[str]:
    libs = _qr_libs()
    if not libs:
        return []
    cv2, np = libs
    try:
        arr = np.array(img.convert("RGB"))
        arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
        det = cv2.QRCodeDetector()
        found: List[str] = []
        try:
            ok, decoded, _pts, _ = det.detectAndDecodeMulti(arr)
            if ok:
                found.extend(d for d in decoded if d)
        except Exception:
            pass
        if not found:
            val, _pts, _ = det.detectAndDecode(arr)
            if val:
                found.append(val)
        return list(dict.fromkeys(found))
    except Exception:
        return []


def _trailing_data(data: bytes, doc: ExtractedDoc):
    """終端マーカーより後ろのデータ(ポリグロット)を隠し領域にする。"""
    tail = b""
    try:
        if data.startswith(b"\x89PNG"):
            i = data.rfind(b"IEND")
            if i >= 0:
                tail = data[i + 8:]          # IEND + CRC(4)
        elif data.startswith(b"\xff\xd8"):
            i = data.rfind(b"\xff\xd9")
            if i >= 0:
                tail = data[i + 2:]
        elif data.startswith((b"GIF87a", b"GIF89a")):
            i = data.rfind(b";")
            if i >= 0:
                tail = data[i + 1:]
    except Exception:
        return
    tail = tail.strip(b"\x00\r\n ")
    if len(tail) < 8:
        return
    t = _bytes_to_text(tail[:20000])
    if t and len(t) >= 8 and _printable_ratio(t) >= 0.85:
        doc.hidden_regions.append(HiddenRegion(
            text=t, reason="画像の終端より後ろに付加されたデータ", location="画像末尾", kind="metadata"))


def extract_image(data: bytes, name: str, limits: Limits, budget: Budget, depth: int = 0) -> ExtractedDoc:
    doc = ExtractedDoc(source=name, kind="image", size=len(data or b""))
    try:
        doc.sha256 = hashlib.sha256(data or b"").hexdigest()
    except Exception:
        pass
    if not data:
        doc.mark("failed", "画像データが空です。")
        return doc
    try:
        from PIL import Image  # type: ignore
    except Exception:
        doc.mark("unsupported", "Pillow が未導入のため画像を解析できません(`pip install pillow`)。")
        return doc
    if len(data) > limits.max_file_bytes:
        doc.mark("failed", f"画像が大きすぎます({len(data) // (1024 * 1024)}MB)。")
        return doc

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            prev = Image.MAX_IMAGE_PIXELS
            Image.MAX_IMAGE_PIXELS = MAX_PIXELS
            try:
                img = Image.open(io.BytesIO(data))
                w, h = img.size
                if w * h > MAX_PIXELS:
                    raise UnsafeInput(f"画素数が多すぎます({w}x{h}): decompression bomb の疑い")
                img.load()
            finally:
                Image.MAX_IMAGE_PIXELS = prev
    except UnsafeInput as e:
        doc.mark("failed", f"画像を拒否しました: {e}")
        return doc
    except Exception as e:  # noqa  (DecompressionBombWarning/Error, 壊れた画像 等)
        msg = str(e)
        if "decompression" in msg.lower() or "pixels" in msg.lower():
            doc.mark("failed", f"画像を拒否しました(画素数が多すぎます。decompression bomb の疑い): {msg[:120]}")
        else:
            doc.mark("failed", f"画像を開けません: {msg[:160]}")
        return doc

    try:
        doc.kind = "image"
        _trailing_data(data, doc)
        try:
            _collect_metadata(img, doc, budget)
        except BudgetExceeded:
            doc.mark("partial", "メタデータ解析が時間予算を超過しました。")
            return doc

        # 同一内容のフレームは飛ばす
        frames = []
        n_frames = getattr(img, "n_frames", 1) or 1
        if n_frames > MAX_FRAMES:
            doc.mark("partial", f"フレーム数が多いため先頭{MAX_FRAMES}フレームのみ解析しました(全{n_frames}フレーム)。")
        seen_hash: Set[str] = set()
        for i in range(min(n_frames, MAX_FRAMES)):
            budget.check()
            try:
                if n_frames > 1:
                    img.seek(i)
                fr = img.copy()
            except Exception:
                break
            hsh = hashlib.md5(fr.tobytes()).hexdigest()
            if hsh in seen_hash:
                continue
            seen_hash.add(hsh)
            frames.append(fr)

        pt, lang, enotes, epartial = _engine()
        ocr_texts: List[str] = []
        ocr_hidden: List[str] = []
        ocr_ran = False
        for idx, fr in enumerate(frames):
            qrs = _decode_qr(fr)
            for q in qrs:
                ocr_texts.append(f"QRコード: {q}")
            if pt is None:
                continue
            res = ocr_pil_image(fr, budget)
            ocr_ran = ocr_ran or res.available
            if res.text:
                ocr_texts.append(res.text)
            for hline in res.hidden:
                if hline not in ocr_hidden:
                    ocr_hidden.append(hline)
            for n in res.notes:
                if n not in doc.notes and n not in enotes:
                    doc.notes.append(n)
            if res.partial:
                epartial = True

        if pt is None:
            doc.mark("partial", "メタデータのみ解析しました。OCR 未実施のため画像内の文字は検査できていません。")
            for n in enotes:
                if n not in doc.notes:
                    doc.notes.append(n)
        else:
            for n in enotes:
                if n not in doc.notes:
                    doc.notes.append(n)
            if epartial:
                doc.mark("partial", "")

        text = "\n".join(t for t in ocr_texts if t).strip()
        doc.text = text
        if ocr_hidden:
            doc.hidden_regions.append(HiddenRegion(
                text="\n".join(ocr_hidden), reason=_LOW_CONTRAST_REASON,
                location="画像内", kind="hidden"))
        if pt is not None and not text and not ocr_hidden:
            doc.notes.append("OCR でテキストを検出できませんでした。")
        for fr in frames:
            try:
                fr.close()
            except Exception:
                pass
    except BudgetExceeded:
        doc.mark("partial", "画像の解析が時間予算を超過したため途中で打ち切りました。")
    except Exception as e:  # noqa
        doc.mark("partial", f"画像の解析中に例外: {str(e)[:160]}")
    return doc
