"""入力ソースからテキストと隠し要素を取り出すディスパッチ層。

形式は拡張子でなく中身で判定し、食い違っていれば偽装の疑いとして報告する。解析できなかった分は
status に残して clean に見せない(unscanned 扱い)。サイズ・zip/XML 爆弾・再帰深さ・時間は全形式で制限。
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from typing import List, Optional

from .encoding import decode_bytes, sniff_declared_charset
from .model import ExtractedDoc, Finding, HiddenRegion
from .safeio import (Budget, BudgetExceeded, Limits, UnsafeInput, open_zip, parse_xml,
                     read_member, localname)

__all__ = ["ExtractedDoc", "extract_from_bytes", "extract_from_path", "extract_from_url",
           "detect_kind"]

_EXT_FAMILY = {
    ".pdf": "pdf",
    ".docx": "ooxml", ".docm": "ooxml", ".dotx": "ooxml", ".dotm": "ooxml",
    ".xlsx": "ooxml", ".xlsm": "ooxml", ".xltx": "ooxml", ".xltm": "ooxml",
    ".pptx": "ooxml", ".pptm": "ooxml", ".potx": "ooxml", ".potm": "ooxml", ".ppsx": "ooxml",
    ".odt": "odf", ".ods": "odf", ".odp": "odf", ".odg": "odf",
    ".epub": "epub",
    ".rtf": "rtf",
    ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".msg": "ole",
    ".zip": "zip", ".jar": "zip",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image", ".bmp": "image",
    ".tif": "image", ".tiff": "image", ".webp": "image",
    ".eml": "eml",
    ".gz": "gzip", ".tgz": "gzip",
}
_TEXTLIKE_EXT = {
    ".txt", ".md", ".markdown", ".text", ".csv", ".tsv", ".log", ".rst", ".ini", ".cfg", ".conf",
    ".yaml", ".yml", ".toml", ".json", ".xml", ".html", ".htm", ".xhtml", ".svg", ".py", ".js",
    ".ts", ".css", ".sql", ".sh", ".bat", ".ps1", ".java", ".c", ".cpp", ".h", ".go", ".rs", ".rb",
    ".php", ".tex", ".srt", ".vtt", ".ics", ".vcf", ".ipynb", "",
}
_BINARY_FAMILIES = {"pdf", "ooxml", "odf", "epub", "ole", "zip", "image", "gzip", "archive7z"}


def _zip_family(data: bytes) -> str:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception:
        return "zip"
    low = [n.lower() for n in names]
    if "[content_types].xml" in low:
        if any(n.startswith(("word/", "xl/", "ppt/")) for n in low):
            return "ooxml"
    if "mimetype" in low:
        try:
            mt = zf.read(names[low.index("mimetype")])[:100].decode("ascii", "ignore")
        except Exception:
            mt = ""
        if "opendocument" in mt:
            return "odf"
        if "epub" in mt:
            return "epub"
    if any(n.startswith("meta-inf/container.xml") for n in low):
        return "epub"
    if any(n.startswith(("word/", "xl/", "ppt/")) for n in low):
        return "ooxml"
    if "content.xml" in low and "meta-inf/manifest.xml" in low:
        return "odf"
    return "zip"


def detect_kind(data: bytes, name: str = "", content_type: Optional[str] = None) -> str:
    """中身から形式(family 名)を判定する。"""
    head = data[:16]
    if data[:5] == b"%PDF-" or b"%PDF-" in data[:1024]:
        return "pdf"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:4] in (b"GIF8",) \
            or head[:2] == b"BM" and len(data) > 26 and data[6:10] == b"\x00\x00\x00\x00" \
            or head[:4] in (b"II*\x00", b"MM\x00*") or (head[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        return "image"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return _zip_family(data)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:5] == b"{\\rtf":
        return "rtf"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!" or head[:6] == b"\xfd7zXZ\x00" or head[:3] == b"BZh":
        return "archive7z"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "executable"
    ct = (content_type or "").split(";")[0].strip().lower()
    if _looks_binary(data):
        return "binary"
    sample = data[:4096]
    lowered = sample.lower().lstrip(b"\xef\xbb\xbf \t\r\n")
    ext = os.path.splitext(name)[1].lower()
    if ct in ("text/html", "application/xhtml+xml") or ext in (".html", ".htm", ".xhtml"):
        return "html"
    if ext == ".eml" or ct == "message/rfc822" or _looks_like_mail(sample):
        return "eml"        # html の中身判定より先に見る。HTML パート付きメールを html と誤認しないため
    if lowered.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in lowered[:1024]:
        return "html"
    if ext == ".svg" or ct == "image/svg+xml" or (b"<svg" in lowered[:1024] and lowered.startswith((b"<?xml", b"<svg"))):
        return "html"      # SVG は htmlx で text/title/desc を扱う
    if ext == ".eml" or ct == "message/rfc822" or _looks_like_mail(sample):
        return "eml"
    if ext in (".json", ".ipynb") or ct.endswith("json") or lowered[:1] in (b"{", b"["):
        if _json_ok(data):
            return "json"
    if ext == ".xml" or ct.endswith("xml") or lowered.startswith(b"<?xml"):
        return "xml"
    if ext in (".md", ".markdown") or ct == "text/markdown":
        return "markdown"
    return "text"


def _looks_binary(data: bytes) -> bool:
    head = data[:8192]
    if not head:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return False
    nul = head.count(0)
    if nul:
        even = head[0::2].count(0) / max(1, len(head[0::2]))
        odd = head[1::2].count(0) / max(1, len(head[1::2]))
        if (odd > 0.1 and even < 0.05) or (even > 0.1 and odd < 0.05):
            return False            # BOMなし UTF-16 テキスト
        return True
    ctrl = sum(1 for b in head if b < 9 or 14 <= b < 32 and b != 27)
    return ctrl / len(head) > 0.05


_MAIL_HEAD = re.compile(rb"^(?:from |return-path:|received:|mime-version:|delivered-to:|message-id:|date:|from:|subject:)",
                        re.I | re.M)


def _looks_like_mail(sample: bytes) -> bool:
    first = sample[:2000]
    hits = len(_MAIL_HEAD.findall(first))
    return hits >= 3 and (b"mime-version:" in first.lower() or b"received:" in first.lower())


def _json_ok(data: bytes) -> bool:
    try:
        text, _, _ = decode_bytes(data[:2_000_000])
        json.loads(text)
        return True
    except Exception:
        return False


def extract_from_bytes(data: bytes, name: str = "", limits: Optional[Limits] = None,
                       budget: Optional[Budget] = None, depth: int = 0,
                       content_type: Optional[str] = None, source: Optional[str] = None) -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = ExtractedDoc(source=source or name or "<bytes>", size=len(data))
    try:
        doc.sha256 = hashlib.sha256(data).hexdigest()
    except Exception:
        pass
    try:
        if depth > limits.max_depth:
            doc.mark("partial", f"入れ子が深すぎるため解析しませんでした(深さ>{limits.max_depth})。")
            return doc
        if len(data) > limits.max_file_bytes:
            doc.mark("partial", f"サイズが大きいため先頭 {limits.max_file_bytes // (1024 * 1024)}MB のみ解析します"
                                f"(全体 {len(data) // (1024 * 1024)}MB)。")
            data = data[:limits.max_file_bytes]
        if not data:
            doc.kind = "empty"
            doc.notes.append("空のデータです。")
            return doc
        family = detect_kind(data, name, content_type)
        _check_mismatch(doc, name, family, content_type)
        _dispatch(doc, family, data, name, limits, budget, depth, content_type)
    except BudgetExceeded as e:
        doc.mark("partial", f"{e}。ここまでの結果のみで判定します。")
    except UnsafeInput as e:
        doc.mark("failed", f"安全のため解析を中止しました: {e}")
    except Exception as e:  # noqa
        doc.mark("failed", f"解析中にエラー: {type(e).__name__}: {e}")
    if len(doc.text) > limits.max_text_chars:
        doc.text = doc.text[:limits.max_text_chars]
        doc.mark("partial", f"抽出テキストが大きいため先頭 {limits.max_text_chars:,} 文字のみ走査します。")
    return doc


def extract_from_path(path: str, limits: Optional[Limits] = None,
                      budget: Optional[Budget] = None) -> ExtractedDoc:
    limits = limits or Limits()
    doc = ExtractedDoc(source=path)
    try:
        if not os.path.exists(path):
            doc.mark("failed", f"ファイルが見つかりません: {path}")
            return doc
        if os.path.isdir(path):
            doc.mark("failed", "ディレクトリです(フォルダは --recursive で走査してください)。")
            return doc
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            raw = f.read(limits.max_file_bytes + 1)
    except Exception as e:  # noqa
        doc.mark("failed", f"読み込み失敗: {e}")
        return doc
    d = extract_from_bytes(raw, name=os.path.basename(path), limits=limits, budget=budget, source=path)
    d.size = size
    return d


def extract_from_url(url: str, **kw) -> ExtractedDoc:
    from .netfetch import extract_from_url as _fetch
    return _fetch(url, **kw)


def _check_mismatch(doc: ExtractedDoc, name: str, family: str, content_type: Optional[str]):
    ext = os.path.splitext(name)[1].lower()
    expected = _EXT_FAMILY.get(ext)
    actual = family
    mismatch = False
    if expected and expected != actual:
        # .tgz/.gz は gzip で一致。.eml/.rtf はテキストも許容
        if not (expected == "gzip" and actual == "gzip"):
            mismatch = True
        if expected in ("eml", "rtf") and actual in ("text", "html", "eml", "rtf"):
            mismatch = False
        if expected == "image" and ext == ".svg":
            mismatch = False
        if expected == "ole" and actual == "ooxml":
            mismatch = True
    elif not expected and ext in _TEXTLIKE_EXT and actual in _BINARY_FAMILIES | {"executable"}:
        mismatch = True
    elif ext in (".html", ".htm") and actual in _BINARY_FAMILIES:
        mismatch = True
    if mismatch:
        doc.findings.append(Finding(
            rule_id="type_mismatch", category="obfuscation", severity="medium",
            description=f"拡張子({ext or 'なし'})と実際の形式({actual})が一致しません(偽装の可能性)。中身の形式で解析しました。",
            location="file", detail=f"拡張子={ext or '-'} / 判定={actual}"))


def _dispatch(doc: ExtractedDoc, family: str, data: bytes, name: str, limits: Limits,
              budget: Budget, depth: int, content_type: Optional[str]):
    def adopt(child: ExtractedDoc):
        doc.kind = child.kind or doc.kind
        doc.text = child.text
        doc.units = list(child.units)
        doc.findings.extend(child.findings)
        doc.notes.extend(child.notes)
        doc.hidden_regions.extend(child.hidden_regions)
        doc.encoding = child.encoding or doc.encoding
        doc.mark(child.status)

    if family == "pdf":
        from .pdfx import extract_pdf
        adopt(extract_pdf(data, name, limits, budget, depth))
    elif family == "image":
        from .imagex import extract_image
        adopt(extract_image(data, name, limits, budget, depth))
    elif family == "ooxml":
        from .office import extract_ooxml
        adopt(extract_ooxml(data, name, limits, budget, depth))
    elif family == "odf":
        from .office import extract_odf
        adopt(extract_odf(data, name, limits, budget, depth))
    elif family == "epub":
        from .office import extract_epub
        adopt(extract_epub(data, name, limits, budget, depth))
    elif family == "rtf":
        from .office import extract_rtf
        adopt(extract_rtf(data, name, limits, budget, depth))
    elif family == "ole":
        from .office import extract_ole_strings
        ext = os.path.splitext(name)[1].lower().lstrip(".") or "ole"
        adopt(extract_ole_strings(data, name, limits, budget, depth, kind=ext))
        # パスワード保護された OOXML は OLE コンテナに包まれる。中身は検査できない
        if "EncryptedPackage".encode("utf-16le") in data[:2_000_000] or b"StrongEncryptionDataSpace" in data[:2_000_000]:
            doc.mark("unsupported", "パスワードで暗号化された Office 文書です。内容を検査できません(解除したうえで再スキャンしてください)。")
    elif family == "html":
        from .htmlx import extract_html_bytes
        adopt(extract_html_bytes(data, name, charset_hint=_charset_from_ct(content_type), limits=limits, budget=budget))
    elif family == "eml":
        from .mailx import extract_eml
        adopt(extract_eml(data, name, limits, budget, depth))
    elif family == "zip":
        _from_zip(doc, data, name, limits, budget, depth)
    elif family == "gzip":
        _from_gzip(doc, data, name, limits, budget, depth)
    elif family == "tar":
        _from_tar(doc, data, name, limits, budget, depth)
    elif family == "json":
        _from_json(doc, data, limits)
    elif family == "xml":
        _from_xml(doc, data, limits)
    elif family in ("markdown", "text"):
        _from_text(doc, data, name, family, content_type)
    elif family == "archive7z":
        doc.kind = "archive"
        doc.mark("unsupported", "未対応のアーカイブ形式(7z/rar/xz/bz2)です。展開してから個別にスキャンしてください。判定不能です。")
    elif family == "executable":
        doc.kind = "executable"
        doc.mark("unsupported", "実行ファイルです。テキストとしては解析できません。判定不能です。")
    else:   # binary
        doc.kind = "binary"
        _binary_strings(doc, data, name, limits, budget, depth)


def _charset_from_ct(ct: Optional[str]) -> Optional[str]:
    if not ct:
        return None
    m = re.search(r"charset\s*=\s*([\w\-:.]+)", ct, re.I)
    return m.group(1) if m else None


_OPAQUE_EXT = (".sig", ".asc", ".der", ".cer", ".crt", ".p7s", ".p7b", ".p7m", ".p12", ".pfx", ".jks", ".key", ".pub",
               ".sha256", ".sha1", ".md5", ".mo", ".ttf", ".otf", ".woff", ".woff2", ".ico", ".icc")


def _is_opaque_data(data: bytes, name: str) -> bool:
    """署名・証明書・フォントなど文章にならない形式か(拡張子か DER の先頭で見る)。"""
    n = (name or "").lower()
    if n.endswith(_OPAQUE_EXT):
        return True
    return data[:2] in (b"\x30\x82", b"\x30\x81", b"\x30\x80") and b"\x00" in data[:16]


def _binary_strings(doc: ExtractedDoc, data: bytes, name: str, limits: Limits, budget: Budget, depth: int):
    """形式不明のバイナリ。文字列抽出で見られる分は見るが、判定不能扱いは変えない。"""
    try:
        from .office import extract_ole_strings
        c = extract_ole_strings(data, name, limits, budget, depth, kind="binary")
        doc.text = c.text
        doc.findings.extend(c.findings)
    except Exception:
        pass
    if _is_opaque_data(data, name):
        doc.kind = "binary"
        doc.notes.append("署名・証明書・鍵などの文字を含まないバイナリです(文字列のみ検査しました)。")
        return
    doc.mark("unsupported", "形式を判別できないバイナリです(文字列抽出のみ実施)。判定不能です。")


_MD_COMMENT = re.compile(r"<!--(.*?)(?:-->|\Z)", re.S)
_MD_LINKREF_COMMENT = re.compile(r"^\s*\[(?://|comment|#)\]\s*:\s*(?:#|<>)?\s*[\(\"'<]?(.+?)[\)\"'>]?\s*$", re.M | re.I)
_HTML_HIDING_HINT = re.compile(r"<[a-z][^>]*\b(style\s*=|hidden\b|class\s*=)", re.I)


def _from_text(doc: ExtractedDoc, data: bytes, name: str, family: str, content_type: Optional[str]):
    doc.kind = "markdown" if family == "markdown" else "text"
    text, enc, notes = decode_bytes(data, charset_hint=_charset_from_ct(content_type))
    doc.encoding = enc
    doc.text = text
    doc.notes.extend(notes)
    if "(replace)" in enc:
        doc.mark("partial")
    # 文字コード推定が外れたときの見逃し対策。別のコードで読んだ版も照合する
    if enc not in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "iso2022_jp") and not isinstance(data, str):
        try:
            from .encoding import alternative_decodings
            alts = alternative_decodings(data, enc)
            for aenc, atext in alts[: (14 if len(data) <= 300_000 else 3)]:
                if atext.strip() and atext != text:
                    doc.hidden_regions.append(HiddenRegion(
                        text=atext, reason=f"{aenc} として読んだ場合", location=f"encoding:{aenc}", kind="reencoded"))
        except Exception:
            pass
    # CSV/TSV のセル数式(DDE、URL 連結での持ち出し)
    if (name or "").lower().endswith((".csv", ".tsv")) and "=" in text:
        try:
            from .formulas import formula_findings
            seen_f = set()
            for ln in text.splitlines()[:5000]:
                if "=" not in ln and "|" not in ln:
                    continue
                for fd in formula_findings(ln, "csv", "csv"):
                    if fd.rule_id not in seen_f:
                        seen_f.add(fd.rule_id)
                        doc.findings.append(fd)
        except Exception:
            pass
    # Markdown に HTML が混ざっている場合の隠し要素
    for m in _MD_COMMENT.finditer(text):
        inner = m.group(1).strip()
        if inner:
            doc.hidden_regions.append(HiddenRegion(
                text=inner, reason="HTML/Markdown コメント(レンダリング時は非表示)",
                location="comment", kind="comment",
                severity="info" if len(inner) < 20 else None))
    for m in _MD_LINKREF_COMMENT.finditer(text):
        inner = m.group(1).strip()
        if len(inner) >= 3:
            doc.hidden_regions.append(HiddenRegion(
                text=inner, reason="Markdown リンク参照コメント(非表示)", location="comment", kind="comment"))
    if "<" in text and _HTML_HIDING_HINT.search(text):
        try:
            from .htmlx import extract_html_text
            tmp = ExtractedDoc(source=doc.source, kind="html")
            extract_html_text(text, tmp)
            seen = {r.text for r in doc.hidden_regions}
            for r in tmp.hidden_regions:
                if r.kind in ("comment",):     # コメントは上で取得済み
                    continue
                if r.text not in seen:
                    doc.hidden_regions.append(r)
            doc.findings.extend(f for f in tmp.findings if f.rule_id.startswith("html_js"))
        except Exception:
            pass


def _from_json(doc: ExtractedDoc, data: bytes, limits: Limits):
    doc.kind = "json"
    text, enc, notes = decode_bytes(data)
    doc.encoding = enc
    doc.notes.extend(notes)
    try:
        obj = json.loads(text)
    except Exception as e:  # noqa
        doc.text = text
        doc.notes.append(f"JSON として解析できなかったためテキストとして走査しました: {e}")
        return
    out: List[str] = []
    count = 0

    def walk(o, depth=0):
        nonlocal count
        if depth > 200 or count > 200000:
            return
        count += 1
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and len(k) > 12:
                    out.append(k)
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                walk(v, depth + 1)

    walk(obj)
    doc.text = "\n".join(out)         # \uXXXX エスケープはデコード済みの値になる
    if count > 200000:
        doc.mark("partial", "JSON が大きいため一部のみ走査しました。")


_XML_COMMENT = re.compile(rb"<!--(.*?)-->", re.S)


def _from_xml(doc: ExtractedDoc, data: bytes, limits: Limits):
    doc.kind = "xml"
    try:
        root = parse_xml(data, limits)
    except UnsafeInput as e:
        doc.mark("partial", f"XML を安全のため構文解析せず、テキストとして走査します: {e}")
        text, enc, notes = decode_bytes(data)
        # ENTITY 定義に命令文を隠せるので、タグは剥がさず生のまま走査
        doc.text = text.replace("<", " <").replace(">", "> ")
        doc.encoding = enc
        doc.findings.append(Finding(
            rule_id="xml_unsafe_entities", category="active_content", severity="medium",
            description="XML に ENTITY/DOCTYPE 内部サブセットがあります(XXE/XML爆弾、またはエンティティ展開で内容を隠す手口の疑い)",
            snippet=text[:120].replace("\n", " "), location="xml"))
        return
    except Exception as e:  # noqa
        text, enc, notes = decode_bytes(data)
        doc.text = text
        doc.encoding = enc
        doc.notes.append(f"XML として解析できなかったためテキストとして走査しました: {e}")
        return
    parts: List[str] = []
    for el in root.iter():
        if el.text and el.text.strip():
            parts.append(el.text.strip())
        if el.tail and el.tail.strip():
            parts.append(el.tail.strip())
        for k, v in el.attrib.items():
            if isinstance(v, str) and len(v) >= 20 and " " in v:
                doc.hidden_regions.append(HiddenRegion(
                    text=v, reason=f"属性 {localname(k)}", location=localname(el.tag), kind="attribute"))
    doc.text = "\n".join(parts)
    for m in _XML_COMMENT.finditer(data):
        inner, _, _ = decode_bytes(m.group(1))
        inner = inner.strip()
        if inner:
            doc.hidden_regions.append(HiddenRegion(text=inner, reason="XML コメント", location="comment", kind="comment",
                                                   severity="info" if len(inner) < 20 else None))


# アーカイブ
def _child(doc: ExtractedDoc, data: bytes, member: str, limits: Limits, budget: Budget, depth: int):
    c = extract_from_bytes(data, name=member, limits=limits, budget=budget, depth=depth + 1,
                           source=f"{doc.source}!{member}")
    doc.merge(c, prefix=member)
    return c


_UNSAFE_NAME = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)|^[\\/]|^[A-Za-z]:[\\/]|\x00")


def _check_member_names(doc: ExtractedDoc, names, where: str):
    """展開先の外へ書き出される名前(zip slip、絶対パス)を警告。"""
    bad = [n for n in names if _UNSAFE_NAME.search(n or "")]
    if bad:
        doc.findings.append(Finding(
            rule_id="archive_path_traversal", category="active_content", severity="medium",
            description="アーカイブ内に展開先の外へ書き出すパス(../ や絶対パス)があります(zip slip)",
            snippet=" | ".join(b[:80] for b in bad[:3]), location=where))


def _from_zip(doc: ExtractedDoc, data: bytes, name: str, limits: Limits, budget: Budget, depth: int):
    doc.kind = "zip"
    zf = open_zip(data, limits)
    members = [i for i in zf.infolist() if not i.is_dir()]
    names = [i.filename for i in members]
    _check_member_names(doc, names, "zip")
    if names:
        doc.hidden_regions.append(HiddenRegion(
            text=" / ".join(names[:200]), reason="zip内のファイル名一覧", location="zip", kind="metadata", severity="info"))
    if zf.comment:
        c, _, _ = decode_bytes(zf.comment)
        if c.strip():
            doc.hidden_regions.append(HiddenRegion(text=c.strip(), reason="zip コメント", location="zip", kind="metadata"))
    total = 0
    for info in members:
        budget.check()
        if info.flag_bits & 0x1:
            doc.mark("unsupported", f"暗号化されたファイルは検査できません: {info.filename}")
            if not any(f.rule_id == "archive_encrypted" for f in doc.findings):
                doc.findings.append(Finding(
                    rule_id="archive_encrypted", category="hidden_content", severity="medium",
                    description="パスワード付きのアーカイブです(中身を検査できません。パスワードを本文で伝えて展開させる手口に注意)",
                    snippet=info.filename, location="zip"))
            continue
        try:
            raw = read_member(zf, info.filename, limits)
        except UnsafeInput as e:
            doc.mark("partial", str(e))
            continue
        except Exception as e:  # noqa
            doc.mark("partial", f"{info.filename} を読めません: {e}")
            continue
        total += len(raw)
        if total > limits.max_total_bytes:
            doc.mark("partial", "展開サイズの合計が上限を超えたため残りは解析しません。")
            break
        _child(doc, raw, info.filename, limits, budget, depth)


def _from_gzip(doc: ExtractedDoc, data: bytes, name: str, limits: Limits, budget: Budget, depth: int):
    doc.kind = "gzip"
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
            raw = g.read(limits.max_member_bytes + 1)
    except Exception as e:  # noqa
        doc.mark("failed", f"gzip を展開できません: {e}")
        return
    if len(raw) > limits.max_member_bytes:
        raw = raw[:limits.max_member_bytes]
        doc.mark("partial", "gzip の展開サイズが上限を超えたため先頭のみ解析します。")
    inner_name = name[:-3] if name.lower().endswith(".gz") else name
    if inner_name.lower().endswith(".tgz"):
        inner_name = inner_name[:-4] + ".tar"
    c = extract_from_bytes(raw, name=inner_name, limits=limits, budget=budget, depth=depth + 1, source=doc.source)
    doc.kind = f"gzip>{c.kind}"
    doc.text = c.text
    doc.findings.extend(c.findings)
    doc.hidden_regions.extend(c.hidden_regions)
    doc.notes.extend(c.notes)
    doc.encoding = c.encoding
    doc.mark(c.status)


def _from_tar(doc: ExtractedDoc, data: bytes, name: str, limits: Limits, budget: Budget, depth: int):
    doc.kind = "tar"
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data))
    except Exception as e:  # noqa
        doc.mark("failed", f"tar を開けません: {e}")
        return
    total = 0
    n = 0
    names = []
    with tf:
        for m in tf:
            budget.check()
            if not m.isfile():
                continue
            n += 1
            if n > limits.max_members:
                doc.mark("partial", "tar 内のファイル数が多いため残りは解析しません。")
                break
            names.append(m.name)
            if m.size > limits.max_member_bytes:
                doc.mark("partial", f"{m.name} は大きいため解析しません。")
                continue
            total += m.size
            if total > limits.max_total_bytes:
                doc.mark("partial", "展開サイズの合計が上限を超えたため残りは解析しません。")
                break
            f = tf.extractfile(m)
            if f is None:
                continue
            _child(doc, f.read(limits.max_member_bytes + 1), m.name, limits, budget, depth)
    _check_member_names(doc, names, "tar")
    if names:
        doc.hidden_regions.append(HiddenRegion(
            text=" / ".join(names[:200]), reason="tar内のファイル名一覧", location="tar", kind="metadata", severity="info"))
