"""Office 系ドキュメントの抽出。標準ライブラリのみ。

OOXML / ODF / EPUB / RTF / 旧形式 OLE(OLE は文字列抽出のベストエフォート)。
見えるテキストは ExtractedDoc.text、見えないものは hidden_regions に分け、同じ文字列を両方に入れない。
公開関数は例外を投げない。失敗や部分解析は doc.status / doc.notes に出す。zip/XML は safeio 経由で読む。
"""
from __future__ import annotations

import hashlib
import posixpath
import re
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .encoding import decode_bytes
from .formulas import formula_findings
from .model import ExtractedDoc, Finding, HiddenRegion
from .safeio import (Budget, BudgetExceeded, Limits, UnsafeInput, localname,
                     open_zip, parse_xml, read_member)

__all__ = [
    "extract_ooxml", "extract_odf", "extract_epub", "extract_rtf", "extract_ole_strings",
]

_HEX6 = re.compile(r"^[0-9A-Fa-f]{6}$")
_HEX8 = re.compile(r"^[0-9A-Fa-f]{8}$")


class _Truncated(Exception):
    """文字数の上限に達した。"""


def _new_doc(name: str, data: bytes, kind: str) -> ExtractedDoc:
    doc = ExtractedDoc(source=name, kind=kind)
    doc.size = len(data) if data is not None else 0
    try:
        doc.sha256 = hashlib.sha256(data or b"").hexdigest()
    except Exception:  # pragma: no cover
        pass
    return doc


def _attr(el, name: str) -> Optional[str]:
    if el is None:
        return None
    for k, v in el.attrib.items():
        if k.rsplit("}", 1)[-1] == name:
            return v
    return None


def _rid(el) -> Optional[str]:
    """r:id だけ拾う。sldId の素の id 属性と混ざらないよう、名前空間付きのみ見る。"""
    if el is None:
        return None
    for k, v in el.attrib.items():
        if k.startswith("{") and k.endswith("}id"):
            return v
    return None


def _child(el, name: str):
    if el is None:
        return None
    for ch in el:
        if localname(ch.tag) == name:
            return ch
    return None


def _children(el, name: str) -> Iterator:
    if el is None:
        return
    for ch in el:
        if localname(ch.tag) == name:
            yield ch


def _desc(el, name: str) -> Iterator:
    for e in el.iter():
        if localname(e.tag) == name:
            yield e


def _rgb_channels(val: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not val:
        return None
    v = val.strip().lstrip("#")
    if _HEX8.match(v):          # AARRGGBB
        v = v[2:]
    if _HEX6.match(v):
        return int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16)
    return None


def _is_whiteish(val: Optional[str], threshold: int = 0xF0) -> bool:
    c = _rgb_channels(val)
    return bool(c) and all(x >= threshold for x in c)


def _luminance(c: Tuple[int, int, int]) -> float:
    return (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255.0


def _is_dark_fill(val: Optional[str]) -> bool:
    c = _rgb_channels(val)
    return bool(c) and _luminance(c) < 0.6


class _Out:
    """見えるテキストの行と隠し領域を組み立てる。同じ種類が続く隠し領域は結合する。"""

    def __init__(self, doc: ExtractedDoc, limits: Limits, budget: Budget):
        self.doc = doc
        self.limits = limits
        self.budget = budget
        self.lines: List[str] = []
        self.chars = 0
        self._pending: Optional[list] = None   # [key, location, parts]
        self._n = 0
        self.loc = ""

    def _tick(self):
        self._n += 1
        if self._n % 128 == 0:
            self.budget.check()

    def visible(self, text: Optional[str]):
        self._tick()
        if not text or not text.strip():
            return
        self.flush()
        self.chars += len(text)
        if self.chars > self.limits.max_text_chars:
            raise _Truncated()
        self.lines.append(text)
        self.doc.units.append((self.loc, text))

    def hidden(self, text: Optional[str], reason: str, kind: str = "hidden",
               location: Optional[str] = None, severity: Optional[str] = None,
               new_para: bool = True, sep: str = ""):
        self._tick()
        if not text or not text.strip():
            return
        self.chars += len(text)
        if self.chars > self.limits.max_text_chars * 2:
            raise _Truncated()
        key = (reason, kind, severity)
        p = self._pending
        if p is not None and p[0] == key:
            if new_para or not p[2]:
                p[2].append(text)
            else:
                p[2][-1] = p[2][-1] + sep + text
            return
        self.flush()
        self._pending = [key, location if location is not None else self.loc, [text]]

    def flush(self):
        p = self._pending
        if p is None:
            return
        self._pending = None
        (reason, kind, severity), loc, parts = p
        text = "\n".join(parts)
        if text.strip():
            self.doc.hidden_regions.append(
                HiddenRegion(text=text, reason=reason, location=loc, kind=kind, severity=severity))

    def region(self, text: Optional[str], reason: str, kind: str, location: Optional[str] = None,
               severity: Optional[str] = None):
        """結合しない版。"""
        self._tick()
        if not text or not text.strip():
            return
        self.chars += len(text)
        if self.chars > self.limits.max_text_chars * 2:
            raise _Truncated()
        self.doc.hidden_regions.append(HiddenRegion(
            text=text, reason=reason, location=location if location is not None else self.loc,
            kind=kind, severity=severity))

    def finish(self) -> str:
        self.flush()
        return "\n".join(self.lines)


def _parse_part(zf, name: str, doc: ExtractedDoc, limits: Limits, optional: bool = False):
    """失敗したら notes に残して partial にし、None を返す。"""
    try:
        data = read_member(zf, name, limits)
        return parse_xml(data, limits)
    except KeyError:
        if not optional:
            doc.mark("partial", f"{name} が見つかりません。")
        return None
    except UnsafeInput as e:
        doc.mark("partial", f"{name} を安全上の理由でスキップしました: {e}")
        return None
    except ET.ParseError as e:
        doc.mark("partial", f"{name} のXMLが壊れています: {e}")
        return None
    except BudgetExceeded:
        raise
    except RecursionError:
        doc.mark("partial", f"{name} の入れ子が深すぎます。")
        return None
    except Exception as e:  # noqa
        doc.mark("partial", f"{name} の読込みに失敗: {type(e).__name__}: {e}")
        return None


def _rels(zf, names_set, part: str, doc, limits) -> Dict[str, dict]:
    """{rId: {target, type, external}}。part は 'xl/workbook.xml' のような名前。"""
    d, b = posixpath.split(part)
    rp = posixpath.join(d, "_rels", b + ".rels")
    out: Dict[str, dict] = {}
    if rp not in names_set:
        return out
    root = _parse_part(zf, rp, doc, limits, optional=True)
    if root is None:
        return out
    for r in root:
        if localname(r.tag) != "Relationship":
            continue
        rid = r.get("Id") or ""
        tgt = r.get("Target") or ""
        typ = (r.get("Type") or "").rsplit("/", 1)[-1]
        ext = (r.get("TargetMode") or "").lower() == "external"
        if not ext:
            tgt = tgt.lstrip("/") if tgt.startswith("/") else posixpath.normpath(posixpath.join(d, tgt))
        out[rid] = {"target": tgt, "type": typ, "external": ext}
    return out


def _all_text(el, names: Iterable[str]) -> str:
    wanted = set(names)
    return "".join(e.text or "" for e in el.iter() if localname(e.tag) in wanted)


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$")
_APP_SKIP = {
    "Application", "AppVersion", "DocSecurity", "TotalTime", "Pages", "Words", "Characters", "Lines",
    "Paragraphs", "CharactersWithSpaces", "ScaleCrop", "LinksUpToDate", "SharedDoc", "HyperlinksChanged",
    "Slides", "Notes", "HiddenSlides", "MMClips", "PresentationFormat", "Template", "TitlesOfParts",
    "HeadingPairs", "revision", "created", "modified", "lastPrinted", "contentStatus", "language", "version",
}


def _meta_ok(val: str) -> bool:
    v = val.strip()
    if len(v) < 4:
        return False
    if v.replace(".", "").replace("-", "").replace(" ", "").isdigit():
        return False
    return not _DATE_RE.match(v)


def _doc_props(zf, names_set, out: _Out, doc, limits):
    """docProps/* と customXml/* のメタデータ。"""
    for part in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        if part not in names_set:
            continue
        root = _parse_part(zf, part, doc, limits, optional=True)
        if root is None:
            continue
        if part.endswith("custom.xml"):
            for prop in _children(root, "property"):
                pname = prop.get("name") or ""
                val = "".join(e.text or "" for e in prop.iter() if e is not prop)
                if _meta_ok(val):
                    out.region(val, f"カスタムプロパティ({pname})", "metadata", part)
            continue
        for ch in root:
            tag = localname(ch.tag)
            if tag in _APP_SKIP or len(ch):
                continue
            val = ch.text or ""
            if _meta_ok(val):
                out.region(val, f"文書プロパティ({tag})", "metadata", part)
    for n in sorted(names_set):
        if not (n.startswith("customXml/") and n.endswith(".xml")):
            continue
        base = posixpath.basename(n)
        if base.startswith("itemProps") or "/_rels/" in n:
            continue
        root = _parse_part(zf, n, doc, limits, optional=True)
        if root is None:
            continue
        txt = " ".join(t.strip() for e in root.iter() if (t := e.text) and t.strip())
        if _meta_ok(txt):
            out.region(txt, "カスタムXML(文書に埋め込まれたデータ)", "metadata", n)


_FORMULA_LITERAL = re.compile(r'"((?:[^"]|"")*)"')


def _formula_literals(f: str) -> str:
    """数式中の文字列リテラルをつなぐ。="a"&"b" なら ab。"""
    return "".join(m.group(1).replace('""', '"') for m in _FORMULA_LITERAL.finditer(f or ""))


def _ooxml_structural(zf, names_set, doc: ExtractedDoc, fmt: str, limits: Limits):
    """マクロ、埋込み、外部参照あたり。"""
    names = sorted(names_set)
    for n in names:
        low = n.lower()
        if low.endswith("vbaproject.bin"):
            doc.findings.append(Finding(
                rule_id=f"{fmt}_macro", category="active_content", severity="medium",
                description="VBAマクロを含むファイルです(実行されると任意コード実行の恐れ)",
                snippet=n, location=n))
        elif "/macrosheets/" in low:
            doc.findings.append(Finding(
                rule_id=f"{fmt}_xlm_macro", category="active_content", severity="medium",
                description="Excel 4.0 マクロシートを含んでいます", snippet=n, location=n))
        elif "/embeddings/" in low:
            doc.findings.append(Finding(
                rule_id=f"{fmt}_embedded_object", category="hidden_content", severity="low",
                description="埋め込みオブジェクト(別ファイル)を含んでいます", snippet=n, location=n))
        elif "/activex/" in low and not low.endswith(".rels"):
            doc.findings.append(Finding(
                rule_id=f"{fmt}_activex", category="active_content", severity="low",
                description="ActiveX コントロールを含んでいます", snippet=n, location=n))
    links: List[str] = []
    for n in names:
        if not n.endswith(".rels"):
            continue
        root = _parse_part(zf, n, doc, limits, optional=True)
        if root is None:
            continue
        for r in root:
            if localname(r.tag) != "Relationship":
                continue
            if (r.get("TargetMode") or "").lower() != "external":
                continue
            typ = (r.get("Type") or "").rsplit("/", 1)[-1]
            tgt = r.get("Target") or ""
            if typ == "attachedTemplate":
                doc.findings.append(Finding(
                    rule_id=f"{fmt}_remote_template", category="active_content", severity="medium",
                    description="外部のテンプレートを参照しています(リモートテンプレート注入の恐れ)",
                    snippet=tgt[:200], location=n))
            elif typ == "oleObject":
                doc.findings.append(Finding(
                    rule_id=f"{fmt}_external_ole", category="active_content", severity="info",
                    description="外部のOLEオブジェクトを参照しています", snippet=tgt[:200], location=n))
            elif typ == "hyperlink":
                links.append(tgt)
            elif typ in ("externalLink", "externalLinkPath", "oleLink", "frame", "subDocument", "image"):
                doc.findings.append(Finding(
                    rule_id=f"{fmt}_external_reference", category="hidden_content", severity="info",
                    description=f"外部リソースへの参照({typ})", snippet=tgt[:200], location=n))
    if links:
        doc.findings.append(Finding(
            rule_id=f"{fmt}_hyperlinks", category="hidden_content", severity="info",
            description=f"外部ハイパーリンクが {len(links)} 件あります",
            snippet=" | ".join(l[:80] for l in links[:5]), location="rels"))


_EMBED_OK_EXT = (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".pdf", ".txt", ".html", ".htm",
                 ".rtf", ".odt", ".ods", ".odp", ".csv", ".md", ".xml", ".json")


def _embedded(zf, names_set, doc: ExtractedDoc, limits: Limits, budget: Budget, depth: int):
    """埋込みファイルは再帰で見る。深さと件数に上限あり。"""
    cands = [n for n in sorted(names_set) if "/embeddings/" in n and not n.endswith("/")]
    if not cands:
        return
    if depth + 1 > limits.max_depth:
        doc.mark("partial", "埋め込みファイルは深さ上限のためスキャンしていません。")
        return
    try:
        from .extractors import extract_from_bytes  # type: ignore
    except Exception:
        extract_from_bytes = None
    for n in cands[:20]:
        budget.check()
        base = posixpath.basename(n)
        try:
            data = read_member(zf, n, limits)
        except Exception as e:  # noqa
            doc.mark("partial", f"{n} を読めません: {e}")
            continue
        try:
            if base.lower().endswith(".bin") or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                child = extract_ole_strings(data, base, limits, budget, depth=depth + 1)
            elif extract_from_bytes is not None and base.lower().endswith(_EMBED_OK_EXT):
                child = extract_from_bytes(data, base, limits, budget, depth + 1)
            else:
                continue
        except BudgetExceeded:
            raise
        except Exception as e:  # noqa
            doc.mark("partial", f"埋め込み {base} の解析に失敗: {e}")
            continue
        doc.merge(child, prefix=f"embedded:{base}")
    if len(cands) > 20:
        doc.mark("partial", f"埋め込みファイルが多いため先頭20件のみ解析しました({len(cands)}件)。")


# DOCX
_WHITE_THEMES = {"bg1", "background1", "window", "lt1", "light1"}


def _rpr_props(rpr) -> dict:
    props: dict = {}
    if rpr is None:
        return props
    for ch in rpr:
        ln = localname(ch.tag)
        if ln in ("vanish", "webHidden", "specVanish"):
            props[ln] = (_attr(ch, "val") or "1").lower() not in ("0", "false", "off")
        elif ln == "sz":
            v = _attr(ch, "val")
            if v and v.isdigit():
                props["sz"] = int(v)
        elif ln == "color":
            props["color"] = _attr(ch, "val")
            props["themeColor"] = _attr(ch, "themeColor")
            props["themeShade"] = _attr(ch, "themeShade")
        elif ln == "highlight":
            props["highlight"] = (_attr(ch, "val") or "").lower()
        elif ln == "shd":
            props["shd"] = _attr(ch, "fill")
        elif ln == "rStyle":
            props["rStyle"] = _attr(ch, "val")
    return props


class _DocxStyles:
    def __init__(self, root):
        self.defaults: dict = {}
        self.styles: Dict[str, dict] = {}
        self.default_para: Optional[str] = None
        self._memo: Dict[str, dict] = {}
        if root is None:
            return
        dd = _child(root, "docDefaults")
        if dd is not None:
            self.defaults = _rpr_props(_child(_child(dd, "rPrDefault"), "rPr"))
        for s in _children(root, "style"):
            sid = _attr(s, "styleId")
            if not sid:
                continue
            based = _attr(_child(s, "basedOn"), "val")
            self.styles[sid] = {"based": based, "props": _rpr_props(_child(s, "rPr"))}
            if (_attr(s, "type") == "paragraph") and (_attr(s, "default") or "").lower() in ("1", "true"):
                self.default_para = sid

    def resolve(self, sid: Optional[str], depth: int = 0) -> dict:
        if not sid or sid not in self.styles or depth > 20:
            return {}
        if sid in self._memo:
            return self._memo[sid]
        st = self.styles[sid]
        merged = dict(self.resolve(st["based"], depth + 1))
        merged.update(st["props"])
        self._memo[sid] = merged
        return merged

    def para_props(self, pstyle: Optional[str]) -> dict:
        base = dict(self.defaults)
        base.update(self.resolve(pstyle or self.default_para))
        return base

    def effective(self, para_props: dict, direct: dict) -> dict:
        eff = dict(para_props)
        rs = direct.get("rStyle")
        if rs:
            eff.update(self.resolve(rs))
        eff.update(direct)
        return eff


def _docx_hidden_reason(props: dict, bg_fill: Optional[str]) -> Optional[str]:
    if props.get("vanish"):
        return "隠し文字属性(vanish)"
    if props.get("specVanish"):
        return "隠し文字属性(specVanish)"
    if props.get("webHidden"):
        return "Web表示で非表示(webHidden)"
    sz = props.get("sz")
    if sz is not None and sz <= 4:
        return "極小フォント(2pt以下)"
    color = props.get("color")
    theme = (props.get("themeColor") or "").lower()
    white = _is_whiteish(color)
    if not white and theme in _WHITE_THEMES and not props.get("themeShade") \
            and (color in (None, "auto") or _rgb_channels(color) is None):
        white = True
    if white:
        hl = props.get("highlight")
        if hl and hl not in ("white", "none"):
            return None                       # 色付きハイライト上なら読める
        fill = props.get("shd") or bg_fill
        if fill and fill.lower() != "auto" and _is_dark_fill(fill):
            return None                       # 暗い背景上の白文字は正当
        return "白色(背景同化)の文字"
    return None


_COMMON_FIELDS = re.compile(
    r"^\s*(PAGE|NUMPAGES|NUMWORDS|TOC|HYPERLINK|REF|PAGEREF|SEQ|DATE|TIME|STYLEREF|MERGEFIELD|"
    r"FILENAME|AUTHOR|TITLE|SUBJECT|XE|TC|SECTION|SECTIONPAGES|CREATEDATE|SAVEDATE|PRINTDATE|"
    r"EDITTIME|SYMBOL|INCLUDEPICTURE|NOTEREF|ADDIN|DOCPROPERTY)\b", re.I)


def _para_runs(el) -> Iterator[Tuple[ET.Element, bool]]:
    """(run, 変更履歴で削除済みか) を文書順に返す。"""
    for ch in el:
        ln = localname(ch.tag)
        if ln == "r":
            yield ch, False
        elif ln in ("del", "moveFrom"):
            for r, _ in _para_runs(ch):
                yield r, True
        elif ln in ("hyperlink", "ins", "moveTo", "smartTag", "fldSimple", "sdt", "sdtContent",
                    "customXml", "dir", "bdo"):
            yield from _para_runs(ch)
        elif ln == "AlternateContent":
            choice = _child(ch, "Choice")
            if choice is None:
                choice = _child(ch, "Fallback")
            if choice is not None:
                yield from _para_runs(choice)


def _scan_drawing(el) -> Iterator[Tuple[str, object]]:
    """図形の代替テキスト ('alt') とテキストボックス ('txbx') を拾う。"""
    for ch in el:
        ln = localname(ch.tag)
        if ln == "AlternateContent":
            choice = _child(ch, "Choice")
            if choice is None:
                choice = _child(ch, "Fallback")
            if choice is not None:
                yield from _scan_drawing(choice)
        elif ln == "txbxContent":
            yield "txbx", ch
        else:
            if ln in ("docPr", "cNvPr"):
                for a in ("descr", "title"):
                    v = _attr(ch, a)
                    if v and v.strip():
                        yield "alt", v
            elif ln in ("shape", "rect", "oval", "roundrect", "imagedata", "group"):
                v = _attr(ch, "alt")
                if v and v.strip():
                    yield "alt", v
            yield from _scan_drawing(ch)


_DOCX_CONTAINERS = {
    "body", "hdr", "ftr", "footnote", "endnote", "footnotes", "endnotes", "txbxContent", "sdtContent",
    "customXml", "ins", "del", "moveTo", "moveFrom", "docParts", "docPart", "docPartBody", "document",
    "glossaryDocument", "tc",
}


class _DocxCtx:
    def __init__(self, styles: _DocxStyles):
        self.styles = styles
        self.alt_seen: set = set()


def _docx_para(p, ctx: _DocxCtx, out: _Out, cell_fill: Optional[str]):
    ppr = _child(p, "pPr")
    pstyle = None
    pfill = None
    if ppr is not None:
        pstyle = _attr(_child(ppr, "pStyle"), "val")
        pfill = _attr(_child(ppr, "shd"), "fill")
    bg = pfill or cell_fill
    base = ctx.styles.para_props(pstyle)
    vis: List[str] = []
    first_hidden = True
    extras: List[Tuple[str, object]] = []
    for run, deleted in _para_runs(p):
        rpr = _child(run, "rPr")
        direct = _rpr_props(rpr)
        props = ctx.styles.effective(base, direct)
        reason = _docx_hidden_reason(props, bg)
        text_parts: List[str] = []
        del_parts: List[str] = []
        for ch in run:
            ln = localname(ch.tag)
            if ln == "t":
                text_parts.append(ch.text or "")
            elif ln == "delText":
                del_parts.append(ch.text or "")
            elif ln == "tab":
                text_parts.append("\t")
            elif ln in ("br", "cr"):
                text_parts.append("\n")
            elif ln == "noBreakHyphen":
                text_parts.append("-")
            elif ln == "instrText":
                ins = ch.text or ""
                if len(ins.strip()) >= 20 and not _COMMON_FIELDS.match(ins):
                    out.region(ins.strip(), "フィールドコード", "attribute", out.loc)
            elif ln in ("drawing", "pict", "object", "AlternateContent", "ruby"):
                extras.extend(_scan_drawing([ch]))
        if deleted and text_parts:
            del_parts = text_parts + del_parts
            text_parts = []
        dtxt = "".join(del_parts)
        if dtxt.strip():
            out.hidden(dtxt, "変更履歴で削除されたテキスト", "deleted", out.loc, None, new_para=True)
        txt = "".join(text_parts)
        if not txt:
            continue
        if reason:
            out.hidden(txt, reason, "hidden", out.loc, None, new_para=first_hidden)
            first_hidden = False
        else:
            vis.append(txt)
    out.visible("".join(vis))
    seen_txbx = set()
    for kind, obj in extras:
        if kind == "alt":
            key = obj
            if key in ctx.alt_seen:
                continue
            ctx.alt_seen.add(key)
            out.region(obj, "画像・図形の代替テキスト", "attribute", out.loc)
        elif kind == "txbx" and id(obj) not in seen_txbx:
            seen_txbx.add(id(obj))
            _docx_blocks(obj, ctx, out, bg)


def _docx_blocks(el, ctx: _DocxCtx, out: _Out, fill: Optional[str] = None, depth: int = 0):
    if depth > 80:
        raise RecursionError("block nesting")
    for ch in el:
        ln = localname(ch.tag)
        if ln == "p":
            _docx_para(ch, ctx, out, fill)
        elif ln == "tbl":
            for tr in _children(ch, "tr"):
                for tc in _children(tr, "tc"):
                    tcpr = _child(tc, "tcPr")
                    cf = _attr(_child(tcpr, "shd"), "fill") if tcpr is not None else None
                    _docx_blocks(tc, ctx, out, cf or fill, depth + 1)
        elif ln == "sdt":
            content = _child(ch, "sdtContent")
            if content is not None:
                _docx_blocks(content, ctx, out, fill, depth + 1)
        elif ln == "AlternateContent":
            choice = _child(ch, "Choice")
            if choice is None:
                choice = _child(ch, "Fallback")
            if choice is not None:
                _docx_blocks(choice, ctx, out, fill, depth + 1)
        elif ln in _DOCX_CONTAINERS:
            _docx_blocks(ch, ctx, out, fill, depth + 1)


def _plain_paras(el) -> str:
    lines = []
    for p in _desc(el, "p"):
        t = "".join(x.text or "" for x in p.iter() if localname(x.tag) in ("t", "delText"))
        if t.strip():
            lines.append(t)
    return "\n".join(lines)


def _num_key(n: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", n)]


def _docx_extras(zf, names_set, main_part: str, doc: ExtractedDoc, out: _Out, limits: Limits, budget: Budget):
    """ブックマーク名、リンクのツールチップと宛先、コンテンツコントロール名、altChunk の埋込み HTML。"""
    root = _parse_part(zf, main_part, doc, limits)
    if root is None:
        return
    rels = _rels(zf, names_set, main_part, doc, limits)
    out.loc = "本文"
    for el in root.iter():
        ln = localname(el.tag)
        if ln == "bookmarkStart":
            nm = _attr(el, "name") or ""
            if not nm.startswith("_") and nm.count("_") >= 2 and len(nm) >= 12:
                out.region(nm.replace("_", " "), "ブックマーク名", "attribute")
        elif ln == "hyperlink":
            tip = _attr(el, "tooltip")
            if tip and tip.strip():
                out.region(tip, "ハイパーリンクのツールチップ", "attribute")
            r = rels.get(_rid(el) or "")
            if r and r.get("external") and r.get("target"):
                out.region(r["target"], "ハイパーリンクの宛先 URL", "attribute")
        elif ln in ("alias", "tag") and _attr(el, "val") and len(_attr(el, "val") or "") >= 8:
            out.region(_attr(el, "val"), "コンテンツコントロールの名前(alias/tag)", "attribute")
        elif ln == "altChunk":
            r = rels.get(_rid(el) or "")
            if r and not r.get("external") and r["target"] in names_set:
                data = read_member(zf, r["target"], limits)
                child = _html_child(data, r["target"], limits, budget)
                doc.merge(child, prefix="altChunk")
    out.flush()


def _docx(zf, names_set, main_part: str, doc: ExtractedDoc, out: _Out, limits: Limits, budget: Budget):
    styles_root = _parse_part(zf, "word/styles.xml", doc, limits, optional=True) \
        if "word/styles.xml" in names_set else None
    ctx = _DocxCtx(_DocxStyles(styles_root))

    def run_part(part: str, label: str):
        budget.check()
        root = _parse_part(zf, part, doc, limits)
        if root is None:
            return
        out.loc = label
        try:
            _docx_blocks(root, ctx, out)
        except RecursionError:
            doc.mark("partial", f"{part} の入れ子が深すぎるため一部のみ解析しました。")
        out.flush()

    run_part(main_part, "本文")
    try:
        _docx_extras(zf, names_set, main_part, doc, out, limits, budget)
    except BudgetExceeded:
        raise
    except Exception as e:  # noqa
        doc.mark("partial", f"docx の付随属性の解析に失敗: {str(e)[:100]}")
    for n in sorted((x for x in names_set if re.match(r"^word/header\d*\.xml$", x)), key=_num_key):
        run_part(n, "ヘッダー")
    for n in sorted((x for x in names_set if re.match(r"^word/footer\d*\.xml$", x)), key=_num_key):
        run_part(n, "フッター")
    for n, label in (("word/footnotes.xml", "脚注"), ("word/endnotes.xml", "文末脚注")):
        if n in names_set:
            run_part(n, label)

    # コメントは hidden 扱い
    for n in sorted(x for x in names_set if re.match(r"^word/comments[^/]*\.xml$", x)):
        root = _parse_part(zf, n, doc, limits)
        if root is None:
            continue
        for c in _desc(root, "comment"):
            author = _attr(c, "author") or ""
            out.region(_plain_paras(c), f"コメント({author})" if author else "コメント", "annotation", n)
        if "commentsExtended" in n or "commentsIds" in n:
            continue
    # glossary
    for n in sorted(x for x in names_set if x.startswith("word/glossary/") and x.endswith("document.xml")):
        root = _parse_part(zf, n, doc, limits, optional=True)
        if root is not None:
            out.region(_plain_paras(root), "用語集/定型句(glossary)", "hidden", n)


# XLSX
def _col_index(ref: str) -> int:
    m = re.match(r"^([A-Za-z]+)", ref or "")
    if not m:
        return 0
    n = 0
    for ch in m.group(1).upper():
        n = n * 26 + (ord(ch) - 64)
    return n


def _si_text(si) -> str:
    parts: List[str] = []
    for ch in si:
        ln = localname(ch.tag)
        if ln == "t":
            parts.append(ch.text or "")
        elif ln == "r":
            for t in _children(ch, "t"):
                parts.append(t.text or "")
    return "".join(parts)


def _xlsx_styles(root) -> set:
    """白フォントで背景が白か無塗りになるセルスタイルの番号。"""
    white_ids: set = set()
    if root is None:
        return white_ids
    fonts: List[bool] = []
    fonts_el = _child(root, "fonts")
    for f in _children(fonts_el, "font"):
        c = _child(f, "color")
        rgb = _attr(c, "rgb") if c is not None else None
        theme = _attr(c, "theme") if c is not None else None
        fonts.append(_is_whiteish(rgb) or (theme == "0" and not _attr(c, "tint")))
    fills: List[str] = []
    for fl in _children(_child(root, "fills"), "fill"):
        pf = _child(fl, "patternFill")
        ptype = _attr(pf, "patternType") if pf is not None else None
        if ptype in (None, "none", "gray125"):
            fills.append("none")
            continue
        fg = _child(pf, "fgColor")
        rgb = _attr(fg, "rgb") if fg is not None else None
        theme = _attr(fg, "theme") if fg is not None else None
        if _is_whiteish(rgb) or (theme == "0" and not _attr(fg, "tint")):
            fills.append("white")
        else:
            fills.append("colored")
    xfs = _child(root, "cellXfs")
    for i, xf in enumerate(_children(xfs, "xf")):
        fid = _attr(xf, "fontId")
        flid = _attr(xf, "fillId")
        try:
            fw = fonts[int(fid)] if fid is not None else False
            fl = fills[int(flid)] if flid is not None else "none"
        except (ValueError, IndexError):
            continue
        if fw and fl in ("none", "white"):
            white_ids.add(i)
    return white_ids


def _xlsx_sheet_extras(sroot, sheet_rels: dict, sname: str, out: "_Out"):
    """画面に出ない文字。ヘッダ/フッタ、入力規則のメッセージ、リンクのツールチップなど。"""
    for hf in _desc(sroot, "headerFooter"):
        for ch in hf:
            t = re.sub(r"&[A-Za-z0-9\"]+", " ", ch.text or "") if (ch.text or "").strip() else ""
            if t.strip():
                out.region(t.strip(), f"ヘッダ/フッタ({localname(ch.tag)})", "attribute", sname)
    for dv in _desc(sroot, "dataValidation"):
        for a, label in (("prompt", "入力規則の入力時メッセージ"), ("error", "入力規則のエラーメッセージ"),
                         ("promptTitle", "入力規則のタイトル"), ("errorTitle", "入力規則のエラータイトル")):
            v = dv.get(a)
            if v and v.strip():
                out.region(v, label, "attribute", f"{sname}!{dv.get('sqref') or ''}")
    for hl in _desc(sroot, "hyperlink"):
        for a, label in (("tooltip", "ハイパーリンクのツールチップ"), ("display", "ハイパーリンクの表示名")):
            v = hl.get(a)
            if v and v.strip():
                out.region(v, label, "attribute", f"{sname}!{hl.get('ref') or ''}")
        rid = _rid(hl)
        r = sheet_rels.get(rid or "")
        if r and r.get("external") and r.get("target"):
            out.region(r["target"], "ハイパーリンクの宛先 URL", "attribute", f"{sname}!{hl.get('ref') or ''}")


def _xlsx(zf, names_set, main_part: str, doc: ExtractedDoc, out: _Out, limits: Limits, budget: Budget):
    wb = _parse_part(zf, main_part, doc, limits)
    rels = _rels(zf, names_set, main_part, doc, limits)
    wb_dir = posixpath.dirname(main_part)

    shared: List[str] = []
    ss_part = None
    for r in rels.values():
        if r["type"] == "sharedStrings":
            ss_part = r["target"]
    if ss_part is None and posixpath.join(wb_dir, "sharedStrings.xml") in names_set:
        ss_part = posixpath.join(wb_dir, "sharedStrings.xml")
    if ss_part and ss_part in names_set:
        sroot = _parse_part(zf, ss_part, doc, limits)
        if sroot is not None:
            for si in _children(sroot, "si"):
                shared.append(_si_text(si))
                if len(shared) % 5000 == 0:
                    budget.check()
    white_styles: set = set()
    for r in rels.values():
        if r["type"] == "styles" and r["target"] in names_set:
            st_root = _parse_part(zf, r["target"], doc, limits)
            white_styles = _xlsx_styles(st_root)
            for nf in _desc(st_root, "numFmt") if st_root is not None else ():
                lit = _formula_literals(nf.get("formatCode") or "")
                if len(lit.strip()) >= 8:
                    out.region(lit, "セルの表示形式に埋め込まれた文字", "attribute", "styles")

    sheets: List[Tuple[str, str, str]] = []   # (name, state, part)
    if wb is not None:
        for s in _desc(wb, "sheet"):
            rid = _rid(s)
            tgt = rels.get(rid or "", {}).get("target")
            if tgt:
                sheets.append((_attr(s, "name") or "", (_attr(s, "state") or "visible").lower(), tgt))
        # 定義名は文字列リテラルだけ見る
        for dn in _desc(wb, "definedName"):
            lit = _formula_literals(dn.text or "")
            if len(lit.strip()) >= 8:
                out.region(lit, f"定義名({dn.get('name') or ''})の文字列", "attribute", "workbook")
    if not sheets:
        for n in sorted((x for x in names_set if re.match(r"^xl/worksheets/sheet\d+\.xml$", x)), key=_num_key):
            sheets.append((posixpath.basename(n), "visible", n))
        if sheets:
            doc.mark("partial", "workbook.xml からシート一覧を取得できなかったためファイル名順で解析しました。")

    for sname, state, part in sheets:
        budget.check()
        if part not in names_set:
            doc.mark("partial", f"シート {sname} のパーツ {part} がありません。")
            continue
        sroot = _parse_part(zf, part, doc, limits)
        if sroot is None:
            continue
        sheet_hidden = state in ("hidden", "veryhidden")
        if sheet_hidden:
            doc.findings.append(Finding(
                rule_id="xlsx_hidden_sheet", category="hidden_content", severity="low",
                description=f"非表示シート「{sname}」があります(state={state})", snippet=sname,
                location=f"{sname}"))
        out.loc = sname
        if not sheet_hidden:
            out.visible(f"[{sname}]")
        elif len(sname) >= 8:
            out.hidden(sname, "非表示シートの名前", "hidden", sname)
        sheet_rels = _rels(zf, names_set, part, doc, limits)
        _xlsx_sheet_extras(sroot, sheet_rels, sname, out)

        hidden_cols: List[Tuple[int, int]] = []
        for col in _desc(sroot, "col"):
            if (_attr(col, "hidden") or "").lower() in ("1", "true"):
                try:
                    hidden_cols.append((int(col.get("min") or 0), int(col.get("max") or 0)))
                except ValueError:
                    pass

        def col_hidden(ci: int) -> bool:
            return any(a <= ci <= b for a, b in hidden_cols)

        sd = _child(sroot, "sheetData")
        n_cells = 0
        for row in _children(sd, "row"):
            row_hidden = (_attr(row, "hidden") or "").lower() in ("1", "true")
            vis_cells: List[Tuple[int, str]] = []
            first_ref = None
            for c in _children(row, "c"):
                n_cells += 1
                if n_cells % 2000 == 0:
                    budget.check()
                ref = c.get("r") or ""
                t = (c.get("t") or "n")
                v = _child(c, "v")
                f = _child(c, "f")
                text = ""
                if t == "s":
                    try:
                        text = shared[int(v.text)] if v is not None and v.text is not None else ""
                    except (ValueError, IndexError):
                        text = ""
                elif t == "str":
                    text = v.text or "" if v is not None else ""
                elif t == "inlineStr":
                    is_ = _child(c, "is")
                    text = _si_text(is_) if is_ is not None else ""
                if f is not None and f.text:
                    doc.findings.extend(formula_findings(f.text, f"{sname}!{ref}", "xlsx"))
                    lit = _formula_literals(f.text)
                    if len(lit.strip()) >= 8 and lit.strip() != text.strip():
                        out.region(lit, "数式内の文字列リテラル", "attribute", f"{sname}!{ref}")
                if not text or not text.strip():
                    continue
                ci = _col_index(ref)
                style_id = c.get("s")
                reason = None
                if sheet_hidden:
                    reason = f"非表示シート({state})"
                elif row_hidden:
                    reason = "非表示の行"
                elif col_hidden(ci):
                    reason = "非表示の列"
                elif style_id and style_id.isdigit() and int(style_id) in white_styles:
                    reason = "白色フォント(背景同化)のセル"
                if reason:
                    out.hidden(text, reason, "hidden", f"{sname}!{ref}", None, new_para=(first_ref is None), sep=" ")
                    first_ref = first_ref or ref
                else:
                    vis_cells.append((ci, text))
            if vis_cells:
                vis_cells.sort(key=lambda x: x[0])
                out.visible(" ".join(t for _, t in vis_cells))
            first_ref = None
        out.flush()

        for r in sheet_rels.values():
            tgt, typ = r["target"], r["type"]
            if r["external"] or tgt not in names_set:
                continue
            if typ == "comments":
                croot = _parse_part(zf, tgt, doc, limits)
                if croot is None:
                    continue
                for cm in _desc(croot, "comment"):
                    txt_el = _child(cm, "text")
                    txt = _si_text(txt_el) if txt_el is not None else ""
                    out.region(txt, "セルのコメント", "annotation", f"{sname}!{cm.get('ref') or ''}")
            elif typ == "threadedComment":
                croot = _parse_part(zf, tgt, doc, limits)
                if croot is None:
                    continue
                for cm in _desc(croot, "threadedComment"):
                    out.region(_all_text(cm, ("text",)), "スレッドコメント", "annotation",
                               f"{sname}!{cm.get('ref') or ''}")
            elif typ == "drawing":
                droot = _parse_part(zf, tgt, doc, limits)
                if droot is None:
                    continue
                for p in _desc(droot, "p"):
                    txt = "".join(x.text or "" for x in p.iter() if localname(x.tag) == "t")
                    if sheet_hidden:
                        out.hidden(txt, f"非表示シート({state})の図形テキスト", "hidden", sname)
                    else:
                        out.visible(txt)
                for el in droot.iter():
                    if localname(el.tag) == "cNvPr":
                        for a in ("descr", "title"):
                            v = _attr(el, a)
                            if v and v.strip():
                                out.region(v, "図形の代替テキスト", "attribute", sname)
        out.flush()
    # チャート内のテキスト
    for n in sorted(x for x in names_set if re.match(r"^xl/charts/chart[^/]*\.xml$", x)):
        croot = _parse_part(zf, n, doc, limits, optional=True)
        if croot is None:
            continue
        out.loc = n
        for t in _desc(croot, "t"):
            out.visible(t.text)
        for v in _desc(croot, "v"):
            if v.text and not v.text.strip().replace(".", "").replace("-", "").isdigit():
                out.visible(v.text)


# PPTX
def _pp_int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def _xfrm_offscreen(xfrm, sw: Optional[int], sh: Optional[int]) -> bool:
    if xfrm is None or not sw or not sh:
        return False
    off, ext = _child(xfrm, "off"), _child(xfrm, "ext")
    x, y = _pp_int(_attr(off, "x")), _pp_int(_attr(off, "y"))
    cx, cy = _pp_int(_attr(ext, "cx")), _pp_int(_attr(ext, "cy"))
    if None in (x, y, cx, cy):
        return False
    return (x + cx <= 0) or (y + cy <= 0) or (x >= sw) or (y >= sh)


def _pptx_run_reason(rpr) -> Tuple[Optional[str], Optional[str]]:
    """(理由, 重大度)。背景が分からない白文字は low。"""
    if rpr is None:
        return None, None
    sz = _pp_int(rpr.get("sz"))
    if sz is not None and sz <= 400:
        return "極小フォント(4pt以下)", None
    fill = _child(rpr, "solidFill")
    if fill is not None:
        for c in fill:
            ln = localname(c.tag)
            if ln == "srgbClr" and _is_whiteish(c.get("val")):
                return "白色文字(背景不明)", "low"
            if ln == "schemeClr" and (c.get("val") or "").lower() in ("bg1", "lt1"):
                return "白色文字(背景不明)", "low"
    return None, None


_PP_BOILER = re.compile(
    r"click to|master (?:title|text|subtitle)|edit master|(?:first|second|third|fourth|fifth) level|^level \d|クリックして|マスター|"
    r"第\s*\d+\s*レベル|‹#›|bearbeiten|Klicken|Cliquez|Modifier|Haga clic|Modificar|Fare clic|单击|点击|클릭|마스터|"
    r"Cliquer|Clique", re.I)


class _PptxCtx:
    def __init__(self, sw, sh, skip_ph: bool = False):
        self.sw, self.sh, self.skip_ph = sw, sh, skip_ph
        self.alt_seen: set = set()


def _pptx_paras(container, ctx: _PptxCtx, out: _Out, base_reason: Optional[Tuple[str, str, Optional[str]]]):
    """a:p を処理する。表は行ごとにセルを半角スペースでつなぐ。base_reason は (理由, kind, 重大度)。"""
    for ch in container:
        ln = localname(ch.tag)
        if ln == "p":
            _pptx_para(ch, ctx, out, base_reason)
        elif ln == "tbl":
            for tr in _children(ch, "tr"):
                cells_vis: List[str] = []
                for tc in _children(tr, "tc"):
                    tx = _child(tc, "txBody")
                    if tx is None:
                        continue
                    for p in _children(tx, "p"):
                        v = _pptx_para(p, ctx, out, base_reason, collect=True)
                        if v:
                            cells_vis.append(v)
                out.visible(" ".join(cells_vis))
        elif ln in ("txBody", "tc"):
            _pptx_paras(ch, ctx, out, base_reason)


def _pptx_para(p, ctx: _PptxCtx, out: _Out, base_reason, collect: bool = False) -> Optional[str]:
    vis: List[str] = []
    first_hidden = True
    for ch in p:
        ln = localname(ch.tag)
        if ln in ("r", "fld"):
            if ln == "fld" and (ch.get("type") or "").lower().startswith("slidenum"):
                continue
            t = _child(ch, "t")
            text = t.text if t is not None and t.text else ""
            if not text:
                continue
            rpr = _child(ch, "rPr")
            reason, sev = _pptx_run_reason(rpr)
            if base_reason:
                out.hidden(text, base_reason[0], base_reason[1], out.loc, base_reason[2], new_para=first_hidden)
                first_hidden = False
            elif reason:
                out.hidden(text, reason, "hidden", out.loc, sev, new_para=first_hidden)
                first_hidden = False
            else:
                vis.append(text)
        elif ln == "br":
            vis.append("\n")
    line = "".join(vis)
    if collect:
        return line
    out.visible(line)
    return None


def _pptx_alt(nv_el, ctx: _PptxCtx, out: _Out):
    c = _child(nv_el, "cNvPr") if nv_el is not None else None
    if c is None:
        return
    for a in ("descr", "title"):
        v = c.get(a)
        if v and v.strip() and v not in ctx.alt_seen:
            ctx.alt_seen.add(v)
            out.region(v, "図形の代替テキスト", "attribute", out.loc)
    nm = (c.get("name") or "").strip()
    # 「TextBox 3」みたいな既定名は無視。文章っぽい名前だけ拾う
    if len(nm) >= 20 and nm.count(" ") >= 3 and nm not in ctx.alt_seen:
        ctx.alt_seen.add(nm)
        out.region(nm, "図形の名前", "attribute", out.loc)


def _is_placeholder(sp) -> Optional[str]:
    nv = _child(sp, "nvSpPr")
    nvpr = _child(nv, "nvPr") if nv is not None else None
    ph = _child(nvpr, "ph") if nvpr is not None else None
    if ph is None:
        return None
    return ph.get("type") or "body"


def _pptx_walk(el, ctx: _PptxCtx, out: _Out, base_reason, depth: int = 0, top: bool = True,
               ph_filter=None):
    if depth > 60:
        raise RecursionError("shape nesting")
    for ch in el:
        ln = localname(ch.tag)
        if ln == "AlternateContent":
            choice = _child(ch, "Choice")
            if choice is None:
                choice = _child(ch, "Fallback")
            if choice is not None:
                _pptx_walk(choice, ctx, out, base_reason, depth + 1, top, ph_filter)
        elif ln == "sp":
            ph = _is_placeholder(ch)
            if ctx.skip_ph and ph is not None:
                # 「クリックしてタイトルを入力」等の定型文だけ除く
                tx0 = _child(ch, "txBody")
                if tx0 is not None:
                    for p0 in _children(tx0, "p"):
                        t0 = "".join(x.text or "" for x in p0.iter() if localname(x.tag) == "t").strip()
                        if len(t0) >= 12 and not _PP_BOILER.search(t0):
                            out.region(t0, "レイアウト/マスターの文字", "attribute", out.loc)
                continue
            if ph_filter is not None and not ph_filter(ph):
                continue
            _pptx_alt(_child(ch, "nvSpPr"), ctx, out)
            br = base_reason
            if br is None and top and _xfrm_offscreen(_child(_child(ch, "spPr"), "xfrm"), ctx.sw, ctx.sh):
                br = ("スライド外に配置された図形", "offpage", None)
            tx = _child(ch, "txBody")
            if tx is not None:
                _pptx_paras(tx, ctx, out, br)
        elif ln == "pic":
            _pptx_alt(_child(ch, "nvPicPr"), ctx, out)
        elif ln == "cxnSp":
            continue
        elif ln == "graphicFrame":
            _pptx_alt(_child(ch, "nvGraphicFramePr"), ctx, out)
            br = base_reason
            if br is None and top and _xfrm_offscreen(_child(ch, "xfrm"), ctx.sw, ctx.sh):
                br = ("スライド外に配置された図形", "offpage", None)
            for tbl in _desc(ch, "tbl"):
                _pptx_paras([tbl], ctx, out, br)
        elif ln == "grpSp":
            _pptx_alt(_child(ch, "nvGrpSpPr"), ctx, out)
            br = base_reason
            if br is None and top and _xfrm_offscreen(_child(_child(ch, "grpSpPr"), "xfrm"), ctx.sw, ctx.sh):
                br = ("スライド外に配置された図形", "offpage", None)
            _pptx_walk(ch, ctx, out, br, depth + 1, False, ph_filter)
        elif ln in ("spTree", "cSld"):
            _pptx_walk(ch, ctx, out, base_reason, depth + 1, top, ph_filter)


def _pptx(zf, names_set, main_part: str, doc: ExtractedDoc, out: _Out, limits: Limits, budget: Budget):
    pres = _parse_part(zf, main_part, doc, limits)
    rels = _rels(zf, names_set, main_part, doc, limits)
    sw = sh = None
    order: List[str] = []
    if pres is not None:
        sz = next(_desc(pres, "sldSz"), None)
        sw, sh = _pp_int(_attr(sz, "cx")), _pp_int(_attr(sz, "cy"))
        for sid in _desc(pres, "sldId"):
            tgt = rels.get(_rid(sid) or "", {}).get("target")
            if tgt and tgt in names_set:
                order.append(tgt)
    if not order:
        order = sorted((x for x in names_set if re.match(r"^ppt/slides/slide\d+\.xml$", x)), key=_num_key)
        if order:
            doc.mark("partial", "presentation.xml からスライド順を取得できなかったためファイル名順で解析しました。")
    ctx = _PptxCtx(sw, sh)
    chart_seen: set = set()
    for idx, spath in enumerate(order, 1):
        budget.check()
        sroot = _parse_part(zf, spath, doc, limits)
        if sroot is None:
            continue
        out.loc = f"スライド{idx}"
        base = None
        if (sroot.get("show") or "1").lower() in ("0", "false"):
            base = ("非表示スライド", "hidden", "low")
            doc.findings.append(Finding(
                rule_id="pptx_hidden_slide", category="hidden_content", severity="low",
                description=f"非表示スライド(スライド{idx})があります", location=f"スライド{idx}"))
        try:
            _pptx_walk(sroot, ctx, out, base)
        except RecursionError:
            doc.mark("partial", f"{spath} の入れ子が深すぎるため一部のみ解析しました。")
        out.flush()
        srels = _rels(zf, names_set, spath, doc, limits)
        for hl in _desc(sroot, "hlinkClick"):
            tip = _attr(hl, "tooltip")
            if tip and tip.strip():
                out.region(tip, "ハイパーリンクのツールチップ", "attribute", f"スライド{idx}")
            rr = srels.get(_rid(hl) or "")
            if rr and rr.get("external") and rr.get("target"):
                out.region(rr["target"], "ハイパーリンクの宛先 URL", "attribute", f"スライド{idx}")
        for r in srels.values():
            tgt, typ = r["target"], r["type"]
            if r["external"] or tgt not in names_set:
                continue
            if typ == "notesSlide":
                nroot = _parse_part(zf, tgt, doc, limits)
                if nroot is None:
                    continue
                nctx = _PptxCtx(None, None)
                out.loc = f"スライド{idx}のノート"
                _pptx_walk(nroot, nctx, out, ("発表者ノート", "hidden", "low"), 0, True,
                           ph_filter=lambda ph: ph not in ("sldImg", "sldNum", "hdr", "ftr", "dt"))
                out.flush()
            elif typ in ("comments",):
                croot = _parse_part(zf, tgt, doc, limits)
                if croot is not None:
                    for cm in _desc(croot, "cm"):
                        out.region(_all_text(cm, ("text",)) or _all_text(cm, ("t",)),
                                   "スライドのコメント", "annotation", f"スライド{idx}")
            elif typ == "chart":
                _pptx_chart(zf, tgt, doc, out, limits, f"スライド{idx}のグラフ", chart_seen)
        # modern comments
    for n in sorted(x for x in names_set if re.match(r"^ppt/comments/modernComment[^/]*\.xml$", x)):
        croot = _parse_part(zf, n, doc, limits, optional=True)
        if croot is None:
            continue
        for cm in _desc(croot, "cm"):
            out.region(_all_text(cm, ("t",)), "スライドのコメント", "annotation", n)
    # レイアウト/マスター
    mctx = _PptxCtx(sw, sh, skip_ph=True)
    for n in sorted((x for x in names_set if re.match(r"^ppt/(slideLayouts|slideMasters)/[^/]+\.xml$", x)),
                    key=_num_key):
        mroot = _parse_part(zf, n, doc, limits, optional=True)
        if mroot is None:
            continue
        out.loc = posixpath.basename(n)
        try:
            _pptx_walk(mroot, mctx, out, None, 0, False)
        except RecursionError:
            doc.mark("partial", f"{n} の入れ子が深すぎます。")
    # SmartArt
    for n in sorted(x for x in names_set if re.match(r"^ppt/diagrams/data[^/]*\.xml$", x)):
        droot = _parse_part(zf, n, doc, limits, optional=True)
        if droot is None:
            continue
        out.loc = n
        for p in _desc(droot, "p"):
            out.visible("".join(x.text or "" for x in p.iter() if localname(x.tag) == "t"))
    # スライドから参照されていないチャート
    for n in sorted(x for x in names_set if re.match(r"^ppt/charts/chart[^/]*\.xml$", x)):
        _pptx_chart(zf, n, doc, out, limits, n, chart_seen)


def _pptx_chart(zf, part, doc, out, limits, label, seen: set):
    if part in seen:
        return
    seen.add(part)
    croot = _parse_part(zf, part, doc, limits, optional=True)
    if croot is None:
        return
    out.loc = label
    for t in _desc(croot, "t"):
        out.visible(t.text)
    for v in _desc(croot, "v"):
        if v.text and not v.text.strip().replace(".", "").replace("-", "").isdigit():
            out.visible(v.text)


def _detect_ooxml(zf, names_set, doc, limits) -> Tuple[Optional[str], Optional[str]]:
    """(形式, 主パーツ)"""
    main = None
    if "_rels/.rels" in names_set:
        root = _parse_part(zf, "_rels/.rels", doc, limits, optional=True)
        if root is not None:
            for r in root:
                if localname(r.tag) == "Relationship" and (r.get("Type") or "").endswith("/officeDocument"):
                    main = (r.get("Target") or "").lstrip("/")
    for fmt, prefix, default in (("docx", "word/", "word/document.xml"), ("xlsx", "xl/", "xl/workbook.xml"),
                                 ("pptx", "ppt/", "ppt/presentation.xml")):
        if main and main.startswith(prefix) and main in names_set:
            return fmt, main
    for fmt, prefix, default in (("docx", "word/", "word/document.xml"), ("xlsx", "xl/", "xl/workbook.xml"),
                                 ("pptx", "ppt/", "ppt/presentation.xml")):
        if default in names_set:
            return fmt, default
    if "xl/workbook.bin" in names_set:
        return "xlsb", None
    return None, None


def extract_ooxml(data: bytes, name: str = "", limits: Optional[Limits] = None,
                  budget: Optional[Budget] = None, depth: int = 0) -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = _new_doc(name, data, "ooxml")
    try:
        zf = open_zip(data, limits)
    except UnsafeInput as e:
        doc.mark("failed", f"Office ファイルを開けません: {e}")
        return doc
    except Exception as e:  # noqa
        doc.mark("failed", f"Office ファイルを開けません: {type(e).__name__}: {e}")
        return doc
    out = _Out(doc, limits, budget)
    try:
        with zf:
            names_set = set(zf.namelist())
            fmt, main = _detect_ooxml(zf, names_set, doc, limits)
            if fmt is None:
                doc.mark("unsupported", "OOXML(docx/xlsx/pptx)として認識できませんでした。XMLパーツの文字列のみ抽出します。")
                _generic_zip_xml(zf, names_set, doc, out, limits, budget)
            elif fmt == "xlsb":
                doc.kind = "xlsb"
                doc.mark("unsupported", "xlsb(バイナリExcel)は非対応です。")
                _generic_zip_xml(zf, names_set, doc, out, limits, budget)
            else:
                doc.kind = fmt
                try:
                    if fmt == "docx":
                        _docx(zf, names_set, main, doc, out, limits, budget)
                    elif fmt == "xlsx":
                        _xlsx(zf, names_set, main, doc, out, limits, budget)
                    else:
                        _pptx(zf, names_set, main, doc, out, limits, budget)
                except _Truncated:
                    doc.mark("partial", f"抽出テキストが上限({limits.max_text_chars}文字)を超えたため以降を切り捨てました。")
                except RecursionError:
                    doc.mark("partial", "XML の入れ子が深すぎるため一部のみ解析しました。")
                try:
                    _doc_props(zf, names_set, out, doc, limits)
                except _Truncated:
                    pass
                _ooxml_structural(zf, names_set, doc, fmt, limits)
                _embedded(zf, names_set, doc, limits, budget, depth)
    except BudgetExceeded as e:
        doc.mark("partial", f"時間上限のため途中までの解析です: {e}")
    except Exception as e:  # noqa
        doc.mark("partial", f"解析中にエラー: {type(e).__name__}: {e}")
    try:
        txt = out.finish()
    except Exception:  # noqa
        txt = "\n".join(out.lines)
    doc.text = (doc.text + "\n" + txt).strip("\n") if doc.text else txt
    if not doc.text.strip() and not doc.hidden_regions and doc.status == "ok":
        doc.notes.append("本文テキストが見つかりませんでした(画像主体の可能性)。")
    return doc


def _generic_zip_xml(zf, names_set, doc, out: _Out, limits: Limits, budget: Budget):
    for n in sorted(names_set):
        if not n.endswith(".xml") or n.endswith(".rels"):
            continue
        budget.check()
        root = _parse_part(zf, n, doc, limits, optional=True)
        if root is None:
            continue
        txt = " ".join(t.strip() for e in root.iter() if (t := e.text) and t.strip())
        out.loc = n
        out.visible(txt)


# ODF
def _css_pt(v: Optional[str]) -> Optional[float]:
    if not v:
        return None
    m = re.match(r"^\s*([0-9.]+)\s*(pt|px|mm|cm|in)?\s*$", v)
    if not m:
        return None
    n = float(m.group(1))
    unit = m.group(2) or "pt"
    return n * {"pt": 1.0, "px": 0.75, "mm": 2.835, "cm": 28.35, "in": 72.0}[unit]


class _OdfStyles:
    def __init__(self, roots: List):
        self.hidden: set = set()
        self.tiny: set = set()
        self.white: set = set()
        for root in roots:
            if root is None:
                continue
            for st in root.iter():
                if localname(st.tag) != "style":
                    continue
                name = _attr(st, "name")
                if not name:
                    continue
                for tp in _children(st, "text-properties"):
                    if (_attr(tp, "display") or "").lower() == "none":
                        self.hidden.add(name)
                    pt = _css_pt(_attr(tp, "font-size"))
                    if pt is not None and pt <= 2.0:
                        self.tiny.add(name)
                    if _is_whiteish(_attr(tp, "color")) and (_attr(tp, "background-color") in (None, "transparent")):
                        self.white.add(name)

    def reason(self, style_name: Optional[str]) -> Optional[Tuple[str, Optional[str]]]:
        if not style_name:
            return None
        if style_name in self.hidden:
            return "隠し文字(text:display=none)", None
        if style_name in self.tiny:
            return "極小フォント(2pt以下)", None
        if style_name in self.white:
            return "白色文字(背景不明)", "low"
        return None


class _OdfCtx:
    def __init__(self, styles: _OdfStyles):
        self.styles = styles
        self.alt_seen: set = set()


def _odf_inline(el, ctx: _OdfCtx, reason, segs: list, side: list, depth: int = 0):
    """segs に (text, reason, severity) を積む。注釈/脚注/フレームは side に回す。"""
    if depth > 80:
        raise RecursionError("odf inline nesting")
    r_txt, r_sev = (reason if reason else (None, None))
    if el.text:
        segs.append((el.text, r_txt, r_sev))
    for ch in el:
        ln = localname(ch.tag)
        if ln == "s":
            c = _attr(ch, "c")
            n = int(c) if c and c.isdigit() and int(c) < 1000 else 1
            segs.append((" " * n, r_txt, r_sev))
        elif ln == "tab":
            segs.append(("\t", r_txt, r_sev))
        elif ln == "line-break":
            segs.append(("\n", r_txt, r_sev))
        elif ln == "annotation":
            side.append(("annotation", ch))
        elif ln == "note":
            side.append(("note", ch))
        elif ln == "frame":
            side.append(("frame", ch))
        elif ln in ("hidden-text",):
            sv = _attr(ch, "string-value")             # 文字列が属性に入っていて画面には出ない
            if sv and sv.strip():
                segs.append((sv, "隠しテキスト(hidden-text の string-value)", None))
            if (_attr(ch, "is-hidden") or "").lower() == "true":
                _odf_inline(ch, ctx, ("隠しテキスト(hidden-text)", None), segs, side, depth + 1)
            else:
                _odf_inline(ch, ctx, reason, segs, side, depth + 1)
        elif ln in ("span", "a", "ruby", "ruby-base", "meta", "meta-field", "text-input", "bookmark-ref",
                    "reference-ref", "sequence-ref", "title", "subject", "description", "initial-creator"):
            r = ctx.styles.reason(_attr(ch, "style-name")) or reason
            _odf_inline(ch, ctx, r, segs, side, depth + 1)
        elif ln in ("bookmark", "bookmark-start", "bookmark-end", "soft-page-break", "ruby-text",
                    "change", "change-start", "change-end"):
            pass
        else:
            _odf_inline(ch, ctx, reason, segs, side, depth + 1)
        if ch.tail:
            segs.append((ch.tail, r_txt, r_sev))


def _odf_emit_segs(segs: list, out: _Out, loc: Optional[str] = None):
    vis = []
    first = True
    for text, reason, sev in segs:
        if reason:
            out.hidden(text, reason, "hidden", loc, sev, new_para=first)
            first = False
        else:
            vis.append(text)
    out.visible("".join(vis))


def _odf_side(side: list, ctx: _OdfCtx, out: _Out, depth: int):
    for kind, el in side:
        if kind == "annotation":
            creator = "".join(x.text or "" for x in el.iter() if localname(x.tag) == "creator")
            body = [_plain_odf(p) for p in el if localname(p.tag) in ("p", "h", "list")]
            out.region("\n".join(b for b in body if b), f"コメント({creator})" if creator else "コメント",
                       "annotation", out.loc)
        elif kind == "note":
            nb = _child(el, "note-body")
            if nb is not None:
                _odf_walk(nb, ctx, out, None, depth + 1)
        elif kind == "frame":
            for ch in el:
                ln = localname(ch.tag)
                if ln in ("title", "desc"):
                    v = "".join(ch.itertext())
                    if v.strip() and v not in ctx.alt_seen:
                        ctx.alt_seen.add(v)
                        out.region(v, "図形の代替テキスト", "attribute", out.loc)
                elif ln == "text-box":
                    _odf_walk(ch, ctx, out, None, depth + 1)


def _plain_odf(el) -> str:
    return "".join(el.itertext()).strip()


def _odf_walk(el, ctx: _OdfCtx, out: _Out, reason, depth: int = 0):
    if depth > 80:
        raise RecursionError("odf nesting")
    for ch in el:
        ln = localname(ch.tag)
        if ln in ("p", "h"):
            r = ctx.styles.reason(_attr(ch, "style-name")) or reason
            segs: list = []
            side: list = []
            _odf_inline(ch, ctx, r, segs, side)
            _odf_emit_segs(segs, out)
            _odf_side(side, ctx, out, depth)
        elif ln == "hidden-paragraph":
            own = (ch.text or "").strip() or _attr(ch, "string-value") or ""        # こっちも属性に入ることがある
            if own.strip():
                out.hidden(own, "隠し段落(hidden-paragraph)", "hidden", None, None)
            if (_attr(ch, "is-hidden") or "").lower() == "true":
                _odf_walk(ch, ctx, out, ("隠し段落(hidden-paragraph)", None), depth + 1)
            else:
                _odf_walk(ch, ctx, out, reason, depth + 1)
        elif ln == "section":
            r = ("非表示セクション(display=none)", None) if (_attr(ch, "display") or "").lower() == "none" else reason
            _odf_walk(ch, ctx, out, r, depth + 1)
        elif ln == "table":
            disp = (_attr(ch, "display") or "").lower()
            r = ("非表示の表/シート(table:display=false)", None) if disp == "false" else reason
            _odf_walk(ch, ctx, out, r, depth + 1)
        elif ln == "table-row":
            vis_state = (_attr(ch, "visibility") or "visible").lower()
            r = ("非表示の行(collapse/filter)", None) if vis_state in ("collapse", "filter") else reason
            cells_vis: List[str] = []
            for cell in ch:
                if localname(cell.tag) != "table-cell":
                    continue
                segs: list = []
                side: list = []
                for p in cell.iter():
                    if localname(p.tag) in ("p", "h"):
                        rr = ctx.styles.reason(_attr(p, "style-name")) or r
                        _odf_inline(p, ctx, rr, segs, side)
                        segs.append((" ", None, None))
                vis = []
                first = True
                for text, rs, sev in segs:
                    if rs:
                        out.hidden(text, rs, "hidden", None, sev, new_para=first, sep=" ")
                        first = False
                    else:
                        vis.append(text)
                v = "".join(vis).strip()
                if v:
                    cells_vis.append(v)
                _odf_side(side, ctx, out, depth)
            out.visible(" ".join(cells_vis))
        elif ln == "annotation":
            _odf_side([("annotation", ch)], ctx, out, depth)
        elif ln in ("scripts", "font-face-decls", "automatic-styles", "styles", "settings", "forms"):
            continue
        else:
            _odf_walk(ch, ctx, out, reason, depth + 1)


def extract_odf(data: bytes, name: str = "", limits: Optional[Limits] = None,
                budget: Optional[Budget] = None, depth: int = 0) -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = _new_doc(name, data, "odf")
    try:
        zf = open_zip(data, limits)
    except UnsafeInput as e:
        doc.mark("failed", f"ODF ファイルを開けません: {e}")
        return doc
    except Exception as e:  # noqa
        doc.mark("failed", f"ODF ファイルを開けません: {type(e).__name__}: {e}")
        return doc
    out = _Out(doc, limits, budget)
    try:
        with zf:
            names_set = set(zf.namelist())
            try:
                mt = read_member(zf, "mimetype", limits).decode("ascii", "ignore") if "mimetype" in names_set else ""
            except Exception:  # noqa
                mt = ""
            kind = "odt"
            if "spreadsheet" in mt:
                kind = "ods"
            elif "presentation" in mt:
                kind = "odp"
            elif "graphics" in mt:
                kind = "odg"
            doc.kind = kind
            content = _parse_part(zf, "content.xml", doc, limits)
            styles = _parse_part(zf, "styles.xml", doc, limits, optional=True) if "styles.xml" in names_set else None
            ctx = _OdfCtx(_OdfStyles([content, styles]))
            try:
                if content is not None:
                    body = _child(content, "body")
                    out.loc = "本文"
                    _odf_walk(body if body is not None else content, ctx, out, None)
                if styles is not None:
                    ms = _child(styles, "master-styles")
                    if ms is not None:
                        out.loc = "ヘッダー/フッター"
                        _odf_walk(ms, ctx, out, None)
            except _Truncated:
                doc.mark("partial", f"抽出テキストが上限({limits.max_text_chars}文字)を超えたため以降を切り捨てました。")
            except RecursionError:
                doc.mark("partial", "XML の入れ子が深すぎるため一部のみ解析しました。")
            meta = _parse_part(zf, "meta.xml", doc, limits, optional=True) if "meta.xml" in names_set else None
            if meta is not None:
                for e in meta.iter():
                    tag = localname(e.tag)
                    if tag in ("title", "description", "subject", "keyword", "user-defined", "initial-creator",
                               "creator") and e.text and _meta_ok(e.text):
                        out.region(e.text, f"文書プロパティ({tag})", "metadata", "meta.xml")
            for n in sorted(names_set):
                low = n.lower()
                if (low.startswith(("basic/", "scripts/")) or "/scripts/" in low) and not n.endswith("/"):
                    doc.findings.append(Finding(
                        rule_id="odf_macro", category="active_content", severity="medium",
                        description="マクロ/スクリプトを含むODFファイルです", snippet=n, location=n))
                    break
            if any(n.startswith("Object ") or "/Object " in n for n in names_set):
                doc.findings.append(Finding(
                    rule_id="odf_embedded_object", category="hidden_content", severity="low",
                    description="埋め込みオブジェクトを含んでいます", location="Object"))
    except BudgetExceeded as e:
        doc.mark("partial", f"時間上限のため途中までの解析です: {e}")
    except Exception as e:  # noqa
        doc.mark("partial", f"解析中にエラー: {type(e).__name__}: {e}")
    try:
        doc.text = out.finish()
    except Exception:  # noqa
        doc.text = "\n".join(out.lines)
    return doc


_TAG_RE = re.compile(r"<[^>]+>")


def _html_child(data: bytes, name: str, limits: Limits, budget: Budget) -> ExtractedDoc:
    try:
        from .htmlx import extract_html_bytes  # type: ignore
        return extract_html_bytes(data, name)
    except ImportError:
        d = ExtractedDoc(source=name, kind="html")
        text, enc, notes = decode_bytes(data)
        d.text = re.sub(r"[ \t]+", " ", _TAG_RE.sub("\n", text)).strip()
        d.encoding = enc
        d.mark("partial", "HTML 解析器が無いため簡易的にタグを除去しました。")
        return d


def extract_epub(data: bytes, name: str = "", limits: Optional[Limits] = None,
                 budget: Optional[Budget] = None, depth: int = 0) -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = _new_doc(name, data, "epub")
    try:
        zf = open_zip(data, limits)
    except UnsafeInput as e:
        doc.mark("failed", f"EPUB を開けません: {e}")
        return doc
    except Exception as e:  # noqa
        doc.mark("failed", f"EPUB を開けません: {type(e).__name__}: {e}")
        return doc
    out = _Out(doc, limits, budget)
    pieces: List[str] = []
    try:
        with zf:
            names_set = set(zf.namelist())
            opf_path = None
            cont = _parse_part(zf, "META-INF/container.xml", doc, limits, optional=True) \
                if "META-INF/container.xml" in names_set else None
            if cont is not None:
                rf = next(_desc(cont, "rootfile"), None)
                if rf is not None:
                    opf_path = (rf.get("full-path") or "").lstrip("/") or None
            if not opf_path:
                opf_path = next((n for n in sorted(names_set) if n.lower().endswith(".opf")), None)
            order: List[str] = []
            if opf_path and opf_path in names_set:
                opf = _parse_part(zf, opf_path, doc, limits)
                base = posixpath.dirname(opf_path)
                if opf is not None:
                    for e in opf.iter():
                        tag = localname(e.tag)
                        if e.text and _meta_ok(e.text) and tag in (
                                "title", "creator", "description", "subject", "publisher", "contributor",
                                "rights", "source", "meta"):
                            out.region(e.text, f"EPUBメタデータ({tag})", "metadata", opf_path)
                    manifest = {}
                    for it in _desc(opf, "item"):
                        manifest[it.get("id") or ""] = posixpath.normpath(posixpath.join(base, it.get("href") or ""))
                    for ir in _desc(opf, "itemref"):
                        href = manifest.get(ir.get("idref") or "")
                        if href and href in names_set:
                            order.append(href)
            seen = set(order)
            rest = [n for n in sorted(names_set) if n.lower().endswith((".xhtml", ".html", ".htm")) and n not in seen]
            for n in order + rest:
                budget.check()
                if not n.lower().endswith((".xhtml", ".html", ".htm", ".xml")) and n in rest:
                    continue
                try:
                    child = _html_child(read_member(zf, n, limits), n, limits, budget)
                except UnsafeInput as e:
                    doc.mark("partial", f"{n} をスキップ: {e}")
                    continue
                doc.merge(child, prefix=n if len(order) > 1 or rest else "")
            for n in sorted(names_set):
                if n.lower().endswith(".ncx"):
                    root = _parse_part(zf, n, doc, limits, optional=True)
                    if root is not None:
                        for t in _desc(root, "text"):
                            if t.text and t.text.strip():
                                pieces.append(t.text.strip())
            if any(re.search(r"\.(js)$", n, re.I) for n in names_set):
                doc.findings.append(Finding(
                    rule_id="epub_script", category="active_content", severity="low",
                    description="EPUB にスクリプトファイルが含まれています", location="epub"))
    except BudgetExceeded as e:
        doc.mark("partial", f"時間上限のため途中までの解析です: {e}")
    except Exception as e:  # noqa
        doc.mark("partial", f"解析中にエラー: {type(e).__name__}: {e}")
    try:
        out.flush()
    except Exception:  # noqa
        pass
    doc.text = (doc.text.strip("\n") + ("\n" + "\n".join(pieces) if pieces else "")).strip("\n")
    return doc


# RTF
_FCHARSET_CP = {
    128: "cp932", 129: "cp949", 130: "johab", 134: "cp936", 136: "cp950", 161: "cp1253", 162: "cp1254",
    163: "cp1258", 177: "cp1255", 178: "cp1256", 186: "cp1257", 204: "cp1251", 222: "cp874", 238: "cp1250",
}
_RTF_SKIP_DEST = {
    "stylesheet", "colortbl", "filetbl", "listtable", "listoverridetable", "revtbl", "rsidtbl", "generator",
    "pict", "datastore", "themedata", "colorschememapping", "latentstyles", "creatim", "revtim", "printim",
    "buptim", "fldinst", "xmlnstbl", "pgdsctbl", "listtext", "pntext", "pntxta", "pntxtb", "blipuid",
    "mmathPr", "objclass", "objname", "nonshppict", "shpinst", "falt", "panose", "fname", "private",
    "wgrffmtfilter", "userprops", "protusertbl", "background",
}
_RTF_META_DEST = {"title", "subject", "author", "manager", "company", "operator", "keywords", "doccomm",
                  "category", "comment", "hlinkbase"}
_RTF_SYMS = {"emdash": "—", "endash": "–", "emspace": " ", "enspace": " ", "bullet": "•",
             "lquote": "‘", "rquote": "’", "ldblquote": "“", "rdblquote": "”", "tab": "\t",
             "par": "\n", "line": "\n", "sect": "\n", "page": "\n", "row": "\n", "cell": " ",
             "nestcell": " ", "nestrow": "\n", "lbr": "\n"}


def extract_rtf(data: bytes, name: str = "", limits: Optional[Limits] = None,
                budget: Optional[Budget] = None, depth: int = 0) -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = _new_doc(name, data, "rtf")
    try:
        _rtf_impl(data, doc, limits, budget)
    except BudgetExceeded as e:
        doc.mark("partial", f"時間上限のため途中までの解析です: {e}")
    except Exception as e:  # noqa
        doc.mark("partial", f"RTF 解析中にエラー: {type(e).__name__}: {e}")
    return doc


def _rtf_impl(data: bytes, doc: ExtractedDoc, limits: Limits, budget: Budget):
    if len(data) > limits.max_file_bytes:
        doc.mark("failed", "RTF が大きすぎます。")
        return
    if not data.lstrip()[:5] == b"{\\rtf":
        doc.mark("partial", "RTF ヘッダが見つかりません(RTFではない可能性)。")
    s = data.decode("latin-1")
    n = len(s)
    i = 0
    cp_default = "cp1252"
    font_cp: Dict[int, str] = {}
    cur_font_in_table: Optional[int] = None
    # state のキー: skip hidden uc font dest fonttbl
    state = {"skip": False, "hidden": False, "uc": 1, "font": None, "dest": None, "fonttbl": False}
    stack: List[dict] = []
    segs: List[Tuple[bool, str]] = []          # (hidden?, text)
    meta: Dict[str, List[str]] = {}
    buf: List[str] = []
    pend_bytes = bytearray()
    skip_chars = 0
    found_object = False
    template_target: List[str] = []
    deff = None

    def cur_cp() -> str:
        f = state["font"]
        if f is not None and f in font_cp:
            return font_cp[f]
        return cp_default

    def flush_text():
        if buf:
            t = "".join(buf)
            buf.clear()
            if t:
                if state_for_buf["dest"] and state_for_buf["dest"] != "template":
                    meta.setdefault(state_for_buf["dest"], []).append(t)
                elif state_for_buf["dest"] == "template":
                    template_target.append(t)
                elif not state_for_buf["skip"] and not state_for_buf["fonttbl"]:
                    segs.append((bool(state_for_buf["hidden"]), t))

    state_for_buf = dict(state)

    def sync():
        nonlocal state_for_buf
        flush_bytes()
        flush_text()
        state_for_buf = dict(state)

    def flush_bytes():
        if pend_bytes:
            b = bytes(pend_bytes)
            pend_bytes.clear()
            try:
                t = b.decode(cur_cp_for_bytes, errors="replace")
            except LookupError:
                t = b.decode("latin-1", errors="replace")
            buf.append(t)

    cur_cp_for_bytes = cp_default

    def emit(ch: str):
        nonlocal skip_chars
        if skip_chars > 0:
            skip_chars -= 1
            return
        buf.append(ch)

    count = 0
    while i < n:
        count += 1
        if count % 20000 == 0:
            budget.check()
        c = s[i]
        if c == "{":
            sync()
            stack.append(dict(state))
            if len(stack) > 500:
                doc.mark("partial", "RTF の入れ子が深すぎます。")
                break
            i += 1
        elif c == "}":
            sync()
            if stack:
                state = stack.pop()
                state_for_buf = dict(state)
            i += 1
        elif c == "\\":
            i += 1
            if i >= n:
                break
            c2 = s[i]
            if c2 in "\\{}":
                flush_bytes()
                emit(c2)
                i += 1
            elif c2 == "'":
                hx = s[i + 1:i + 3]
                i += 3
                try:
                    byte = int(hx, 16)
                except ValueError:
                    continue
                if skip_chars > 0:
                    skip_chars -= 1
                    continue
                if not pend_bytes:
                    cur_cp_for_bytes = cur_cp()
                pend_bytes.append(byte)
            elif c2 == "*":
                # {\*\xxx} は template 以外読み飛ばす
                m = re.match(r"\\([a-zA-Z]+)", s[i + 1:i + 40])
                word = m.group(1) if m else ""
                if word == "template":
                    sync()
                    state["dest"] = "template"
                    state_for_buf = dict(state)
                else:
                    sync()
                    state["skip"] = True
                    state_for_buf = dict(state)
                i += 1
            elif c2 in "\r\n":
                flush_bytes()
                emit("\n")
                i += 1
            elif c2 == "~":
                flush_bytes()
                emit(" ")
                i += 1
            elif c2 == "_":
                flush_bytes()
                emit("-")
                i += 1
            elif c2 in "-|:":
                i += 1
            elif c2.isalpha():
                j = i
                while j < n and s[j].isalpha():
                    j += 1
                word = s[i:j]
                k = j
                if k < n and (s[k] == "-" or s[k].isdigit()):
                    k += 1
                    while k < n and s[k].isdigit():
                        k += 1
                param_s = s[j:k]
                param = int(param_s) if param_s not in ("", "-") else None
                if k < n and s[k] == " ":
                    k += 1
                i = k
                if word in ("u",) and param is not None:
                    flush_bytes()
                    cp = param + 65536 if param < 0 else param
                    try:
                        emit(chr(cp))
                    except (ValueError, OverflowError):
                        pass
                    skip_chars = state["uc"]
                elif word == "uc" and param is not None:
                    state["uc"] = param
                elif word in _RTF_SYMS:
                    flush_bytes()
                    emit(_RTF_SYMS[word])
                elif word == "v":
                    sync()
                    state["hidden"] = (param is None or param != 0)
                    state_for_buf = dict(state)
                elif word == "plain":
                    sync()
                    state["hidden"] = False
                    state_for_buf = dict(state)
                elif word == "ansicpg" and param:
                    cp_default = f"cp{param}"
                    try:
                        "".encode(cp_default)
                    except LookupError:
                        cp_default = "cp1252"
                elif word == "deff" and param is not None:
                    deff = param
                elif word == "f" and param is not None:
                    sync()
                    if state["fonttbl"]:
                        cur_font_in_table = param
                    state["font"] = param
                elif word == "fcharset" and param is not None:
                    if state["fonttbl"] and cur_font_in_table is not None and param in _FCHARSET_CP:
                        font_cp[cur_font_in_table] = _FCHARSET_CP[param]
                elif word == "fonttbl":
                    sync()
                    state["fonttbl"] = True
                    state_for_buf = dict(state)
                elif word in _RTF_SKIP_DEST:
                    sync()
                    state["skip"] = True
                    state_for_buf = dict(state)
                elif word in _RTF_META_DEST:
                    sync()
                    state["dest"] = word
                    state_for_buf = dict(state)
                elif word in ("object", "objdata", "objemb", "objlink"):
                    found_object = True
                    if word == "objdata":
                        sync()
                        state["skip"] = True
                        state_for_buf = dict(state)
                elif word == "bin" and param:
                    i += param
            else:
                i += 1
        elif c in "\r\n":
            i += 1
        else:
            if pend_bytes:
                flush_bytes()
            if ord(c) >= 0x80:
                if skip_chars > 0:
                    skip_chars -= 1
                else:
                    if not pend_bytes:
                        cur_cp_for_bytes = cur_cp()
                    pend_bytes.append(ord(c))
            else:
                emit(c)
            i += 1
    sync()
    # segs を見える/隠すに振り分ける
    vis: List[str] = []
    pending: List[str] = []

    def flush_pending():
        if pending:
            t = "".join(pending)
            pending.clear()
            if t.strip():
                doc.hidden_regions.append(HiddenRegion(
                    text=t.strip("\n"), reason="隠し文字(\\v)", location="rtf", kind="hidden"))

    for hid, t in segs:
        if hid:
            pending.append(t)
        else:
            if t.strip():
                flush_pending()
            vis.append(t)
    flush_pending()
    text = "".join(vis)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > limits.max_text_chars:
        text = text[:limits.max_text_chars]
        doc.mark("partial", "抽出テキストが上限を超えたため切り捨てました。")
    doc.text = text
    for k, parts in meta.items():
        v = "".join(parts).strip()
        if _meta_ok(v):
            doc.hidden_regions.append(HiddenRegion(text=v, reason=f"文書プロパティ({k})",
                                                  location="rtf:info", kind="metadata"))
    if found_object:
        doc.findings.append(Finding(
            rule_id="rtf_embedded_object", category="hidden_content", severity="low",
            description="RTF に埋め込みオブジェクト(\\object)が含まれています", location="rtf"))
    tt = "".join(template_target).strip()
    if tt and re.match(r"^(https?:|\\\\\\\\|//|ftp:)", tt, re.I):
        doc.findings.append(Finding(
            rule_id="rtf_remote_template", category="active_content", severity="medium",
            description="RTF が外部のテンプレートを参照しています(リモートテンプレート注入の恐れ)",
            snippet=tt[:200], location="rtf"))


# 旧形式 OLE
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_U16_TEXT = re.compile(r"[\u0020-\u007e\t\r\n\u3000-\u9fff\uff00-\uffef\uac00-\ud7a3]{6,}")
_ASCII_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{8,}")
_CP932_RUN = re.compile(
    rb"(?:[\x20-\x7e]|[\x81-\x9f\xe0-\xfc][\x40-\x7e\x80-\xfc]){8,}")


def _kana_ratio(s: str) -> float:
    if not s:
        return 0.0
    k = sum(1 for ch in s if "぀" <= ch <= "ヿ")
    return k / len(s)


def _letter_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for ch in s if ch.isalpha() or ch == " ") / len(s)


def extract_ole_strings(data: bytes, name: str = "", limits: Optional[Limits] = None,
                        budget: Optional[Budget] = None, depth: int = 0, kind: str = "ole") -> ExtractedDoc:
    limits = limits or Limits()
    budget = budget or Budget(limits.timeout_sec)
    doc = _new_doc(name, data, kind)
    try:
        _ole_impl(data, doc, limits, budget)
    except BudgetExceeded as e:
        doc.mark("partial", f"時間上限のため途中までの解析です: {e}")
    except Exception as e:  # noqa
        doc.mark("partial", f"解析中にエラー: {type(e).__name__}: {e}")
    return doc


def _ole_impl(data: bytes, doc: ExtractedDoc, limits: Limits, budget: Budget):
    if len(data) > limits.max_file_bytes:
        data = data[:limits.max_file_bytes]
        doc.mark("partial", "ファイルが大きいため先頭のみ解析しました。")
    if not data.startswith(_OLE_MAGIC):
        doc.notes.append("OLE 複合ファイルのヘッダが見つかりません(文字列抽出のみ実施)。")
    found: List[str] = []
    seen: set = set()
    total = 0
    CAP_CHARS = 500_000

    def add(s: str):
        nonlocal total
        s = s.replace("\x00", "").strip()
        if len(s) < 6:
            return
        key = re.sub(r"\s+", " ", s)
        if key in seen:
            return
        seen.add(key)
        total += len(s)
        found.append(s)

    CH = 1 << 21          # 2MB。UTF-16 は並びが分からないので offset 0/1 の両方で読む
    for off in (0, 1):
        pos = off
        while pos < len(data):
            budget.check()
            if total > CAP_CHARS or len(found) > 5000:
                break
            chunk = data[pos:pos + CH + 4096]
            if len(chunk) % 2:
                chunk = chunk[:-1]
            if len(chunk) >= 12:
                u = chunk.decode("utf-16-le", errors="replace")
                for m in _U16_TEXT.finditer(u):
                    seg = m.group(0)
                    if len(set(seg)) <= 2:
                        continue
                    # バイナリがたまたま CJK に化けたものを弾く。ASCII 主体かかな多めだけ通す
                    ascii_ratio = sum(1 for ch in seg if ord(ch) < 0x80) / len(seg)
                    if ascii_ratio >= 0.5 or _kana_ratio(seg) >= 0.2:
                        add(seg)
            pos += CH
    for m in _ASCII_RUN.finditer(data):
        budget.check()
        if total > CAP_CHARS or len(found) > 5000:
            break
        s = m.group(0).decode("ascii", "ignore")
        if (" " in s or len(s) >= 16) and _letter_ratio(s) >= 0.6:
            add(s)
    for m in _CP932_RUN.finditer(data):
        budget.check()
        if total > CAP_CHARS or len(found) > 5000:
            break
        raw = m.group(0)
        if not re.search(rb"[\x81-\x9f\xe0-\xfc]", raw):
            continue
        try:
            s = raw.decode("cp932")
        except UnicodeDecodeError:
            continue
        if _kana_ratio(s) >= 0.2:
            add(s)
    doc.text = "\n".join(found)
    if re.search(rb"_VBA_PROJECT|Attribute VB_Name|V\x00B\x00A\x00|M\x00a\x00c\x00r\x00o\x00s\x00|Macros", data):
        doc.findings.append(Finding(
            rule_id="ole_macro", category="active_content", severity="medium",
            description="VBAマクロを含む可能性があります(OLE内に VBA/Macros の記述を検出)",
            location="ole"))
    doc.mark("partial", "旧形式(OLE)のため文字列抽出による簡易解析です。見落としの可能性があります")
