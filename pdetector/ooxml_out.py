"""無害化した本文から、素の pptx / docx / xlsx を作り直す(標準ライブラリのみ)。

元ファイルの XML は引き継がない。見えている本文だけの最小構成なので、隠しスライド・ノート・コメント・
プロパティ・埋込み・マクロ・画像は構造上入らない。レイアウトや書式も落ちる。

groups は [(ラベル, [行, ...]), ...]。pptx はグループごとにスライド(長ければ分割)、docx は全部まとめて
1 行 1 段落、xlsx はグループごとにシートで、行内のタブをセル区切りにする。
"""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from typing import List, Sequence, Tuple
from xml.sax.saxutils import escape

Groups = Sequence[Tuple[str, Sequence[str]]]

_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

EXTS = ("pptx", "docx", "xlsx")
MAX_CELL = 30000
MAX_XLSX_ROWS = 1_000_000


def _x(s: str) -> str:
    """XML で使えない制御文字を落としてエスケープ。"""
    return escape(_BAD_XML.sub("", s))


def _zip(files: List[Tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, (_XML + data).encode("utf-8") if not data.startswith("<?xml") else data.encode("utf-8"))
    return buf.getvalue()


def _rels(items: Sequence[Tuple[str, str, str]]) -> str:
    return (f'<Relationships xmlns="{_NS_PKG}">'
            + "".join(f'<Relationship Id="{i}" Type="{_NS_R}/{t}" Target="{tg}"/>' for i, t, tg in items)
            + "</Relationships>")


def _core(title: str) -> str:
    return ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(title)}</dc:title><dc:creator>pdetector</dc:creator></cp:coreProperties>')


def _app() -> str:
    return ('<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            '<Application>pdetector</Application></Properties>')


def _flatten(groups: Groups) -> List[str]:
    return [ln for _lab, lines in groups for ln in lines]


# docx
def build_docx(groups: Groups, title: str = "") -> bytes:
    paras = []
    for ln in _flatten(groups):
        if ln.strip():
            paras.append(f'<w:p><w:r><w:t xml:space="preserve">{_x(ln)}</w:t></w:r></w:p>')
        else:
            paras.append("<w:p/>")
    doc = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
           f'xmlns:r="{_NS_R}"><w:body>' + "".join(paras) +
           '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
           '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>'
           "</w:sectPr></w:body></w:document>")
    ct = (f'<Types xmlns="{_NS_CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
    return _zip([
        ("[Content_Types].xml", ct),
        ("_rels/.rels", _root_rels("word/document.xml")),
        ("word/document.xml", doc),
        ("word/_rels/document.xml.rels", _rels([])),
        ("docProps/core.xml", _core(title)),
        ("docProps/app.xml", _app()),
    ])


# xlsx
_BAD_SHEET = re.compile(r"[\[\]:*?/\\]")


def _sheet_names(labels: Sequence[str]) -> List[str]:
    out: List[str] = []
    for i, lab in enumerate(labels, start=1):
        n = _BAD_SHEET.sub("_", _BAD_XML.sub("", lab or "")).strip().strip("'")[:31] or f"Sheet{i}"
        base, k = n, 1
        while n.lower() in {x.lower() for x in out}:
            k += 1
            suffix = f"_{k}"
            n = base[: 31 - len(suffix)] + suffix
        out.append(n)
    return out


def _col(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def build_xlsx(groups: Groups, title: str = "") -> bytes:
    if not groups:
        groups = [("Sheet1", [])]
    names = _sheet_names([g[0] for g in groups])
    sheets = []
    for _lab, lines in groups:
        rows = []
        r = 0
        for ln in lines:
            for chunk_i in range(0, max(len(ln), 1), MAX_CELL):
                piece = ln[chunk_i:chunk_i + MAX_CELL]
                r += 1
                if r > MAX_XLSX_ROWS:
                    raise ValueError("rows")
                cells = piece.split("\t") if chunk_i == 0 and len(ln) <= MAX_CELL else [piece]
                cs = "".join(
                    f'<c r="{_col(ci)}{r}" t="inlineStr"><is><t xml:space="preserve">{_x(c)}</t></is></c>'
                    for ci, c in enumerate(cells[:16384]) if c != "")
                rows.append(f'<row r="{r}">{cs}</row>')
        sheets.append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
                      + "".join(rows) + "</sheetData></worksheet>")
    wb = ('<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          f'xmlns:r="{_NS_R}"><sheets>'
          + "".join(f'<sheet name="{_x(n)}" sheetId="{i}" r:id="rId{i}"/>' for i, n in enumerate(names, start=1))
          + "</sheets></workbook>")
    ct = (f'<Types xmlns="{_NS_CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                    for i in range(1, len(sheets) + 1))
          + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
    files = [
        ("[Content_Types].xml", ct),
        ("_rels/.rels", _root_rels("xl/workbook.xml")),
        ("xl/workbook.xml", wb),
        ("xl/_rels/workbook.xml.rels", _rels([(f"rId{i}", "worksheet", f"worksheets/sheet{i}.xml") for i in range(1, len(sheets) + 1)])),
    ]
    files += [(f"xl/worksheets/sheet{i}.xml", s) for i, s in enumerate(sheets, start=1)]
    files += [("docProps/core.xml", _core(title)), ("docProps/app.xml", _app())]
    return _zip(files)


def _root_rels(main: str) -> str:
    return (f'<Relationships xmlns="{_NS_PKG}">'
            f'<Relationship Id="rId1" Type="{_NS_R}/officeDocument" Target="{main}"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            f'<Relationship Id="rId3" Type="{_NS_R}/extended-properties" Target="docProps/app.xml"/></Relationships>')


# pptx
SLIDE_W, SLIDE_H = 12192000, 6858000
_SLIDE_WEIGHT = 18       # 1 枚の行数の目安。折り返しも重みに入れる
_LINE_COLS = 70          # 1 行に入る全角換算の文字数


def _width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def _weight(line: str) -> int:
    return max(1, -(-_width(line) // (_LINE_COLS * 2)))


def split_slides(lines: Sequence[str]) -> List[List[str]]:
    out: List[List[str]] = []
    cur: List[str] = []
    w = 0
    for ln in lines:
        lw = _weight(ln)
        if cur and w + lw > _SLIDE_WEIGHT:
            out.append(cur)
            cur, w = [], 0
        cur.append(ln)
        w += lw
    if cur:
        out.append(cur)
    return out


_THEME = (
    '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Plain"><a:themeElements>'
    '<a:clrScheme name="Plain"><a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
    '<a:dk2><a:srgbClr val="1F2937"/></a:dk2><a:lt2><a:srgbClr val="F3F4F6"/></a:lt2>'
    '<a:accent1><a:srgbClr val="2563EB"/></a:accent1><a:accent2><a:srgbClr val="DC2626"/></a:accent2>'
    '<a:accent3><a:srgbClr val="16A34A"/></a:accent3><a:accent4><a:srgbClr val="CA8A04"/></a:accent4>'
    '<a:accent5><a:srgbClr val="7C3AED"/></a:accent5><a:accent6><a:srgbClr val="0891B2"/></a:accent6>'
    '<a:hlink><a:srgbClr val="2563EB"/></a:hlink><a:folHlink><a:srgbClr val="7C3AED"/></a:folHlink></a:clrScheme>'
    '<a:fontScheme name="Plain"><a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
    '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>'
    '<a:fmtScheme name="Plain"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>'
    '<a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
    '<a:ln w="25400"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
    '<a:ln w="38100"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>'
    '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle>'
    '<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
    '<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
    '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>'
)

_P_NS = ('xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
         f'xmlns:r="{_NS_R}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"')
_EMPTY_TREE = ('<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
               '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>')
_MASTER = (
    f'<p:sldMaster {_P_NS}><p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>'
    f'<p:spTree>{_EMPTY_TREE}</p:spTree></p:cSld>'
    '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" '
    'accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
    '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
    '<p:txStyles><p:titleStyle><a:lvl1pPr><a:defRPr sz="3200"/></a:lvl1pPr></p:titleStyle>'
    '<p:bodyStyle><a:lvl1pPr><a:defRPr sz="1800"/></a:lvl1pPr></p:bodyStyle>'
    '<p:otherStyle><a:lvl1pPr><a:defRPr sz="1800"/></a:lvl1pPr></p:otherStyle></p:txStyles></p:sldMaster>'
)
_LAYOUT = (f'<p:sldLayout {_P_NS} type="blank" preserve="1"><p:cSld name="Blank"><p:spTree>{_EMPTY_TREE}</p:spTree></p:cSld>'
           '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>')


def _slide(lines: Sequence[str]) -> str:
    paras = "".join(
        (f'<a:p><a:r><a:rPr lang="ja-JP" sz="1600" dirty="0"/><a:t>{_x(ln)}</a:t></a:r></a:p>' if ln.strip() else "<a:p/>")
        for ln in lines) or "<a:p/>"
    sp = ('<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
          '<p:spPr><a:xfrm><a:off x="609600" y="457200"/><a:ext cx="10972800" cy="5943600"/></a:xfrm>'
          '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
          f'<p:txBody><a:bodyPr wrap="square" rtlCol="0"><a:normAutofit/></a:bodyPr><a:lstStyle/>{paras}</p:txBody></p:sp>')
    return (f'<p:sld {_P_NS}><p:cSld><p:spTree>{_EMPTY_TREE}{sp}</p:spTree></p:cSld>'
            '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>')


def build_pptx(groups: Groups, title: str = "") -> bytes:
    slides: List[List[str]] = []
    for _lab, lines in groups:
        slides.extend(split_slides(lines))
    if not slides:
        slides = [[]]
    n = len(slides)
    pres = (f'<p:presentation {_P_NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            "<p:sldIdLst>" + "".join(f'<p:sldId id="{255 + i}" r:id="rId{i + 1}"/>' for i in range(1, n + 1)) + "</p:sldIdLst>"
            f'<p:sldSz cx="{SLIDE_W}" cy="{SLIDE_H}"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>')
    pres_rels = _rels([("rId1", "slideMaster", "slideMasters/slideMaster1.xml")]
                      + [(f"rId{i + 1}", "slide", f"slides/slide{i}.xml") for i in range(1, n + 1)]
                      + [(f"rId{n + 2}", "theme", "theme/theme1.xml")])
    ct = (f'<Types xmlns="{_NS_CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
          '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
          '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
          '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
          + "".join(f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
                    for i in range(1, n + 1))
          + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
    files = [
        ("[Content_Types].xml", ct),
        ("_rels/.rels", _root_rels("ppt/presentation.xml")),
        ("ppt/presentation.xml", pres),
        ("ppt/_rels/presentation.xml.rels", pres_rels),
        ("ppt/slideMasters/slideMaster1.xml", _MASTER),
        ("ppt/slideMasters/_rels/slideMaster1.xml.rels", _rels([("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                                                                ("rId2", "theme", "../theme/theme1.xml")])),
        ("ppt/slideLayouts/slideLayout1.xml", _LAYOUT),
        ("ppt/slideLayouts/_rels/slideLayout1.xml.rels", _rels([("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")])),
        ("ppt/theme/theme1.xml", _THEME),
    ]
    for i, sl in enumerate(slides, start=1):
        files.append((f"ppt/slides/slide{i}.xml", _slide(sl)))
        files.append((f"ppt/slides/_rels/slide{i}.xml.rels", _rels([("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")])))
    files += [("docProps/core.xml", _core(title)), ("docProps/app.xml", _app())]
    return _zip(files)


BUILDERS = {"pptx": build_pptx, "docx": build_docx, "xlsx": build_xlsx}


def build(fmt: str, groups: Groups, title: str = "") -> bytes:
    return BUILDERS[fmt](groups, title)
