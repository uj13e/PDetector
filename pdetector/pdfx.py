"""PDF の抽出。

可視テキストは doc.text、見えないテキスト(白文字・極小文字・ページ外・Tr 3・メタデータ・注釈・
フォーム値など)は HiddenRegion に分けて入れる。二重に数えない。
pdfplumber / pypdf はどちらか欠けても動く。できなかった分は doc.mark("partial", ...) で残す。
"""
from __future__ import annotations

import hashlib
import io
import re
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from .encoding import decode_bytes
from .model import ExtractedDoc, Finding, HiddenRegion
from .safeio import Budget, BudgetExceeded, Limits, UnsafeInput

WHITE_RGB_MIN = 0.94        # RGB/グレーがすべてこれ以上なら「白〜ほぼ白」
WHITE_CMYK_MAX = 0.06       # CMYK がすべてこれ以下なら白
DARK_LUMA_MAX = 0.60        # これ未満の塗りは暗い背景扱い(白文字が正当になる)
TINY_FONT_PT = 2.0          # これ未満は極小フォント
MIN_HIDDEN_LEN = 4          # 短すぎる隠し文字列はノイズなので捨てる
MAX_OCR_PAGES = 5           # 画像のみPDFのOCRはここまで
MAX_LINK_REPORT = 10
MAX_NAME_TREE = 2000

_META_SKIP_KEYS = {"/CreationDate", "/ModDate", "/Trapped"}
_META_BORING = {"anonymous", "unspecified", "untitled", "false", "true", "none", "null"}


def _ob(x: Any) -> Any:
    """IndirectObject なら実体を取る。"""
    try:
        if hasattr(x, "get_object"):
            return x.get_object()
    except Exception:
        return None
    return x


def _to_text(x: Any) -> str:
    x = _ob(x)
    if x is None:
        return ""
    if isinstance(x, bytes):
        try:
            return decode_bytes(x)[0]
        except Exception:
            return x.decode("latin-1", errors="replace")
    return str(x)


def _clean(s: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", s.replace("\x00", "")).strip()


def _short(s: str, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[:n] + "…"


def _rgb_of(color: Any) -> Optional[Tuple[float, float, float]]:
    """RGB にする。パターン/Separation等は None。未指定は黒。"""
    if color is None:
        return (0.0, 0.0, 0.0)
    try:
        if isinstance(color, (int, float)):
            g = float(color)
            return (g, g, g)
        if isinstance(color, (list, tuple)):
            vals = [float(c) for c in color]
            if len(vals) == 1:
                return (vals[0],) * 3
            if len(vals) == 3:
                return (vals[0], vals[1], vals[2])
            if len(vals) == 4:
                c, m, y, k = vals
                return ((1 - c) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    except Exception:
        return None
    return None


def _is_white(color: Any) -> bool:
    if isinstance(color, (list, tuple)) and len(color) == 4:
        try:
            return all(float(c) <= WHITE_CMYK_MAX for c in color)
        except Exception:
            return False
    rgb = _rgb_of(color)
    return rgb is not None and all(v >= WHITE_RGB_MIN for v in rgb)


def _luma(rgb: Tuple[float, float, float]) -> float:
    return 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2]


def _norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


# Tr 3(不可視描画モード)
_TR3_QUICK = re.compile(rb"(?<![\w.])3\s+Tr(?![\w])")
_WS = b" \t\r\n\x0c\x00"
_DELIM = b"()<>[]{}/%"


def _iter_tokens(data: bytes) -> Iterator[Tuple[str, Any]]:
    """コンテンツストリームの最小トークナイザ。(type, value) で type は str/num/op/name。"""
    i, n = 0, len(data)
    while i < n:
        c = data[i:i + 1]
        if c in _WS:
            i += 1
        elif c == b"%":
            while i < n and data[i:i + 1] not in b"\r\n":
                i += 1
        elif c == b"(":
            depth, i, buf = 1, i + 1, bytearray()
            while i < n and depth:
                ch = data[i:i + 1]
                if ch == b"\\":
                    nx = data[i + 1:i + 2]
                    if nx in b"nrtbf":
                        buf += {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}[nx]
                        i += 2
                    elif nx.isdigit() if nx else False:
                        j = i + 1
                        while j < n and j < i + 4 and data[j:j + 1].isdigit():
                            j += 1
                        try:
                            buf.append(int(data[i + 1:j], 8) & 0xFF)
                        except Exception:
                            pass
                        i = j
                    elif nx in (b"\r", b"\n"):
                        i += 2
                    else:
                        buf += nx
                        i += 2
                elif ch == b"(":
                    depth += 1
                    buf += ch
                    i += 1
                elif ch == b")":
                    depth -= 1
                    if depth:
                        buf += ch
                    i += 1
                else:
                    buf += ch
                    i += 1
            yield "str", bytes(buf)
        elif c == b"<":
            if data[i + 1:i + 2] == b"<":
                i += 2
                yield "op", "<<"
            else:
                j = data.find(b">", i + 1)
                if j < 0:
                    return
                hx = re.sub(rb"[^0-9A-Fa-f]", b"", data[i + 1:j])
                if len(hx) % 2:
                    hx += b"0"
                try:
                    yield "str", bytes.fromhex(hx.decode("ascii"))
                except Exception:
                    yield "str", b""
                i = j + 1
        elif c == b">":
            i += 2 if data[i + 1:i + 2] == b">" else 1
            yield "op", ">>"
        elif c in b"[]":
            i += 1
            yield "op", c.decode()
        elif c in b"{}":
            i += 1
        elif c == b"/":
            j = i + 1
            while j < n and data[j:j + 1] not in _WS and data[j:j + 1] not in _DELIM:
                j += 1
            yield "name", data[i + 1:j].decode("latin-1")
            i = j
        else:
            j = i
            while j < n and data[j:j + 1] not in _WS and data[j:j + 1] not in _DELIM:
                j += 1
            tok = data[i:j].decode("latin-1")
            i = max(j, i + 1)
            try:
                yield "num", float(tok)
            except ValueError:
                yield "op", tok
                if tok == "BI":      # インライン画像のバイナリはトークンにならないので飛ばす
                    m = re.compile(rb"\sEI(?=[\s]|$)").search(data, i)
                    i = m.end() if m else n


def _decode_pdf_string(b: bytes) -> Tuple[str, bool]:
    """(テキスト, 読めたか)。ASCII/Latin-1 の標準フォントだけ想定した簡易版。"""
    if not b:
        return "", True
    if b.startswith(b"\xfe\xff"):
        try:
            return b[2:].decode("utf-16-be", errors="replace"), True
        except Exception:
            return "", False
    t = b.decode("latin-1")
    ok = sum(1 for ch in t if ch.isprintable() or ch in "\r\n\t") / len(t) >= 0.85
    return t, ok


def _invisible_text_strings(content: bytes) -> Tuple[List[str], int]:
    """Tr 3 で描かれた文字列(行ごと)と、デコードできなかった個数。"""
    lines: List[str] = []
    undecodable = 0
    mode, stack = 0, []
    cur: List[str] = []
    nums: List[float] = []
    in_array = False
    arr: List[Any] = []

    def flush():
        nonlocal cur
        if cur:
            lines.append("".join(cur))
            cur = []

    for typ, val in _iter_tokens(content):
        if typ == "num":
            nums.append(val)
            if in_array:
                arr.append(val)
            continue
        if typ == "str":
            if in_array:
                arr.append(val)
            else:
                nums.append(val)   # 次のオペレータの引数
            continue
        if typ == "name":
            nums.append(val)
            continue
        op = val
        if op == "[":
            in_array, arr = True, []
            continue
        if op == "]":
            in_array = False
            continue
        if op == "q":
            stack.append(mode)
        elif op == "Q":
            if stack:
                mode = stack.pop()
        elif op == "Tr":
            nn = [x for x in nums if isinstance(x, float)]
            if nn:
                mode = int(nn[-1])
        elif op in ("Tj", "'", '"'):
            ss = [x for x in nums if isinstance(x, bytes)]
            if ss and mode == 3:
                t, ok = _decode_pdf_string(ss[-1])
                if ok:
                    cur.append(t)
                else:
                    undecodable += 1
        elif op == "TJ":
            if mode == 3:
                for el in arr:
                    if isinstance(el, bytes):
                        t, ok = _decode_pdf_string(el)
                        if ok:
                            cur.append(t)
                        else:
                            undecodable += 1
                    elif isinstance(el, float) and el < -200:
                        cur.append(" ")
        elif op in ("ET", "T*", "Td", "TD", "Tm"):
            if op in ("ET", "T*", "Td", "TD", "Tm"):
                flush()
        nums = []
        arr = arr if in_array else []
    flush()
    return [l for l in (x.strip() for x in lines) if l], undecodable


def _remove_from_text(text: str, fragment: str) -> Tuple[str, bool]:
    """可視テキストから fragment を1回だけ消す。空白の揺れは許す。"""
    words = fragment.split()
    if not words:
        return text, False
    pat = r"\s*".join(re.escape(w) for w in words)
    m = re.search(pat, text)
    if not m:
        return text, False
    return text[:m.start()] + text[m.end():], True


# 構造解析 (pypdf)
class _State:
    """抽出中の共有状態。"""

    def __init__(self, doc: ExtractedDoc, limits: Limits, budget: Budget, depth: int):
        self.doc = doc
        self.limits = limits
        self.budget = budget
        self.depth = depth
        self.uris: List[str] = []
        self.seen_regions: Set[Tuple[str, str]] = set()
        self.js_found = False
        self.embedded_names: Set[str] = set()

    def region(self, text: str, reason: str, location: str, kind: str, severity: Optional[str] = None):
        t = _clean(text)
        if len(t) < MIN_HIDDEN_LEN:
            return
        key = (kind, t[:200])
        if key in self.seen_regions:
            return
        self.seen_regions.add(key)
        self.doc.hidden_regions.append(HiddenRegion(text=t[:20000], reason=reason, location=location,
                                                    kind=kind, severity=severity))

    def finding(self, rule_id: str, category: str, severity: str, description: str,
                snippet: str = "", location: str = "", detail: str = ""):
        self.doc.findings.append(Finding(rule_id=rule_id, category=category, severity=severity,
                                         description=description, snippet=_short(snippet),
                                         location=location, detail=detail))


def _walk_name_tree(node: Any, out: List[Tuple[str, Any]], seen: Set[int], depth: int = 0):
    node = _ob(node)
    if not hasattr(node, "get") or depth > 25 or id(node) in seen or len(out) >= MAX_NAME_TREE:
        return
    seen.add(id(node))
    names = _ob(node.get("/Names"))
    if names:
        for i in range(0, len(names) - 1, 2):
            out.append((_to_text(names[i]), _ob(names[i + 1])))
            if len(out) >= MAX_NAME_TREE:
                return
    kids = _ob(node.get("/Kids"))
    if kids:
        for k in kids:
            _walk_name_tree(k, out, seen, depth + 1)


def _action_dicts(action: Any, depth: int = 0) -> Iterator[Any]:
    """アクション辞書を /Next も含めて辿る。"""
    a = _ob(action)
    if depth > 8 or a is None:
        return
    if isinstance(a, list):
        for x in a:
            yield from _action_dicts(x, depth + 1)
        return
    if hasattr(a, "get"):
        yield a
        nxt = a.get("/Next")
        if nxt is not None:
            yield from _action_dicts(nxt, depth + 1)


def _stream_text(obj: Any, cap: int) -> str:
    o = _ob(obj)
    try:
        if hasattr(o, "get_data"):
            return _to_text(o.get_data()[:cap])
    except Exception:
        return ""
    return _to_text(o)


def _handle_action(st: _State, action: Any, where: str):
    for a in _action_dicts(action):
        try:
            s = str(_ob(a.get("/S")) or "")
        except Exception:
            continue
        if s == "/JavaScript":
            js = _stream_text(a.get("/JS"), 20000)
            st.js_found = True
            st.finding("pdf_javascript", "active_content", "medium",
                       "PDF内にJavaScriptが含まれています", snippet=js, location=where)
            st.region(js, "PDF内JavaScript", where, "hidden")
        elif s == "/Launch":
            st.finding("pdf_launch_action", "active_content", "info",
                       "外部プログラムを起動するアクション(/Launch)があります", location=where)
        elif s == "/URI":
            u = _to_text(a.get("/URI"))
            if u:
                st.uris.append(u)
                if "?" in u or "{{" in u or "%7B" in u.upper():
                    st.region(u, "PDF リンクの宛先 URL", where, "attribute")
        elif s in ("/SubmitForm", "/ImportData", "/GoToR"):
            st.finding("pdf_external_action", "active_content", "info",
                       f"外部へ送信/参照するアクション({s})があります", location=where,
                       snippet=_to_text(a.get("/F") or ""))


def _embedded_from_filespec(st: _State, fs: Any, where: str, depth: int):
    fs = _ob(fs)
    if not hasattr(fs, "get"):
        return
    name = _to_text(fs.get("/UF") or fs.get("/F") or "") or "(無名)"
    ef = _ob(fs.get("/EF"))
    if name in st.embedded_names:
        return
    st.embedded_names.add(name)
    st.finding("pdf_embedded_file", "hidden_content", "low",
               "PDFに埋め込みファイルがあります", snippet=name, location=where)
    if not hasattr(ef, "get"):
        return
    stream = _ob(ef.get("/F") or ef.get("/UF"))
    if stream is None or not hasattr(stream, "get_data"):
        return
    if depth >= st.limits.max_depth:
        st.doc.mark("partial", f"埋め込みファイル {name} は入れ子の深さ上限のため解析しませんでした。")
        return
    try:
        params = _ob(stream.get("/Params")) if hasattr(stream, "get") else None
        declared = int(_ob(params.get("/Size"))) if hasattr(params, "get") and params.get("/Size") is not None else 0
        if declared > st.limits.max_member_bytes:
            st.doc.mark("partial", f"埋め込みファイル {name} が大きすぎるため解析しませんでした({declared // (1024 * 1024)}MB)。")
            return
        data = stream.get_data()
        if len(data) > st.limits.max_member_bytes:
            st.doc.mark("partial", f"埋め込みファイル {name} が大きすぎるため解析しませんでした。")
            return
    except Exception as e:  # noqa
        st.doc.mark("partial", f"埋め込みファイル {name} を読めませんでした: {_short(str(e), 80)}")
        return
    try:
        from .extractors import extract_from_bytes  # 循環import回避
    except Exception:
        st.doc.mark("partial", f"埋め込みファイル {name} は解析器が未接続のため未検査です。")
        return
    try:
        child = extract_from_bytes(data, name=name, limits=st.limits, budget=st.budget, depth=depth + 1)
        st.doc.merge(child, prefix=name)
    except BudgetExceeded:
        raise
    except Exception as e:  # noqa
        st.doc.mark("partial", f"埋め込みファイル {name} の解析に失敗: {_short(str(e), 80)}")


def _structure_pypdf(reader: Any, st: _State):
    """メタデータ・しおり・フォーム・JS・埋め込み・レイヤー・XFA。1項目が壊れても他は続ける。"""
    doc = st.doc

    def guard(label: str, fn):
        try:
            fn()
        except BudgetExceeded:
            raise
        except Exception as e:  # noqa
            doc.mark("partial", f"PDF構造解析の一部({label})に失敗: {_short(str(e), 100)}")

    root = None
    try:
        root = _ob(reader.trailer["/Root"])
    except Exception:
        pass

    def meta():
        md = reader.metadata
        if not md:
            return
        lines = []
        for k, v in md.items():
            if str(k) in _META_SKIP_KEYS:
                continue
            t = _clean(_to_text(v))
            if re.fullmatch(r"D:\d{4,}.*", t or "") or t.lower() in _META_BORING or len(t) < MIN_HIDDEN_LEN:
                continue
            lines.append(f"{str(k).lstrip('/')}: {t}")
        if lines:
            # 項目ごとに分けると普通のPDFでも検知が並ぶので1つにまとめる
            st.region("\n".join(lines), "文書情報(Title/Author/Subject等)", "メタデータ", "metadata")

    guard("文書情報", meta)

    def xmp():
        if root is None:
            return
        m = _ob(root.get("/Metadata"))
        if m is not None and hasattr(m, "get_data"):
            raw = m.get_data()[:2_000_000]
            txt = _to_text(raw)
            parts = [p.strip() for p in re.findall(r">([^<>]+)<", txt)]
            parts = [p for p in parts if len(p) >= MIN_HIDDEN_LEN
                     and not re.fullmatch(r"[\d\-:T.+Z/ ]+", p) and p != "application/pdf"
                     and not re.fullmatch(r"(?:uuid|xmp\.[a-z]+):[\w\-.]+", p, re.I)]
            if parts:
                st.region("\n".join(dict.fromkeys(parts)), "XMPメタデータ", "メタデータ", "metadata")

    guard("XMP", xmp)

    def outline():
        titles: List[str] = []

        def walk(items, depth=0):
            if depth > 20 or len(titles) > 2000:
                return
            for it in items:
                if isinstance(it, list):
                    walk(it, depth + 1)
                else:
                    t = getattr(it, "title", None)
                    if t:
                        titles.append(str(t))

        walk(reader.outline)
        if titles:
            st.region("\n".join(titles), "しおり(ブックマーク)", "メタデータ", "metadata")

    guard("しおり", outline)

    def fields():
        flds = reader.get_fields()
        if not flds:
            return
        vals = []
        for name, f in flds.items():
            v = f.get("/V") if hasattr(f, "get") else None
            t = _to_text(v)
            if t and t not in ("/Off", "/Yes", "/On"):
                vals.append(f"{name}: {t}")
        if vals:
            st.region("\n".join(vals), "フォームフィールドの値", "フォーム", "annotation")

    guard("フォーム", fields)

    def xfa():
        if root is None:
            return
        af = _ob(root.get("/AcroForm"))
        if not hasattr(af, "get"):
            return
        x = _ob(af.get("/XFA"))
        if x is None:
            return
        chunks = []
        if isinstance(x, list):
            for el in x:
                el = _ob(el)
                if hasattr(el, "get_data"):
                    chunks.append(_stream_text(el, 1_000_000))
        elif hasattr(x, "get_data"):
            chunks.append(_stream_text(x, 1_000_000))
        txt = "\n".join(re.findall(r">([^<>]{4,})<", "\n".join(chunks)))
        st.finding("pdf_xfa", "hidden_content", "low", "XFAフォーム(XMLデータ)を含みます")
        st.region(txt, "XFAフォームデータ", "フォーム", "annotation")

    guard("XFA", xfa)

    # カタログの OpenAction / AA / Names
    def catalog_actions():
        if root is None:
            return
        oa = root.get("/OpenAction")
        if oa is not None:
            o = _ob(oa)
            if hasattr(o, "get"):
                _handle_action(st, o, "OpenAction")
        aa = _ob(root.get("/AA"))
        if hasattr(aa, "get"):
            for k in list(aa.keys()):
                _handle_action(st, aa.get(k), f"文書AA{k}")
        names = _ob(root.get("/Names"))
        if hasattr(names, "get"):
            js = names.get("/JavaScript")
            if js is not None:
                out: List[Tuple[str, Any]] = []
                _walk_name_tree(js, out, set())
                for nm, act in out:
                    _handle_action(st, act, f"JavaScript:{nm}")
                if not out:
                    st.js_found = True
                    st.finding("pdf_javascript", "active_content", "medium", "PDF内にJavaScriptの名前ツリーがあります")
            ef = names.get("/EmbeddedFiles")
            if ef is not None:
                out2: List[Tuple[str, Any]] = []
                _walk_name_tree(ef, out2, set())
                for nm, fs in out2:
                    st.budget.check()
                    _embedded_from_filespec(st, fs, "EmbeddedFiles", st.depth)

    guard("カタログ", catalog_actions)

    # OCG(レイヤー)
    def ocg():
        if root is None:
            return
        ocp = _ob(root.get("/OCProperties"))
        if not hasattr(ocp, "get"):
            return
        d = _ob(ocp.get("/D"))
        off = _ob(d.get("/OFF")) if hasattr(d, "get") else None
        if off:
            names = []
            for o in off:
                o = _ob(o)
                if hasattr(o, "get"):
                    names.append(_to_text(o.get("/Name")))
            st.finding("pdf_hidden_layer", "hidden_content", "low",
                       "非表示に設定されたレイヤー(OCG)があります",
                       snippet=", ".join(n for n in names if n),
                       detail="レイヤー内のテキストは可視テキストとして抽出されている可能性があります(レイヤー単位の分離は未対応)")
            doc.notes.append("非表示レイヤー(OCG)があります。レイヤー内のテキストは可視テキストに含まれる可能性があります。")

    guard("レイヤー", ocg)


def _page_annotations(page: Any, pageno: int, st: _State):
    annots = _ob(page.get("/Annots")) if hasattr(page, "get") else None
    if not annots:
        return
    for a in annots:
        st.budget.check()
        a = _ob(a)
        if not hasattr(a, "get"):
            continue
        where = f"ページ{pageno}"
        subtype = str(_ob(a.get("/Subtype")) or "")
        for key, label in (("/Contents", "注釈本文"), ("/TU", "ツールチップ"), ("/Subj", "注釈の件名"), ("/T", "注釈の作成者欄"),
                           ("/RC", "リッチテキスト注釈")):
            v = a.get(key)
            if v is not None:
                t = _to_text(v)
                if key == "/RC":
                    t = " ".join(re.findall(r">([^<>]+)<", t))
                st.region(t, f"{label}({subtype.lstrip('/')})", where, "annotation")
        act = a.get("/A")
        if act is not None:
            _handle_action(st, act, where)
        aa = _ob(a.get("/AA"))
        if hasattr(aa, "get"):
            for k in list(aa.keys()):
                _handle_action(st, aa.get(k), where)
        if subtype == "/FileAttachment" and a.get("/FS") is not None:
            _embedded_from_filespec(st, a.get("/FS"), where, st.depth)


def _page_has_image_pypdf(page: Any, depth: int = 0) -> bool:
    try:
        res = _ob(page.get("/Resources"))
        xo = _ob(res.get("/XObject")) if hasattr(res, "get") else None
        if not hasattr(xo, "values"):
            return False
        for v in list(xo.values())[:200]:
            v = _ob(v)
            if not hasattr(v, "get"):
                continue
            st = str(_ob(v.get("/Subtype")) or "")
            if st == "/Image":
                return True
            if st == "/Form" and depth < 2 and _page_has_image_pypdf(v, depth + 1):
                return True
    except Exception:
        return False
    return False


def _page_content_pypdf(page: Any) -> bytes:
    try:
        c = page.get_contents()
        if c is None:
            return b""
        data = c.get_data()
        return data[:30_000_000]
    except Exception:
        return b""


# pdfplumber 側: 文字単位の隠し判定
def _overlaps_center(ch: Dict[str, Any], shape: Dict[str, Any]) -> bool:
    cx = (ch["x0"] + ch["x1"]) / 2.0
    cy = (ch["top"] + ch["bottom"]) / 2.0
    return shape["x0"] - 0.5 <= cx <= shape["x1"] + 0.5 and shape["top"] - 0.5 <= cy <= shape["bottom"] + 0.5


def _analyze_page_chars(page: Any, pageno: int, st: _State) -> Tuple[Set[int], int]:
    """隠し文字を HiddenRegion に登録し、(隠し文字の id 集合, 文字数) を返す。"""
    chars = page.chars
    if not chars:
        return set(), 0
    bx0, by0, bx1, by1 = page.bbox
    dark_shapes: Optional[List[Dict[str, Any]]] = None
    images: Optional[List[Dict[str, Any]]] = None
    hidden_ids: Set[int] = set()
    groups: Dict[Tuple[str, str, Optional[str]], List[str]] = {}

    for i, ch in enumerate(chars):
        if i % 3000 == 0:
            st.budget.check()
        reasons: List[str] = []
        kind = "hidden"
        sev: Optional[str] = None
        try:
            if ch["x1"] <= bx0 or ch["x0"] >= bx1 or ch["bottom"] <= by0 or ch["top"] >= by1:
                reasons.append("ページ領域外に配置")
                kind = "offpage"
            size = ch.get("size")
            if size is not None and size < TINY_FONT_PT:
                reasons.append(f"極小フォント({size:.1f}pt)")
            col = ch.get("non_stroking_color")
            if _is_white(col):
                if dark_shapes is None:
                    dark_shapes = []
                    for shp in list(page.rects) + list(page.curves):
                        if not shp.get("fill"):
                            continue
                        rgb = _rgb_of(shp.get("non_stroking_color"))
                        if rgb is not None and _luma(rgb) < DARK_LUMA_MAX:
                            dark_shapes.append(shp)
                if any(_overlaps_center(ch, s) for s in dark_shapes):
                    pass   # 暗い帯の上の白文字は普通のデザイン
                else:
                    if images is None:
                        images = list(page.images)
                    if any(_overlaps_center(ch, im) for im in images):
                        reasons.append("画像上の白文字")
                        sev = "low"
                    else:
                        reasons.append("白色(背景同化)テキスト")
        except Exception:
            continue
        if reasons:
            hidden_ids.add(id(ch))
            groups.setdefault((" + ".join(reasons), kind, sev), []).append(ch.get("text", ""))

    n_hidden = 0
    for (reason, kind, sev), texts in groups.items():
        txt = _norm_ws("".join(texts))
        if len(txt) >= MIN_HIDDEN_LEN:
            n_hidden += len(txt)
            st.region(txt, reason, f"ページ{pageno}", kind, severity=sev)
    return hidden_ids, n_hidden


def _visible_text_plumber(page: Any, hidden_ids: Set[int]) -> str:
    if hidden_ids:
        try:
            fp = page.filter(lambda o: o.get("object_type") != "char" or id(o) not in hidden_ids)
            return fp.extract_text() or ""
        except Exception:
            # filter が失敗したら自前で組み直す。レイアウトは崩れる
            vis = [c for c in page.chars if id(c) not in hidden_ids]
            return _norm_ws("".join(c.get("text", "") for c in vis))
    return page.extract_text() or ""


def _ocr_image_pages(data: bytes, pages: List[int], st: _State) -> Tuple[str, List[str], bool]:
    """(OCR本文, 隠し行, 実行できたか)。pypdfium2 + imagex。"""
    try:
        import pypdfium2 as pdfium  # type: ignore
        from . import imagex
    except Exception:
        return "", [], False
    ok, why = imagex.ocr_available()
    if not ok:
        for n in imagex._engine()[2]:
            if n not in st.doc.notes:
                st.doc.notes.append(n)
        return "", [], False
    texts: List[str] = []
    hidden: List[str] = []
    try:
        pdf = pdfium.PdfDocument(data)
        for idx in pages[:MAX_OCR_PAGES]:
            st.budget.check()
            rem = st.budget.remaining
            if rem is not None and rem < 5:
                st.doc.mark("partial", "時間予算が少ないため残りのページの OCR を省略しました。")
                break
            page = pdf[idx]
            img = page.render(scale=2.0).to_pil()
            res = imagex.ocr_pil_image(img, st.budget, max_variants=3)
            if res.text:
                texts.append(res.text)
            hidden.extend(h for h in res.hidden if h not in hidden)
            for n in res.notes:
                if n not in st.doc.notes:
                    st.doc.notes.append(n)
            if res.partial:
                st.doc.mark("partial", "")
        return "\n".join(texts), hidden, True
    except BudgetExceeded:
        raise
    except Exception as e:  # noqa
        st.doc.mark("partial", f"画像のみPDFの OCR に失敗: {_short(str(e), 100)}")
        return "\n".join(texts), hidden, bool(texts)


def extract_pdf(data: bytes, name: str, limits: Limits, budget: Budget, depth: int = 0) -> ExtractedDoc:
    doc = ExtractedDoc(source=name, kind="pdf", size=len(data or b""))
    try:
        doc.sha256 = hashlib.sha256(data or b"").hexdigest()
    except Exception:
        pass
    try:
        _extract_pdf(doc, data, limits, budget, depth)
    except BudgetExceeded:
        doc.mark("partial", "PDFの解析が時間予算を超過したため途中で打ち切りました。")
    except UnsafeInput as e:
        doc.mark("failed", f"PDFを安全上の理由で拒否しました: {e}")
    except RecursionError:
        doc.mark("failed", "PDFの構造が深すぎて解析できませんでした。")
    except Exception as e:  # noqa
        doc.mark("failed", f"PDF解析中に予期しないエラー: {_short(str(e), 160)}")
    return doc


def _extract_pdf(doc: ExtractedDoc, data: bytes, limits: Limits, budget: Budget, depth: int):
    if not data:
        doc.mark("failed", "PDFデータが空です。")
        return
    if len(data) > limits.max_file_bytes:
        doc.mark("failed", f"PDFが大きすぎます({len(data) // (1024 * 1024)}MB)。")
        return

    try:
        import pdfplumber  # type: ignore
    except Exception:
        pdfplumber = None
    try:
        import pypdf  # type: ignore
    except Exception:
        try:
            import PyPDF2 as pypdf  # type: ignore
        except Exception:
            pypdf = None

    if pdfplumber is None and pypdf is None:
        doc.mark("unsupported", "PDF解析ライブラリ(pdfplumber / pypdf)が未導入のため PDF を解析できません"
                                "(`pip install pdfplumber pypdf`)。")
        return

    st = _State(doc, limits, budget, depth)

    # 暗号化の確認も pypdf 側でやる
    reader = None
    if pypdf is not None:
        try:
            reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
            if getattr(reader, "is_encrypted", False):
                ok = 0
                try:
                    ok = reader.decrypt("")
                except Exception:
                    ok = 0
                if not ok:
                    doc.mark("failed", "暗号化されたPDF(パスワードが必要)のため内容を検査できません。")
                    return
                doc.notes.append("空パスワードで復号して解析しました。")
        except BudgetExceeded:
            raise
        except Exception as e:  # noqa
            reader = None
            doc.notes.append(f"pypdf でPDFを開けませんでした: {_short(str(e), 100)}")

    plumber = None
    if pdfplumber is not None:
        try:
            plumber = pdfplumber.open(io.BytesIO(data), password="")
        except Exception as e:  # noqa
            msg = str(e)
            if "assword" in msg or type(e).__name__.lower().startswith("pdfpassword"):
                doc.mark("failed", "暗号化されたPDF(パスワードが必要)のため内容を検査できません。")
                return
            doc.notes.append(f"pdfplumber でPDFを開けませんでした: {_short(msg, 100)}")
            plumber = None

    if plumber is None and reader is None:
        doc.mark("failed", "PDFを解析できませんでした(壊れている、または非対応のPDFです)。")
        return

    try:
        if reader is not None:
            try:
                _structure_pypdf(reader, st)
            except BudgetExceeded:
                raise
            except Exception as e:  # noqa
                doc.mark("partial", f"PDF構造解析に失敗: {_short(str(e), 100)}")
        else:
            doc.mark("partial", "pypdf 未導入(または読込失敗)のため、しおり・埋め込みファイル・JavaScript・"
                                "フォーム・不可視描画モードの構造解析は簡易検出のみです。")
            _raw_scan(data, st)
            if plumber is not None:
                _plumber_metadata(plumber, st)

        if plumber is None:
            doc.mark("partial", "pdfplumber が使えないため、文字単位の隠し判定(白文字/極小文字/ページ外)は"
                                "未実施です。可視テキストは pypdf で抽出しました。")

        n_pages = len(plumber.pages) if plumber is not None else len(reader.pages)
        total = 0
        visible_parts: List[str] = []
        image_pages: List[int] = []
        tr3_info_pages: List[int] = []
        undecodable_total = 0
        truncated = False

        for pi in range(n_pages):
            budget.check()
            pageno = pi + 1
            py_page = None
            if reader is not None:
                try:
                    py_page = reader.pages[pi]
                except Exception:
                    py_page = None

            has_image = False
            pl_page = None
            if plumber is not None:
                try:
                    pl_page = plumber.pages[pi]
                except Exception as e:  # noqa
                    doc.mark("partial", f"ページ{pageno}を読めませんでした: {_short(str(e), 80)}")
            if py_page is not None:
                has_image = _page_has_image_pypdf(py_page)
            elif pl_page is not None:
                try:
                    has_image = bool(pl_page.images)
                except Exception:
                    has_image = False

            page_text = ""
            hidden_ids: Set[int] = set()
            if pl_page is not None:
                try:
                    hidden_ids, _ = _analyze_page_chars(pl_page, pageno, st)
                    page_text = _visible_text_plumber(pl_page, hidden_ids)
                except BudgetExceeded:
                    raise
                except Exception as e:  # noqa
                    doc.mark("partial", f"ページ{pageno}の文字解析に失敗: {_short(str(e), 80)}")
                    try:
                        page_text = pl_page.extract_text() or ""
                    except Exception:
                        page_text = ""
                finally:
                    try:
                        pl_page.flush_cache()
                    except Exception:
                        pass
            elif py_page is not None:
                try:
                    page_text = py_page.extract_text() or ""
                except Exception as e:  # noqa
                    doc.mark("partial", f"ページ{pageno}のテキスト抽出に失敗: {_short(str(e), 80)}")

            if py_page is not None:
                try:
                    _page_annotations(py_page, pageno, st)
                except BudgetExceeded:
                    raise
                except Exception as e:  # noqa
                    doc.mark("partial", f"ページ{pageno}の注釈解析に失敗: {_short(str(e), 80)}")
                try:
                    aa = _ob(py_page.get("/AA"))
                    if hasattr(aa, "get"):
                        for k in list(aa.keys()):
                            _handle_action(st, aa.get(k), f"ページ{pageno}")
                except Exception:
                    pass

            content = b""
            if py_page is not None:
                content = _page_content_pypdf(py_page)
            elif pl_page is not None:
                content = _page_content_plumber(pl_page)
            if content and _TR3_QUICK.search(content):
                try:
                    lines, undec = _invisible_text_strings(content)
                except Exception:
                    lines, undec = [], 0
                undecodable_total += undec
                if has_image:
                    # スキャン+OCR層は普通に Tr 3 を使う。隠し扱いにせず本文として検査する
                    tr3_info_pages.append(pageno)
                elif lines:
                    hidden_txt = "\n".join(lines)
                    st.region(hidden_txt, "不可視描画モード(Tr 3)のテキスト", f"ページ{pageno}", "hidden")
                    for l in lines:
                        page_text, _ = _remove_from_text(page_text, l)
                elif undec:
                    st.finding("pdf_invisible_text_mode", "hidden_content", "low",
                               "不可視描画モード(Tr 3)のテキストがありますが、文字コードの都合で内容を取り出せませんでした",
                               location=f"ページ{pageno}")
                    doc.mark("partial", f"ページ{pageno}: 不可視描画モードのテキストを復元できませんでした(CIDフォント等)。")

            page_text = page_text.strip()
            if has_image:
                image_pages.append(pi)
            if page_text:
                if total + len(page_text) > limits.max_text_chars:
                    keep = max(0, limits.max_text_chars - total)
                    visible_parts.append(page_text[:keep])
                    total += keep
                    truncated = True
                    break
                visible_parts.append(page_text)
                total += len(page_text)

        if truncated:
            doc.mark("partial", f"テキスト量が上限({limits.max_text_chars}文字)を超えたため、ページ{pageno}以降は未検査です。")

        if tr3_info_pages:
            st.finding("pdf_invisible_text_layer", "hidden_content", "info",
                       "不可視描画モード(Tr 3)のテキスト層があります(スキャン画像のOCR層の可能性)",
                       location="ページ" + ",".join(str(p) for p in tr3_info_pages[:20]))

        if st.uris:
            uniq = list(dict.fromkeys(st.uris))
            st.finding("pdf_uri_links", "active_content", "info",
                       f"PDF内に外部リンク(URI)が{len(uniq)}件あります",
                       snippet=uniq[0], detail="\n".join(uniq[:MAX_LINK_REPORT]))

        text = "\n".join(visible_parts).strip()

        if len(text) < 20 and n_pages > 0 and not truncated:
            if image_pages:
                ocr_text, ocr_hidden, ran = _ocr_image_pages(data, image_pages, st)
                if ran:
                    if ocr_text:
                        text = (text + "\n" + ocr_text).strip()
                    if ocr_hidden:
                        st.region("\n".join(ocr_hidden), "低コントラストの隠し文字(強調時のみ検出)", "画像内", "hidden")
                    if len(image_pages) > MAX_OCR_PAGES:
                        doc.mark("partial", f"画像のみのPDFのため先頭{MAX_OCR_PAGES}ページのみ OCR しました"
                                            f"(全{len(image_pages)}ページ)。")
                else:
                    doc.mark("partial", "本文テキストが無く画像のみの可能性があります。OCRは未実施です"
                                        "(画像内の文字は検査できていません)。")
            elif not doc.hidden_regions:
                doc.mark("partial", "本文テキストを抽出できませんでした(文字がアウトライン化された、"
                                    "または空のPDFの可能性)。")
        elif image_pages and len(image_pages) > 0 and text:
            # 画像内の文字は見ていないのでその旨を残す
            doc.notes.append(f"{len(image_pages)}ページに画像が含まれます。画像内の文字は検査していません"
                             "(本文テキストのみ検査)。")

        # 埋め込みファイルの merge() で入った本文を上書きしない
        doc.text = (text + (doc.text or ""))[:limits.max_text_chars]
    finally:
        if plumber is not None:
            try:
                plumber.close()
            except Exception:
                pass


# pypdf が無いときのフォールバック
def _raw_scan(data: bytes, st: _State):
    """生バイト列の名前だけで JS 等を拾う。圧縮されたオブジェクトの中は見えない。"""
    head = data[:20_000_000]
    if re.search(rb"/JavaScript|/JS\b", head):
        st.js_found = True
        st.finding("pdf_javascript", "active_content", "medium",
                   "PDF内にJavaScriptの記述があります(簡易検出)")
    if re.search(rb"/Launch\b", head):
        st.finding("pdf_launch_action", "active_content", "info", "起動アクション(/Launch)の記述があります(簡易検出)")
    if re.search(rb"/EmbeddedFile\b", head):
        st.finding("pdf_embedded_file", "hidden_content", "low", "埋め込みファイルの記述があります(簡易検出・内容は未検査)")


def _plumber_metadata(plumber: Any, st: _State):
    try:
        lines = []
        for k, v in (plumber.metadata or {}).items():
            if str(k).lstrip("/") in ("CreationDate", "ModDate", "Trapped"):
                continue
            if isinstance(v, bytes):
                v = _to_text(v)
            if isinstance(v, str):
                t = _clean(v)
                if len(t) >= MIN_HIDDEN_LEN and not re.fullmatch(r"D:\d{4,}.*", t) and t.lower() not in _META_BORING:
                    lines.append(f"{str(k).lstrip('/')}: {t}")
        if lines:
            st.region("\n".join(lines), "文書情報(Title/Author/Subject等)", "メタデータ", "metadata")
    except Exception:
        pass


def _page_content_plumber(page: Any) -> bytes:
    try:
        parts = []
        contents = page.page_obj.contents
        if not isinstance(contents, list):
            contents = [contents]
        for s in contents:
            try:
                parts.append(s.get_data())
            except Exception:
                continue
        return b"\n".join(parts)[:30_000_000]
    except Exception:
        return b""
