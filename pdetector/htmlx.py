"""HTML 抽出。html.parser だけで動かす(bs4 の有無で結果がブレるのを避けたい)。

可視テキストは doc.text、人には見えないが LLM は読む部分は doc.hidden_regions に分ける。
hidden 属性・display:none・色の同化・クラス名などで隠しを判定し、コメント/noscript/template/
JSON-LD/meta/各種属性/srcdoc/data: URI も走査対象にする。

領域の severity は、その領域自体を報告するときのヒント。
None=検知器の既定(隠し要素)、"low"=要確認程度、"info"=ルールに当たったときだけ問題にする。
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote_to_bytes

from .encoding import decode_bytes, sniff_declared_charset
from .model import ExtractedDoc, Finding, HiddenRegion
from .safeio import Budget, BudgetExceeded, Limits, UnsafeInput

__all__ = ["extract_html_bytes", "extract_html_text", "parse_color", "parse_style"]

_MAX_DEPTH = 500            # 要素スタックの深さ。超えたら構造解析を手抜きする
_MAX_ATTR_REGIONS = 3000
_MAX_REGION_CHARS = 100_000
_MAX_SUB_DEPTH = 3          # srcdoc / data: の入れ子

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
         "source", "track", "wbr", "command", "keygen", "frame", "basefont", "bgsound"}

_BLOCK = {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "table",
          "ul", "ol", "blockquote", "pre", "header", "footer", "nav", "aside", "main", "form",
          "fieldset", "dl", "dt", "dd", "figure", "figcaption", "address", "hr", "details", "summary",
          "tbody", "thead", "tfoot", "caption", "center", "body", "html", "menu", "dir",
          "legend", "hgroup", "dialog", "iframe", "object", "video", "audio", "canvas", "noscript"}

_CELL = {"td", "th", "button", "option", "select", "optgroup", "textarea"}

_INLINE = {"a", "b", "i", "em", "strong", "span", "u", "small", "sub", "sup", "font", "mark", "code",
           "abbr", "cite", "q", "s", "big", "strike", "tt", "var", "kbd", "samp", "bdi", "bdo", "label",
           "ins", "del", "dfn", "time", "data", "ruby", "rt", "rp", "wbr", "img", "svg", "text", "tspan"}

_P_CLOSERS = {"address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset",
              "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
              "hr", "main", "menu", "nav", "ol", "p", "pre", "section", "table", "ul"}

_HIDE_CLASSES = {"hidden", "d-none", "display-none", "invisible", "is-hidden", "u-hidden", "hide"}
_SR_CLASSES = {"sr-only", "visually-hidden", "screen-reader-text", "sr_only", "visuallyhidden",
               "screen-reader-only"}

_TEXT_ATTRS = {"title", "aria-label", "aria-description", "aria-roledescription", "aria-placeholder",
               "aria-valuetext", "placeholder", "label", "value", "summary", "abbr", "alt"}

_BENIGN_META = {"viewport", "charset", "theme-color", "format-detection", "robots", "googlebot",
                "referrer", "color-scheme", "generator", "mobile-web-app-capable", "twitter:card",
                "twitter:site", "og:type", "og:url", "og:image", "og:locale", "content-type",
                "x-ua-compatible", "application-name", "msapplication-tilecolor", "msapplication-config",
                "apple-mobile-web-app-capable", "apple-mobile-web-app-status-bar-style", "hostname",
                "google-site-verification", "msvalidate.01", "yandex-verification"}

_URL_PLACEHOLDER = re.compile(r"\{\{|\{%|\[\[|<%|\$\{|%7B%7B|%7b%7b|%24%7B|%24%7b|\{[A-Za-z_]+\}")
_JS_TYPES = ("javascript", "ecmascript", "module", "babel", "jsx", "text/jscript")
_NAMED_COLORS = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0),
    "blue": (0, 0, 255), "yellow": (255, 255, 0), "gray": (128, 128, 128), "grey": (128, 128, 128),
    "silver": (192, 192, 192), "navy": (0, 0, 128), "maroon": (128, 0, 0), "purple": (128, 0, 128),
    "orange": (255, 165, 0), "lime": (0, 255, 0), "aqua": (0, 255, 255), "cyan": (0, 255, 255),
    "fuchsia": (255, 0, 255), "magenta": (255, 0, 255), "teal": (0, 128, 128), "olive": (128, 128, 0),
    "whitesmoke": (245, 245, 245), "snow": (255, 250, 250), "ivory": (255, 255, 240),
    "ghostwhite": (248, 248, 255), "floralwhite": (255, 250, 240), "aliceblue": (240, 248, 255),
    "honeydew": (240, 255, 240), "mintcream": (245, 255, 250), "azure": (240, 255, 255),
    "seashell": (255, 245, 238), "lavenderblush": (255, 240, 245), "linen": (250, 240, 230),
    "oldlace": (253, 245, 230), "beige": (245, 245, 220), "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211), "darkgray": (169, 169, 169), "darkgrey": (169, 169, 169),
    "dimgray": (105, 105, 105), "dimgrey": (105, 105, 105), "gainsboro": (220, 220, 220),
    "darkblue": (0, 0, 139), "darkred": (139, 0, 0), "darkgreen": (0, 100, 0), "brown": (165, 42, 42),
    "pink": (255, 192, 203), "gold": (255, 215, 0), "indigo": (75, 0, 130), "violet": (238, 130, 238),
    "tan": (210, 180, 140), "coral": (255, 127, 80), "crimson": (220, 20, 60),
    "midnightblue": (25, 25, 112), "slategray": (112, 128, 144), "slategrey": (112, 128, 144),
}


# CSS
def parse_style(s: str) -> Dict[str, str]:
    """宣言ブロックを {プロパティ: 値} に。括弧や引用符の中の ; では区切らない。"""
    out: Dict[str, str] = {}
    if not s:
        return out
    buf: List[str] = []
    depth = 0
    quote = ""
    parts: List[str] = []
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        k = k.strip().lower()
        v = re.sub(r"\s*!important\s*$", "", v.strip(), flags=re.I).strip().lower()
        if k and v:
            out[k] = v
    return out


_SEL_RE = re.compile(r"^([a-z][a-z0-9-]*)?(#[\w-]+)?((?:\.[\w-]+)*)$", re.I)


class _Rule:
    __slots__ = ("idx", "tag", "id", "classes", "decls")

    def __init__(self, idx, tag, id_, classes, decls):
        self.idx, self.tag, self.id, self.classes, self.decls = idx, tag, id_, classes, decls


def _parse_stylesheets(raw: str):
    """<style> から単純セレクタ(.class #id tag tag.class)のルールだけ拾う。"""
    by_id: Dict[str, List[_Rule]] = {}
    by_class: Dict[str, List[_Rule]] = {}
    by_tag: Dict[str, List[_Rule]] = {}
    n = 0
    for m in re.finditer(r"<style\b[^>]*>(.*?)(?:</style\s*>|\Z)", raw, re.I | re.S):
        css = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
        i, L = 0, len(css)
        while i < L:
            j = css.find("{", i)
            if j < 0:
                break
            prelude = css[i:j].strip()
            if prelude.startswith("@"):
                # @media 等は中身ごと飛ばす。波括弧の対応は数える
                depth, k = 1, j + 1
                while k < L and depth:
                    c = css[k]
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                    k += 1
                i = k
                continue
            k = css.find("}", j + 1)
            if k < 0:
                k = L
            decls = parse_style(css[j + 1:k])
            i = k + 1
            if not decls:
                continue
            for sel in prelude.split(","):
                sel = sel.strip()
                mm = _SEL_RE.match(sel)
                if not sel or not mm:
                    continue
                tag = (mm.group(1) or "").lower()
                id_ = (mm.group(2) or "")[1:]
                classes = tuple(c for c in (mm.group(3) or "").split(".") if c)
                if not (tag or id_ or classes):
                    continue
                n += 1
                r = _Rule(n, tag, id_, classes, decls)
                if id_:
                    by_id.setdefault(id_, []).append(r)
                elif classes:
                    by_class.setdefault(classes[0], []).append(r)
                else:
                    by_tag.setdefault(tag, []).append(r)
    return by_id, by_class, by_tag


def _px(v: str, pct_base: Optional[float] = None) -> Optional[float]:
    """px に換算。できなければ None。"""
    m = re.fullmatch(r"\s*(-?\d*\.?\d+)\s*(px|pt|em|rem|%|cm|mm|in|ex|ch)?\s*", v or "")
    if not m:
        return None
    x = float(m.group(1))
    u = m.group(2) or "px"
    if u == "px":
        return x
    if u == "pt":
        return x * 1.3333
    if u in ("em", "rem"):
        return x * 16
    if u == "ex" or u == "ch":
        return x * 8
    if u == "cm":
        return x * 37.8
    if u == "mm":
        return x * 3.78
    if u == "in":
        return x * 96
    if u == "%":
        return None if pct_base is None else x * pct_base / 100.0
    return None


def _ratio(v: str) -> Optional[float]:
    v = (v or "").strip()
    try:
        if v.endswith("%"):
            return float(v[:-1]) / 100.0
        return float(v)
    except ValueError:
        return None


_COLOR_CACHE: Dict[str, Optional[Tuple[int, int, int, float]]] = {}


def parse_color(s: str) -> Optional[Tuple[int, int, int, float]]:
    """CSS 色を (r,g,b,alpha) に。読めなければ None。"""
    if s is None:
        return None
    if s in _COLOR_CACHE:
        return _COLOR_CACHE[s]
    res = _parse_color(s)
    if len(_COLOR_CACHE) < 5000:
        _COLOR_CACHE[s] = res
    return res


def _parse_color(s: str):
    t = s.strip().lower()
    t = re.sub(r"\s*!important\s*$", "", t).strip()
    if t == "transparent":
        return (0, 0, 0, 0.0)
    if t.startswith("#"):
        h = t[1:]
        if not re.fullmatch(r"[0-9a-f]+", h or "x"):
            return None
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) == 6:
            h += "ff"
        if len(h) != 8:
            return None
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), int(h[6:8], 16) / 255.0)
    m = re.fullmatch(r"(rgba?|hsla?)\((.*)\)", t)
    if m:
        fn, inner = m.group(1), m.group(2).strip()
        parts = [p for p in re.split(r"[\s,/]+", inner) if p]
        if len(parts) < 3:
            return None
        try:
            alpha = 1.0
            if len(parts) >= 4:
                a = parts[3]
                alpha = float(a[:-1]) / 100.0 if a.endswith("%") else float(a)
            if fn.startswith("rgb"):
                vals = []
                for p in parts[:3]:
                    vals.append(float(p[:-1]) * 2.55 if p.endswith("%") else float(p))
                r, g, b = (max(0, min(255, int(round(v)))) for v in vals)
                return (r, g, b, max(0.0, min(1.0, alpha)))
            h = float(parts[0].replace("deg", "")) % 360 / 360.0
            sat = float(parts[1].rstrip("%")) / 100.0
            lig = float(parts[2].rstrip("%")) / 100.0
            r, g, b = _hsl_to_rgb(h, sat, lig)
            return (r, g, b, max(0.0, min(1.0, alpha)))
        except ValueError:
            return None
    if t in _NAMED_COLORS:
        r, g, b = _NAMED_COLORS[t]
        return (r, g, b, 1.0)
    return None


def _hsl_to_rgb(h, s, l):
    if s == 0:
        v = int(round(l * 255))
        return v, v, v

    def f(p, q, t):
        t %= 1.0
        if t < 1 / 6:
            return p + (q - p) * 6 * t
        if t < 1 / 2:
            return q
        if t < 2 / 3:
            return p + (q - p) * (2 / 3 - t) * 6
        return p

    q = l * (1 + s) if l < 0.5 else l + s - l * s
    p = 2 * l - q
    return tuple(int(round(f(p, q, h + d) * 255)) for d in (1 / 3, 0, -1 / 3))


def _luminance(c) -> float:
    return (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255.0


def _near_white(c) -> bool:
    return c is not None and c[3] > 0.05 and min(c[0], c[1], c[2]) >= 240


def _close(a, b, tol: int = 24) -> bool:
    return max(abs(a[0] - b[0]), abs(a[1] - b[1]), abs(a[2] - b[2])) <= tol


_BG_TOKEN = re.compile(r"rgba?\([^)]*\)|hsla?\([^)]*\)|#[0-9a-f]{3,8}\b|[a-z]+", re.I)


def _parse_bg(decls: Dict[str, str]):
    """色タプル / "image" / None(指定なし・透明)。"""
    bc = decls.get("background-color")
    if bc:
        for tok in _BG_TOKEN.findall(bc):
            c = parse_color(tok)
            if c is not None:
                return c if c[3] >= 0.5 else None
    sh = decls.get("background")
    if sh:
        if "url(" in sh or "gradient" in sh:
            return "image"
        for tok in _BG_TOKEN.findall(sh):
            c = parse_color(tok)
            if c is not None:
                return c if c[3] >= 0.5 else None
    bi = decls.get("background-image")
    if bi and ("url(" in bi or "gradient" in bi):
        return "image"
    return None


def _strong_hide(d: Dict[str, str], attrs: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """(理由, 子が打ち消せるキー)。隠しでなければ None。"""
    if "hidden" in attrs:
        return "hidden属性", ""
    if d.get("display") == "none":
        return "display:none", ""
    vis = d.get("visibility")
    if vis in ("hidden", "collapse"):
        return f"visibility:{vis}", "visibility"
    op = d.get("opacity")
    if op is not None:
        f = _ratio(op)
        if f is not None and f <= 0.05:
            return f"opacity:{op}", ""
    fo = d.get("fill-opacity")
    if fo is not None:
        f = _ratio(fo)
        if f is not None and f <= 0.05:
            return f"fill-opacity:{fo}", ""
    fs = d.get("font-size")
    if fs is not None:
        px = _px(fs, 16.0)
        if px is not None and px <= 2.0:
            return f"font-size:{fs}", "font-size"
    col = d.get("color")
    if col is not None:
        c = parse_color(col)
        if c is not None and c[3] <= 0.05:
            return "透明な文字色(color:transparent / alpha≈0)", "color"
    clip = d.get("clip")
    if clip and re.fullmatch(r"rect\(\s*0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?\s*\)", clip):
        return "clip:rect(0,0,0,0)", ""
    cp = d.get("clip-path")
    if cp:
        m = re.fullmatch(r"inset\(\s*(\d+(?:\.\d+)?)%.*\)", cp)
        if (m and float(m.group(1)) >= 50) or re.fullmatch(r"circle\(\s*0(?:px|%)?\b.*\)", cp):
            return f"clip-path:{cp}", ""
    ov = (d.get("overflow") == "hidden" or d.get("overflow-x") == "hidden" or d.get("overflow-y") == "hidden")
    if ov:
        def small(key, lim):
            v = d.get(key)
            if v is None:
                return False
            px = _px(v, 16.0)
            return px is not None and px <= lim
        h0, w0 = small("height", 0.0), small("width", 0.0)
        mh0, mw0 = small("max-height", 0.0), small("max-width", 0.0)
        if h0 or w0 or mh0 or mw0:
            return "サイズ0かつoverflow:hidden", ""
        if small("height", 1.0) and small("width", 1.0):
            return "1px四方かつoverflow:hidden", ""
    ti = d.get("text-indent")
    if ti:
        px = _px(ti)
        if px is not None and px <= -500:
            return f"text-indent:{ti}(画面外へ押し出し)", ""
    if d.get("position") in ("absolute", "fixed"):
        for key in ("left", "top", "margin-left", "right", "bottom"):
            v = d.get(key)
            if v is None:
                continue
            px = _px(v)
            if px is not None and px <= -500:
                return f"画面外配置({key}:{v})", ""
    tr = d.get("transform")
    if tr and re.search(r"scale(?:3d|x|y)?\(\s*0(?:\.0+)?\s*[,)]", tr):
        return "transform:scale(0)", ""
    return None


def _override(key: str, d: Dict[str, str]) -> bool:
    """親の隠しを子の宣言が打ち消しているか。"""
    if key == "font-size":
        px = _px(d.get("font-size", ""), 16.0) if "font-size" in d else None
        return px is not None and px > 2.0
    if key == "visibility":
        return d.get("visibility") == "visible"
    if key == "color":
        c = parse_color(d["color"]) if "color" in d else None
        return c is not None and c[3] > 0.05
    return False


class _Region:
    __slots__ = ("reason", "severity", "key", "color_based", "location", "parts", "sig")

    def __init__(self, reason, severity, key, color_based, location):
        self.reason, self.severity, self.key = reason, severity, key
        self.color_based, self.location = color_based, location
        self.parts: List[str] = []
        self.sig = (reason, severity, color_based)


class _El:
    __slots__ = ("tag", "region", "owns", "color", "bg", "svg", "pre", "attrs")

    def __init__(self, tag, region, owns, color, bg, svg, pre):
        self.tag, self.region, self.owns, self.color, self.bg = tag, region, owns, color, bg
        self.svg, self.pre = svg, pre


def _describe(tag: str, attrs: Dict[str, str]) -> str:
    s = tag
    if attrs.get("id"):
        s += "#" + attrs["id"][:30]
    cls = (attrs.get("class") or "").split()
    if cls:
        s += "." + cls[0][:30]
    return s


def _tidy(s: str) -> str:
    s = s.replace("\xa0", " ")
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r" ?\n ?", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _worth(v: str) -> bool:
    """短い値や URL/ID っぽい1語は走査しない。"""
    v = v.strip()
    if len(v) < 3:
        return False
    if re.fullmatch(r"-?\d+(?:\.\d+)?", v):
        return False
    if not re.search(r"\s", v):
        if v.lower().startswith(("http://", "https://", "//", "/", "#", "data:", "mailto:", "tel:", "javascript:")):
            return False
        if len(v) < 24 and re.fullmatch(r"[A-Za-z0-9_\-.:/#?=&%@+~,;]*", v):
            return False
    return True


def _json_strings(obj, out: List[str], depth: int = 0):
    if depth > 30 or len(out) > 2000:
        return
    if isinstance(obj, str):
        if _worth(obj):
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _json_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _json_strings(v, out, depth + 1)


def _parse_data_uri(uri: str):
    m = re.match(r"data:([^,]*),(.*)$", uri.strip(), re.I | re.S)
    if not m:
        return None, None
    meta, payload = m.group(1), m.group(2)
    mt = (meta.split(";")[0].strip().lower()) or "text/plain"
    try:
        if meta.lower().endswith(";base64"):
            p = re.sub(r"\s+", "", unquote_to_bytes(payload).decode("latin-1"))
            data = base64.b64decode(p + "=" * (-len(p) % 4))
        else:
            data = unquote_to_bytes(payload)
    except (binascii.Error, ValueError):
        return mt, None
    return mt, data[:2_000_000]


class _Extractor(HTMLParser):
    def __init__(self, doc: ExtractedDoc, rules, limits: Limits, budget: Optional[Budget], depth: int):
        super().__init__(convert_charrefs=True)
        self.doc, self.limits, self.budget, self.depth = doc, limits, budget, depth
        self.by_id, self.by_class, self.by_tag = rules
        self.has_rules = bool(self.by_id or self.by_class or self.by_tag)
        self.root = _El("#root", None, False, None, None, False, False)
        self.stack: List[_El] = []
        self.out: List[str] = []
        self.regions: List[HiddenRegion] = []
        self.findings: List[Finding] = []
        self.cap: Optional[Tuple[str, _El, Dict[str, str]]] = None   # script/style/title/textarea/svg-title の収集
        self.cap_buf: List[str] = []
        self.nev = 0
        self.truncated = False
        self.seen_attr = set()
        self.n_attr = 0
        self.ext_refs = 0

    @property
    def _top(self) -> _El:
        return self.stack[-1] if self.stack else self.root

    def _tick(self):
        self.nev += 1
        if self.budget is not None and (self.nev & 255) == 0:
            self.budget.check()

    def _emit(self, text: str):
        top = self._top
        parts = top.region.parts if top.region is not None else self.out
        if text == "\n" or text == " ":
            # ブロックの終了と開始が重なって空行が増えるのを防ぐ
            if parts:
                last = parts[-1]
                if last.endswith("\n") or (text == " " and last.endswith(" ")):
                    return
            elif text == " ":
                return
        parts.append(text)

    def _add_region(self, text: str, reason: str, location: str, kind: str, severity: Optional[str]):
        text = _tidy(text)
        if not text:
            return
        if len(text) > _MAX_REGION_CHARS:
            text = text[:_MAX_REGION_CHARS]
        if kind in ("attribute", "metadata", "comment"):
            key = (kind, reason, text)
            if key in self.seen_attr:
                return
            self.seen_attr.add(key)
            self.n_attr += 1
            if self.n_attr > _MAX_ATTR_REGIONS:
                if self.n_attr == _MAX_ATTR_REGIONS + 1:
                    self.doc.mark("partial", f"属性/コメント由来の領域が多すぎるため先頭 {_MAX_ATTR_REGIONS} 件のみ解析しました。")
                return
        self.regions.append(HiddenRegion(text=text, reason=reason, location=location, kind=kind, severity=severity))

    def _finish_region(self, reg: _Region):
        self._add_region("".join(reg.parts), reg.reason, reg.location, "hidden", reg.severity)

    def _attr_region(self, text: str, reason: str, tag: str, severity: Optional[str] = "info", kind: str = "attribute"):
        top = self._top
        if top.region is not None and kind == "attribute" and severity == "info":
            # 隠し要素内の属性値は、その領域に入れて重大度を引き継ぐ
            top.region.parts.append("\n" + text + "\n")
            return
        self._add_region(text, reason, tag, kind, severity)

    def _decls(self, tag: str, attrs: Dict[str, str], in_svg: bool) -> Dict[str, str]:
        d: Dict[str, str] = {}
        if self.has_rules:
            cand: List[_Rule] = []
            id_ = attrs.get("id")
            if id_ and id_ in self.by_id:
                cand += self.by_id[id_]
            cls = attrs.get("class")
            classes = cls.split() if cls else []
            for c in classes:
                if c in self.by_class:
                    cand += self.by_class[c]
            if tag in self.by_tag:
                cand += self.by_tag[tag]
            if cand:
                cand.sort(key=lambda r: r.idx)
                cs = set(classes)
                for r in cand:
                    if r.tag and r.tag != tag:
                        continue
                    if r.id and r.id != id_:
                        continue
                    if r.classes and not set(r.classes) <= cs:
                        continue
                    d.update(r.decls)
        st = attrs.get("style")
        if st:
            d.update(parse_style(st))
        if in_svg:
            for k in ("font-size", "opacity", "display", "visibility", "fill", "fill-opacity"):
                if k in attrs and k not in d:
                    d[k] = attrs[k].strip().lower()
        return d

    # 開始タグ
    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, False)

    def handle_startendtag(self, tag, attrs):
        self._start(tag, attrs, True)

    def _implied_close(self, tag: str):
        st = self.stack
        if not st:
            return
        if tag in _P_CLOSERS:
            for i in range(len(st) - 1, -1, -1):
                t = st[i].tag
                if t == "p":
                    self._pop_to(i)
                    return
                if t not in _INLINE:
                    return
        elif tag == "li":
            self._pop_nearest(("li",), ("ul", "ol", "menu"))
        elif tag in ("dt", "dd"):
            self._pop_nearest(("dt", "dd"), ("dl",))
        elif tag in ("td", "th"):
            self._pop_nearest(("td", "th"), ("tr", "table"))
        elif tag == "tr":
            self._pop_nearest(("tr",), ("table",))
        elif tag in ("thead", "tbody", "tfoot"):
            self._pop_nearest(("thead", "tbody", "tfoot"), ("table",))
        elif tag == "option":
            self._pop_nearest(("option",), ("select", "datalist", "optgroup"))

    def _pop_nearest(self, targets, boundaries):
        st = self.stack
        for i in range(len(st) - 1, -1, -1):
            t = st[i].tag
            if t in targets:
                self._pop_to(i)
                return
            if t in boundaries:
                return

    def _pop_to(self, i: int):
        while len(self.stack) > i:
            self._close_el(self.stack.pop())

    def _start(self, tag: str, attr_list, selfclosing: bool):
        self._tick()
        tag = tag.lower()
        if self.cap is not None and self.cap[0] in ("script", "style"):
            return
        attrs: Dict[str, str] = {}
        for k, v in attr_list:
            k = k.lower()
            if k not in attrs:
                attrs[k] = v if v is not None else ""
        self._implied_close(tag)
        parent = self._top
        in_svg = parent.svg or tag == "svg"
        decls = self._decls(tag, attrs, in_svg)

        # 色と背景は親から継承
        color = parent.color
        if "color" in decls:
            c = parse_color(decls["color"])
            if c is not None:
                color = c
        if in_svg and "fill" in decls:
            c = parse_color(decls["fill"])
            if c is not None:
                color = c
        bg = parent.bg
        if "background" in decls or "background-color" in decls or "background-image" in decls:
            nb = _parse_bg(decls)
            if nb is not None:
                bg = nb

        reg = parent.region
        owns = False
        if reg is not None and reg.key and _override(reg.key, decls):
            reg = None
        if reg is not None and reg.color_based:
            reg = None      # 色ベースの隠しは要素ごとにやり直す
        if reg is None:
            info = None
            sh = _strong_hide(decls, attrs)
            if tag == "noscript":
                sh = ("noscript", "")
            elif tag == "template":
                sh = ("template", "")
            if sh:
                info = (sh[0], None, sh[1], False)
            else:
                classes = {c.lower() for c in (attrs.get("class") or "").split()}
                if classes & _HIDE_CLASSES:
                    info = ("隠しクラス(要確認)", "low", "", False)
                elif classes & _SR_CLASSES:
                    info = ("スクリーンリーダー専用(視覚的に非表示)", "low", "", False)
                elif color is not None and _near_white(color):
                    if isinstance(bg, tuple):
                        if _close(color, bg):
                            info = (f"文字色が背景色と同化(文字色={color[:3]}, 背景色={bg[:3]})", None, "", True)
                    else:
                        info = ("背景不明の白文字", "low", "", True)
                elif isinstance(bg, tuple) and color is not None and _close(color, bg) and bg[3] >= 0.5 and color[3] >= 0.5:
                    info = (f"文字色が背景色と同化(文字色={color[:3]}, 背景色={bg[:3]})", None, "", True)
            if info is not None:
                pr = parent.region
                if pr is not None and pr.color_based and info[3] and pr.sig == (info[0], info[1], True):
                    reg = pr            # 同じ色の隠しが続くだけなので親の領域にまとめる
                else:
                    reg = _Region(info[0], info[1], info[2], info[3], _describe(tag, attrs))
                    owns = True

        is_block = tag in _BLOCK
        if is_block:
            self._emit("\n")
        elif tag in _CELL:
            self._emit(" ")

        el = _El(tag, reg, owns, color, bg, in_svg, parent.pre or tag in ("pre", "textarea"))
        void = tag in _VOID or (selfclosing and (in_svg or tag in _VOID))

        # 属性は領域に入る前の親の文脈で処理する
        self._attrs(tag, attrs, el, void)

        if tag == "br":
            self._emit("\n")
        if void:
            if owns and reg is not None:
                self._finish_region(reg)
            return

        if tag in ("script", "style"):
            self.cap, self.cap_buf = (tag, el, attrs), []
        elif tag == "title" and not in_svg:
            self.cap, self.cap_buf = ("title", el, attrs), []
        elif tag == "textarea":
            self.cap, self.cap_buf = ("textarea", el, attrs), []
        elif in_svg and tag in ("title", "desc"):
            self.cap, self.cap_buf = ("svgmeta", el, attrs), []

        if len(self.stack) >= _MAX_DEPTH and self.cap is None:
            if not self.truncated:
                self.truncated = True
                self.doc.mark("partial", f"HTML のネストが {_MAX_DEPTH} 階層を超えたため、以降は構造(隠し判定)の解析を簡略化しました。")
            if owns and reg is not None:
                self._finish_region(reg)
            return
        self.stack.append(el)
        if selfclosing and not in_svg:
            pass    # 仕様上、非void要素の /> は無視される。開いたまま
        elif selfclosing and in_svg:
            self._pop_to(len(self.stack) - 1)

    def _attrs(self, tag: str, attrs: Dict[str, str], el: _El, void: bool):
        if not attrs:
            return
        # alt/title は画像が出ないとき見える文字なので可視扱い
        if tag == "img":
            for k in ("alt", "title"):
                v = (attrs.get(k) or "").strip()
                if v and len(v) >= 2:
                    (el.region.parts if el.region is not None else self.out).append(f"\n{v}\n")
        for k, v in attrs.items():
            if not v:
                continue
            if tag == "img" and k in ("alt", "title"):
                continue
            if k in _TEXT_ATTRS or k.startswith("data-") or (k.startswith("aria-") and k.endswith(("label", "description"))):
                vv = v.strip()
                if k.startswith("data-") and vv[:1] in "{[" :
                    try:
                        strs: List[str] = []
                        _json_strings(json.loads(vv), strs)
                        for s in strs:
                            self._attr_region(s, f"属性 {k}(JSON)", tag)
                        continue
                    except (ValueError, RecursionError):
                        pass
                if _worth(vv):
                    self._attr_region(vv, f"属性 {k}", tag)
        st_attr = attrs.get("style")
        if st_attr and "content" in st_attr:
            self._css_strings(st_attr, tag)
        # URL にテンプレート変数があれば持ち出しを疑う
        for uk in ("href", "action", "formaction", "src", "data", "poster", "background"):
            uv = (attrs.get(uk) or "").strip()
            if uv and _URL_PLACEHOLDER.search(uv):
                self._add_region(uv[:600], f"属性 {uk} の URL にテンプレート変数", tag, "attribute", "info")
        if tag == "meta" and attrs.get("content"):
            name = (attrs.get("name") or attrs.get("property") or attrs.get("http-equiv") or "").strip().lower()
            content = attrs["content"].strip()
            if name == "refresh":
                if _URL_PLACEHOLDER.search(content):
                    self._add_region(content[:600], "meta refresh の URL にテンプレート変数", "meta", "attribute", "info")
                self.findings.append(Finding(
                    rule_id="html_meta_refresh", category="active_content", severity="info",
                    description="meta refresh による自動遷移", snippet=content[:160], location="meta"))
            elif name not in _BENIGN_META and not name.startswith(("msapplication-", "apple-")) and _worth(content):
                self._add_region(content, f"meta {name or '(名前なし)'}", "meta", "metadata", "info")
        if "srcdoc" in attrs and attrs["srcdoc"].strip():
            self._srcdoc(attrs["srcdoc"], el)
        href = attrs.get("href") if tag in ("a", "area") else None
        if href:
            h = href.strip()
            hl = h.lower()
            if hl.startswith("javascript:"):
                self.findings.append(Finding(
                    rule_id="html_js_link", category="active_content", severity="medium",
                    description="javascript: リンク(クリックでスクリプト実行)", snippet=h[:160], location=tag))
                body = h[11:]
                if _worth(body):
                    self._add_region(body, "javascript: リンク", tag, "attribute", "info")
            elif hl.startswith("data:"):
                self._data_uri(h, tag)
        if tag in ("iframe", "object", "embed", "frame"):
            u = attrs.get("src") or attrs.get("data") or ""
            if u.strip().lower().startswith("data:"):
                self._data_uri(u.strip(), tag)
            elif u.strip() and self.ext_refs < 20:
                self.ext_refs += 1
                self.findings.append(Finding(
                    rule_id="html_external_ref", category="active_content", severity="info",
                    description=f"外部コンテンツの参照(<{tag}>)。取得内容はこのスキャンの対象外です",
                    snippet=u.strip()[:160], location=tag))

    def _data_uri(self, uri: str, tag: str):
        mt, data = _parse_data_uri(uri)
        if data is None and mt is None:
            return
        self.findings.append(Finding(
            rule_id="html_data_uri_link", category="active_content", severity="low",
            description=f"data: URI の埋め込み({mt or '不明'})", snippet=uri[:100], location=tag))
        if not data:
            return
        if self.depth >= _MAX_SUB_DEPTH:
            self.doc.mark("partial", "data: URI の入れ子が深いため一部を解析していません。")
            return
        if mt in ("text/html", "application/xhtml+xml"):
            sub = ExtractedDoc(source=self.doc.source, kind="html")
            text, _, _ = decode_bytes(data, sniff_declared_charset(data))
            extract_html_text(text, sub, self.limits, self.budget, _depth=self.depth + 1)
            self._add_region(sub.text, "data: URI(HTML)", tag, "attribute", "info")
            self.regions.extend(sub.hidden_regions)
            self.findings.extend(sub.findings)
        elif mt.startswith("text/") or mt in ("application/json", "application/xml"):
            text, _, _ = decode_bytes(data)
            self._add_region(text, f"data: URI({mt})", tag, "attribute", "info")

    def _srcdoc(self, srcdoc: str, el: _El):
        if self.depth >= _MAX_SUB_DEPTH:
            self.doc.mark("partial", "iframe srcdoc の入れ子が深いため一部を解析していません。")
            return
        sub = ExtractedDoc(source=self.doc.source, kind="html")
        extract_html_text(srcdoc, sub, self.limits, self.budget, _depth=self.depth + 1)
        if sub.text:
            (el.region.parts if el.region is not None else self.out).append("\n" + sub.text + "\n")
        self.regions.extend(sub.hidden_regions)
        self.findings.extend(sub.findings)

    def handle_endtag(self, tag):
        self._tick()
        tag = tag.lower()
        if self.cap is not None and self.cap[0] in ("script", "style") and self.cap[1].tag != tag:
            return      # script/style 中の他の終了タグは無視
        if tag == "br":
            self._emit("\n")
            return
        if tag in _VOID:
            return
        st = self.stack
        for i in range(len(st) - 1, -1, -1):
            if st[i].tag == tag:
                self._pop_to(i)
                break

    def _close_el(self, el: _El):
        if self.cap is not None and self.cap[1] is el:
            self._flush_capture(el)
        if el.owns and el.region is not None:
            self._finish_region(el.region)
        if el.tag in _BLOCK:
            self._emit("\n")
        elif el.tag in _CELL:
            self._emit(" ")

    def _flush_capture(self, el: _El):
        kind, _el, attrs = self.cap
        raw = "".join(self.cap_buf)
        self.cap, self.cap_buf = None, []
        loc = _describe(el.tag, attrs)
        if kind == "style":
            self._css_strings(raw, loc)
            return
        if kind == "script":
            stype = (attrs.get("type") or "").strip().lower()
            if not stype or any(j in stype for j in _JS_TYPES):
                self._js_strings(raw, loc)
                return
            if "json" in stype:
                try:
                    strs: List[str] = []
                    _json_strings(json.loads(raw), strs)
                    text = "\n".join(strs)
                except (ValueError, RecursionError):
                    text = raw
                self._attr_region(text, f"スクリプト({stype})", loc, "info", "metadata")
            else:
                self._attr_region(raw, f"スクリプト({stype})", loc, "info", "metadata")
        elif kind == "title":
            self._attr_region(raw, "<title>", loc, "info", "metadata")
        elif kind == "textarea":
            if el.region is not None:
                el.region.parts.append("\n" + raw + "\n")
            else:
                self._add_region(raw, "textarea の内容", loc, "attribute", "info")
        elif kind == "svgmeta":
            self._attr_region(raw, f"SVG <{el.tag}>", loc, "info", "attribute")

    # CSS / JS 内の文章
    def _css_strings(self, css: str, loc: str):
        """content:"…" の文字と CSS コメント。ルールに当たったときだけ報告(info)。"""
        n = 0
        for m in re.finditer(r"content\s*:\s*([\"'])((?:\\.|(?!\1)[^\\\n]){8,}?)\1", css):
            self._attr_region(m.group(2), "CSS の content(擬似要素のテキスト)", loc, "info", "attribute")
            n += 1
            if n >= 100:
                break
        for m in re.finditer(r"/\*(.{12,}?)\*/", css, re.S):
            self._attr_region(m.group(1).strip(), "CSS コメント", loc, "info", "comment")
            n += 1
            if n >= 200:
                break

    def _js_strings(self, js: str, loc: str):
        """スクリプト内の文章っぽい文字列とコメント(25文字以上で空白あり)。"""
        n = 0
        for m in re.finditer(r"([\"'`])((?:\\.|(?!\1)[^\\\n]){25,300}?)\1", js):
            v = m.group(2)
            if v.count(" ") >= 3:
                self._attr_region(v, "スクリプト内の文字列", loc, "info", "attribute")
                n += 1
                if n >= 200:
                    break
        for m in re.finditer(r"//([^\n]{20,300})|/\*(.{20,2000}?)\*/", js, re.S):
            v = (m.group(1) or m.group(2) or "").strip()
            if v.count(" ") >= 3 and not v.startswith(("http:", "https:")):
                self._attr_region(v, "スクリプト内のコメント", loc, "info", "comment")
                n += 1
                if n >= 300:
                    break

    def handle_data(self, data):
        if self.cap is not None:
            self.cap_buf.append(data)
            return
        top = self._top
        if not top.pre:
            data = re.sub(r"\s+", " ", data)
        if not data.strip():
            if data:
                self._emit(" ")
            return
        self._emit(data)

    def handle_comment(self, data):
        text = data.strip()
        if not text:
            return
        sev = "info" if (text.startswith(("[if", "[endif", "<![endif")) or len(text) < 20) else None
        self._add_region(text, "HTMLコメント", "html_comment", "comment", sev)

    def finalize(self):
        while self.stack:
            self._close_el(self.stack.pop())
        if self.cap is not None:
            self._flush_capture(self.cap[1])


def _close_unterminated_comments(raw: str) -> str:
    """閉じ忘れの <!-- を閉じる。HTML5 だと残り全部がコメントになるので。"""
    pos = 0
    while True:
        i = raw.find("<!--", pos)
        if i < 0:
            return raw
        j = raw.find("-->", i + 4)
        if j < 0:
            return raw + "-->"
        pos = j + 3


def extract_html_text(raw: str, doc: ExtractedDoc, limits: Optional[Limits] = None,
                      budget: Optional[Budget] = None, _depth: int = 0) -> ExtractedDoc:
    """HTML 文字列を解析して doc に足す。例外は投げない。"""
    limits = limits or Limits()
    if doc.kind in ("unknown", ""):
        doc.kind = "html"
    try:
        raw = _close_unterminated_comments(raw)
        ex = _Extractor(doc, _parse_stylesheets(raw), limits, budget, _depth)
        try:
            ex.feed(raw)
            ex.close()
        except BudgetExceeded:
            doc.mark("partial", "処理時間の上限に達したため、HTML の一部のみ解析しました。")
        except RecursionError:
            doc.mark("partial", "HTML の構造が複雑すぎるため、一部のみ解析しました。")
        except Exception as e:  # noqa: BLE001  壊れたHTMLでも落とさない
            doc.mark("partial", f"HTML の解析中にエラーが発生しました({type(e).__name__}): 一部のみ解析しました。")
        try:
            ex.finalize()
        except Exception:  # noqa: BLE001
            pass
        visible = _tidy("".join(ex.out))
        if len(visible) > limits.max_text_chars:
            visible = visible[:limits.max_text_chars]
            doc.mark("partial", f"テキストが長いため先頭 {limits.max_text_chars} 文字のみ解析しました。")
        doc.text = (doc.text + "\n" + visible).strip() if doc.text else visible
        doc.hidden_regions.extend(ex.regions)
        doc.findings.extend(ex.findings)
    except Exception as e:  # noqa: BLE001
        doc.mark("failed", f"HTML 解析に失敗しました({type(e).__name__}: {e})。")
    return doc


def extract_html_bytes(data: bytes, name: str = "", charset_hint: Optional[str] = None,
                       limits: Optional[Limits] = None, budget: Optional[Budget] = None) -> ExtractedDoc:
    """文字コードは BOM、HTTP ヘッダや meta の宣言、自動判定の順に決めてから解析する。"""
    doc = ExtractedDoc(source=name, kind="html", size=len(data))
    limits = limits or Limits()
    try:
        if len(data) > limits.max_file_bytes:
            data = data[:limits.max_file_bytes]
            doc.mark("partial", "HTML が大きいため先頭のみ解析しました。")
        hint = charset_hint or sniff_declared_charset(data)
        text, enc, notes = decode_bytes(data, hint)
        doc.encoding = enc
        doc.notes.extend(notes)
        extract_html_text(text, doc, limits, budget)
    except (UnsafeInput, BudgetExceeded) as e:
        doc.mark("failed", f"HTML の処理を中止しました: {e}")
    except Exception as e:  # noqa: BLE001
        doc.mark("failed", f"HTML 解析に失敗しました({type(e).__name__}: {e})。")
    return doc
