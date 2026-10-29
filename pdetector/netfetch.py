"""URL 取得。SSRF 対策、サイズ/時間上限、クローキング検査つき。標準ライブラリのみ。

http/https だけ。名前解決した全アドレスを見て、内部/予約アドレスは既定で拒否する(10進/16進/8進表記、
IPv4 射影 IPv6、169.254.169.254 も)。リダイレクトは自動で追わず、ホップごとに検証し直す。
直接接続は検証済み IP に固定する(DNS rebinding 対策)。プロキシ経由は名前解決がプロキシ側なので固定できない。
UA を変えて再取得し、内容が違えばクローキングとして出す。LLM クローラにだけ攻撃文を見せる手口の対策。
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .encoding import decode_bytes, sniff_declared_charset
from .model import ExtractedDoc, Finding, HiddenRegion
from .safeio import Budget, BudgetExceeded, Limits

__all__ = ["extract_from_url", "check_url", "BlockedURL", "FetchError", "FetchResult"]

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0.0.0 Safari/537.36")
ALT_USER_AGENTS = (
    "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)",
    "ClaudeBot/1.0",
    "ChatGPT-User/1.0",
)
_REDIRECT_CODES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    """取得失敗。メッセージは日本語。"""


class BlockedURL(FetchError):
    """SSRF 対策で拒否。"""


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    truncated: bool = False
    chain: List[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


def _ip_forbidden(ip) -> Optional[str]:
    """内部・予約アドレスなら理由を返す。問題なければ None。"""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _ip_forbidden(ip.ipv4_mapped)
        # NAT64 (64:ff9b::/96) と 6to4 (2002::/16) は埋め込まれた IPv4 を見る
        packed = ip.packed
        if packed[:12] == bytes.fromhex("0064ff9b0000000000000000"):
            return _ip_forbidden(ipaddress.IPv4Address(packed[12:]))
        if packed[:2] == b"\x20\x02":
            return _ip_forbidden(ipaddress.IPv4Address(packed[2:6]))
    if ip.is_multicast:
        return "マルチキャスト"
    if ip.is_loopback:
        return "ループバック"
    if ip.is_link_local:
        return "リンクローカル(クラウドのメタデータ等)"
    if ip.is_unspecified:
        return "未指定アドレス"
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "共有アドレス空間(CGNAT)"
    if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("fc00::/7"):
        return "ユニークローカル"
    if ip.is_private:
        return "プライベート"
    if ip.is_reserved or not ip.is_global:
        return "予約/非グローバル"
    return None


def _resolve(host: str, port: int) -> List[str]:
    """ホスト名を IP 文字列のリストにする。10進/16進/8進表記も正規化される。"""
    ips: List[str] = []
    try:
        # inet_aton は "2130706433" "0x7f.1" "0177.0.0.1" 等も受け付ける
        ips.append(socket.inet_ntoa(socket.inet_aton(host)))
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        if not ips:
            raise FetchError(f"名前解決に失敗しました({host}): {e}")
        infos = []
    for fam, _t, _p, _c, sa in infos:
        ip = sa[0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise FetchError(f"名前解決に失敗しました({host})")
    return ips


def check_url(url: str, allow_private: bool = False) -> List[str]:
    """接続してよい IP のリストを返す。拒否は BlockedURL、それ以外の不備は FetchError。"""
    try:
        sp = urllib.parse.urlsplit(url.strip())
    except ValueError as e:
        raise FetchError(f"URL が不正です: {e}")
    if sp.scheme.lower() not in ("http", "https"):
        raise FetchError(f"http/https 以外のスキームは取得できません: {sp.scheme or '(なし)'}")
    host = sp.hostname
    if not host:
        raise FetchError("URL にホスト名がありません")
    try:
        port = sp.port or (443 if sp.scheme.lower() == "https" else 80)
    except ValueError:
        raise FetchError("ポート番号が不正です")
    ips = _resolve(host, port)
    if not allow_private:
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                raise FetchError(f"解決結果が不正です: {ip}")
            why = _ip_forbidden(addr)
            if why:
                raise BlockedURL(f"{host} → {ip} ({why})")
    return ips


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ips, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ips = ips

    def _connect_any(self):
        last = None
        for ip in self._ips:
            try:
                return socket.create_connection((ip, self.port), self.timeout)
            except OSError as e:
                last = e
        raise last or OSError("接続できません")

    def connect(self):
        self.sock = self._connect_any()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ips, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ips = ips

    def connect(self):
        last = None
        for ip in self._ips:
            try:
                sock = socket.create_connection((ip, self.port), self.timeout)
                break
            except OSError as e:
                last = e
        else:
            raise last or OSError("接続できません")
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _uses_proxy(url: str) -> bool:
    try:
        sp = urllib.parse.urlsplit(url)
        proxies = urllib.request.getproxies()
        if not proxies.get(sp.scheme.lower()):
            return False
        return not urllib.request.proxy_bypass(sp.hostname or "")
    except Exception:  # noqa: BLE001
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _read_limited(resp, max_bytes: int, deadline: float, budget: Optional[Budget]) -> Tuple[bytes, bool]:
    chunks: List[bytes] = []
    total = 0
    truncated = False
    while True:
        if time.monotonic() > deadline:
            raise FetchError("読み込みが制限時間を超えました")
        if budget is not None:
            budget.check()
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            chunks.append(chunk[: len(chunk) - (total - max_bytes)])
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def _hop_default(url: str, ips: List[str], headers: Dict[str, str], timeout: float, max_bytes: int,
                 deadline: float, budget: Optional[Budget]):
    """GET を1回。(status, headers(キーは小文字), body, truncated)。リダイレクトは追わない。"""
    sp = urllib.parse.urlsplit(url)
    scheme = sp.scheme.lower()
    host = sp.hostname or ""
    port = sp.port or (443 if scheme == "https" else 80)
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query

    if _uses_proxy(url):
        # プロキシ経由: IP固定はできない(プロキシが名前解決する)
        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            raise FetchError(f"接続に失敗しました: {getattr(e, 'reason', e)}")
        try:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            cl = hdrs.get("content-length")
            if cl and cl.isdigit() and int(cl) > max_bytes * 10:
                raise FetchError(f"Content-Length が大きすぎます({int(cl) // (1024 * 1024)}MB)")
            body, trunc = _read_limited(resp, max_bytes, deadline, budget)
            return resp.status if hasattr(resp, "status") else resp.code, hdrs, body, trunc
        finally:
            try:
                resp.close()
            except Exception:  # noqa: BLE001
                pass

    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = _PinnedHTTPSConnection(host, port, ips, timeout, ctx)
    else:
        conn = _PinnedHTTPConnection(host, port, ips, timeout)
    try:
        h = dict(headers)
        conn.request("GET", path, headers=h)
        resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        cl = hdrs.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_bytes * 10:
            raise FetchError(f"Content-Length が大きすぎます({int(cl) // (1024 * 1024)}MB)")
        body, trunc = _read_limited(resp, max_bytes, deadline, budget)
        return resp.status, hdrs, body, trunc
    except ssl.SSLError as e:
        raise FetchError(f"TLS 接続に失敗しました: {e}")
    except (OSError, http.client.HTTPException) as e:
        raise FetchError(f"接続に失敗しました: {e}")
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


Hop = Callable[..., Tuple[int, Dict[str, str], bytes, bool]]


def _fetch(url: str, *, ua: str, timeout: float, max_bytes: int, max_redirects: int, allow_private: bool,
           budget: Optional[Budget], hop: Optional[Hop] = None) -> FetchResult:
    hop = hop or _hop_default
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf;q=0.8,*/*;q=0.7",
        "Accept-Language": "ja,en;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    cur = url.strip()
    chain: List[str] = []
    for n in range(max_redirects + 1):
        if budget is not None:
            budget.check()
        ips = check_url(cur, allow_private)
        eff_timeout = timeout
        if budget is not None and budget.remaining is not None:
            eff_timeout = max(1.0, min(timeout, budget.remaining))
        deadline = time.monotonic() + max(timeout * 4, 10.0)
        if budget is not None and budget.remaining is not None:
            deadline = min(deadline, time.monotonic() + budget.remaining)
        status, hdrs, body, trunc = hop(cur, ips, headers, eff_timeout, max_bytes, deadline, budget)
        if status in _REDIRECT_CODES and hdrs.get("location"):
            nxt = urllib.parse.urljoin(cur, hdrs["location"].strip())
            chain.append(f"リダイレクト {n + 1}: {cur} → {nxt} (HTTP {status})")
            cur = nxt
            continue
        return FetchResult(url=url, final_url=cur, status=status, headers=hdrs, body=body,
                           truncated=trunc, chain=chain)
    raise FetchError(f"リダイレクトが {max_redirects} 回を超えました: {' / '.join(chain[-3:])}")


def _name_from_url(url: str) -> str:
    sp = urllib.parse.urlsplit(url)
    last = urllib.parse.unquote(sp.path.rsplit("/", 1)[-1])
    return last or (sp.hostname or url)


def _fallback_extract(data: bytes, name: str = "", limits=None, budget=None, depth: int = 0,
                      content_type=None, source=None) -> ExtractedDoc:
    """extract_from_bytes が無いときの代わり。HTML とテキストだけ。"""
    from .htmlx import extract_html_bytes
    charset = None
    ct = (content_type or "").lower()
    if "charset=" in ct:
        charset = ct.split("charset=", 1)[1].split(";")[0].strip().strip("\"'")
    head = data[:512].lstrip().lower()
    if "html" in ct or head.startswith((b"<!doctype html", b"<html")) or name.lower().endswith((".html", ".htm")):
        d = extract_html_bytes(data, name=source or name, charset_hint=charset, limits=limits, budget=budget)
    else:
        d = ExtractedDoc(source=source or name, kind="text", size=len(data))
        text, enc, notes = decode_bytes(data, charset or sniff_declared_charset(data))
        d.text, d.encoding = text, enc
        d.notes.extend(notes)
    if source:
        d.source = source
    return d


def _extract(data: bytes, name: str, limits, budget, depth: int, content_type: str, source: str) -> ExtractedDoc:
    try:
        from . import extractors as _ex
        fn = getattr(_ex, "extract_from_bytes", None)
    except Exception:  # noqa: BLE001
        fn = None
    if fn is None:
        fn = _fallback_extract
    try:
        return fn(data, name=name, limits=limits, budget=budget, depth=depth,
                  content_type=content_type or None, source=source)
    except BudgetExceeded:
        raise
    except Exception as e:  # noqa: BLE001
        d = ExtractedDoc(source=source, kind="unknown", size=len(data))
        d.mark("failed", f"取得した内容の解析に失敗しました({type(e).__name__}: {e})。")
        return d


def _norm_text(s: str) -> str:
    return " ".join(s.lower().split())


def _similarity(a: str, b: str) -> float:
    """文字3-gram の多重集合で類似度(0..1)。言語に依らず O(n)。"""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    def sample(x):
        return x if len(x) <= 200_000 else x[:100_000] + x[-100_000:]
    a, b = sample(a), sample(b)
    ca = Counter(a[i:i + 3] for i in range(max(1, len(a) - 2)))
    cb = Counter(b[i:i + 3] for i in range(max(1, len(b) - 2)))
    inter = sum((ca & cb).values())
    return 2.0 * inter / (sum(ca.values()) + sum(cb.values()))


def _lines(doc: ExtractedDoc) -> List[Tuple[str, str]]:
    """(正規化した行, 元の行)。短い行は除く。"""
    parts = [doc.text] + [r.text for r in doc.hidden_regions]
    out: List[Tuple[str, str]] = []
    for p in parts:
        for ln in p.splitlines():
            n = _norm_text(ln)
            if len(n) >= 8:
                out.append((n, ln.strip()))
    return out


def _all_text(doc: ExtractedDoc) -> str:
    return _norm_text(doc.text + "\n" + "\n".join(r.text for r in doc.hidden_regions))


def _textlike(res: FetchResult) -> bool:
    ct = res.content_type.lower()
    if not ct:
        return True
    return any(t in ct for t in ("html", "text", "xml", "json"))


def _cloak_check(url: str, main: FetchResult, main_doc: ExtractedDoc, *, limits, budget, depth,
                 timeout, max_bytes, max_redirects, allow_private, hop, fetch=None) -> None:
    fetch = fetch or _fetch
    main_all = _all_text(main_doc)
    main_lines = {n for n, _o in _lines(main_doc)}
    for ua in ALT_USER_AGENTS:
        if budget is not None:
            try:
                budget.check()
            except BudgetExceeded:
                main_doc.mark("partial", "時間上限のため、User-Agent 別の内容比較(クローキング検査)を一部省略しました。")
                return
        try:
            alt = fetch(url, ua=ua, timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects,
                        allow_private=allow_private, budget=budget, hop=hop)
        except BlockedURL:
            continue
        except (FetchError, BudgetExceeded):
            main_doc.notes.append(f"クローキング検査: UA『{ua}』での再取得に失敗しました。")
            continue
        if alt.status >= 400 or not _textlike(alt):
            continue
        alt_doc = _extract(alt.body, _name_from_url(alt.final_url), limits, budget, depth,
                           alt.content_type, url)
        sim = _similarity(main_all, _all_text(alt_doc))
        extra = [o for n, o in _lines(alt_doc) if n not in main_lines]
        extra_text = "\n".join(extra)[:50_000]
        extra_chars = sum(len(x) for x in extra)
        region_sev: Optional[str] = None
        if sim < 0.9:
            main_doc.findings.append(Finding(
                rule_id="url_cloaking", category="obfuscation", severity="high",
                description="User-Agent によって配信内容が異なります(クローキングの疑い)",
                snippet=extra_text[:160], location="url",
                detail=f"UA={ua} / 通常UAとの類似度={sim:.2f}"))
        elif extra_chars >= 80:
            main_doc.findings.append(Finding(
                rule_id="url_content_varies", category="obfuscation", severity="medium",
                description="User-Agent によって一部の内容が異なります(動的ページの可能性もあります)",
                snippet=extra_text[:160], location="url",
                detail=f"UA={ua} / 通常UAとの類似度={sim:.2f} / 差分={extra_chars}文字"))
        elif extra_chars >= 20:
            region_sev = "info"     # 差分が小さい。指摘は出さず照合だけ回す(攻撃文ならヒットする)
        else:
            continue
        if extra_text:
            main_doc.hidden_regions.append(HiddenRegion(
                text=extra_text, reason=f"UA『{ua}』にだけ配信された内容", location="url", kind="hidden",
                severity=region_sev))
        # 最初に差が出た UA だけ報告する。UA ごとに同じ指摘を重ねない
        return


def extract_from_url(url: str, limits: Optional[Limits] = None, budget: Optional[Budget] = None, *,
                     allow_private: bool = False, cloak_check: bool = True, timeout: float = 15.0,
                     max_bytes: int = 10 * 1024 * 1024, max_redirects: int = 5, depth: int = 0,
                     _hop: Optional[Hop] = None) -> ExtractedDoc:
    """URL を取得して解析する。例外は投げず、失敗は status="failed" と notes に入れる。"""
    limits = limits or Limits()
    doc = ExtractedDoc(source=url, kind="url")
    try:
        try:
            main = _fetch(url, ua=BROWSER_UA, timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects,
                          allow_private=allow_private, budget=budget, hop=_hop)
        except BlockedURL as e:
            doc.mark("failed", f"内部/プライベートアドレスへのアクセスはSSRF対策のため拒否しました: {e}")
            return doc
        except FetchError as e:
            doc.mark("failed", f"取得失敗: {e}")
            return doc
        except BudgetExceeded as e:
            doc.mark("failed", f"取得を中止しました: {e}")
            return doc

        doc.notes.append(f"HTTP {main.status}, Content-Type: {main.content_type or '不明'}")
        doc.notes.extend(main.chain)
        if main.final_url != url:
            doc.notes.append(f"最終URL: {main.final_url}")
        if main.truncated:
            doc.mark("partial", f"レスポンスが大きいため先頭 {max_bytes // (1024 * 1024) or 1}MB のみ解析しました。")
        if main.status >= 400:
            doc.mark("partial", f"HTTP {main.status} が返されました(エラーページを解析している可能性があります)。")
        elif 300 <= main.status < 400:
            doc.mark("partial", f"HTTP {main.status} でリダイレクト先が不明です。")

        inner = _extract(main.body, _name_from_url(main.final_url), limits, budget, depth,
                         main.content_type, url)
        # 抽出結果を本体にして、取得時のメタ情報を足す
        inner.source = url
        inner.kind = f"url({inner.kind})"
        inner.size = len(main.body)
        inner.notes = doc.notes + inner.notes
        if doc.status != "ok":
            inner.mark(doc.status)
        doc = inner

        if cloak_check and main.status < 400 and _textlike(main):
            try:
                _cloak_check(url, main, doc, limits=limits, budget=budget, depth=depth, timeout=timeout,
                             max_bytes=max_bytes, max_redirects=max_redirects, allow_private=allow_private,
                             hop=_hop)
            except BudgetExceeded:
                doc.mark("partial", "時間上限のため、User-Agent 別の内容比較(クローキング検査)を省略しました。")
    except BudgetExceeded as e:
        doc.mark("partial", f"処理時間の上限に達しました: {e}")
    except Exception as e:  # noqa: BLE001
        doc.mark("failed", f"URL の処理中に予期しないエラーが発生しました({type(e).__name__}: {e})。")
    return doc
