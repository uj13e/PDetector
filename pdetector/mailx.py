"""メール(.eml)の抽出。標準 email パッケージのみ。

本文は htmlx 経由で可視テキストと隠し領域に分ける。ヘッダは Subject/From/To/Cc だけ可視、残りは metadata 扱い。
添付は再帰で解析。multipart/alternative の plain と html が大きく違えば検知する。
"""
from __future__ import annotations

import email
import email.policy
from email.header import decode_header, make_header
from typing import List, Optional, Tuple

from .encoding import decode_bytes
from .htmlx import extract_html_bytes
from .model import ExtractedDoc, Finding, HiddenRegion
from .netfetch import _norm_text, _similarity
from .safeio import Budget, BudgetExceeded, Limits

__all__ = ["extract_eml"]

_MAX_ATTACHMENTS = 50
_MAX_HEADERS = 300
_VISIBLE_HEADERS = ("subject", "from", "to", "cc")
# 長くて機械的なヘッダ。ここに攻撃文を入れてもまず読まれないので誤検知と量を減らすために除外
_SKIP_HEADERS = {"received", "dkim-signature", "arc-seal", "arc-message-signature", "arc-authentication-results",
                 "authentication-results", "mime-version", "content-transfer-encoding", "return-path",
                 "received-spf", "x-google-dkim-signature", "domainkey-signature"}


def _hdr_str(v) -> str:
    try:
        return str(v)
    except Exception:  # noqa: BLE001  RFC2047 が壊れたヘッダ等
        try:
            return str(make_header(decode_header(str(getattr(v, "_value", v)))))
        except Exception:  # noqa: BLE001
            return repr(v)


def _headers(msg) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    try:
        for k, v in msg.items():
            out.append((k, _hdr_str(v)))
    except Exception:  # noqa: BLE001
        try:
            for k, v in msg.raw_items():
                try:
                    out.append((k, str(make_header(decode_header(v)))))
                except Exception:  # noqa: BLE001
                    out.append((k, v))
        except Exception:  # noqa: BLE001
            pass
    return out


def _extract_bytes_fn():
    try:
        from . import extractors as _ex
        fn = getattr(_ex, "extract_from_bytes", None)
        if fn is not None:
            return fn
    except Exception:  # noqa: BLE001
        pass
    from .netfetch import _fallback_extract
    return _fallback_extract


def _payload(part) -> bytes:
    try:
        p = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        p = None
    if p is None:
        try:
            raw = part.get_payload()
            if isinstance(raw, str):
                p = raw.encode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            p = None
    return p or b""


def _alt_groups(msg):
    """multipart/alternative ごとの (plain, html) の組。"""
    groups = []
    for part in msg.walk():
        if part.get_content_type() == "multipart/alternative":
            plain = html = None
            for sub in part.iter_parts():
                ct = sub.get_content_type()
                if ct == "text/plain" and plain is None:
                    plain = sub
                elif ct == "text/html" and html is None:
                    html = sub
            if plain is not None and html is not None:
                groups.append((plain, html))
    return groups


def extract_eml(data: bytes, name: str = "", limits: Optional[Limits] = None, budget: Optional[Budget] = None,
                depth: int = 0) -> ExtractedDoc:
    limits = limits or Limits()
    doc = ExtractedDoc(source=name, kind="eml", size=len(data))
    try:
        _extract(data, name, limits, budget, depth, doc)
    except BudgetExceeded:
        doc.mark("partial", "処理時間の上限に達したため、メールの一部のみ解析しました。")
    except Exception as e:  # noqa: BLE001
        doc.mark("failed", f"メールの解析に失敗しました({type(e).__name__}: {e})。")
    return doc


def _extract(data: bytes, name: str, limits: Limits, budget: Optional[Budget], depth: int, doc: ExtractedDoc):
    if len(data) > limits.max_file_bytes:
        data = data[:limits.max_file_bytes]
        doc.mark("partial", "メールが大きいため先頭のみ解析しました。")
    msg = email.message_from_bytes(data, policy=email.policy.default)

    headers = _headers(msg)
    vis_lines = []
    visible_done = set()
    for k, v in headers:
        kl = k.lower()
        if kl in _VISIBLE_HEADERS and kl not in visible_done:
            visible_done.add(kl)
            vis_lines.append(f"{k}: {v}")
    if vis_lines:
        doc.text = "\n".join(vis_lines)
    n_reg = 0
    for k, v in headers:
        kl = k.lower()
        if kl in _SKIP_HEADERS or (kl in _VISIBLE_HEADERS):
            continue
        v = v.strip()
        if not v:
            continue
        n_reg += 1
        if n_reg > _MAX_HEADERS:
            doc.mark("partial", f"ヘッダが多いため先頭 {_MAX_HEADERS} 件のみ解析しました。")
            break
        doc.hidden_regions.append(HiddenRegion(
            text=f"{k}: {v[:20000]}", reason=f"メールヘッダ {k}", location=k, kind="metadata", severity="info"))

    # plain と html の食い違い。表示するクライアントで見え方が変わる
    plain_ids = {}
    for plain_part, html_part in _alt_groups(msg):
        if budget is not None:
            budget.check()
        p_bytes, h_bytes = _payload(plain_part), _payload(html_part)
        p_text, _, _ = decode_bytes(p_bytes, plain_part.get_content_charset())
        h_doc = extract_html_bytes(h_bytes, charset_hint=html_part.get_content_charset(), limits=limits, budget=budget)
        pn, hn = _norm_text(p_text), _norm_text(h_doc.text)
        if len(pn) >= 20 and len(hn) >= 20:
            sim = _similarity(pn, hn)
            if sim < 0.6:
                doc.findings.append(Finding(
                    rule_id="mail_alternative_mismatch", category="hidden_content", severity="medium",
                    description="text/plain と text/html で内容が大きく異なります(メールクライアントによって表示が変わる攻撃の疑い)",
                    snippet=(hn[:160]), location="mail_alternative",
                    detail=f"本文の類似度={sim:.2f}"))
        plain_ids[id(html_part)] = pn

    plain_norms: List[str] = []
    n_attach = 0
    attach_overflow = False
    extract_bytes = None
    for part in msg.walk():
        if budget is not None:
            budget.check()
        if part.is_multipart():
            continue
        ct = part.get_content_type()
        try:
            filename = part.get_filename()
        except Exception:  # noqa: BLE001
            filename = None
        try:
            disp = part.get_content_disposition()
        except Exception:  # noqa: BLE001
            disp = None
        is_body = ct in ("text/plain", "text/html") and not filename and disp != "attachment"
        payload = _payload(part)

        if is_body:
            charset = part.get_content_charset()
            if ct == "text/plain":
                text, enc, notes = decode_bytes(payload, charset)
                doc.notes.extend(notes)
                if text.strip():
                    doc.text += "\n" + text
                    plain_norms.append(_norm_text(text))
            else:
                child = extract_html_bytes(payload, charset_hint=charset, limits=limits, budget=budget)
                vis = child.text
                child.text = ""
                doc.merge(child, "html本文")
                if vis.strip():
                    vn = _norm_text(vis)
                    dup = bool(plain_norms) and any(len(pn) >= 8 and _similarity(vn, pn) >= 0.9 for pn in plain_norms)
                    prev = plain_ids.get(id(part))
                    if prev is not None and len(prev) >= 8 and _similarity(vn, prev) >= 0.9:
                        dup = True
                    if not dup:
                        doc.text += "\n" + vis
            continue

        # ここから添付(本文でない葉パートも含む)
        if not payload:
            continue
        n_attach += 1
        aname = filename or f"添付{n_attach}.{part.get_content_subtype()}"
        if n_attach > _MAX_ATTACHMENTS:
            attach_overflow = True
            continue
        if depth + 1 > limits.max_depth:
            doc.mark("partial", f"添付「{aname}」は入れ子が深いため解析していません。")
            continue
        if extract_bytes is None:
            extract_bytes = _extract_bytes_fn()
        try:
            child = extract_bytes(payload, name=aname, limits=limits, budget=budget, depth=depth + 1,
                                  content_type=ct, source=aname)
        except BudgetExceeded:
            raise
        except Exception as e:  # noqa: BLE001
            doc.mark("partial", f"添付「{aname}」の解析に失敗しました({type(e).__name__}: {e})。")
            continue
        doc.merge(child, aname)
        if child.status in ("failed", "unsupported"):
            doc.mark("partial", f"添付「{aname}」は解析できませんでした({child.status})。")
    if attach_overflow:
        doc.mark("partial", f"添付が {_MAX_ATTACHMENTS} 件を超えたため、超過分は解析していません(全{n_attach}件)。")

    doc.text = doc.text.strip()
    if len(doc.text) > limits.max_text_chars:
        doc.text = doc.text[:limits.max_text_chars]
        doc.mark("partial", f"テキストが長いため先頭 {limits.max_text_chars} 文字のみ解析しました。")
