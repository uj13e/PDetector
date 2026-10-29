"""ファイルの無害化。AI に読ませてよいテキスト版を作る。

見える本文だけを取り出し、不可視文字を除き、命令文と判定した文(行)を [REDACTED] にして、出力をもう一度検知器にかけて残りを確認する。確認できなければ「無害化できず」。
元ファイルは触らない。出力はプレーンテキストだが、pptx/docx/xlsx は見える本文から同形式の素のファイルを作り直す(ooxml_out.py。元の XML は引き継がない。再検査に通らなければ出さない)。
暗号化・破損・非対応で読めないものは安全と偽らずスキップ扱い(fail-closed)。
"""
from __future__ import annotations

import csv
import dataclasses
import io
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import normalize as nz
from . import ooxml_out
from .detector import Detector
from .i18n import TMap, tr
from .model import ExtractedDoc, Finding, SEV_ORDER
from .safeio import Budget, Limits

# 伏せ字にルールIDは入れない。ID の単語が squashed 照合で再検知されるので、IDはレポート側だけに残す
REDACT = "[REDACTED]"
MAX_SEGMENT = 500          # これより長い文は空白位置で割って判定する
_TERM = re.compile(r"(?<=[。．！？!?])|(?<=\.)(?=\s)")
_MAX_FULL_SCAN_LINES = 5000


@dataclass
class SanitizeOutcome:
    source: str
    kind: str = ""
    # ok / partial(元の解析が一部だけ、または確認に注意あり) / skipped(読めない) / unsafe(確認で検知が残った)
    state: str = "ok"
    text: str = ""
    removed: List[dict] = field(default_factory=list)       # {"kind","reason","location","snippet"}
    invisible_removed: int = 0
    redacted: int = 0
    hidden_dropped: int = 0
    residual: List[Finding] = field(default_factory=list)   # unsafe のとき、出力に残った検知
    notes: List[str] = field(default_factory=list)
    out_path: str = ""
    elapsed_sec: float = 0.0
    fmt: str = "txt"                 # txt / pptx / docx / xlsx
    data: bytes = b""                # fmt が txt 以外のときの中身。再検査済み

    @property
    def usable(self) -> bool:
        """確認済みの出力があるか。partial は要確認なので False。"""
        return self.state == "ok" and bool(self.text.strip())

    @property
    def written(self) -> bool:
        return bool(self.out_path)


def split_segments(line: str, max_len: int = MAX_SEGMENT) -> List[str]:
    """1行を文単位に割る。連結すれば元の行に戻る。"""
    out: List[str] = []
    for piece in _TERM.split(line):
        while len(piece) > max_len:
            cut = piece.rfind(" ", int(max_len * 0.6), max_len)
            cut = (cut + 1) if cut > 0 else max_len
            out.append(piece[:cut])
            piece = piece[cut:]
        out.append(piece)
    return [p for p in out if p != ""] or [""]


def _bad_findings(det: Detector, text: str, min_sev: str) -> Tuple[List[Finding], str]:
    r = det.scan_text(text)
    bad = [f for f in r.findings if SEV_ORDER.get(f.severity, 0) >= SEV_ORDER[min_sev]]
    return bad, r.status


def _quiet(det: Detector) -> Detector:
    """keep_text を切った検知器。メモリ節約。"""
    cfg = dataclasses.replace(det.config, keep_text=False)
    return type(det)(cfg)


def _mask_segments(text: str, det: Detector, min_sev: str, only_lines: Optional[set]) -> Tuple[str, List[dict]]:
    removed: List[dict] = []
    lines = text.split("\n")
    out_lines: List[str] = []
    for i, line in enumerate(lines, start=1):
        if not line.strip() or (only_lines is not None and i not in only_lines):
            out_lines.append(line)
            continue
        segs = split_segments(line)
        if len(segs) == 1:
            bad, _st = _bad_findings(det, segs[0], min_sev)
            kept = [segs[0]] if not bad else [REDACT]
            if bad:
                removed.append(_rec("redacted", bad[0], i, segs[0]))
        else:
            kept = []
            for sg in segs:
                if not sg.strip():
                    kept.append(sg)
                    continue
                bad, _st = _bad_findings(det, sg, min_sev)
                if bad:
                    lead = sg[: len(sg) - len(sg.lstrip())]
                    kept.append(lead + REDACT + (" " if sg.endswith(" ") else ""))
                    removed.append(_rec("redacted", bad[0], i, sg))
                else:
                    kept.append(sg)
        out_lines.append("".join(kept))
    return "\n".join(out_lines), removed


def _mask_blocks(text: str, det: Detector, min_sev: str) -> Tuple[str, List[dict]]:
    """段落ごとに改行を空白にして文単位で判定し、命令文を伏せ字にする。
    折り返しで行をまたいだ命令文を拾う最後の手段。伏せた段落だけ改行が消える。"""
    removed: List[dict] = []
    blocks = re.split(r"(\n\s*\n)", text)
    for bi in range(0, len(blocks), 2):
        blk = blocks[bi]
        if not blk.strip():
            continue
        flat = re.sub(r"\s*\n\s*", " ", blk) if "\n" in blk else blk
        segs = split_segments(flat)
        new, hit = [], False
        for sg in segs:
            if sg.strip():
                bad, _st = _bad_findings(det, sg, min_sev)
                if bad:
                    hit = True
                    removed.append(_rec("redacted_block", bad[0], 0, sg))
                    new.append(REDACT + (" " if sg.endswith(" ") else ""))
                    continue
            new.append(sg)
        if hit:
            blocks[bi] = "".join(new)
    return "".join(blocks), removed


def _rec(kind: str, f: Finding, line: int, snippet: str) -> dict:
    return {"kind": kind, "reason": f.description, "rule_id": f.rule_id, "severity": f.severity,
            "location": tr('text (行 {0})').format(line), "snippet": snippet.strip()[:160]}


def sanitize_text_doc(text: str, source: str, det: Detector, *, kind: str = "", hidden: Sequence = (),
                      min_severity: str = "medium", doc_status: str = "ok", notes: Sequence[str] = ()) -> SanitizeOutcome:
    t0 = time.monotonic()
    out = SanitizeOutcome(source=source, kind=kind, notes=list(notes))
    det = _quiet(det)
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")

    # 隠し領域は丸ごと捨てる。記録だけ残す
    for reg in hidden:
        out.hidden_dropped += 1
        out.removed.append({"kind": "hidden", "reason": getattr(reg, "reason", ""), "rule_id": "",
                            "severity": "", "location": getattr(reg, "location", "") or getattr(reg, "kind", ""),
                            "snippet": (getattr(reg, "text", "") or "").strip().replace("\n", " ")[:160]})

    stripped = nz.strip_hidden_chars(text)
    out.invisible_removed = len(text) - len(stripped)
    if out.invisible_removed:
        out.removed.append({"kind": "invisible", "reason": "invisible_chars", "rule_id": "", "severity": "",
                            "location": "text", "snippet": f"{out.invisible_removed}"})
    cur = stripped

    # 全体を1回走査し、検知のある行だけ文単位で判定する
    try:
        bad, status = _bad_findings(det, cur, min_severity)
        if bad:
            lines = {f.line for f in bad if f.line > 0}
            localized = all(f.line > 0 for f in bad)
            n_lines = cur.count("\n") + 1
            only = lines if localized else (None if n_lines <= _MAX_FULL_SCAN_LINES else lines)
            cur, rem = _mask_segments(cur, det, min_severity, only)
            out.removed.extend(rem)
            out.redacted += len(rem)
        # 再確認。残っていたら検知行を丸ごと伏せ字にする。位置不明のものは段落を1行に繋いで文単位で再判定。最大3回
        for _attempt in range(3):
            bad, status = _bad_findings(det, cur, min_severity)
            if not bad:
                break
            lines_list = cur.split("\n")
            changed = False
            for f in bad:
                if 0 < f.line <= len(lines_list) and lines_list[f.line - 1] != REDACT:
                    out.removed.append(_rec("redacted_line", f, f.line, lines_list[f.line - 1]))
                    lines_list[f.line - 1] = REDACT
                    out.redacted += 1
                    changed = True
            cur = "\n".join(lines_list)
            if any(f.line <= 0 for f in bad):
                cur, rem = _mask_blocks(cur, det, min_severity)
                if rem:
                    out.removed.extend(rem)
                    out.redacted += len(rem)
                    changed = True
            if not changed:
                break
        bad, status = _bad_findings(det, cur, min_severity)
    except Exception as e:  # noqa  fail-closed
        out.state = "unsafe"
        out.notes.append(f"{type(e).__name__}: {e}")
        out.text = ""
        out.elapsed_sec = round(time.monotonic() - t0, 3)
        return out

    out.text = cur
    out.residual = bad
    if bad:
        out.state = "unsafe"
        out.text = ""                     # 確認できなかった出力は渡さない
    elif doc_status in ("partial",) or status == "partial":
        out.state = "partial"
    out.elapsed_sec = round(time.monotonic() - t0, 3)
    return out


_MARK = re.compile(r"^@@PDETECTOR-UNIT-(\d+)@@$")


def native_format(kind: str) -> str:
    """作り直せる形式ならその拡張子(pptx/docx/xlsx)、そうでなければ空文字。"""
    return kind if kind in ooxml_out.EXTS else ""


def _doc_groups(doc: ExtractedDoc) -> List[Tuple[str, List[str]]]:
    """可視テキストをスライド/シート単位に分ける。構造を復元できなければ全体で1グループ。"""
    units = list(getattr(doc, "units", None) or [])
    flat = "\n".join(t for _l, t in units)
    if not units or flat.strip("\n") != (doc.text or "").strip("\n"):
        lines = (doc.text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        return [("", lines)]
    if doc.kind == "docx":
        return [("", flat.split("\n"))]
    groups: List[Tuple[str, List[str]]] = []
    for loc, text in units:
        if not groups or groups[-1][0] != loc:
            groups.append((loc, []))
        groups[-1][1].extend(text.split("\n"))
    if doc.kind == "xlsx":
        for lab, lines in groups:                # [シート名] の見出し行はシート名として別に持つので除く
            if lines and lines[0] == f"[{lab}]":
                del lines[0]
    return groups


def _marked_text(groups: Sequence[Tuple[str, Sequence[str]]]) -> str:
    parts: List[str] = []
    for i, (_lab, lines) in enumerate(groups):
        parts += [f"@@PDETECTOR-UNIT-{i}@@", ""] + list(lines) + [""]
    return "\n".join(parts)


def _unmark(text: str, n: int) -> Optional[List[List[str]]]:
    cur: Optional[List[str]] = None
    got: List[Tuple[int, List[str]]] = []
    for ln in text.split("\n"):
        m = _MARK.match(ln.strip())
        if m:
            cur = []
            got.append((int(m.group(1)), cur))
        elif cur is None:
            if ln.strip():
                return None
        else:
            cur.append(ln)
    if [i for i, _ in got] != list(range(n)):
        return None
    res = []
    for _i, ls in got:
        while ls and not ls[0].strip():
            ls.pop(0)
        while ls and not ls[-1].strip():
            ls.pop()
        res.append(ls)
    return res


def _safe_label(label: str, det: Detector, min_sev: str, idx: int) -> str:
    """シート名など出力に残るラベル。名前も攻撃文の入れ場所になるので、検知されたら Sheet{n} に置き換える。"""
    lab = nz.strip_hidden_chars(label or "").strip()
    if not lab:
        return ""
    try:
        bad, _st = _bad_findings(det, lab, min_sev)
    except Exception:  # noqa
        bad = [True]
    return f"Sheet{idx + 1}" if bad else lab


def _build_native(out: SanitizeOutcome, doc: ExtractedDoc, groups, det: Detector, min_sev: str, fmt: str) -> None:
    """out.text(マーカー入り)から pptx/docx/xlsx を作り直し、再検査して out に載せる。
    作れない/通らないときは unsafe にして何も渡さない(fail-closed)。"""
    from .scan import scan_bytes
    parts = _unmark(out.text, len(groups))
    if parts is None:                                    # マーカーが壊れたので構造は諦める
        flat = [ln for ln in out.text.split("\n") if not _MARK.match(ln.strip())]
        parts = [flat]
        labels = [""]
        out.notes.append(tr("スライド/シートの区切りを復元できなかったため、1 つにまとめました。"))
    else:
        labels = [_safe_label(g[0], det, min_sev, i) if fmt == "xlsx" else g[0] for i, g in enumerate(groups)]
    clean_groups = [(lab, ls) for lab, ls in zip(labels, parts)]
    out.text = "\n\n".join("\n".join(ls) for ls in parts if any(x.strip() for x in ls))   # 報告・件数用。マーカーなし
    try:
        data = ooxml_out.build(fmt, clean_groups, "Sanitized")
    except Exception as e:  # noqa
        out.notes.append(tr('{0} 形式のファイルを作れませんでした({1})。テキストで保存します。').format(fmt, type(e).__name__))
        return                                           # テキストのまま。state は変えない
    # 作ったファイルを検知器にかけ直す。形式違い・隠し領域・検知が残っていれば渡さない
    chk = scan_bytes(data, name=f"sanitized.{fmt}", detector=det)
    bad = [f for f in chk.findings if SEV_ORDER.get(f.severity, 0) >= SEV_ORDER[min_sev]]
    if bad or chk.status != "scanned" or chk.kind != fmt:
        out.state = "unsafe"
        out.residual = bad
        out.data = b""
        out.text = ""
        out.notes.append(tr("作り直したファイルの再検査で問題が見つかったため、出力しません。"))
        return
    out.data = data
    out.fmt = fmt


def sanitize_doc(doc: ExtractedDoc, detector: Optional[Detector] = None, min_severity: str = "medium",
                 fmt: str = "auto") -> SanitizeOutcome:
    """fmt は auto(元が pptx/docx/xlsx なら同形式、他はテキスト)か txt(常にテキスト)。"""
    det = detector or Detector()
    if doc.status in ("failed", "unsupported"):
        return SanitizeOutcome(source=doc.source, kind=doc.kind, state="skipped",
                               notes=list(doc.notes) or [tr("内容を読み取れませんでした。")])
    native = native_format(doc.kind) if fmt == "auto" else ""
    if not native or not (doc.text or "").strip():
        return sanitize_text_doc(doc.text, doc.source, det, kind=doc.kind, hidden=doc.hidden_regions,
                                 min_severity=min_severity, doc_status=doc.status, notes=doc.notes)
    groups = _doc_groups(doc)
    out = sanitize_text_doc(_marked_text(groups), doc.source, det, kind=doc.kind, hidden=doc.hidden_regions,
                            min_severity=min_severity, doc_status=doc.status, notes=doc.notes)
    if out.state in ("ok", "partial"):
        _build_native(out, doc, groups, _quiet(det), min_severity, native)
    return out


def sanitize_path(path: str, detector: Optional[Detector] = None, min_severity: str = "medium", fmt: str = "auto") -> SanitizeOutcome:
    from .extractors import extract_from_path
    det = detector or Detector()
    try:
        lim = Limits(timeout_sec=det.config.timeout_sec)
        doc = extract_from_path(path, limits=lim, budget=Budget(lim.timeout_sec))
    except Exception as e:  # noqa
        return SanitizeOutcome(source=path, state="skipped", notes=[f"{type(e).__name__}: {e}"])
    return sanitize_doc(doc, det, min_severity, fmt)


def sanitize_url(url: str, detector: Optional[Detector] = None, min_severity: str = "medium", fmt: str = "auto", **fetch_kw) -> SanitizeOutcome:
    from .extractors import extract_from_url
    det = detector or Detector()
    try:
        lim = Limits(timeout_sec=det.config.timeout_sec)
        doc = extract_from_url(url, limits=lim, budget=Budget(lim.timeout_sec), **fetch_kw)
    except Exception as e:  # noqa
        return SanitizeOutcome(source=url, state="skipped", notes=[f"{type(e).__name__}: {e}"])
    return sanitize_doc(doc, det, min_severity, fmt)


def sanitize_string(text: str, source: str = "(text)", detector: Optional[Detector] = None,
                    min_severity: str = "medium") -> SanitizeOutcome:
    return sanitize_text_doc(text, source, detector or Detector(), kind="text", min_severity=min_severity)


def sanitize_source(source: str, detector: Optional[Detector] = None, min_severity: str = "medium",
                    fmt: str = "auto", **fetch_kw) -> SanitizeOutcome:
    if source.lower().startswith(("http://", "https://")):
        return sanitize_url(source, detector, min_severity, fmt, **fetch_kw)
    return sanitize_path(source, detector, min_severity, fmt)


def default_name(source: str, ext: str = "txt") -> str:
    if source.lower().startswith(("http://", "https://")):
        base = re.sub(r"[^\w.-]+", "_", re.sub(r"^https?://", "", source)).strip("_")[:60] or "page"
        stem = base
    else:
        stem = os.path.splitext(os.path.basename(source.rstrip("/\\")))[0] or "output"
    return stem + ".sanitized." + ext.lstrip(".")


def fix_ext(path: str, outcome: SanitizeOutcome) -> str:
    """拡張子を実際の出力形式に合わせる。pptx を作ったのに .txt、を防ぐ。"""
    root, ext = os.path.splitext(path)
    want = "." + outcome.fmt
    if ext.lower() == want:
        return path
    if ext.lower() in (".txt", ".pptx", ".docx", ".xlsx", ""):
        return root + want
    return path + want


def unique_path(directory: str, name: str) -> str:
    base, ext = os.path.splitext(name)
    p = os.path.join(directory, name)
    n = 1
    while os.path.exists(p):
        p = os.path.join(directory, f"{base}-{n}{ext}")
        n += 1
    return p


def write_outcome(outcome: SanitizeOutcome, path: str, overwrite: bool = False) -> str:
    """確認済み(ok/partial)の出力だけ書く。元ファイルと同じパスには書かない。"""
    if outcome.state not in ("ok", "partial") or not outcome.text.strip() and outcome.state == "skipped":
        raise ValueError(tr("無害化できなかったため、ファイルは書き出しません。"))
    if os.path.exists(outcome.source) and os.path.abspath(path) == os.path.abspath(outcome.source):
        raise ValueError(tr("元のファイルには上書きしません。別の名前または場所を指定してください。"))
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    if outcome.data:
        with open(tmp, "wb") as fh:
            fh.write(outcome.data)
    else:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(outcome.text if outcome.text.endswith("\n") else outcome.text + "\n")
    os.replace(tmp, path)
    outcome.out_path = path
    return path


def sanitize_to_dir(sources: Iterable[str], out_dir: str, detector: Optional[Detector] = None,
                    min_severity: str = "medium", on_each=None, cancel=None, fmt: str = "auto", **fetch_kw) -> List[SanitizeOutcome]:
    os.makedirs(out_dir, exist_ok=True)
    outs: List[SanitizeOutcome] = []
    for s in sources:
        if cancel is not None and cancel.is_set():
            break
        o = sanitize_source(s, detector, min_severity, fmt, **fetch_kw)
        if o.state in ("ok", "partial"):
            try:
                write_outcome(o, unique_path(out_dir, default_name(s, o.fmt)))
            except (OSError, ValueError) as e:
                o.state = "skipped"
                o.notes.append(str(e))
        outs.append(o)
        if on_each:
            on_each(o)
    return outs


STATE_JA = TMap({"ok": "無害化・確認済み", "partial": "一部のみ(要確認)", "skipped": "スキップ(読めない)", "unsafe": "無害化できず(検知が残った)"})


def summarize_outcome(o: SanitizeOutcome) -> Dict[str, int]:
    return {"hidden": o.hidden_dropped, "invisible": o.invisible_removed, "redacted": o.redacted}


def report_csv(outcomes: Sequence[SanitizeOutcome], headers: Optional[Sequence[str]] = None,
               state_names: Optional[Dict[str, str]] = None) -> str:
    names = state_names or STATE_JA
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(headers or ["source", "state", "hidden_dropped", "invisible_chars_removed", "redacted", "output", "notes"])
    for o in outcomes:
        w.writerow([o.source, names.get(o.state, o.state), o.hidden_dropped, o.invisible_removed, o.redacted,
                    o.out_path, " / ".join(o.notes)[:300]])
    return buf.getvalue()
