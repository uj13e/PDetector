"""検知結果の整形。text / json / markdown / csv / html。"""
from __future__ import annotations

import csv
import io
import json
from typing import List

from .i18n import TMap, tr
from .model import SEV_ORDER, ScanResult

LEVEL_LABEL = TMap({
    "clean": "問題なし", "low": "低", "medium": "中", "high": "高", "critical": "重大",
    "unscanned": "解析不可(安全とは判断できません)",
})
STATUS_LABEL = TMap({
    "scanned": "完全に解析", "partial": "一部のみ解析(未解析の部分があります)", "unscanned": "解析できませんでした",
})


def verdict_line(r: ScanResult) -> str:
    s = LEVEL_LABEL.get(r.risk_level, r.risk_level)
    if r.status == "partial" and r.risk_level in ("clean", "low"):
        s += tr("(ただし一部未解析)")
    return s


def format_text(r: ScanResult, show_info: bool = True) -> str:
    L: List[str] = []
    L.append("=" * 72)
    L.append(tr('対象  : {0}').format(r.source))
    L.append(tr('判定  : {0}   (risk={1}/100)').format(verdict_line(r), r.risk_score))
    meta = [tr('形式={0}').format(r.kind or '-'), tr('文字数={0:,}').format(r.text_length), tr('検知={0}件').format(len(r.findings))]
    if r.encoding:
        meta.append(tr('文字コード={0}').format(r.encoding))
    L.append("        " + " / ".join(meta))
    if r.status != "scanned":
        L.append(tr('状態  : {0}').format(STATUS_LABEL.get(r.status, r.status)))
    if r.sha256:
        L.append(f"SHA-256: {r.sha256}")
    for n in r.notes:
        L.append(f"  * {tr(n)}")
    L.append("-" * 72)
    fs = [f for f in r.findings if show_info or f.severity != "info"]
    if not fs:
        if r.status == "scanned":
            L.append(tr("  間接プロンプトインジェクションの兆候は検出されませんでした。"))
        else:
            L.append(tr("  検知はありませんが、解析が不完全です。上記の注記を確認してください。"))
    for f in sorted(fs, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
        L.append(f"  [{f.severity.upper():8}] {tr(f.description)}  ({f.category}/{f.rule_id})")
        if f.location:
            L.append(tr('             位置: {0}').format(tr(f.location)) + (tr(' 行{0}').format(f.line) if f.line else ""))
        if f.snippet:
            L.append(tr('             抜粋: {0}').format(f.snippet))
        if f.detail:
            L.append(tr('             詳細: {0}').format(tr(f.detail)))
    L.append("=" * 72)
    return "\n".join(L)


def format_json(results: List[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2)


def format_markdown(results: List[ScanResult]) -> str:
    L = [tr("# PDetector スキャン結果"), ""]
    L.append(tr("| 対象 | 判定 | 状態 | 検知数 | 形式 |"))
    L.append("|---|---|---|---|---|")
    for r in results:
        L.append(f"| {_md(r.source)} | {verdict_line(r)} | {r.status} | {len(r.findings)} | {r.kind or '-'} |")
    for r in results:
        if not r.findings and r.status == "scanned":
            continue
        L += ["", f"## {_md(r.source)}", ""]
        for n in r.notes:
            L.append(tr('- 注記: {0}').format(tr(n)))
        for f in sorted(r.findings, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
            L.append(f"- **{f.severity}** `{f.rule_id}` {tr(f.description)}")
            if f.location:
                L.append(tr('  - 位置: {0}').format(tr(f.location)) + (tr(' 行{0}').format(f.line) if f.line else ""))
            if f.snippet:
                L.append(tr('  - 抜粋: `{0}`').format(f.snippet.replace('`', chr(39))))
    return "\n".join(L) + "\n"


def _md(s: str) -> str:
    return s.replace("|", "\\|")


def format_csv(results: List[ScanResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source", "level", "status", "severity", "rule_id", "category", "location", "line", "description", "snippet"])
    for r in results:
        if not r.findings:
            w.writerow([r.source, r.risk_level, r.status, "", "", "", "", "", "", ""])
        for f in r.findings:
            w.writerow([r.source, r.risk_level, r.status, f.severity, f.rule_id, f.category, tr(f.location), f.line,
                        tr(f.description), f.snippet])
    return buf.getvalue()


# HTML は単一ファイルで外部リソースなし(共有・印刷用)
_HTML_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1f2937;--mut:#6b7280;--bd:#e5e7eb;
--clean:#15803d;--low:#a16207;--medium:#c2410c;--high:#b91c1c;--critical:#7f1d1d;--unscanned:#6d28d9;--info:#475569}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--card:#1e293b;--fg:#e5e7eb;--mut:#94a3b8;--bd:#334155;
--clean:#4ade80;--low:#facc15;--medium:#fb923c;--high:#f87171;--critical:#fca5a5;--unscanned:#c4b5fd;--info:#94a3b8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 "Yu Gothic UI","Meiryo UI","Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--mut);margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:0 0 14px}
.head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.badge{display:inline-block;padding:1px 10px;border-radius:999px;border:1.5px solid currentColor;font-weight:700;font-size:12px;white-space:nowrap}
.src{font-weight:700;word-break:break-all}.meta{color:var(--mut);font-size:12px;margin-top:2px;word-break:break-all}
.f{border-top:1px solid var(--bd);padding:8px 0}.f:first-of-type{border-top:0}
.desc{font-weight:600}.kv{color:var(--mut);font-size:12px}
pre{margin:4px 0 0;padding:6px 8px;background:var(--bg);border-radius:6px;white-space:pre-wrap;word-break:break-all;font:12px/1.5 ui-monospace,Consolas,monospace}
table{border-collapse:collapse;width:100%}td,th{padding:4px 8px;border-bottom:1px solid var(--bd);text-align:left;font-size:13px}
.note{color:var(--mut);font-size:12px}
.c-clean{color:var(--clean)}.c-low{color:var(--low)}.c-medium{color:var(--medium)}.c-high{color:var(--high)}
.c-critical{color:var(--critical)}.c-unscanned{color:var(--unscanned)}.c-info{color:var(--info)}
"""


def format_html(results: List[ScanResult], title: str = "") -> str:
    title = title or tr("PDetector スキャンレポート")
    from html import escape as e
    import time as _t
    from .detector import TOOL_VERSION
    from . import patterns
    cnt: dict = {}
    for r in results:
        cnt[r.risk_level] = cnt.get(r.risk_level, 0) + 1
    order = ["critical", "high", "unscanned", "medium", "low", "clean"]
    summary = " ".join(f'<span class="badge c-{k}">{e(LEVEL_LABEL[k].split("(")[0])} {cnt[k]}</span>' for k in order if k in cnt)
    L = ["<!doctype html><html lang=\"ja\"><head><meta charset=\"utf-8\">",
         "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
         f"<title>{e(title)}</title><style>{_HTML_CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1>",
         tr('<div class="sub">{0} / PDetector {1} (rules {2}) / {3} 件</div>').format(e(_t.strftime('%Y-%m-%d %H:%M')), e(TOOL_VERSION), e(patterns.RULES_VERSION), len(results)),
         f'<div class="card head">{summary}</div>']
    if len(results) > 1:
        L.append(tr('<div class="card"><table><tr><th>対象</th><th>判定</th><th>検知</th><th>状態</th></tr>'))
        for r in results:
            L.append(f'<tr><td>{e(r.source)}</td><td class="c-{e(r.risk_level)}"><b>{e(verdict_line(r))}</b></td>'
                     f'<td>{len(r.findings)}</td><td>{e(r.status)}</td></tr>')
        L.append("</table></div>")
    for r in results:
        L.append('<div class="card">')
        L.append(f'<div class="head"><span class="badge c-{e(r.risk_level)}">{e(verdict_line(r))}</span>'
                 f'<span class="src">{e(r.source)}</span></div>')
        meta = [tr('形式 {0}').format(r.kind or '-'), tr('{0:,}文字').format(r.text_length), f"risk {r.risk_score}/100"]
        if r.encoding:
            meta.append(tr('文字コード {0}').format(r.encoding))
        if r.sha256:
            meta.append(f"SHA-256 {r.sha256}")
        L.append(f'<div class="meta">{e(" / ".join(meta))}</div>')
        if r.status != "scanned":
            L.append(tr('<div class="note">状態: {0}</div>').format(e(STATUS_LABEL.get(r.status, r.status))))
        for n in r.notes:
            L.append(f'<div class="note">・{e(tr(n))}</div>')
        if not r.findings and r.status == "scanned":
            L.append(tr('<p class="note">兆候は検出されませんでした。</p>'))
        for f in sorted(r.findings, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
            L.append(f'<div class="f"><span class="badge c-{e(f.severity)}">{e(f.severity.upper())}</span> '
                     f'<span class="desc">{e(tr(f.description))}</span>'
                     f'<div class="kv">{e(f.category)} / {e(f.rule_id)}'
                     + (tr(' / 位置: {0}').format(e(tr(f.location))) if f.location else "") + (tr(' 行{0}').format(f.line) if f.line else "") + '</div>')
            if f.snippet:
                L.append(f"<pre>{e(f.snippet)}</pre>")
            if f.detail:
                L.append(f'<div class="kv">{e(tr(f.detail))}</div>')
            L.append("</div>")
        L.append("</div>")
    L.append("</main></body></html>")
    return "\n".join(L)
