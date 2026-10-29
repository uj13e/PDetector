"""抽出と検知をまとめた API と CLI。
例外が出ても clean にはせず、必ず status/risk_level が "unscanned" の結果を返す(fail-closed)。
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import traceback
from typing import Iterable, Iterator, List, Optional

from .config import DetectorConfig, load_config
from .detector import Detector, TOOL_VERSION
from .extractors import extract_from_bytes, extract_from_path, extract_from_url as _extract_url
from .model import ExtractedDoc, LEVEL_RANK, ScanResult
from .safeio import Budget, Limits
from . import i18n
from .i18n import tr


def _failed_result(source: str, msg: str, detector: Optional[Detector] = None) -> ScanResult:
    doc = ExtractedDoc(source=source, status="failed")
    doc.notes.append(msg)
    return (detector or Detector()).scan_doc(doc)


def _limits_for(det: Detector) -> Limits:
    return Limits(timeout_sec=det.config.timeout_sec)


def scan_doc(doc: ExtractedDoc, detector: Optional[Detector] = None) -> ScanResult:
    return (detector or Detector()).scan_doc(doc)


def scan_path(path: str, detector: Optional[Detector] = None) -> ScanResult:
    det = detector or Detector()
    try:
        limits = _limits_for(det)
        doc = extract_from_path(path, limits=limits, budget=Budget(limits.timeout_sec))
        return det.scan_doc(doc, source=path)
    except Exception as e:  # noqa  fail-closed
        return _failed_result(path, tr('内部エラーのため解析できませんでした: {0}: {1}').format(type(e).__name__, e), det)


def scan_bytes(data: bytes, name: str = "", detector: Optional[Detector] = None,
               content_type: Optional[str] = None, source: Optional[str] = None) -> ScanResult:
    det = detector or Detector()
    try:
        limits = _limits_for(det)
        doc = extract_from_bytes(data, name=name, limits=limits, budget=Budget(limits.timeout_sec),
                                 content_type=content_type, source=source or name or "<bytes>")
        return det.scan_doc(doc)
    except Exception as e:  # noqa
        return _failed_result(source or name or "<bytes>", tr('内部エラーのため解析できませんでした: {0}: {1}').format(type(e).__name__, e), det)


def scan_url(url: str, detector: Optional[Detector] = None, **fetch_kw) -> ScanResult:
    det = detector or Detector()
    try:
        limits = _limits_for(det)
        doc = _extract_url(url, limits=limits, budget=Budget(limits.timeout_sec), **fetch_kw)
        return det.scan_doc(doc, source=url)
    except Exception as e:  # noqa
        return _failed_result(url, tr('内部エラーのため解析できませんでした: {0}: {1}').format(type(e).__name__, e), det)


def scan_text(text: str, source: str = "<text>", detector: Optional[Detector] = None) -> ScanResult:
    det = detector or Detector()
    try:
        return det.scan_text(text, source=source)
    except Exception as e:  # noqa
        return _failed_result(source, tr('内部エラーのため解析できませんでした: {0}: {1}').format(type(e).__name__, e), det)


def iter_files(paths: Iterable[str], recursive: bool = False, include: Optional[List[str]] = None,
               exclude: Optional[List[str]] = None) -> Iterator[str]:
    def ok(p: str) -> bool:
        name = os.path.basename(p)
        if include and not any(fnmatch.fnmatch(name, g) for g in include):
            return False
        if exclude and any(fnmatch.fnmatch(name, g) for g in exclude):
            return False
        return True

    for p in paths:
        if os.path.isdir(p):
            if not recursive:
                # サブフォルダには入らない
                for n in sorted(os.listdir(p)):
                    fp = os.path.join(p, n)
                    if os.path.isfile(fp) and ok(fp):
                        yield fp
            else:
                for root, dirs, files in os.walk(p):
                    dirs.sort()
                    for n in sorted(files):
                        fp = os.path.join(root, n)
                        if ok(fp):
                            yield fp
        else:
            yield p


# CLI
def _setup_stdout():
    """cp932 のコンソールで出せない文字があっても落とさない。"""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")
        except Exception:
            pass


def _pick_lang(argv: List[str]) -> str:
    """--lang か PDETECTOR_LANG で決める。指定なしは ja(従来の挙動を変えない)。"""
    val = None
    for i, a in enumerate(argv):
        if a.startswith("--lang="):
            val = a.split("=", 1)[1]
        elif a == "--lang" and i + 1 < len(argv):
            val = argv[i + 1]
    val = val or os.environ.get("PDETECTOR_LANG") or "ja"
    return i18n.resolve_lang(val)


def main(argv: Optional[List[str]] = None) -> int:
    _setup_stdout()
    i18n.set_lang(_pick_lang(list(sys.argv[1:] if argv is None else argv)))
    p = argparse.ArgumentParser(
        prog="pdetector",
        description=tr("間接プロンプトインジェクション検知ツール(ルールベース+ヒューリスティック)"))
    p.add_argument("targets", nargs="*", help=tr("ファイル/フォルダ/URL(http/https)。'-' で標準入力"))
    p.add_argument("--lang", choices=["auto", "ja", "en"], default=None, help=tr("表示言語(既定 ja。auto は OS の表示言語)"))
    p.add_argument("--version", action="store_true", help=tr("バージョンを表示して終了"))
    p.add_argument("--check", action="store_true", help=tr("実行中Pythonの依存関係を表示して終了"))
    p.add_argument("--list-rules", action="store_true", help=tr("ルール一覧を表示して終了"))
    p.add_argument("--format", choices=["text", "json", "markdown", "csv", "html"], default="text", help=tr("出力形式"))
    p.add_argument("--json", action="store_true", help=tr("--format json の別名"))
    p.add_argument("-o", "--output", help=tr("結果をファイルにも保存する"))
    p.add_argument("-r", "--recursive", action="store_true", help=tr("フォルダを再帰的に走査"))
    p.add_argument("--include", action="append", help=tr("対象ファイル名のglob(複数可)"))
    p.add_argument("--exclude", action="append", help=tr("除外ファイル名のglob(複数可)"))
    p.add_argument("--config", help=tr("設定JSON(未指定なら環境変数 PDETECTOR_CONFIG)"))
    p.add_argument("--no-decode", action="store_true", help=tr("base64等のデコード検査を行わない"))
    p.add_argument("--allow-private", action="store_true", help=tr("URL取得でプライベート/内部アドレスを許可(SSRF保護を解除)"))
    p.add_argument("--no-cloak-check", action="store_true", help=tr("URLのUAクローキング検査(2回取得)を行わない"))
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "unscanned"],
                   help=tr("指定レベル以上(または解析不可)を検知したら終了コード1で終了(CI用)"))
    p.add_argument("--strict", action="store_true", help=tr("一部のみ解析(partial)も解析不可として扱う"))
    p.add_argument("--sanitize", metavar="DIR",
                   help=tr("無害化: 安全なテキスト版(隠し要素・不可視文字を除去し命令文を伏せ字)を DIR に書き出す。元ファイルは変更しない"))
    p.add_argument("--sanitize-format", choices=["auto", "txt"], default="auto",
                   help=tr("無害化の出力形式(既定 auto: pptx/docx/xlsx は同じ形式で作り直し、それ以外はテキスト。txt: 常にテキスト)"))
    p.add_argument("--sanitize-level", choices=["low", "medium", "high", "critical"], default="medium",
                   help=tr("無害化で伏せ字にする重大度の下限(既定 medium)"))
    p.add_argument("--log", nargs="?", const="", metavar="DIR",
                   help=tr("スキャンログ(JSON Lines)を保存する。DIR 省略時は既定の保存先(GUI の履歴と共通)"))
    p.add_argument("-q", "--quiet", action="store_true", help=tr("問題なしの対象は出力しない"))
    args = p.parse_args(argv)

    if args.version:
        from . import patterns
        print(f"PDetector {TOOL_VERSION} (rules {patterns.RULES_VERSION})")
        return 0
    if args.check:
        from . import deps
        print(deps.format_report())
        miss = deps.missing_pip_names()
        if miss:
            print(tr("\n不足を導入するには:"))
            print(f'  "{sys.executable}" -m pip install ' + " ".join(miss))
        return 0
    if args.list_rules:
        from . import patterns
        for rid, desc, rx, sev, cat in patterns.ALL_PATTERNS:
            print(f"{sev:9} {cat:22} {rid:32} {desc}")
        return 0
    if not args.targets:
        p.error(tr("スキャン対象(ファイル/フォルダ/URL)を指定してください。環境確認は --check。"))

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(tr('設定ファイルを読み込めません: {0}').format(e), file=sys.stderr)
        return 2
    if args.no_decode:
        cfg.decode = False
    det = Detector(cfg)

    fetch_kw = dict(allow_private=args.allow_private, cloak_check=not args.no_cloak_check)
    results: List[ScanResult] = []
    logger = None
    if args.log is not None:
        from .scanlog import ScanLogger
        logger = ScanLogger(args.log or None, args.targets, mode="cli").start()
        if logger.error:
            print(tr('ログを保存できません: {0}').format(logger.error), file=sys.stderr)
    urls = [t for t in args.targets if t.lower().startswith(("http://", "https://"))]
    others = [t for t in args.targets if t not in urls]
    stdin_data: Optional[bytes] = None
    for t in others:
        if t == "-":
            data = sys.stdin.buffer.read()
            stdin_data = data
            results.append(scan_bytes(data, name="stdin", detector=det, source="<stdin>"))
    paths = [t for t in others if t != "-"]
    scanned_files: List[str] = []
    for fp in iter_files(paths, recursive=args.recursive, include=args.include, exclude=args.exclude):
        scanned_files.append(fp)
        results.append(scan_path(fp, det))
    for u in urls:
        results.append(scan_url(u, det, **fetch_kw))

    if args.strict:
        for r in results:
            if r.status == "partial":
                r.status = "unscanned"
                r.risk_level = "unscanned" if LEVEL_RANK[r.risk_level] < LEVEL_RANK["unscanned"] else r.risk_level
                r.notes.append(tr("--strict のため、一部のみの解析を解析不可として扱いました。"))

    if logger is not None:
        for r in results:
            logger.write(r)
        logger.end(len(results), False)
        if logger.path and not logger.error:
            print(tr('ログを保存しました: {0}').format(logger.path), file=sys.stderr)

    from . import report
    fmt = "json" if args.json else args.format
    shown = [r for r in results if not (args.quiet and r.risk_level == "clean" and r.status == "scanned")]
    if fmt == "json":
        out = report.format_json(shown)
    elif fmt == "markdown":
        out = report.format_markdown(shown)
    elif fmt == "csv":
        out = report.format_csv(shown)
    elif fmt == "html":
        out = report.format_html(shown)
    else:
        out = "\n".join(report.format_text(r) for r in shown)
        if len(results) > 1:
            out += "\n" + _summary(results)
    print(out)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as fh:
                fh.write(out + "\n")
        except OSError as e:
            print(tr('出力ファイルを書き込めません: {0}').format(e), file=sys.stderr)
            return 2

    if args.sanitize:
        rc = _run_sanitize(args, det, scanned_files, urls, stdin_data, fetch_kw)
        if rc:
            return rc

    if args.fail_on:
        thr = LEVEL_RANK[args.fail_on]
        if any(LEVEL_RANK.get(r.risk_level, 0) >= thr for r in results):
            return 1
    return 0


def _run_sanitize(args, det: Detector, files: List[str], urls: List[str], stdin_data: Optional[bytes], fetch_kw: dict) -> int:
    from . import neutralize as nt
    out_dir = args.sanitize
    outs = []
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        print(tr('無害化の出力先を作れません: {0}').format(e), file=sys.stderr)
        return 2
    if stdin_data is not None:
        lim = _limits_for(det)
        doc = extract_from_bytes(stdin_data, name="stdin", limits=lim, budget=Budget(lim.timeout_sec), source="<stdin>")
        o = nt.sanitize_doc(doc, det, args.sanitize_level, args.sanitize_format)
        if o.state in ("ok", "partial"):
            nt.write_outcome(o, nt.unique_path(out_dir, nt.default_name("stdin", o.fmt)))
        outs.append(o)
    outs += nt.sanitize_to_dir(files + urls, out_dir, det, args.sanitize_level,
                               fmt=args.sanitize_format, allow_private=args.allow_private, cloak_check=False)
    for o in outs:
        label = nt.STATE_JA.get(o.state, o.state)
        print(tr('[無害化] {0}: {1}').format(label, o.source) + (f" -> {o.out_path}" if o.out_path else ""), file=sys.stderr)
    try:
        with open(os.path.join(out_dir, "sanitize_report.csv"), "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(nt.report_csv(outs))
    except OSError as e:
        print(tr('レポートを書けません: {0}').format(e), file=sys.stderr)
    bad = [o for o in outs if o.state in ("unsafe", "skipped")]
    if bad:
        print(tr('無害化できなかった対象が {0} 件あります(安全なテキストは出力していません)。').format(len(bad)), file=sys.stderr)
    return 0


def _summary(results: List[ScanResult]) -> str:
    cnt = {}
    for r in results:
        cnt[r.risk_level] = cnt.get(r.risk_level, 0) + 1
    parts = [f"{k}={v}" for k, v in sorted(cnt.items(), key=lambda kv: -LEVEL_RANK.get(kv[0], 0))]
    return tr('合計 {0} 件: ').format(len(results)) + ", ".join(parts)


if __name__ == "__main__":
    sys.exit(main())
