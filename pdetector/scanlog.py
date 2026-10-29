"""スキャンログ(JSON Lines)。GUI と CLI 共通。
1 スキャン 1 ファイル(scan-YYYYmmdd-HHMMSS.jsonl)。途中で落ちても残るよう、結果ごとに flush する。

    {"type":"session", "started":..., "mode":"gui|cli", "targets":[...], "tool_version":..., "rules_version":...}
    {"type":"result",  "at":..., <ScanResult.to_dict()>}      # 抜粋は 300 文字まで。本文は保存しない
    {"type":"end",     "finished":..., "done":N, "cancelled":bool, "error":"", "worst":..., "counts":{...}}

パス・SHA-256・抜粋は残る。ログが書けなくてもスキャンは止めない。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import fields
from typing import Dict, List, Optional, Sequence, Tuple

from .model import Finding, ScanResult
from .i18n import tr

SNIPPET_MAX = 300
_RESULT_FIELDS = {f.name for f in fields(ScanResult)}
_FINDING_FIELDS = {f.name for f in fields(Finding)}


def now_iso() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def default_log_dir() -> str:
    from .gui_logic import state_dir
    return os.path.join(state_dir(), "logs")


def _trim(d: dict) -> dict:
    for f in d.get("findings", []):
        for k in ("snippet", "detail"):
            if isinstance(f.get(k), str) and len(f[k]) > SNIPPET_MAX:
                f[k] = f[k][:SNIPPET_MAX] + "…"
    return d


def result_to_record(r: ScanResult) -> dict:
    d = _trim(r.to_dict())
    rec = {"type": "result", "at": now_iso()}
    rec.update(d)
    return rec


def result_from_record(rec: dict) -> ScanResult:
    d = {k: v for k, v in rec.items() if k in _RESULT_FIELDS and k != "findings"}
    fs = []
    for f in rec.get("findings", []) or []:
        try:
            fs.append(Finding(**{k: v for k, v in f.items() if k in _FINDING_FIELDS}))
        except TypeError:
            continue
    d.setdefault("source", "?")
    r = ScanResult(**d)
    r.findings = fs
    return r


class ScanLogger:
    """start() -> write() を繰り返す -> end()。書き込み失敗は例外にせず .error に入れる。"""

    def __init__(self, directory: Optional[str] = None, targets: Sequence[str] = (), mode: str = "gui"):
        self.dir = directory or default_log_dir()
        self.targets = list(targets)
        self.mode = mode
        self.path = ""
        self.error = ""
        self._fh = None
        self._results: List[ScanResult] = []
        self._ended = False

    @property
    def active(self) -> bool:
        return self._fh is not None

    def start(self) -> "ScanLogger":
        from . import patterns
        from .detector import TOOL_VERSION
        try:
            os.makedirs(self.dir, exist_ok=True)
            base = "scan-" + time.strftime("%Y%m%d-%H%M%S")
            for n in range(0, 100):
                name = base + (f"-{n}" if n else "") + ".jsonl"
                try:
                    self._fh = open(os.path.join(self.dir, name), "x", encoding="utf-8", newline="\n")
                    self.path = os.path.join(self.dir, name)
                    break
                except FileExistsError:
                    continue
            if self._fh is None:
                raise OSError(tr("ログファイル名を確保できません"))
            self._line({"type": "session", "started": now_iso(), "mode": self.mode, "targets": self.targets,
                        "tool_version": TOOL_VERSION, "rules_version": patterns.RULES_VERSION})
        except Exception as e:  # noqa
            self._fail(e)
        return self

    def write(self, r: ScanResult) -> None:
        self._results.append(r)
        if self._fh is not None:
            try:
                self._line(result_to_record(r))
            except Exception as e:  # noqa
                self._fail(e)

    def end(self, done: Optional[int] = None, cancelled: bool = False, error: str = "") -> None:
        if self._ended:
            return
        self._ended = True
        if self._fh is None:
            return
        try:
            from .gui_logic import worst_level, count_levels
            self._line({"type": "end", "finished": now_iso(),
                        "done": len(self._results) if done is None else done, "cancelled": bool(cancelled),
                        "error": error, "worst": worst_level(self._results), "counts": count_levels(self._results)})
        except Exception as e:  # noqa
            self._fail(e)
        finally:
            self.close()

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def _line(self, rec: dict) -> None:
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._fh.flush()

    def _fail(self, e: Exception) -> None:
        self.error = f"{type(e).__name__}: {e}"
        self.close()


def _iter_records(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue            # 書きかけの行は捨てる
            if isinstance(rec, dict):
                yield rec


def read_session(path: str) -> Tuple[dict, List[ScanResult], dict]:
    """(ヘッダ, 結果, フッタ)。フッタが空 dict なら途中で終わったスキャン。"""
    head: dict = {}
    foot: dict = {}
    results: List[ScanResult] = []
    for rec in _iter_records(path):
        t = rec.get("type")
        if t == "session":
            head = rec
        elif t == "result":
            try:
                results.append(result_from_record(rec))
            except Exception:  # noqa
                continue
        elif t == "end":
            foot = rec
    return head, results, foot


def summarize(path: str) -> dict:
    """履歴一覧用の要約。"""
    from .gui_logic import worst_level, count_levels
    head, results, foot = read_session(path)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    name = os.path.basename(path)
    return {
        "path": path, "name": name,
        "started": head.get("started") or _started_from_name(name),
        "mode": head.get("mode", ""), "targets": head.get("targets", []),
        "count": len(results), "finished": bool(foot), "cancelled": bool(foot.get("cancelled")),
        "error": foot.get("error", ""), "worst": foot.get("worst") or (worst_level(results) if results else "clean"),
        "counts": foot.get("counts") or count_levels(results), "size": size,
        "tool_version": head.get("tool_version", ""), "rules_version": head.get("rules_version", ""),
    }


def _started_from_name(name: str) -> str:
    try:
        t = time.strptime(name[5:20], "%Y%m%d-%H%M%S")
        return time.strftime("%Y-%m-%d %H:%M:%S", t)
    except ValueError:
        return ""


def list_logs(directory: Optional[str] = None) -> List[str]:
    d = directory or default_log_dir()
    try:
        names = [n for n in os.listdir(d) if n.startswith("scan-") and n.endswith(".jsonl")]
    except OSError:
        return []
    return sorted((os.path.join(d, n) for n in names), reverse=True)


def list_sessions(directory: Optional[str] = None) -> List[dict]:
    out = []
    for p in list_logs(directory):
        try:
            out.append(summarize(p))
        except OSError:
            continue
    return out


def prune(directory: Optional[str] = None, keep_days: int = 90, max_files: int = 500) -> int:
    """古いログを消して件数を返す。keep_days<=0 なら日数では消さない。max_files 超過分も消す。"""
    paths = list_logs(directory)               # 新しい順
    removed = 0
    cutoff = time.time() - keep_days * 86400 if keep_days and keep_days > 0 else None
    for i, p in enumerate(paths):
        try:
            old = cutoff is not None and os.path.getmtime(p) < cutoff
            if old or i >= max_files:
                os.remove(p)
                removed += 1
        except OSError:
            continue
    return removed


def delete_logs(paths: Sequence[str]) -> int:
    n = 0
    for p in paths:
        if os.path.basename(p).startswith("scan-") and p.endswith(".jsonl"):
            try:
                os.remove(p)
                n += 1
            except OSError:
                pass
    return n
