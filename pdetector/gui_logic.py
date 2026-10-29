"""GUI のうち Tk に依存しない部分(設定の保存、入力の解釈、走査、集計、フィルタ)。
Tk なしでテストできるように分けてある。
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import threading
from dataclasses import asdict
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .config import DetectorConfig
from .i18n import TMap, tr
from .model import Finding, LEVEL_RANK, SEV_ORDER, ScanResult

LEVEL_NAME = TMap({
    "clean": "問題なし", "low": "低リスク", "medium": "中リスク", "high": "高リスク",
    "critical": "重大リスク", "unscanned": "解析不可",
})
LEVEL_ORDER = ["critical", "high", "unscanned", "medium", "low", "clean"]      # 重い順
SEV_NAME = TMap({"critical": "重大", "high": "高", "medium": "中", "low": "低", "info": "情報"})
SEV_LIST = ["critical", "high", "medium", "low", "info"]

CATEGORY_NAME = TMap({
    "instruction_override": "命令の上書き", "role_manipulation": "役割の書き換え", "jailbreak": "ジェイルブレイク",
    "stealth": "隠蔽の指示", "exfiltration": "情報の送出", "tool_abuse": "ツール悪用", "delimiter_spoof": "区切りの偽装",
    "obfuscation": "難読化", "hidden_content": "隠しコンテンツ", "active_content": "能動的コンテンツ", "custom": "独自ルール",
})

# カテゴリごとの対処の助言
ADVICE = TMap({
    "instruction_override": "文書が AI の既存の指示を打ち消そうとしています。この文書を AI に読ませる前に該当箇所を取り除くか、文書自体を信頼しないでください。",
    "role_manipulation": "AI に別の役割・人格を与えて振る舞いを変えさせようとしています。通常の文書には現れない書き方です。",
    "jailbreak": "AI の安全制限を外させようとする典型的な文言です。AI に渡さず、出所を確認してください。",
    "stealth": "『ユーザーには知らせるな』など、利用者に隠れて動作させる指示です。特に危険度が高い兆候です。",
    "exfiltration": "会話・認証情報・内部データを外部へ送らせる指示の疑いがあります。AI に外部通信やメール送信の権限がある場合は特に危険です。",
    "tool_abuse": "AI のツール(ファイル操作・コマンド・API)を勝手に実行させる指示の疑いがあります。エージェント用途では必ず取り除いてください。",
    "delimiter_spoof": "システムメッセージ等の区切りを偽装して、AI に『文書の外の指示』だと誤認させようとしています。",
    "obfuscation": "人の目では読めない形(不可視文字・エンコード・似た文字)で内容が隠されています。隠す正当な理由はほぼ無く、悪意のある可能性が高いです。",
    "hidden_content": "人間の目に見えない(見えにくい)テキストが含まれています。AI だけが読む内容を仕込む手口に使われます。",
    "active_content": "マクロ・JavaScript・外部参照など、読み込むだけで動く要素があります。内容を AI に渡す前に除去してください。",
    "custom": "独自ルールに一致しました。",
})

STATUS_TEXT = TMap({
    "scanned": "完全に解析", "partial": "一部のみ解析", "unscanned": "解析できませんでした",
})


def advice_for(f: Finding) -> str:
    base = ADVICE.get(f.category, "")
    if f.rule_id.startswith("encoded:") or f.rule_id.startswith("obfuscated:"):
        base = ADVICE["obfuscation"]
    return base


def state_dir() -> str:
    if os.environ.get("PDETECTOR_HOME"):
        d = os.environ["PDETECTOR_HOME"]
    elif sys.platform.startswith("win"):
        d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "pdetector")
    else:
        d = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "pdetector")
    return d


def _atomic_write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def user_config_path() -> str:
    return os.path.join(state_dir(), "config.json")


def ui_state_path() -> str:
    return os.path.join(state_dir(), "gui.json")


def load_user_config() -> Tuple[DetectorConfig, str]:
    """(設定, 読んだ場所の説明)。優先順は PDETECTOR_CONFIG、ユーザー設定、既定値。壊れていたら既定値と警告文。"""
    from .config import load_config
    env = os.environ.get("PDETECTOR_CONFIG")
    path = env or user_config_path()
    if not os.path.exists(path):
        return DetectorConfig(), tr("既定の設定")
    try:
        return load_config(path), path
    except Exception as e:  # noqa
        return DetectorConfig(), tr('設定ファイルを読めないため既定値を使います({0}: {1})').format(path, e)


def save_user_config(cfg: DetectorConfig, path: Optional[str] = None) -> str:
    path = path or user_config_path()
    d = cfg.to_dict()
    d.pop("keep_text", None)                    # GUI 内部用なのでファイルには書かない
    _atomic_write(path, json.dumps(d, ensure_ascii=False, indent=2))
    return path


DEFAULT_UI = {
    "theme": "auto", "font_scale": 1.0, "geometry": "", "last_dir": "", "recent": [],
    "sev_filter": ["critical", "high", "medium", "low"], "pane_ratio": 0.46, "show_welcome": True,
    "log_enabled": True, "log_keep_days": 90, "lang": "auto",
}


def load_ui_state() -> dict:
    st = dict(DEFAULT_UI)
    try:
        with open(ui_state_path(), "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, dict):
            for k in DEFAULT_UI:
                if k in raw and isinstance(raw[k], type(DEFAULT_UI[k])):
                    st[k] = raw[k]
    except Exception:
        pass
    st["font_scale"] = min(1.8, max(0.8, float(st["font_scale"])))
    return st


def save_ui_state(st: dict) -> None:
    try:
        _atomic_write(ui_state_path(), json.dumps(st, ensure_ascii=False, indent=2))
    except OSError:
        pass


def add_recent(st: dict, target: str, limit: int = 15) -> None:
    rec = [t for t in st.get("recent", []) if t != target]
    rec.insert(0, target)
    st["recent"] = rec[:limit]


def is_url(s: str) -> bool:
    return s.strip().lower().startswith(("http://", "https://"))


def split_targets(s: str) -> List[str]:
    """入力欄の文字列を対象に分ける。引用符付き、空白区切り、ドロップ由来の {C:/a b/c.txt} 形式に対応。"""
    s = (s or "").strip()
    if not s:
        return []
    # tkinterdnd2 は空白入りパスを {} で囲んで渡してくる
    items: List[str] = re.findall(r"\{([^}]*)\}", s)
    rest = re.sub(r"\{[^}]*\}", " ", s).strip()
    if rest:
        try:
            parts = shlex.split(rest, posix=False)
        except ValueError:
            parts = rest.split()
        items += [p.strip('"') for p in parts]
    # 空白入りパスが引用符なしで来た場合。全体で実在するパスなら1件扱いにする
    if len(items) > 1 and (os.path.exists(s.strip('"')) or is_url(s)):
        return [s.strip('"')]
    return [i for i in items if i]


def normalize_url(u: str) -> str:
    u = u.strip()
    if not is_url(u) and re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", u, re.I):
        return "https://" + u
    return u


def looks_like_target(s: str) -> bool:
    s = s.strip().strip('"')
    return bool(s) and (is_url(s) or os.path.exists(s) or bool(re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", s, re.I)))


MAX_FILES = 5000


class Progress:
    __slots__ = ("done", "total", "current", "truncated")

    def __init__(self, done=0, total=0, current="", truncated=False):
        self.done, self.total, self.current, self.truncated = done, total, current, truncated


def expand_targets(targets: Sequence[str], recursive: bool = True) -> Tuple[List[str], bool]:
    """フォルダを展開する。MAX_FILES で打ち切ったら 2 番目の値が True。"""
    from .scan import iter_files
    out: List[str] = []
    truncated = False
    for t in targets:
        if is_url(t):
            out.append(t)
            continue
        for fp in iter_files([t], recursive=recursive):
            out.append(fp)
            if len(out) >= MAX_FILES:
                return out, True
    return out, truncated


def run_scan(targets: Sequence[str], detector, cancel: threading.Event,
             on_progress: Callable[[Progress], None], on_result: Callable[[ScanResult], None],
             allow_private: bool = False) -> Tuple[int, bool]:
    """順に走査して (完了件数, キャンセルされたか) を返す。例外は scan_* 側で unscanned になる。"""
    from .scan import scan_path, scan_url
    files, trunc = expand_targets(targets)
    total = len(files)
    done = 0
    on_progress(Progress(0, total, "", trunc))
    for f in files:
        if cancel.is_set():
            return done, True
        on_progress(Progress(done, total, f, trunc))
        r = scan_url(f, detector, allow_private=allow_private) if is_url(f) else scan_path(f, detector)
        done += 1
        on_result(r)
    on_progress(Progress(done, total, "", trunc))
    return done, False


def worst_level(results: Sequence[ScanResult]) -> str:
    """総合判定。unscanned は high と同格で、同点なら unscanned を優先する。"""
    if not results:
        return "clean"
    best = "clean"
    for r in results:
        lv = r.risk_level
        if LEVEL_RANK.get(lv, 0) > LEVEL_RANK.get(best, 0) or (
                LEVEL_RANK.get(lv, 0) == LEVEL_RANK.get(best, 0) and LEVEL_ORDER.index(lv) < LEVEL_ORDER.index(best)):
            best = lv
    return best


def count_levels(results: Sequence[ScanResult]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for r in results:
        c[r.risk_level] = c.get(r.risk_level, 0) + 1
    return c


def count_severities(results: Sequence[ScanResult]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for r in results:
        for f in r.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
    return c


def sort_results(results: Sequence[ScanResult]) -> List[ScanResult]:
    return sorted(results, key=lambda r: (LEVEL_ORDER.index(r.risk_level) if r.risk_level in LEVEL_ORDER else 9,
                                          -len(r.findings), r.source.lower()))


def finding_matches(f: Finding, sevs: Set[str], query: str) -> bool:
    if f.severity not in sevs:
        return False
    q = query.strip().lower()
    if not q:
        return True
    hay = " ".join((f.rule_id, f.description, f.snippet, f.location, f.category, CATEGORY_NAME.get(f.category, ""),
                    f.detail)).lower()
    return all(w in hay for w in q.split())


def visible_findings(r: ScanResult, sevs: Set[str], query: str) -> List[Finding]:
    return [f for f in sorted(r.findings, key=lambda x: -SEV_ORDER.get(x.severity, 0)) if finding_matches(f, sevs, query)]


def result_visible(r: ScanResult, sevs: Set[str], query: str, only_problem: bool) -> bool:
    """一覧に出すか。見える検知がある、解析が不完全、または問題なし表示が有効なら出す。"""
    if visible_findings(r, sevs, query):
        return True
    if query.strip():
        return query.strip().lower() in r.source.lower()
    if r.status != "scanned":
        return True
    return not only_problem and not r.findings


def short_name(source: str, width: int = 60) -> str:
    if source == "(貼り付けテキスト)":
        return tr(source)
    if is_url(source):
        s = source
    else:
        s = os.path.basename(source.rstrip("/\\")) or source
    return s if len(s) <= width else s[: width - 1] + "…"


def human_size(n: int) -> str:
    f = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if f < 1024 or u == "GB":
            return f"{f:.0f} {u}" if u == "B" else f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


def highlight_spans(r: ScanResult, limit: int) -> List[Tuple[int, int, str]]:
    """プレビューで強調する (開始, 終了, 重大度)。limit を超える分は出さない。"""
    spans = []
    for f in r.findings:
        if f.offset >= 0 and f.length > 0 and f.offset < limit:
            spans.append((f.offset, min(limit, f.offset + f.length), f.severity))
    spans.sort()
    return spans


def allow_pattern_for(f: Finding) -> str:
    """抜粋から許可リスト用の正規表現を作る。エスケープ済みなので抜粋中の記号は効かない。"""
    s = f.snippet.replace(" ⏎ ", " ").strip("…").strip()
    s = s[:80]
    return re.escape(s)


_HIDDEN_PREFIX = re.compile(r"^【隠し要素内:[^】]*】")


def tree_label(f: Finding) -> str:
    """ツリー用の見出し。長い「【隠し要素内: …】」は [隠] に縮める。詳細欄には全文が出る。"""
    d = f.description
    if _HIDDEN_PREFIX.match(d):
        return tr("[隠] ") + tr(_HIDDEN_PREFIX.sub("", d))
    return tr(d)
