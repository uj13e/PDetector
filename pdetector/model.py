"""共有データモデル。循環 import を避けるため独立させてある。"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Tuple, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}[self.value]


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_BY_RANK = {v: k for k, v in SEV_ORDER.items()}

# unscanned は解析できなかったもの。安全とは言えないので rank は high 相当
LEVELS = ("clean", "low", "medium", "high", "critical", "unscanned")
LEVEL_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unscanned": 3}


def downgrade(sev: str, steps: int = 1) -> str:
    return SEV_BY_RANK[max(0, SEV_ORDER[sev] - steps)]


def upgrade(sev: str, steps: int = 1) -> str:
    return SEV_BY_RANK[min(4, SEV_ORDER[sev] + steps)]


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    snippet: str = ""
    location: str = ""         # 例: text, html_comment, pdf_page_3
    detail: str = ""           # 文字名・統計値など
    line: int = 0              # 1始まり。不明は0
    offset: int = -1           # 位置は正規化後の本文基準。不明は-1
    length: int = 0            # offset が有効なときだけ意味がある

    def to_dict(self):
        return asdict(self)


@dataclass
class HiddenRegion:
    """人には見えない(見えにくい)が LLM には読まれ得るテキスト。

    領域ごとに独立して照合し、ヒットしたら重大度を上げる。隠れた命令文は普通の命令文よりずっと怪しい。
    """
    text: str
    reason: str                # 例: "display:none", "白文字", "発表者ノート"
    location: str = ""
    kind: str = "hidden"       # hidden | attribute | metadata | comment | annotation | deleted | offpage
    # 領域そのものを報告するときの重大度。None なら kind と長さで決める
    severity: Optional[str] = None


@dataclass
class ExtractedDoc:
    """抽出結果。可視テキストと、抽出側で見つけた隠し要素。"""
    source: str
    text: str = ""
    kind: str = "unknown"
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    hidden_regions: List[HiddenRegion] = field(default_factory=list)
    # ok / partial / unsupported / failed (mark 参照)
    status: str = "ok"
    encoding: str = ""
    size: int = 0
    sha256: str = ""
    # (場所, 行) の並び。無害化で pptx/docx/xlsx を作り直すとき、スライドやシートの構造を戻すのに使う
    units: List[Tuple[str, str]] = field(default_factory=list)

    def mark(self, status: str, note: str = ""):
        """状態は悪化する方向にしか動かさない(ok < partial < unsupported < failed)。"""
        order = {"ok": 0, "partial": 1, "unsupported": 2, "failed": 3}
        if order.get(status, 0) > order.get(self.status, 0):
            self.status = status
        if note:
            self.notes.append(note)

    def merge(self, child: "ExtractedDoc", prefix: str = ""):
        """zip 内ファイルやメール添付などの子ドキュメントを取り込む。"""
        tag = f"[{prefix}] " if prefix else ""
        if child.text:
            self.text += "\n" + child.text
            self.units.extend(child.units)
        for f in child.findings:
            if prefix:
                f.location = f"{prefix}:{f.location}" if f.location else prefix
            self.findings.append(f)
        for r in child.hidden_regions:
            if prefix:
                r.location = f"{prefix}:{r.location}" if r.location else prefix
            self.hidden_regions.append(r)
        for n in child.notes:
            self.notes.append(tag + n)
        if child.status != "ok":
            self.mark("partial", "")


@dataclass
class ScanResult:
    source: str
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "clean"
    text_length: int = 0
    notes: List[str] = field(default_factory=list)
    # scanned / partial / unscanned
    status: str = "scanned"
    kind: str = ""
    encoding: str = ""
    size: int = 0
    sha256: str = ""
    scanned_at: str = ""
    tool_version: str = ""
    rules_version: str = ""
    elapsed_sec: float = 0.0
    # GUI プレビュー用の正規化済み本文。config.keep_text が True のときだけ入る。JSON には出さない
    text: str = field(default="", repr=False)

    def to_dict(self):
        d = asdict(self)
        d.pop("text", None)
        return d

    @property
    def ok(self) -> bool:
        return self.status == "scanned"
