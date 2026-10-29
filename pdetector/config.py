"""検知器の設定。JSON から読める(誤検知の除外や社内ルールの追加用)。

例 (pdetector.json):
{
  "disabled_rules": ["you_are_now"],
  "severity_overrides": {"end_of_document_marker": "info"},
  "allow_patterns": ["internal-wiki\\\\.example\\\\.com"],
  "extra_rules": [
    {"id": "corp_secret", "description": "社内機密語の外部送信指示",
     "pattern": "send\\\\s+.{0,40}project\\\\s+x\\\\s+to", "severity": "high", "category": "exfiltration"}
  ],
  "invisible_ratio_threshold": 0.02,
  "timeout_sec": 60
}
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .model import SEV_ORDER


@dataclass
class DetectorConfig:
    # 不可視文字の割合がこれを超えたら high(3文字以上のとき)
    invisible_ratio_threshold: float = 0.02
    disabled_rules: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    # snippet がマッチした検知は捨てる(既知の無害な文言用)
    allow_patterns: List[str] = field(default_factory=list)
    # 追加ルール: {"id","description","pattern","severity","category"}
    extra_rules: List[dict] = field(default_factory=list)
    # base64/hex/ROT13 等のデコード検査と、その多段の深さ
    decode: bool = True
    decode_depth: int = 2
    scan_hidden_regions: bool = True
    max_lines_per_finding: int = 8
    # 超過分は切り捨てて partial 扱い
    max_scan_chars: int = 5_000_000
    # 秒。0 で無制限
    timeout_sec: float = 60.0
    include_info: bool = True
    # GUI のプレビュー用。メモリを食うので既定はオフ
    keep_text: bool = False

    def validate(self) -> "DetectorConfig":
        for k, v in self.severity_overrides.items():
            if v not in SEV_ORDER:
                raise ValueError(f"severity_overrides[{k!r}] の重大度が不正です: {v!r}")
        for r in self.extra_rules:
            for key in ("id", "pattern"):
                if key not in r:
                    raise ValueError(f"extra_rules の項目に {key!r} がありません: {r}")
            if r.get("severity", "medium") not in SEV_ORDER:
                raise ValueError(f"extra_rules[{r['id']}] の重大度が不正です")
        if self.decode_depth < 1:
            self.decode_depth = 1
        return self

    def to_dict(self) -> dict:
        return asdict(self)


def load_config(path: Optional[str] = None) -> DetectorConfig:
    """path が None なら環境変数 PDETECTOR_CONFIG。それも無ければ既定値。"""
    path = path or os.environ.get("PDETECTOR_CONFIG")
    if not path:
        return DetectorConfig()
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    known = set(DetectorConfig.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"設定ファイルに未知のキーがあります: {sorted(unknown)}")
    return DetectorConfig(**raw).validate()
