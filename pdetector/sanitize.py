"""LLM に渡す前の掃除。不可視文字を落として、検知した指示文を伏せ字にする。

あくまで補助で、防御としては不十分。high 以上が出たらそもそも渡さないほうがいい。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import normalize as nz
from .detector import Detector
from .model import Finding


@dataclass
class SanitizeResult:
    text: str
    removed_invisible: int = 0
    redacted: List[str] = field(default_factory=list)      # 伏せ字にしたルールID
    findings: List[Finding] = field(default_factory=list)


def sanitize_text(text: str, detector: Optional[Detector] = None, redact_min_severity: str = "high",
                  placeholder: str = "[REDACTED:{rule}]") -> SanitizeResult:
    from .model import SEV_ORDER
    det = detector or Detector()
    stripped = nz.strip_hidden_chars(text)
    removed = len(text) - len(stripped)
    norm = nz.normalize_for_match(text)
    out = norm
    redacted: List[str] = []
    spans = []
    for rid, desc, regex, sev, cat in det.rules:
        if SEV_ORDER[sev] < SEV_ORDER[redact_min_severity]:
            continue
        for m in regex.finditer(out):
            spans.append((m.start(), m.end(), rid))
    spans.sort()
    merged = []
    for a, b, rid in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]), merged[-1][2])
        else:
            merged.append((a, b, rid))
    for a, b, rid in reversed(merged):
        out = out[:a] + placeholder.format(rule=rid) + out[b:]
        redacted.append(rid)
    redacted.reverse()
    res = det.scan_text(text)
    return SanitizeResult(text=out, removed_invisible=removed, redacted=redacted, findings=res.findings)
