"""検知エンジン。ルール照合・ヒューリスティック・隠し領域の文脈判定をまとめる。

scan_text の流れは、Unicode 検査、正規化後の全ルール照合、バリアント照合(flat/squashed/compact/folded)、
デコード照合、隠し領域ごとの照合、設定の適用と判定の順。
解析できなかった/一部だけの場合は fail-open にせず unscanned か status=partial で明示する。
"""
from __future__ import annotations

import re
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import decoders, normalize as nz, patterns
from .config import DetectorConfig
from .model import (ExtractedDoc, Finding, HiddenRegion, LEVEL_RANK, SEV_ORDER, ScanResult,
                    Severity, downgrade, upgrade)
from .safeio import Budget, BudgetExceeded
from .unicode_checks import check_unicode

TOOL_VERSION = "1.2.0"

Rule = Tuple[str, str, "re.Pattern", str, str]

# ルールに当たらない領域そのものを報告するときの既定の重さ
_REGION_DEFAULT_SEV = {
    "hidden": "medium", "offpage": "medium", "deleted": "low", "comment": "low",
    "metadata": "info", "annotation": "low", "attribute": "info",
}
_CHARMAP_SCHEMES = frozenset({"rot13", "rot47", "atbash", "reversed", "reversed_words", "leet"})
_UI_TEXT = re.compile(
    r"\b(?:cookies?|consent|privacy\s+policy|javascript|skip\s+to|main\s+content|navigation|menu|sign\s*in|log\s*in|search|accept|close|home|about|contact|products?|enable\s+js|loading)\b"
    r"|Cookie|同意|プライバシー|ナビゲーション|メニュー|ログイン|検索|閉じる|ホーム|お問い合わせ|JavaScript", re.I)
_REGION_MIN_REPORT_CHARS = 12      # これより短い隠しテキストは単体では報告しない

# 1文字ずつ区切られた並びを探す。compact 照合に渡す窓の切り出し用
_SPLIT_RUN = re.compile(r"(?:(?<![A-Za-z])[A-Za-z][^A-Za-z\n]{1,3}){8,}[A-Za-z]?")


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


class Detector:
    def __init__(self, config: Optional[DetectorConfig] = None, *,
                 invisible_ratio_threshold: Optional[float] = None):
        self.config = (config or DetectorConfig()).validate()
        if invisible_ratio_threshold is not None:      # 旧API互換
            self.config.invisible_ratio_threshold = invisible_ratio_threshold
        self._disabled = set(self.config.disabled_rules)
        self._allow = [re.compile(p, re.I) for p in self.config.allow_patterns]
        self.rules: List[Rule] = [r for r in patterns.ALL_PATTERNS if r[0] not in self._disabled]
        for er in self.config.extra_rules:
            self.rules.append((er["id"], er.get("description", er["id"]), re.compile(er["pattern"], re.I),
                               er.get("severity", "medium"), er.get("category", "custom")))
        self._rule_by_id: Dict[str, Rule] = {r[0]: r for r in self.rules}
        self._instr = [r for r in self.rules if r[0] in patterns.INSTRUCTIONAL_IDS]
        self._latin = [r for r in self.rules if r[0] in patterns.LATIN_RULE_IDS]

    # 旧API互換
    @property
    def invisible_ratio_threshold(self) -> float:
        return self.config.invisible_ratio_threshold

    # 公開API
    def scan_doc(self, doc: ExtractedDoc, source: Optional[str] = None) -> ScanResult:
        status = {"ok": "scanned", "partial": "partial"}.get(doc.status, "unscanned")
        return self.scan_text(doc.text, source=source or doc.source, extra_findings=doc.findings,
                              notes=doc.notes, hidden_regions=doc.hidden_regions, status=status,
                              kind=doc.kind, encoding=doc.encoding, size=doc.size, sha256=doc.sha256)

    def scan_text(self, text: str, source: str = "<text>",
                  extra_findings: Optional[List[Finding]] = None,
                  notes: Optional[List[str]] = None,
                  hidden_regions: Optional[Sequence[HiddenRegion]] = None,
                  status: str = "scanned", kind: str = "", encoding: str = "",
                  size: int = 0, sha256: str = "") -> ScanResult:
        t0 = time.monotonic()
        cfg = self.config
        text = text or ""
        result = ScanResult(source=source, text_length=len(text), status=status, kind=kind,
                            encoding=encoding, size=size or len(text.encode("utf-8", "ignore")),
                            sha256=sha256, scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            tool_version=TOOL_VERSION, rules_version=patterns.RULES_VERSION)
        if notes:
            result.notes.extend(notes)
        budget = Budget(cfg.timeout_sec)
        found: List[Finding] = []
        if extra_findings:
            found.extend(extra_findings)

        if len(text) > cfg.max_scan_chars:
            half = cfg.max_scan_chars // 2
            text = text[:half] + "\n" + text[-half:]
            result.notes.append(f"テキストが長いため先頭と末尾 {cfg.max_scan_chars:,} 文字のみ解析しました。")
            result.status = _worse(result.status, "partial")

        try:
            if text:
                found.extend(self._analyze(text, "text", budget, with_lines=True))
            if hidden_regions and cfg.scan_hidden_regions:
                for reg in hidden_regions:
                    budget.check()
                    found.extend(self._analyze_region(reg, budget))
        except BudgetExceeded:
            result.notes.append("処理時間の上限に達したため、解析を途中で打ち切りました。")
            result.status = _worse(result.status, "partial")
        except RecursionError:      # 深い入れ子でも黙って通さない
            result.notes.append("内部エラー(再帰深度超過)のため解析を中断しました。")
            result.status = _worse(result.status, "unscanned")

        result.findings = self._finalize(found)
        if cfg.keep_text and text:
            result.text = nz.normalize_for_match(text)[:cfg.max_scan_chars]
        self._judge(result)
        result.elapsed_sec = round(time.monotonic() - t0, 3)
        return result

    def _analyze(self, text: str, location: str, budget: Budget, with_lines: bool = False) -> List[Finding]:
        out: List[Finding] = []
        ufind, payloads = check_unicode(text, self.config.invisible_ratio_threshold)
        for f in ufind:
            f.location = location
        out.extend(ufind)

        norm = nz.normalize_for_match(text)
        matched: Dict[str, Finding] = {}

        self._match(norm, self.rules, location, matched, budget, with_lines=with_lines)
        out.extend(matched.values())
        primary_ids = set(matched)

        out.extend(self._variants(norm, text, location, primary_ids, budget))

        # Tags/VS に埋め込まれた文字列の中身も照合する
        for reason, payload in payloads:
            pn = nz.normalize_for_match(payload)
            for f in self._match_all(pn, self.rules, budget):
                out.append(self._as_obfuscated(f, f"unicode:{reason}", f"{reason}の中に指示文", location))

        if self.config.decode:
            out.extend(self._decoded(nz.strip_hidden_chars(text), location, primary_ids, budget))
        return out

    @staticmethod
    def _prefilter_ok(rid: str, low: str, cache: Dict[str, bool]) -> bool:
        pre = patterns.PREFILTER.get(rid)
        if not pre:
            return True
        for p in pre:
            v = cache.get(p)
            if v is None:
                v = cache[p] = p in low
            if v:
                return True
        return False

    def _match(self, norm: str, rules: Iterable[Rule], location: str, matched: Dict[str, Finding],
               budget: Budget, with_lines: bool = False, skip: Optional[set] = None) -> None:
        """ルールごとに最初の1件だけ matched に入れる。2件目以降は行番号と件数を detail に残す。"""
        if not norm:
            return
        low = norm.lower()
        kw_cache: Dict[str, bool] = {}
        max_lines = self.config.max_lines_per_finding
        for rid, desc, regex, sev, cat in rules:
            if rid in matched or (skip and rid in skip):
                continue
            if not self._prefilter_ok(rid, low, kw_cache):
                continue
            budget.check()
            it = regex.finditer(norm)
            m = next(it, None)
            if m is None:
                continue
            f = Finding(rule_id=rid, category=cat, severity=sev, description=desc,
                        snippet=self._context(norm, m.start(), m.end()), location=location)
            if with_lines:
                f.offset = m.start()
                f.length = m.end() - m.start()
                f.line = _line_of(norm, m.start())
                extra = [f.line]
                n_more = 0
                for m2 in it:
                    n_more += 1
                    if len(extra) < max_lines:
                        ln = _line_of(norm, m2.start())
                        if ln not in extra:
                            extra.append(ln)
                    if n_more >= 200:
                        break
                if n_more:
                    f.detail = f"全{n_more + 1}箇所" + (f"(行: {', '.join(map(str, extra))})" if len(extra) > 1 else "")
            matched[rid] = f

    def _match_all(self, norm: str, rules: Iterable[Rule], budget: Budget) -> List[Finding]:
        m: Dict[str, Finding] = {}
        self._match(norm, rules, "text", m, budget)
        return list(m.values())

    def _variants(self, norm: str, raw: str, location: str, primary_ids: set, budget: Budget) -> List[Finding]:
        out: List[Finding] = []
        seen = set(primary_ids)

        # flat: 改行で折り返された文。普通の文書でも起きるので重大度は上げない
        if "\n" in norm:
            flat = nz.flat_variant(norm)
            m: Dict[str, Finding] = {}
            self._match(flat, self.rules, location, m, budget, skip=seen)
            for f in m.values():
                f.detail = (f.detail + " " if f.detail else "") + "(改行をまたいで一致)"
                out.append(f)
            seen |= set(m)

        # squashed: 1文字ずつ空白/記号で区切られたもの
        sq_hit = False
        sq = nz.squashed_variant(norm)
        if sq != nz.flat_variant(norm):
            m = {}
            self._match(sq, self._instr, location, m, budget, skip=seen)
            for f in m.values():
                grp = patterns.GROUP.get(f.rule_id, "latin")
                out.append(self._as_obfuscated(f, "squashed", "空白/記号で文字が分断された指示文", location,
                                               bump=(grp == "latin")))
            seen |= set(m)
            sq_hit = bool(m)

        # compact: 区切りだらけの箇所の定型句。squashed で捕まっていれば不要
        for win in ([] if sq_hit else self._split_windows(norm)):
            c = nz.compact_variant(win)
            for rid, desc, regex, sev, cat in patterns.COMPACT_PATTERNS:
                if rid in seen:
                    continue
                m2 = regex.search(c)
                if m2:
                    seen.add(rid)
                    out.append(Finding(rule_id=rid, category="obfuscation", severity=_at_least(sev, "high"),
                                       description=desc, snippet=self._context(win, 0, len(win), pad=0),
                                       location=location, detail="空白/記号を除去して一致"))

        # folded: ホモグリフ。ラテンとキリル/ギリシャの混在語があるときだけ
        if not norm.isascii() and nz.mixed_script_tokens(norm, limit=1):
            folded = nz.fold_confusables(norm)
            m = {}
            self._match(folded, self._latin, location, m, budget, skip=seen)
            for f in m.values():
                out.append(self._as_obfuscated(f, "homoglyph", "見た目が似た別文字(ホモグリフ)で偽装された指示文", location))
            seen |= set(m)
            # 分断とホモグリフの併用
            sq2 = nz.squashed_variant(folded)
            m = {}
            self._match(sq2, self._instr, location, m, budget, skip=seen)
            for f in m.values():
                out.append(self._as_obfuscated(f, "homoglyph+squashed", "ホモグリフと文字分断を併用した指示文", location))
        return out

    @staticmethod
    def _split_windows(norm: str, limit: int = 20) -> List[str]:
        wins: List[str] = []
        for m in _SPLIT_RUN.finditer(norm):
            a = max(0, m.start() - 4)
            b = min(len(norm), m.end() + 4)
            wins.append(norm[a:b])
            if len(wins) >= limit:
                break
        return wins

    def _decoded(self, text: str, location: str, primary_ids: set, budget: Budget) -> List[Finding]:
        out: List[Finding] = []
        seen = set()      # (scheme, rule_id)
        n_cands = 0
        for dec in decoders.iter_decodings(text, budget, depth=self.config.decode_depth):
            budget.check()
            n_cands += 1
            dn = nz.normalize_for_match(dec.text)
            skip = primary_ids if dec.whole else None
            m: Dict[str, Finding] = {}
            # ROT13/反転などは英字にしか効かないので、ラテン文字系ルールだけでいい
            rules = self._latin if dec.scheme in _CHARMAP_SCHEMES else self.rules
            self._match(dn, rules, location, m, budget, skip=skip)
            # 分断とエンコードの併用
            sq = nz.squashed_variant(dn)
            if sq != dn:
                self._match(sq, self._instr, location, m, budget, skip=skip)
            for rid, f in m.items():
                if (dec.scheme, rid) in seen:
                    continue
                seen.add((dec.scheme, rid))
                lab = decoders.label(dec.scheme)
                out.append(Finding(
                    rule_id=f"encoded:{dec.scheme}:{rid}", category="obfuscation",
                    severity=_at_least(f.severity, "high"),
                    description=f"{lab}でエンコードされた中に指示文(デコードで出現: {f.description})",
                    snippet=f.snippet, detail=f"方式={lab} / 内部ルール={rid}",
                    location=f"{location}|encoded/{dec.scheme}"))
        return out

    def _analyze_region(self, reg: HiddenRegion, budget: Budget) -> List[Finding]:
        text = reg.text or ""
        if not text.strip():
            return []
        loc = reg.location or reg.kind
        inner = self._analyze(text, loc, budget)
        out: List[Finding] = []
        if reg.kind == "reencoded":
            # 文字コードを変えて読み直したもの。隠し要素ではないので重大度は上げず、ルールに当たったものだけ出す
            for f in inner:
                if f.category in ("hidden_content", "obfuscation") or f.rule_id.startswith(("unicode", "invisible", "homoglyph")):
                    continue
                f.description = f"【{reg.reason}】{f.description}"
                f.detail = (f.detail + " / " if f.detail else "") + "文字コードの推定が外れていた場合に読める内容です"
                out.append(f)
            return out
        hit_rules = False
        for f in inner:
            if f.rule_id in ("homoglyph_mixed_script",) or f.category == "obfuscation":
                # 隠し領域の中の難読化は更に怪しい
                f.severity = upgrade(f.severity, 1) if SEV_ORDER[f.severity] >= 1 else f.severity
            elif f.category in ("hidden_content",):
                pass
            else:
                hit_rules = True
                # 隠れた命令文は重大度を上げる。命令系ルールは最低でも high
                if SEV_ORDER[f.severity] >= SEV_ORDER["medium"]:
                    f.severity = upgrade(f.severity, 1)
                if f.rule_id in patterns.INSTRUCTIONAL_IDS and SEV_ORDER[f.severity] < SEV_ORDER["high"]:
                    f.severity = "high"
            f.description = f"【隠し要素内: {reg.reason}】{f.description}"
            f.detail = (f.detail + " / " if f.detail else "") + f"隠し要素の種別={reg.kind}, 理由={reg.reason}"
            out.append(f)

        any_sev_hit = any(SEV_ORDER[f.severity] >= SEV_ORDER["medium"] for f in out)
        base = reg.severity or _REGION_DEFAULT_SEV.get(reg.kind, "medium")
        if base == "medium" and len(text.strip()) <= 200 and _UI_TEXT.search(text):
            base = "low"           # Cookie バナーや nav など、よくある UI 用の隠し文言は低めにする
        length_ok = len(text.strip()) >= _REGION_MIN_REPORT_CHARS
        if not hit_rules and not any_sev_hit and length_ok and base != "info":
            out.append(Finding(
                rule_id=f"hidden_text:{reg.kind}", category="hidden_content", severity=base,
                description=f"人の目には見えない(見えにくい)テキストがあります: {reg.reason}",
                snippet=self._context(text.replace("\n", " "), 0, min(len(text), 120), pad=0),
                detail=f"{len(text)}文字 / 種別={reg.kind}", location=loc))
        return out

    @staticmethod
    def _as_obfuscated(f: Finding, variant: str, desc: str, location: str, bump: bool = True) -> Finding:
        return Finding(
            rule_id=f"obfuscated:{variant}:{f.rule_id}", category="obfuscation",
            severity=_at_least(f.severity, "high") if bump else f.severity,
            description=f"{desc}(一致ルール: {f.description})",
            snippet=f.snippet, detail=f"方式={variant} / 内部ルール={f.rule_id}", location=location)

    @staticmethod
    def _context(text: str, start: int, end: int, pad: int = 40) -> str:
        a = max(0, start - pad)
        b = min(len(text), end + pad)
        s = text[a:b].replace("\r", " ").replace("\n", " ⏎ ").strip()
        if len(s) > 400:
            s = s[:400] + "…"
        return f"{'…' if a > 0 else ''}{s}{'…' if b < len(text) else ''}"

    def _finalize(self, found: List[Finding]) -> List[Finding]:
        cfg = self.config
        out: List[Finding] = []
        seen = set()
        for f in found:
            base_id = f.rule_id.rsplit(":", 1)[-1]
            if f.rule_id in self._disabled or base_id in self._disabled:
                continue
            ov = cfg.severity_overrides.get(f.rule_id) or cfg.severity_overrides.get(base_id)
            if ov:
                f.severity = ov
            if f.severity == "info" and not cfg.include_info:
                continue
            if self._allow and f.snippet and any(p.search(f.snippet) for p in self._allow):
                continue
            key = (f.rule_id, f.location, f.snippet[:80], f.detail[:40])
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        out.sort(key=lambda x: -SEV_ORDER.get(x.severity, 0))
        return out

    @staticmethod
    def _judge(result: ScanResult) -> None:
        """スコアと判定レベルを決める。info は判定に影響しない。解析できていなければ unscanned。"""
        worst = -1
        scores = []
        for f in result.findings:
            r = SEV_ORDER.get(f.severity, 0)
            if r >= 1:
                worst = max(worst, r)
                scores.append(Severity(f.severity).score)
        scores.sort(reverse=True)
        score = (scores[0] + 0.25 * sum(scores[1:])) if scores else 0
        result.risk_score = int(min(100, score))

        if worst >= 4:
            level = "critical"
        elif worst == 3:
            level = "high"
        elif worst == 2:
            level = "medium"
        elif worst == 1:
            level = "low"
        else:
            level = "clean"
        if result.status == "unscanned" and LEVEL_RANK[level] < LEVEL_RANK["unscanned"]:
            level = "unscanned"
        result.risk_level = level


def _worse(a: str, b: str) -> str:
    order = {"scanned": 0, "partial": 1, "unscanned": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _at_least(sev: str, floor: str) -> str:
    return sev if SEV_ORDER[sev] >= SEV_ORDER[floor] else floor
