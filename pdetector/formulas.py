"""表計算(xlsx/csv/ods)の数式を使った攻撃の検出。

DDE(`=cmd|' /C calc'!A0` で外部プログラムを起動)と、
HYPERLINK/WEBSERVICE/IMPORTXML 等に外部URL+セル参照を連結して渡すデータ持ち出し。
"""
import re
from typing import List

from .model import Finding

_DDE = re.compile(r"""(?:^|[=+\-@,;\t]\s*)[A-Za-z][\w.]{1,30}\s*\|\s*['"]?\s*[^\n]{0,120}?!\s*[A-Za-z0-9_$]{1,12}""")
_NET_FN = (r"HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|IMAGE|"
           r"FILTERXML|ENCODEURL|RTD|CALL|REGISTER|EXEC|SHELL")
_EXFIL = re.compile(
    rf"""\b(?:{_NET_FN})\s*\(\s*(?:[^()]{{0,40}}?)["']{{1,2}}\s*(?:https?|ftp|file|\\\\)[:/\\][^"']{{0,200}}["']{{1,2}}\s*&""", re.I)
_EXFIL_REF = re.compile(
    rf"""\b(?:{_NET_FN})\s*\(.{{0,300}}?https?://[^\n]{{0,200}}?["']{{1,2}}\s*&\s*(?:[A-Za-z$]{{1,3}}\$?\d+|CONCAT|TEXTJOIN|ENCODEURL|SUBSTITUTE|INDIRECT)""", re.I)
_EXEC_FN = re.compile(r"""(?:^|[=+\-@])\s*(?:EXEC|SHELL|CALL|REGISTER|MSEXCEL\|)\s*\(""", re.I)


def formula_findings(f: str, location: str = "", fmt: str = "sheet") -> List[Finding]:
    out: List[Finding] = []
    if not f:
        return out
    s = f.strip()
    if len(s) > 4000:
        s = s[:4000]
    if _DDE.search(s) or _DDE.search("=" + s):
        out.append(Finding(
            rule_id=f"{fmt}_formula_dde", category="active_content", severity="high",
            description="数式が外部プログラムを起動しようとしています(DDE)", snippet=s[:200], location=location))
    if _EXEC_FN.search(s) and not out:
        out.append(Finding(
            rule_id=f"{fmt}_formula_exec", category="active_content", severity="high",
            description="数式が外部コマンド/DLL を呼び出そうとしています", snippet=s[:200], location=location))
    if _EXFIL.search(s) or _EXFIL_REF.search(s):
        out.append(Finding(
            rule_id=f"{fmt}_formula_exfil", category="exfiltration", severity="medium",
            description="数式がセルの内容を外部 URL に連結して送信しようとしています(データ持ち出し)",
            snippet=s[:200], location=location))
    return out
