"""翻訳が要る日本語文字列を洗い出して JSON に書く。python tools/i18n_catalog.py /tmp/catalog.json

キーは tr() の引数と、検知メッセージ(patterns の説明、抽出時の注記)のテンプレート。{0} {1} は f-string の式の位置。
"""
import ast
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
JP = re.compile(r"[\u3041-\u3096\u30a1-\u30fa\u30fc-\u30ff\u3400-\u4dbf\u4e00-\u9fff]")
RX = re.compile(r"\\[sSbBdDwW]|\(\?|\||\[\^|\.\{|\{\d+,|\\\\|\.\*|\.\+|\[\\")
UI = ["gui", "gui_settings", "gui_history", "gui_logic", "report", "scan", "neutralize", "scanlog", "crashlog", "deps"]
CORE = ["detector", "unicode_checks", "extractors", "htmlx", "pdfx", "office", "imagex", "mailx", "netfetch",
        "safeio", "encoding", "decoders", "config", "model", "sanitize"]


def template_of(node: ast.JoinedStr):
    tm, i = "", 0
    for v in node.values:
        if isinstance(v, ast.Constant):
            tm += v.value.replace("{", "{{").replace("}", "}}")
        else:
            spec = ""
            if v.format_spec is not None and all(isinstance(x, ast.Constant) for x in v.format_spec.values):
                spec = ":" + "".join(x.value for x in v.format_spec.values)
            conv = {-1: "", 115: "!s", 114: "!r", 97: "!a"}[v.conversion]
            tm += "{" + str(i) + conv + spec + "}"
            i += 1
    return tm


def collect(path: str, only_tr: bool):
    src = open(path, encoding="utf-8").read()
    t = ast.parse(src)
    parents = {}
    for n in ast.walk(t):
        for c in ast.iter_child_nodes(n):
            parents[c] = n

    def under(n, cls):
        while n in parents:
            n = parents[n]
            if isinstance(n, cls):
                return True
        return False

    def in_call(n, names):
        while n in parents:
            n = parents[n]
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in names:
                return True
        return False

    out = {}
    for n in ast.walk(t):
        if isinstance(parents.get(n), ast.Expr):
            continue
        if only_tr and not in_call(n, ("tr", "TMap")):
            continue
        if isinstance(n, ast.JoinedStr):
            if under(n, ast.JoinedStr):
                continue
            if any(isinstance(v, ast.Constant) and JP.search(v.value) for v in n.values):
                out.setdefault(template_of(n), os.path.basename(path))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and JP.search(n.value):
            if under(n, ast.JoinedStr) or RX.search(n.value) or len(n.value.strip()) < 2:
                continue
            if only_tr is False and re.fullmatch(r"[\u3000-\u9fff\uff00-\uffef]", n.value):
                continue
            out.setdefault(n.value, os.path.basename(path))
    return out


def main(dest: str):
    cat = {}
    for m in UI:
        cat.update({k: v for k, v in collect(os.path.join(ROOT, "pdetector", m + ".py"), True).items() if k not in cat})
    for m in CORE:
        for k, v in collect(os.path.join(ROOT, "pdetector", m + ".py"), False).items():
            cat.setdefault(k, v)
    from pdetector import patterns, deps
    for rid, desc, rx, sev, c in patterns.ALL_PATTERNS:
        cat.setdefault(desc, "patterns")
    for _imp, _pip, purpose in deps.OPTIONAL_DEPS:
        cat.setdefault(purpose, "deps")
    for extra in ("PDetector — 間接プロンプトインジェクション検知", "有効", "無効", "(貼り付けテキスト)"):
        cat.setdefault(extra, "gui")
    items = [{"key": k, "src": v} for k, v in cat.items()]
    json.dump(items, open(dest, "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    print(len(items), "keys")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "catalog.json")
