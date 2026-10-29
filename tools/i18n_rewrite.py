"""日本語の表示文字列を tr("...") で包む、一回きりの書き換えツール。
python tools/i18n_rewrite.py pdetector/gui.py ...  ファイルを直接書き換える。tr() 内の文字列は触らないので再実行しても同じ。

対象は関数/メソッド内の文字列だけ。モジュール直下の定数は TMap か使う側で訳す。
docstring、比較の相手、辞書キー、添字、デフォルト引数は除外。f-string は tr("{0} 件").format(x) にする。
"""
import ast
import re
import sys

JP = re.compile(r"[ぁ-ゖァ-ヺー-ヿ㐀-䶿一-鿿]")


def has_jp(s: str) -> bool:
    return bool(JP.search(s))


class Rewriter(ast.NodeVisitor):
    def __init__(self, src: str):
        self.src = src
        self.b = src.encode("utf-8")
        self.starts = [0]
        for line in self.b.split(b"\n"):
            self.starts.append(self.starts[-1] + len(line) + 1)
        self.edits = []          # (start, end, replacement)
        self.skipped = []
        self.func_depth = 0

    def off(self, lineno, col):
        return self.starts[lineno - 1] + col

    def span(self, node):
        return self.off(node.lineno, node.col_offset), self.off(node.end_lineno, node.end_col_offset)

    # 文脈
    def visit_FunctionDef(self, node):
        # 既定引数は import 時に評価されるので対象外
        for d in node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
            self.mark_skip(d)
        self.func_depth += 1
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
            body = body[1:]
        for st in body:
            self.visit(st)
        self.func_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.func_depth += 1
        self.visit(node.body)
        self.func_depth -= 1

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return
        self.generic_visit(node)

    def mark_skip(self, node):
        for n in ast.walk(node):
            setattr(n, "_skip", True)

    def visit_Compare(self, node):
        self.visit(node.left)          # 左は表示用のことがあるが比較なので触らない
        self.mark_skip(node)

    def visit_Subscript(self, node):
        self.visit(node.value)
        self.mark_skip(node.slice)

    def visit_Dict(self, node):
        for k in node.keys:
            if k is not None:
                self.mark_skip(k)
        for v in node.values:
            self.visit(v)

    def visit_Call(self, node):
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
        if name in ("tr", "startswith", "endswith", "split", "rsplit", "strip", "lstrip", "rstrip", "replace", "get",
                    "compile", "search", "match", "fullmatch", "sub", "findall", "finditer", "pop", "index", "find",
                    "tag_configure", "tag_add", "tag_remove", "getattr", "setattr", "hasattr", "open", "join",
                    "exists", "insert_tag", "encode", "decode", "count", "format_map", "add_tag"):
            if name == "join":
                self.mark_skip(f)            # 区切り文字
                for a in node.args:
                    self.visit(a)
                return
            for a in node.args:
                self.mark_skip(a)
            for k in node.keywords:
                self.mark_skip(k.value)
            self.visit(f)
            return
        self.generic_visit(node)

    # 文字列
    def visit_Constant(self, node):
        if getattr(node, "_skip", False) or self.func_depth == 0:
            return
        if isinstance(node.value, str) and has_jp(node.value):
            a, b = self.span(node)
            self.edits.append((a, b, "tr(" + self.b[a:b].decode("utf-8") + ")"))

    def visit_JoinedStr(self, node):
        if getattr(node, "_skip", False) or self.func_depth == 0:
            return
        if not any(isinstance(v, ast.Constant) and has_jp(v.value) for v in node.values):
            self.generic_visit(node)
            return
        tmpl, args = "", []
        for v in node.values:
            if isinstance(v, ast.Constant):
                tmpl += v.value.replace("{", "{{").replace("}", "}}")
            else:
                spec = ""
                if v.format_spec is not None:
                    if not all(isinstance(x, ast.Constant) for x in v.format_spec.values):
                        self.skipped.append((node.lineno, "dynamic format spec"))
                        return
                    spec = ":" + "".join(x.value for x in v.format_spec.values)
                conv = {-1: "", 115: "!s", 114: "!r", 97: "!a"}[v.conversion]
                tmpl += "{" + str(len(args)) + conv + spec + "}"
                args.append(ast.unparse(v.value))
        a, b = self.span(node)
        rep = "tr(" + repr(tmpl) + ")" + (".format(" + ", ".join(args) + ")" if args else "")
        self.edits.append((a, b, rep))
        for v in node.values:        # 式の中の入れ子(まれ)は触らない
            pass


def rewrite(path: str) -> int:
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    rw = Rewriter(src)
    rw.visit(tree)
    # 重複・入れ子の編集は外側を優先
    edits = sorted(rw.edits, key=lambda e: (e[0], -(e[1] - e[0])))
    out, last = [], -1
    for a, b, r in edits:
        if a < last:
            continue
        out.append((a, b, r))
        last = b
    bs = rw.b
    res = bytearray()
    pos = 0
    for a, b, r in out:
        res += bs[pos:a] + r.encode("utf-8")
        pos = b
    res += bs[pos:]
    new = res.decode("utf-8")
    if out and "from .i18n import tr" not in new:
        # 先頭の import 群の直後に入れる
        m = re.search(r"^(from \.[\w.]* import .*|import \w+.*)$", new, re.M)
        lines = new.split("\n")
        idx = 0
        for i, ln in enumerate(lines):
            if ln.startswith(("from .", "from . ")):
                idx = i
        new = "\n".join(lines[:idx + 1] + ["from .i18n import tr"] + lines[idx + 1:])
    open(path, "w", encoding="utf-8").write(new)
    for ln, why in rw.skipped:
        print(f"  skipped line {ln}: {why}")
    return len(out)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(p, rewrite(p))
