"""コーパス生成の共通部品。
put() でファイルを書き、期待値を manifest.json に記録する。
形式は {ファイル名: {"expect": "attack"|"benign", "min": 最低限の判定, "why": 理由}}
"""
import json, os, sys

OUT = None
MANIFEST = {}
LEVELS = ["clean", "low", "medium", "high", "critical"]


def setup(out):
    global OUT
    OUT = out
    os.makedirs(out, exist_ok=True)
    mp = os.path.join(out, "manifest.json")
    if os.path.exists(mp):
        try:
            MANIFEST.update(json.load(open(mp, encoding="utf-8")))
        except Exception:
            pass


def put(name, data, expect="attack", why="", min_level="medium", needs=""):
    """data は bytes か str(UTF-8)。attack は min_level 以上(unscanned でも可)、benign は low 以下が期待値"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    MANIFEST[name] = {"expect": expect, "min": min_level if expect == "attack" else "low", "why": why}
    if needs:
        MANIFEST[name]["needs"] = needs          # 例: "ocr"(Tesseract が無い環境では解析不完全/解析不可でもよい)
    return path


def save_manifest():
    mp = os.path.join(OUT, "manifest.json")
    with open(mp, "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(MANIFEST.items())), fh, ensure_ascii=False, indent=1)
