"""samples/manifest.json の全件をスキャンして期待どおりか見る。
python verification/t_corpus.py [ツールのルート] [samples フォルダ]
attack は期待の判定以上(unscanned も可)、benign は low 以下。
"""
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath(os.path.join(here, ".."))
fx = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(root, "samples")
sys.path.insert(0, root)
from pdetector.scan import scan_path
LV = ["clean", "low", "medium", "high", "critical"]


def _ocr_ok():
    try:
        from pdetector.imagex import ocr_available
        return bool(ocr_available()[0])
    except Exception:
        return False


def evaluate(fx):
    man = json.load(open(os.path.join(fx, "manifest.json"), encoding="utf-8"))
    rows = []
    for name, m in sorted(man.items()):
        p = os.path.join(fx, name)
        if not os.path.exists(p):
            rows.append((name, m, None, "missing"))
            continue
        r = scan_path(p)
        lv = r.risk_level
        if m["expect"] == "attack":
            ok = lv == "unscanned" or (lv in LV and LV.index(lv) >= LV.index(m["min"]))
            if not ok and m.get("needs") == "ocr" and r.status == "partial" and not _ocr_ok():
                ok = True      # OCR エンジンが無い環境では「未検査(partial)」と明示されていれば許容
        else:
            ok = lv in ("clean", "low") and r.status in ("scanned", "partial")
        rows.append((name, m, r, "ok" if ok else "NG"))
    return rows


if __name__ == "__main__":
    t = time.time()
    rows = evaluate(fx)
    ng = [x for x in rows if x[3] != "ok"]
    for name, m, r, st in rows:
        if st != "ok" or "-v" in sys.argv:
            print(f"{st:7} {m['expect']:6} want>={m['min']:6} got={(r.risk_level if r else '-'):9} {name}  ({m['why']})")
    n_att = sum(1 for x in rows if x[1]["expect"] == "attack")
    print(f"\nattack {n_att - sum(1 for x in ng if x[1]['expect']=='attack')}/{n_att} detected, "
          f"benign {sum(1 for x in rows if x[1]['expect']=='benign') - sum(1 for x in ng if x[1]['expect']=='benign')}/{sum(1 for x in rows if x[1]['expect']=='benign')} clean  ({time.time()-t:.1f}s)")
    sys.exit(1 if ng else 0)
