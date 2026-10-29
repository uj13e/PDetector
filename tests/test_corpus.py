"""samples を manifest.json に沿って全件検査する。

attack は manifest の min 以上(解析不可でも可)、benign は低リスク以下で完全解析されること。
サンプルは `python verification/mk_corpus.py` で作り直せる。無ければ skip。
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from pdetector.scan import scan_path

FIX = os.path.join(HERE, "..", "samples")
MAN = os.path.join(FIX, "manifest.json")
LV = ["clean", "low", "medium", "high", "critical"]


@unittest.skipUnless(os.path.exists(MAN), "manifest.json がありません(verification/mk_corpus.py で生成)")
class Corpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.man = json.load(open(MAN, encoding="utf-8"))

    def test_manifest_not_empty_and_files_exist(self):
        self.assertGreater(len(self.man), 100)
        missing = [n for n in self.man if not os.path.exists(os.path.join(FIX, n))]
        self.assertEqual(missing, [])

    def test_every_attack_is_detected_and_no_benign_is_flagged(self):
        bad = []
        for name, m in sorted(self.man.items()):
            r = scan_path(os.path.join(FIX, name))
            lv = r.risk_level
            if m["expect"] == "attack":
                ok = lv == "unscanned" or LV.index(lv) >= LV.index(m["min"])
                if not ok and m.get("needs") == "ocr" and r.status == "partial" and not _ocr_ok():
                    ok = True      # OCR エンジンが無い環境では「未検査(partial)」と明示されていれば許容
            else:
                ok = lv in ("clean", "low") and r.status in ("scanned", "partial")
            if not ok:
                bad.append((name, m["expect"], m["min"], lv, m.get("why", "")))
        self.assertEqual(bad, [], "\n" + "\n".join(map(str, bad)))

    def test_attack_categories_are_covered(self):
        names = " ".join(self.man)
        for cat in ("lang_", "jailbreak_", "delim_", "exfil_", "tool_", "goal_", "obf_", "enc_", "struct_", "code_"):
            self.assertIn("attack_" + cat, names)


if __name__ == "__main__":
    unittest.main()
