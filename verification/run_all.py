"""検証一式を回して結果をテキストに保存する。
python verification/run_all.py [ツールのルート] [結果ファイル]

先に samples/ を生成する。生成には reportlab, python-docx, python-pptx, openpyxl が要る。
"""
import os, subprocess, sys, time
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.abspath(os.path.join(here, ".."))
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "results_latest.txt")
fx = os.path.join(root, "samples")
env = dict(os.environ, PYTHONIOENCODING="utf-8")
steps = [
  ("samples", ["mk_files.py", fx, os.path.join(root, "samples")]),
  ("text rules (FP/FN/unicode/decoders/perf)", ["t_text.py", root]),
  ("evasion matrix", ["t_text2.py", root]),
  ("files", ["t_files.py", root, fx]),
  ("files (structural summary)", ["t_files2.py", root, fx]),
  ("html", ["t_html.py", root]),
  ("corpus (manifest-driven)", ["t_corpus.py", root, fx, "-v"]),
  ("url (local server)", ["t_url.py", root, fx]),
]
with open(out, "w", encoding="utf-8") as fh:
    fh.write(f"# verification results  root={root}  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    for title, args in steps:
        fh.write(f"\n\n======== {title} ========\n"); fh.flush()
        r = subprocess.run([sys.executable, os.path.join(here, args[0])] + args[1:], capture_output=True, text=True, env=env, cwd=here)
        fh.write(r.stdout + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")); fh.flush()
        print("done:", title)
print("saved:", out)
