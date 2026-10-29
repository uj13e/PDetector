import sys, glob, os
sys.path.insert(0, sys.argv[1])
from pdetector.scan import scan_path
for p in sorted(glob.glob(sys.argv[2]+"/*")):
    r = scan_path(p)
    rules = sorted({f.rule_id for f in r.findings})
    n = "; ".join(r.notes)[:60]
    print(f"{r.risk_level:9} | {os.path.basename(p):32} | {','.join(rules)[:70]:70} | {n}")
