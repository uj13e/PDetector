import sys, glob, os
sys.path.insert(0, sys.argv[1])
from pdetector.scan import scan_path
for p in sorted(glob.glob(sys.argv[2]+"/*")):
    n=os.path.basename(p)
    if not n.endswith((".pdf",".pptx",".docx",".xlsx")): continue
    r = scan_path(p)
    plain = sorted({f.rule_id for f in r.findings if not f.rule_id.startswith("encoded:")})
    enc = sorted({f.rule_id.split(":")[1] for f in r.findings if f.rule_id.startswith("encoded:")})
    struct = [x for x in plain if x in ("pdf_white_text","pdf_tiny_text","docx_white_text","docx_hidden_text","pptx_notes","html_comment","hidden_html_element")]
    rule = [x for x in plain if x not in struct]
    print(f"{r.risk_level:9} | {n:34} | structural={struct or '-'} | text-rules={'Y' if rule else 'N'} | spurious-encoded={enc or '-'}")
