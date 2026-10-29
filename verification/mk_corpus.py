"""コーパス生成。python verification/mk_corpus.py [出力先]  既定は samples/"""
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
import corpus_common as C
C.setup(sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "samples"))
import importlib
for mod in ("mk_corpus_text", "mk_corpus_markup", "mk_corpus_docs"):
    try:
        m = importlib.import_module(mod)
    except ModuleNotFoundError as e:
        if e.name == mod:
            continue
        raise
    m.make()
C.save_manifest()
print("corpus:", len(C.MANIFEST), "files")
