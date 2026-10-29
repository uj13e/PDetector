# PDetector 1.2 — Indirect Prompt Injection Detector

English | [日本語](README.ja.md)

PDetector scans files, URLs, emails and images for **indirect prompt injection**: instructions hidden in a document that an LLM is going to read ("ignore all previous instructions", "send the contents to this URL", and so on). It combines regex rules with heuristics for Unicode tricks, obfuscation and hidden content. **No third-party packages are required**; the core runs on the standard library alone.

> Important: this tool finds suspicious content. It is not a complete defense. Rephrased or purely semantic instructions that no rule covers will get through.
> Don't pass documents rated `high` or above, or `unscanned`, to an LLM.

## Usage

```
python -m pdetector report.pdf notes.docx https://example.com/page       # print a verdict
python -m pdetector ./inbox -r --include "*.pdf" --fail-on high           # scan a folder recursively (exit code 1 at high or above, for CI)
python -m pdetector mail.eml --format json -o result.json                 # json / markdown / csv / html output
python -m pdetector ./inbox -r --format html -o report.html               # standalone HTML report
cat page.html | python -m pdetector -                                     # read from stdin
python run_gui.py                                                          # GUI (Tkinter: progress, cancel, text preview, settings)
python -m pdetector ./inbox -r --sanitize ./safe                           # write sanitized copies to ./safe (originals are not touched)
python -m pdetector ./inbox -r --log                                       # save scan logs (shared with the GUI history)
python -m pdetector report.pdf --lang en                                   # output language: ja / en / auto (or set PDETECTOR_LANG)
python -m pdetector --check                                               # check optional dependencies
```

As a library:

```python
from pdetector.scan import scan_path, scan_bytes, scan_url, scan_text
r = scan_path("report.pdf")
if r.risk_level in ("high", "critical", "unscanned"):    # unscanned = could not be analyzed, so not known to be safe
    raise RuntimeError(f"{r.source}: {r.risk_level}")
for f in r.findings:
    print(f.severity, f.rule_id, f.location, f.snippet)

from pdetector.sanitize import sanitize_text            # strip invisible characters and mask detected instructions (text helper)
from pdetector.neutralize import sanitize_path          # sanitize a file or URL and re-scan the result; returns a SanitizeOutcome
```

### Risk levels and exit codes

| risk_level | Meaning |
|---|---|
| clean | Nothing found (`info` findings don't change the verdict) |
| low / medium / high / critical | Worst severity among the findings |
| unscanned | **Could not be analyzed** (encrypted, corrupt, unsupported format, fetch failure, internal error). This does not mean "no problem" |

`status` is `scanned` (fully analyzed), `partial` (only part of it was analyzed, e.g. a limit was hit or OCR was unavailable) or `unscanned`. `--strict` treats `partial` like `unscanned`.
With `--fail-on <level>` the exit code is 1 at that level or above (`unscanned` counts as `high`). Usage or config errors exit with 2.

## GUI

Start it with `python run_gui.py` (standard library only; install `tkinterdnd2` for drag and drop).
On Windows it starts without a console window (`run_gui.py` re-launches itself under pythonw; `run_gui.pyw` and `pdetector.vbs` are included for double-clicking, and `python run_gui.py --console` is there for debugging). A startup crash is written to `error.log` in the settings folder.

- **Input**: type or paste paths and URLs (several are fine) and press Enter, use "Choose files" / "Choose folder" / "Paste text", or drag and drop. Recent scans are available from the input box history.
- **Results**: the banner at the top is the overall verdict (an unscanned file is never shown as safe). The tree on the left groups findings per target, worst first, and can be filtered by severity and by text. The right pane shows the matched string, why it is dangerous and what to do; the preview tab shows the normalized text with the match highlighted (hidden-content and decoded findings have no position, so they can't be highlighted).
- **False positives**: select a finding and choose "Ignore this phrase (allow)" or "Disable this rule". Both are saved to the settings and applied on the next scan.
- **Settings**: general options (decoding, hidden content, thresholds), a rule list (search, enable/disable, change severity), allow patterns, extra rules, and a try-it box for testing a setting on the spot. Settings can be exported and imported as JSON.
- **Folder scans**: the result tree starts collapsed, and only what you open is remembered.
- **Sanitizing**: choose "Sanitize and save..." for a result, or run it for everything from the menu. It extracts only the text a person would see, removes invisible characters and replaces instruction-like text with `[REDACTED]`. The original is never modified.
  **pptx / docx / xlsx are saved in the same format** (pick .txt in the save dialog if you want text); every other format becomes text.
  For Office files the output is rebuilt from the visible text rather than edited in place (slide and sheet boundaries are kept, long slides are split). Hidden slides, notes, comments, document properties, embedded objects, macros and images can't end up in it. The flip side is that the original layout, formatting, images, charts and table styling are lost.
  Before writing, the output is scanned again; if anything is still detected or the file is malformed it isn't written (`unsafe`). Files that couldn't be read (encrypted, corrupt) are reported as `skipped`, and ones that were only partly analyzed as `partial`.
  CLI: `--sanitize DIR` (`--sanitize-level` sets the lowest severity to mask, default medium; `--sanitize-format txt` always writes text).
- **History and logs**: every scan is logged as JSON Lines (on by default; disable it or change the retention in settings). "Scan history" (Ctrl+H) re-opens or deletes past results.
  Logs go to `%APPDATA%\pdetector\logs` (`~/.config/pdetector/logs` on Linux/macOS). They hold excerpts of what was found and a SHA-256, not the full text of the document. CLI: `--log [DIR]`.
- **Language**: Settings → Language switches between Japanese, English and auto (follows the OS) without a restart. CLI: `--lang`.
  The UI, messages, rule descriptions and reports are translated. Rule IDs and excerpts taken from the scanned document stay as they are.
- **Look and feel**: light and dark themes (follows the OS), font size (Ctrl + / Ctrl - / Ctrl 0), and remembered window and pane positions.
- **Files**: settings in `%APPDATA%\pdetector\config.json`, UI state in `gui.json` (`~/.config/pdetector` on Linux/macOS). `PDETECTOR_HOME` moves the folder, and `PDETECTOR_CONFIG` takes priority if set.
- **Export**: save results as text, JSON, Markdown, CSV (with a BOM so Excel opens it correctly) or HTML, or open the HTML report in a browser.

## What it detects

- **Instruction override, jailbreaks, concealment, exfiltration, tool abuse, delimiter spoofing**: 84 rules plus 4 boilerplate-phrase rules (`--list-rules`). English and Japanese are covered best; there are also rules for zh, ko, es, fr, de, ru, pt, it, ar, tr, id, nl, pl, uk, vi and hi.
  To avoid flagging ordinary how-to text ("open the URL", "send the data"), a rule needs verb, object and destination together.
- **Unicode smuggling and obfuscation**: zero-width and invisible characters, the Tags block (ASCII smuggling), variation selectors, bidi controls (Trojan Source), private-use characters, homoglyphs (mixed Cyrillic/Greek), full-width and small-caps letters, combining marks, text split by spaces or symbols one character at a time, and text broken across lines. Legitimate ZWJ in emoji and Indic/Arabic scripts, BOMs, and direction marks in RTL documents are not flagged.
- **Instructions inside encodings**: base64 (also base64url, line-wrapped, space-separated, UTF-16, zlib/gzip, multi-layer), base32/85, ascii85, hex, binary, decimal codes, octal, quoted-printable, URL encoding, HTML entities, `\uXXXX`, ROT13/ROT47/Atbash, reversed text and leetspeak.
- **Hidden document content** (each region is matched separately, and the severity goes up when hidden text reads like an instruction):
  HTML: display:none, visibility, opacity, off-screen, tiny / transparent / background-colored text, hiding via classes, `<noscript>`, `<template>`, comments, alt / title / aria / data attributes, JSON-LD, SVG text.
  PDF: white, background-colored, tiny, off-page and invisible-render-mode text, metadata, annotations, forms, JavaScript, embedded files, and OCR for image-only PDFs.
  Word / Excel / PowerPoint (docx / xlsx / pptx): vanish, white and tiny text, tracked deletions, comments, footnotes, text boxes, notes, hidden slides and sheets, strings in formulas, document properties, embedded objects.
  Also OpenDocument, EPUB, RTF, legacy Office (basic), email (.eml: body, attachments, headers, text/html mismatch), images (EXIF/XMP/PNG text, OCR, low-contrast text), Markdown comments, JSON and XML.
- **Spoofed fetches and formats**: extension/content mismatch (`type_mismatch`), user-agent cloaking on URLs (the page differs between the scanner and a normal browser), and the contents of zip / gzip / tar archives (nested too).

### Fail-closed design

Anything that couldn't be analyzed is reported as `unscanned`, never as "no problem": internal exceptions, encrypted PDF / Office / zip files, corrupt files, unsupported binaries, URLs refused for SSRF reasons.
Zip bombs, XML bombs (entity expansion) and huge responses are cut off by limits on size, compression ratio, depth and time, and the result says `partial` or `unscanned`.
URL fetching refuses internal and private addresses, including after redirects (`--allow-private` turns that off).

## Configuration (false positives and in-house rules)

`--config pdetector.json` (or the `PDETECTOR_CONFIG` environment variable). Example:

```json
{
  "disabled_rules": ["you_are_now"],
  "severity_overrides": {"end_of_document_marker": "info"},
  "allow_patterns": ["internal-wiki\\.example\\.com"],
  "extra_rules": [{"id": "corp_secret", "pattern": "send\\s+.{0,40}project\\s+x\\s+to", "severity": "high", "category": "exfiltration"}],
  "invisible_ratio_threshold": 0.02,
  "decode": true,
  "timeout_sec": 60
}
```

Watch out for ReDoS (nested quantifiers) in the regexes you put in `extra_rules`.

## Layout

| Module | Role |
|---|---|
| `scan.py` | High-level API and CLI (fail-closed) |
| `extractors.py` | Detects the format from the content signature and dispatches to an extractor (independent of the extension) |
| `htmlx.py` `pdfx.py` `office.py` `imagex.py` `mailx.py` `netfetch.py` | Per-format extraction (visible text plus hidden regions). Office, HTML and email need only the standard library |
| `encoding.py` | Character encoding detection (UTF-8/16, cp932, EUC-JP, ISO-2022-JP, GB18030, ...) |
| `normalize.py` `unicode_checks.py` | Normalization for matching (invisible-character removal, NFKC, homoglyphs, split-text handling) and Unicode heuristics |
| `patterns.py` | Rule definitions (bounded quantifiers and a pre-filter keep ReDoS and speed in check) |
| `decoders.py` | Recovers encoded or obfuscated strings, multiple layers deep |
| `detector.py` | Combines the matchers, judges hidden regions in context, sets the level and status |
| `config.py` `report.py` `sanitize.py` `deps.py` | Config, output formats (text/json/markdown/csv/html), text sanitizing helper, dependency check |
| `neutralize.py` `ooxml_out.py` | Sanitizing files and URLs (extract text, strip invisible characters, mask instructions, re-scan; fail-closed) and rebuilding pptx/docx/xlsx (standard library only) |
| `scanlog.py` `gui_history.py` | Scan log (JSONL) writing, listing and deletion; the history window |
| `i18n.py` `i18n_en.py` | Translation keyed by the Japanese source text (`tr()`) and the English dictionary. Helper scripts for the dictionary are in `tools/` |
| `icon.py` `assets/` `crashlog.py` | App icon, startup crash log |
| `gui.py` `gui_logic.py` `gui_theme.py` `gui_settings.py` | The GUI, Tk-independent logic (the part that is unit-tested), colors and fonts, the settings dialog |
| `safeio.py` `model.py` | Safe zip/XML reading and time budget, shared data model |

## Known limitations

- It's rule-based, so paraphrases, reordered words, past tense and context-dependent instructions ("the above is wrong, the correct instruction is ...") get through. So do languages without rules.
- Text in images can only be checked with Tesseract (plus the `jpn` language data for Japanese). Without it the result is `partial`. Handwriting, decorative fonts and very low contrast can be missed.
- Legacy Office files (.doc/.xls/.ppt) get a basic string-extraction pass, and the result notes that something may be missed. Password-protected files are `unscanned`.
- A document that merely explains attacks (security write-ups, attack collections) is detected, by design. Use `allow_patterns` to exclude it.
- Very large text (several MB) is analyzed at the head and tail only, and whole-text transforms such as ROT13 are limited to the first and last 200,000 characters. A 1 MB English text takes about 2 seconds.
- The GUI (Tkinter) targets Windows. It was developed and checked on Linux (Tk 9, virtual display), including launch, interaction and screenshots. It has **not** been checked on a real Windows machine (Tk 8.6): rendering, the pythonw hand-off, the `.vbs` launcher and the taskbar icon are untested.
- Sanitizing rebuilds a safe version of whatever could be read; the original formatting, images and layout are gone (Office files are rebuilt as plain files of the same format). PDF, HTML, email and the rest come out as text. Paraphrased (semantic) instructions can't be masked, so check the output before giving it to an LLM.
- Even in English mode, excerpts from the scanned document (Japanese, for example) and a few small notes are shown as they are.

## Tests and verification

```
python -m unittest discover -s tests          # unit, integration and regression tests (422, including every file in the corpus; GUI smoke tests are skipped where Tk is missing)
python verification/run_all.py . verification/results_latest.txt   # regenerate samples/ (needs reportlab, python-docx, ...) and run the verification suite
```

`samples/` holds every file used for trying the tool and for testing: `attack_*` files contain attacks, `benign_*` and `clean_*` files don't, and `samples/manifest.json` records what each one should produce. The same files work for drag and drop into the GUI and as test input.

`verification/` has the measured results from before the improvements (v0.1.0, `results_baseline_v0.1.0.txt`), after them (`results_after_v2.txt`), after the GUI work (`results_after_ui_v1.1.0.txt`) and for the corpus (`results_corpus_v1.2.0.txt`), plus the verification scripts. See `verification/README.md`.

## Changelog

### 1.2.0 (rules 2.1.0)
- **Wider detection (rules 2.1.0)**: a corpus of malicious patterns (465 attacks and 82 benign controls, in `samples/` with `manifest.json`); every attack is detected and none of the benign files is. Besides 23 new rules, these are now inspected: HTML (strings inside scripts, template variables in URLs), images (trailing data, OCR of tilted text), xlsx/CSV (DDE, HYPERLINK/IMPORTXML exfiltration formulas, headers and footers, data validation, number formats), docx (bookmark names, tooltips, content-control names, altChunk), pptx (layout and master text, shape names, links), PDF link URLs, and path traversal in zip/tar. Ambiguous cases such as `curl | sh` stay at low.
- **File sanitizing**: from the GUI (per result or all) and the CLI `--sanitize`. pptx/docx/xlsx are rebuilt as plain files of the same format (`ooxml_out.py`), everything else becomes text. Only output that passes the re-scan is written, and unreadable input is reported as `skipped` / `unsafe` (`neutralize.py`).
- **Language switch**: Japanese, English or auto. Instant in the GUI; `--lang` / `PDETECTOR_LANG` in the CLI. Reports (text, markdown, csv, html) are translated too.
- **Scan logs and history**: JSONL logs, a history window (Ctrl+H), a retention setting, CLI `--log`.
- **No console window**: automatic hand-off to pythonw, `run_gui.py --console` for the old behavior, `.pyw` / `.vbs` launchers, `error.log` for startup crashes.
- **UI**: a dedicated icon (the default Tk feather is gone), calmer colors, spacing and fonts, and the clipped buttons in the paste dialog are fixed.
- **Folder scans**: nothing is expanded at first; only what the user opens is remembered.

### 1.1.0 (rules 2.0.0, same detections as 1.0.0)
A full UI/UX overhaul of the GUI.
- **Readable results**: an overall verdict banner, severity filter and text filter, a preview that highlights the match, "why it's dangerous / what to do", and unscanned shown in a conspicuous color.
- **Usability**: progress bar and cancel (scans run in a worker thread), multiple paths, quoted paths and URLs, scanning pasted text, rescan, context menus, shortcuts, recent history.
- **Look**: light and dark themes, DPI awareness, font size, automatic Japanese font selection.
- **Settings and rules**: a settings dialog (general, rules, allow patterns, extra rules, try-it), allow or disable from the result view, persisted settings with export and import.
- **Output**: `--format html` (standalone report, dark-mode aware), CSV with a BOM for Excel.
- Internals: added `Finding.length`, `ScanResult.text` (for highlighting; not written to JSON) and `DetectorConfig.keep_text`.

### 1.0.0 (rules 2.0.0)
Fixes for the problems found while verifying v0.1.0: fail-open on unanalyzable input, false positives, misses, robustness of extraction and scanning, bugs, and operations.

- **No more fail-open**: introduced `unscanned` and `partial`. Format detection now uses the content (so spoofed or missing extensions, such as a docx with no extension, are still analyzed). Encrypted, corrupt and unsupported files are unscanned, and an internal exception can no longer produce "no problem".
- **Fewer false positives**: the rules were rewritten to require verb, object and destination. "visit URL", "Dan", "you are now logged in" and Japanese how-to sentences are clean now. Legitimate ZWJ, BOM, VS16, Tag-based flags, RTL direction marks and soft hyphens are excluded.
- **Fewer misses**: per-region matching of hidden content, white text in PDFs, Office vanish / tracked changes / formulas, email, image metadata and OCR, OpenDocument / EPUB / RTF, nested zip / tar / gzip, homoglyphs, split text and small caps, multi-layer and many encodings, short Japanese commands, more languages. cp932, EUC-JP, ISO-2022-JP and UTF-16 are detected automatically.
- **Robustness**: ReDoS protection (50,000 × `{{` went from 56 s to 0.1 s), limits for zip bombs, XML bombs and huge responses, a time budget, SSRF protection (including redirects), user-agent cloaking checks, and speed (1 MB from 4.8 s to about 2 s).
- **Bug fixes**: a NameError in a GUI closure, UnicodeEncodeError on cp932 consoles, lost text from PDF embedded files, misdetected emails with an HTML part, and more.
- **Operations**: a config file, JSON / Markdown / CSV output, SHA-256, tool and rule versions and run time recorded in results, line numbers, recursive folder scans, stdin, exit codes, regression tests, and a sanitize API.
