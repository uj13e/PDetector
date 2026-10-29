# verification — 検証用スクリプトと結果

v0.1.0 の問題点を実測するために作った検証一式です。改善後(v1.0)も同じものを実行して、改善前後を比較できます。

| ファイル | 内容 |
|---|---|
| `run_all.py` | 下記すべてを実行して結果を1つのテキストに保存: `python verification/run_all.py <ツールのルート> <結果ファイル>` |
| `mk_files.py` | 攻撃/正常のフィクスチャ生成(PDF/docx/pptx/xlsx/odt/旧doc/各種文字コード)。要 reportlab, python-docx, python-pptx, openpyxl |
| `t_text.py` | A: サンプル、B: 正常文(誤検知)、C: 攻撃文(見逃し)、D: Unicode 誤検知、E: デコーダ、F: 性能/ReDoS |
| `t_text2.py` | 回避手法マトリクス(ホモグリフ・不可視文字・分断・エンコード各種) |
| `t_files.py` `t_files2.py` | samples のファイル(PDF/Office/文字コード)の判定と構造的な要約 |
| `t_html.py` | HTML の隠し要素(display:none・クラス経由・属性・noscript・JSON-LD・SVG など)と正常ページ |
| `t_url.py` | ローカルサーバでの URL 取得(文字コード・SSRF・リダイレクト・PDF・UA クローキング・巨大応答) |
| `mk_corpus.py` (+ `mk_corpus_text.py` / `_markup.py` / `_docs.py`, `corpus_common.py`) | **コーパス生成**: 悪意あるパターン 465 件 + 正常コントロール 82 件を `samples/` に書き出し、期待値を `fixtures/manifest.json` に記録 |
| `t_corpus.py` | コーパス全件のスキャンと判定(attack は期待以上で検知 / benign は clean か low): `python verification/t_corpus.py [-v]` |
| `../samples/` | 検証用ファイル一式(最初の 8 件の見本、旧 36 件、コーパス 547 件、manifest.json)。テストもここを見る |
| `results_corpus_v1.2.0.txt` | コーパスの全件結果(ルール 2.1.0) |
| `results_baseline_v0.1.0.txt` | **改善前**の実測結果 |
| `results_after_v2.txt` | **改善後**(v1.0.0 / ルール 2.0.0)の実測結果 |

読み方の注意:
- v1.0 は SSRF 対策で loopback への接続を既定で拒否するため、`t_url.py` はテスト用に `allow_private=True` を付けて実行します(拒否されることの確認も別行で行います)。
- 一部の期待値は「見逃しが残ること」を示します(語順入れ替え・過去形・意味的な言い換え。README の既知の限界を参照)。
- `unscanned` は「解析できなかった(安全とは言えない)」で、`clean` ではありません。

## コーパス(manifest.json)について
- `manifest.json` は `{ファイル名: {expect: attack|benign, min: 期待する最低判定, why: 説明, needs?: "ocr"}}`。`tests/test_corpus.py` が同じ判定を単体テストとして実行します。
- 範囲: 平文(言語別・脱獄・区切り偽装・持ち出し・ツール悪用・目的すり替え・難読化・エンコード・構造・コード)、HTML/SVG/EML/EPUB/RTF/ODF、PDF(不可視文字・微小/白文字・範囲外・注釈・フォーム・しおり・添付・リンク等)、docx/pptx/xlsx(非表示・コメント・ノート・代替テキスト・数式 DDE/HYPERLINK 持ち出し・ヘッダ/フッタ・入力規則・表示形式・ブックマーク・altChunk 等)、画像(EXIF/XMP/PNG テキスト/末尾データ/OCR 文字)、アーカイブ(zip/tar/gz、zip slip)。
- 「判断が割れるもの」(`curl | sh`、「今後は〜語で答えて」等)は誤検知を避けるため期待判定を low にしてあります。
- `needs: "ocr"` の画像は Tesseract が無い環境では partial(未検査と明示)を許容します。日本語の画像内文字には `jpn` 学習データが必要です。
