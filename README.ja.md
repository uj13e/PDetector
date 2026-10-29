# PDetector 1.2 — 間接プロンプトインジェクション検知ツール

[English](README.md) | 日本語

ファイル・URL・メール・画像などに埋め込まれた **間接プロンプトインジェクション**(LLM に読ませる文書の中に仕込まれた「以前の指示を無視しろ」等の命令)を、
ルールベース(正規表現)とヒューリスティック(Unicode/難読化/隠し要素)で検知します。**必須の外部パッケージはありません**(標準ライブラリのみで動作)。

> 重要: これは「怪しいものを見つける」ための検知器で、完全な防御ではありません。ルールに無い言い回し・意味的な言い換えは見逃します。
> 判定が `high` 以上、または `unscanned`(解析不可)の文書は LLM に渡さない運用を推奨します。

## 使い方

```
python -m pdetector report.pdf notes.docx https://example.com/page       # 判定を表示
python -m pdetector ./inbox -r --include "*.pdf" --fail-on high           # フォルダを再帰走査(CI向け: high以上で終了コード1)
python -m pdetector mail.eml --format json -o result.json                 # JSON/markdown/csv/html で出力
python -m pdetector ./inbox -r --format html -o report.html               # 単体で開ける HTML レポート
cat page.html | python -m pdetector -                                     # 標準入力
python run_gui.py                                                          # GUI(Tkinter。進捗・キャンセル・本文プレビュー・設定画面つき)
python -m pdetector ./inbox -r --sanitize ./safe                           # 無害化した安全なテキスト版を ./safe に書き出す(元ファイルは変更しない)
python -m pdetector ./inbox -r --log                                       # スキャンログを保存(GUI の「スキャン履歴」と共通)
python -m pdetector report.pdf --lang en                                   # 英語表示(ja/en/auto。環境変数 PDETECTOR_LANG でも指定可)
python -m pdetector --check                                               # 依存ライブラリの確認
```

Python ライブラリとして:

```python
from pdetector.scan import scan_path, scan_bytes, scan_url, scan_text
r = scan_path("report.pdf")
if r.risk_level in ("high", "critical", "unscanned"):    # unscanned = 解析できなかった(安全とは言えない)
    raise RuntimeError(f"{r.source}: {r.risk_level}")
for f in r.findings:
    print(f.severity, f.rule_id, f.location, f.snippet)

from pdetector.sanitize import sanitize_text            # 不可視文字の除去 + 検知した指示文の伏せ字化(テキスト用の補助)
from pdetector.neutralize import sanitize_path          # ファイル/URL を無害化(再検査つき)。SanitizeOutcome を返す
```

### 判定レベルと終了コード

| risk_level | 意味 |
|---|---|
| clean | 兆候なし(info の検知は判定に影響しません) |
| low / medium / high / critical | 検知された最悪の重大度 |
| unscanned | **解析できなかった**(暗号化・破損・非対応形式・取得失敗・内部エラー)。「問題なし」ではありません |

`status` は `scanned`(完全に解析)/ `partial`(一部のみ。時間切れ・サイズ超過・OCR未実施など)/ `unscanned`。`--strict` で partial も unscanned 扱いにできます。
`--fail-on <level>` を付けると、そのレベル以上(`unscanned` は high 相当)で終了コード 1。引数/設定ミスは 2。

## GUI の使い方

`python run_gui.py` で起動します(標準ライブラリのみ。ドラッグ&ドロップは `pip install tkinterdnd2` で有効)。
Windows ではコンソール窓を出さずに起動します(`run_gui.py` が自動で pythonw に引き継ぎます。ダブルクリック用に `run_gui.pyw` と `pdetector.vbs` も同梱。
デバッグ時は `python run_gui.py --console`)。起動時に例外が出た場合は設定フォルダの `error.log` に記録します。

- **入力**: 入力欄にパス/URL(複数可)を入れて Enter、「ファイルを選ぶ」「フォルダを選ぶ」「テキストを貼り付け」、または D&D。最近のスキャンは入力欄の履歴から呼び出せます。
- **結果**: 上部のバナーが総合判定です(解析不可は「安全」と表示しません)。左のツリーは対象ごとに検知を重大度順に並べ、重大度チェックと絞り込み欄で表示を切り替えます。
  右の「詳細」に見つかった文字列・なぜ危険か・対処、「本文プレビュー」に正規化済み本文と検知箇所の強調が出ます(隠し要素やデコード由来の検知は位置を持たないため強調できません)。
- **誤検知への対処**: 検知を選んで「この文言を無視する(許可)」「このルールを無効化」。設定に保存され、再スキャンで反映されます。
- **検知設定**(メニュー/ボタン): 一般(デコード・隠し要素・しきい値など)、ルール一覧(検索・有効/無効・重大度変更)、許可パターン、追加ルール、設定のその場での「試し打ち」。設定は JSON で書き出し/読み込みできます。
- **フォルダ走査**: 結果ツリーは折りたたんだ状態で始まります(開閉は利用者が操作したものだけ記憶)。
- **無害化**: 結果を選んで「無害化して保存…」、またはメニューから全件。人に見える本文だけを取り出し、不可視文字を除去し、命令文を `[REDACTED]` に置換して保存します(元ファイルは変更しません)。
  **pptx / docx / xlsx は同じ形式のファイル(.pptx/.docx/.xlsx)として保存**します(保存ダイアログで .txt を選べばテキスト)。それ以外の形式はテキストです。
  Office 形式は、元のファイルを加工するのではなく、見えている本文だけで素のファイルを作り直します(スライド/シートの区切りは保持、長いスライドは分割)。
  そのため隠しスライド・ノート・コメント・文書プロパティ・埋め込み・マクロ・画像は構造上入りません。反対に、元のレイアウト・書式・画像・グラフ・表の体裁は残りません。
  保存前に出力ファイルをもう一度検知器にかけ、検知が残る/形式が崩れているなら書き出しません(`unsafe`)。解析できなかったもの(暗号化・破損など)は `skipped`、元の解析が一部のみなら `partial` と明示します。
  CLI は `--sanitize DIR`(`--sanitize-level` で伏せ字にする重大度の下限。既定 medium、`--sanitize-format txt` で常にテキスト)。
- **スキャン履歴・ログ**: スキャンごとに JSON Lines のログを残します(既定で有効。設定画面で無効化・保存日数を変更)。メニューの「スキャン履歴」(Ctrl+H)から過去の結果を再表示・削除できます。
  保存先は `%APPDATA%\pdetector\logs`(Linux/Mac は `~/.config/pdetector/logs`)。ログには検知の抜粋と SHA-256 を含みますが、本文全体は保存しません。CLI は `--log [DIR]`。
- **言語**: 設定 → 言語 で 日本語/English/自動(OS に追従)を切り替えます(再起動不要)。CLI は `--lang`。
  画面・メッセージ・ルール説明・出力レポートは翻訳されます。ルール ID と、検知した文書からの抜粋は原文のままです。
- **見た目**: ライト/ダーク(OS に追従)、文字サイズ変更(Ctrl + / Ctrl - / Ctrl 0)、ウィンドウ位置・分割位置の記憶。専用アイコンと落ち着いた配色を採用(Tk 既定の羽アイコンは使いません)。
- **保存先**: 設定 `%APPDATA%\pdetector\config.json`、UI 状態 `gui.json`(Linux/Mac は `~/.config/pdetector`、`PDETECTOR_HOME` で変更可、`PDETECTOR_CONFIG` があればそちらが優先)。
- **出力**: テキスト/JSON/Markdown/CSV(Excel 対応の BOM 付き)/HTML を保存、HTML レポートをブラウザで表示。

## 検知するもの

- **命令の上書き・ジェイルブレイク・隠蔽指示・情報送出・ツール悪用・区切り偽装** … 84 ルール+4 つの定型句ルール(`--list-rules`)。英語/日本語を中心に zh・ko・es・fr・de・ru・pt・it・ar・tr・id・nl・pl・uk・vi・hi。
  通常の手順書に出る文(「URL を開く」「データを送信する」等)を拾わないよう、動詞+対象+宛先まで要求します。
- **Unicode 密輸・難読化** … ゼロ幅/不可視文字、Tags ブロック(ASCII スマグリング)、異体字セレクタ、双方向制御(Trojan Source)、私用領域、ホモグリフ(キリル/ギリシャ混在)、全角・小型大文字、結合記号、
  1 文字ずつの空白/記号区切り、改行による分断。絵文字・インド系/アラビア文字の正当な ZWJ・BOM・RTL 文書の方向マークは誤検知しません。
- **エンコードの中の命令** … base64(base64url/改行折返し/空白区切り/UTF-16/zlib・gzip/多段)、base32/85、ascii85、hex、2 進、10 進コード、8 進、quoted-printable、URL エンコード、HTML エンティティ、`\uXXXX`、ROT13/ROT47/Atbash、反転、leet。
- **隠された文書内容(領域ごとに照合し、隠されていて命令文なら重大度を引き上げ)**
  HTML: display:none / visibility / opacity / 画面外 / 極小・透明・背景同化文字 / クラス経由の隠し / `<noscript>` / `<template>` / コメント / alt・title・aria・data 属性 / JSON-LD / SVG テキスト。
  PDF: 白・背景同化・極小・ページ外・不可視描画モードの文字 / メタデータ / 注釈 / フォーム / JavaScript / 埋め込みファイル / 画像のみ PDF の OCR。
  Word/Excel/PowerPoint(docx/xlsx/pptx): vanish・白文字・極小文字・変更履歴の削除文・コメント・脚注・テキストボックス・ノート・非表示スライド/シート・数式中の文字列・文書プロパティ・埋め込み。
  OpenDocument・EPUB・RTF・旧 Office(簡易)・メール(.eml: 本文/添付/ヘッダ/text と html の食い違い)・画像(EXIF/XMP/PNG テキスト、OCR、低コントラスト文字)・Markdown コメント・JSON/XML。
- **取得・形式の偽装** … 拡張子と中身の不一致(`type_mismatch`)、URL の UA クローキング(スキャナと通常ブラウザで内容が違う)、zip/gzip/tar の中身(入れ子可)。

### 安全側の設計(fail-closed)

解析できなかったものを「問題なし」と報告しません(`unscanned`)。内部例外・暗号化 PDF/Office/zip・破損ファイル・非対応バイナリ・SSRF で拒否した URL などが対象です。
zip 爆弾・XML 爆弾(ENTITY)・巨大レスポンスには上限(サイズ/圧縮率/深さ/時間)があり、超えたら打ち切って `partial`/`unscanned` を明示します。
URL 取得は内部/プライベートアドレス(SSRF)をリダイレクト先も含めて拒否します(`--allow-private` で解除)。

## 設定(誤検知の抑制・社内ルール)

`--config pdetector.json`(または環境変数 `PDETECTOR_CONFIG`)。例:

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

`extra_rules` の正規表現は利用者の責任で ReDoS(入れ子の量指定子)に注意してください。

## 構成

| モジュール | 役割 |
|---|---|
| `scan.py` | 高レベル API と CLI(fail-closed) |
| `extractors.py` | 中身のシグネチャで形式判定し、各抽出器へ振り分け(拡張子に依存しない) |
| `htmlx.py` `pdfx.py` `office.py` `imagex.py` `mailx.py` `netfetch.py` | 形式別の抽出(可視テキスト+隠し領域)。Office/HTML/メールは標準ライブラリのみ |
| `encoding.py` | 文字コード判定(UTF-8/16、cp932、EUC-JP、ISO-2022-JP、GB18030 等) |
| `normalize.py` `unicode_checks.py` | 照合用正規化(不可視除去・NFKC・ホモグリフ・分断対策)と Unicode ヒューリスティック |
| `patterns.py` | ルール定義(上限付き量指定子+事前フィルタで ReDoS/速度に配慮) |
| `decoders.py` | エンコード/暗号化された文字列の復元(多段) |
| `detector.py` | 照合の統合、隠し領域の文脈判定、判定レベル/ステータス |
| `config.py` `report.py` `sanitize.py` `deps.py` | 設定、出力整形(text/json/markdown/csv/html)、テキストのサニタイズ補助、依存確認 |
| `neutralize.py` `ooxml_out.py` | ファイル/URL の無害化(本文抽出→不可視文字除去→命令文の伏せ字→再検査。fail-closed)と、pptx/docx/xlsx の作り直し(標準ライブラリのみ) |
| `scanlog.py` `gui_history.py` | スキャンログ(JSONL)の記録・一覧・削除、履歴ウィンドウ |
| `i18n.py` `i18n_en.py` | 日本語原文をキーにした翻訳(`tr()`)と英語辞書。`tools/` に辞書作成の補助スクリプト |
| `icon.py` `assets/` `crashlog.py` | アプリアイコン、起動時クラッシュの記録 |
| `gui.py` `gui_logic.py` `gui_theme.py` `gui_settings.py` | GUI 本体、Tk 非依存のロジック(テスト対象)、配色・フォント、設定ダイアログ |
| `safeio.py` `model.py` | 安全な zip/XML 読み込み・時間予算、共有データモデル |

## 既知の限界

- ルールベースなので、言い換え・語順入れ替え・過去形・文脈依存の指示(「上は間違い。正しい指示は…」等)は見逃します。未対応言語も同様です。
- 画像内の文字は Tesseract(+ `jpn` 言語データ)が無いと検査できず、その旨が `partial` として出ます。手書き・装飾文字・微小コントラストは取りこぼし得ます。
- 旧 Office(.doc/.xls/.ppt)は文字列抽出による簡易解析です(見落としの可能性を注記します)。パスワード保護は解析不可になります。
- セキュリティ解説文や攻撃事例集など「攻撃文そのものを説明する文書」は、正しく検知されます(誤検知ではなく仕様)。`allow_patterns` で除外してください。
- 極端に大きいテキスト(数MB)は先頭/末尾のみ解析し、ROT13 等の全文変換は先頭+末尾 20 万文字に限定します。処理時間は 1MB の英文で約 2 秒です。
- GUI(Tkinter)は Windows での利用を想定しています。開発環境では Linux(Tk 9 / 仮想ディスプレイ)での起動・操作テストとスクリーンショット確認まで実施しており、Windows 実機(Tk 8.6)での表示、pythonw への引き継ぎ、`.vbs` ランチャー、タスクバーのアイコンは未確認です。
- 無害化は「読めた本文を安全側に作り直す」処理で、元の書式・画像・レイアウトは残りません(Office 形式も同じ形式の素のファイルになるだけです)。PDF・HTML・メール等はテキストで出力します。ルールに無い言い換え(意味的な指示)は伏せ字にできないため、無害化後も LLM に渡す前の確認は必要です。
- 英語表示でも、検知した文書からの抜粋(日本語など)と一部の細かい注記は原文のまま表示されます。

## テストと検証

```
python -m unittest discover -s tests          # 単体・統合・回帰テスト(422件。コーパス全件の判定を含む。Tk が無い環境では GUI 煙テストを自動スキップ)
python verification/run_all.py . verification/results_latest.txt   # samples/ の生成(要 reportlab/python-docx 等)+ 検証一式
```

`samples/` には試用・検証用のファイルが全部入っています(`attack_*` は攻撃入り、`benign_*` と `clean_*` は正常、期待値は `samples/manifest.json`)。GUI にドラッグして挙動を見るのにも、テストの入力にも同じものを使います。

`verification/` には、改善前(v0.1.0)の実測結果 `results_baseline_v0.1.0.txt` と改善後 `results_after_v2.txt`、GUI 改善後 `results_after_ui_v1.1.0.txt`、検証用ファイルは `samples/` にまとめてあります(コーパスの結果は `results_corpus_v1.2.0.txt`)、各検証スクリプトがあります。詳細は `verification/README.md`。

## 変更履歴

### 1.2.0(ルール 2.1.0)
- **検知の拡張(ルール 2.1.0)**: 悪意あるパターンのコーパス(攻撃 465 件+正常コントロール 82 件、`samples/` と `manifest.json`)を用意し、全件を検知(正常は誤検知なし)。追加ルール 23 件に加え、HTML(スクリプト内文字列・URL のテンプレート変数)、画像(末尾データ・傾いた文字の OCR)、xlsx/CSV(DDE・HYPERLINK/IMPORTXML でのデータ持ち出し数式、ヘッダ/フッタ、入力規則、表示形式)、docx(ブックマーク名・ツールチップ・コンテンツコントロール名・altChunk)、pptx(レイアウト/マスターの文字・図形名・リンク)、PDF リンク URL、zip/tar のパストラバーサルを検査対象に追加。判断が割れるもの(`curl | sh` 等)は low 止まりです。
- **ファイルの無害化**: GUI(結果から保存/全件)と CLI `--sanitize`。pptx/docx/xlsx は同じ形式の素のファイルとして作り直して出力(`ooxml_out.py`)、それ以外はテキスト。再検査に通ったものだけ書き出し、読めないものは `skipped`/`unsafe` と明示(`neutralize.py`)。
- **言語切り替え**: 日本語/English/自動。GUI は即時反映、CLI は `--lang`/`PDETECTOR_LANG`。レポート(text/markdown/csv/html)も翻訳。
- **スキャンログと履歴**: JSONL ログ、履歴ウィンドウ(Ctrl+H)、保存日数の設定、CLI `--log`。
- **コンソール非表示**: pythonw への自動引き継ぎ、`run_gui.py --console` で従来動作。`.pyw`/`.vbs` ランチャー、起動時クラッシュの `error.log`。
- **UI**: 専用アイコン(Tk 既定の羽を廃止)、配色・余白・フォントを控えめに調整、貼り付けダイアログのボタン切れを修正。
- **フォルダ走査**: 初期状態で全展開しない(展開/折りたたみボタンは設けず、利用者が開いたものだけ保持)。

### 1.1.0(ルール 2.0.0 のまま。検知結果は 1.0.0 と同一)
UI/UX の全面改善(GUI)。
- **結果の見やすさ**: 総合判定バナー、重大度フィルタ+絞り込み、検知箇所を強調する本文プレビュー、「なぜ危険か・対処」の表示、解析不可を目立つ色で表示。
- **操作性**: 進捗バー+キャンセル(別スレッド実行)、複数パス/引用符付きパス/URL の入力、貼り付けスキャン、再スキャン、右クリックメニュー、ショートカット、最近の履歴。
- **見た目**: ライト/ダーク、DPI 対応、文字サイズ変更、日本語フォントの自動選択。
- **設定・ルール管理**: 設定画面(一般/ルール/許可パターン/追加ルール/試し打ち)、結果画面から許可・無効化、設定の永続化と書き出し/読み込み。
- **出力**: `--format html`(単体 HTML レポート、ダーク対応)、CSV は Excel 向け BOM 付き。
- 内部: `Finding.length` と `ScanResult.text`(GUI の強調用。JSON には出さない)、`DetectorConfig.keep_text` を追加。

### 1.0.0(ルール 2.0.0)
v0.1.0 の検証で見つかった課題(A 解析不能時の fail-open / B 誤検知 / C 見逃し / D 抽出・走査の頑健性 / E バグ / F 運用)を一括で改善。

- **A fail-open の解消**: `unscanned`/`partial` を導入。形式判定を中身ベースに変更(拡張子偽装・拡張子なしの docx 等も解析)。暗号化/破損/非対応は解析不可。内部例外でも「問題なし」にならない。
- **B 誤検知の削減**: 動詞+対象+宛先まで要求する形にルール全面改訂。"visit URL"・"Dan"・"you are now logged in"・日本語の手順書文などが clean に。ZWJ/BOM/VS16/Tag 国旗/RTL 方向マーク/ソフトハイフンの正当な使用を除外。
- **C 見逃しの解消**: 隠し要素の領域別照合、PDF 白文字・Office の vanish/変更履歴/数式、メール、画像メタ/OCR、OpenDocument/EPUB/RTF、zip/tar/gzip の入れ子、ホモグリフ/空白分断/小型大文字、
  多段/各種エンコード、日本語の短い命令、追加言語。cp932/EUC-JP/ISO-2022-JP/UTF-16 を自動判定。
- **D 頑健性**: ReDoS 対策(`{{`×50000 で 56 秒 → 0.1 秒)、zip/XML 爆弾・巨大レスポンスの上限、時間予算、SSRF 対策(リダイレクト含む)、UA クローキング検査、速度改善(1MB で 4.8 秒 → 約 2 秒)。
- **E バグ修正**: GUI のクロージャ NameError、cp932 コンソールでの UnicodeEncodeError、PDF 埋め込みファイルの本文消失、HTML パート付きメールの形式誤判定 など。
- **F 運用**: 設定ファイル、JSON/Markdown/CSV 出力、SHA-256・ツール/ルールのバージョン・実行時刻を結果に記録、行番号、フォルダ再帰走査、標準入力、終了コード、回帰テスト、サニタイズ API。
