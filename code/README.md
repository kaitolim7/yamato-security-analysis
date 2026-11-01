# KADAI INFO Cloudflare Log Bridge — Python版

Cloudflare Workers Observability REST APIからログを取得し、匿名化・重複排除した上でiwatobi向けファイルを作成します。

Python 3.10以降の標準ライブラリだけを使います。pip、Rust、C++ Build Tools、PowerShellスクリプトの実行許可は不要です。Cloudflare設定変更・デプロイ・攻撃リクエスト送信は行いません。

## 推奨運用: 取得も解析も1日1回

```powershell
py -3 daily.py --prompt-secrets --iwatobi "C:\Users\植村海翔\Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe"
```

APIトークンと以前と同じHMAC鍵を入力します。初回は直近24時間分（既存チェックポイントがそれ以前ならそこから）、2回目以降は前回終了時刻から今回までを回収します。`delay_seconds`で指定した直近1分は反映待ちのため次回取得します。各API照会は既存の15分窓に分け、全ページを取得してから次の窓へ進みます。日次処理中は途中の窓ごとにiwatobiを起動せず、対象期間を回収した後に1回だけ解析します。

**1日1回起動することと、APIを1回だけ呼ぶことは異なります。** 24時間分を安全に取得するため、1回の起動中に多数のAPI照会が発生します。日次処理の取得状況はSQLiteの`daily_jobs`に保存します。

毎日自動で繰り返す場合:

```powershell
py -3 daily.py --prompt-secrets --iwatobi "C:\Users\植村海翔\Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe" --repeat
```

端末とPCを起動したままにすると初回実行後、約24時間ごとに取得・解析します。起動時に秘密値を1回入力し、Ctrl+Cで停止します。成功した日次処理から24時間未満に再実行すると`not_due`となり、API取得・解析を繰り返しません。失敗した未完了処理は24時間を待たず、同じコマンドで再開できます。再開時は元の期間を固定して、成功した取得窓をやり直しません。解析だけが失敗した場合は保存済みログから再解析します。

既存の`Start-Collector.ps1`も、この日次モードへ変更しました。`-Once`で1回、それ以外は24時間ごとの繰り返しです。旧`bridge.py collect`は手動診断・短周期運用のために残していますが、日次運用では使いません。

出力は`data/daily/<取得終了日の日本時間日付>/<ジョブID-試行ID>/`です。`events.jsonl`、`access.log`、`analysis/`と、期間・件数を記録した`daily.json`を保存します。解析対象はDB全体ではなく**今回の取得期間 `[from_ms, to_ms)`**です。境界の相関検知のため次回は5分重ねます。隣接日の検知件数は重複する可能性があるため単純加算しないでください。ルールの相関時間幅が5分を超える場合、設定の`overlap_minutes`をそれ以上に増やし、`lookback_minutes`はその値より大きくしてください。

これは暦上の前日0時〜24時に固定するモードではなく、**前回から今回までの約24時間**を解析するモードです。Cloudflare側で消えたログ・未保存ログ・サンプリングで省かれたログは回収できません。PC停止が長引いた場合は保持期間内に再実行してください。Windowsタスクスケジューラへの登録や資格情報の永続保存は行っていません。

## 最初に動作確認

コマンドプロンプトまたはPowerShellで実行します。

```powershell
cd 'C:\Users\植村海翔\Documents\ChatGPT\github\kadaiinfo-log-bridge'
py -3 test_local.py
```

コマンドプロンプトでは移動コマンドを`cd /d "C:\Users\植村海翔\Documents\ChatGPT\github\kadaiinfo-log-bridge"`としてください。

単体テストとサンプル変換を実行し、成功時だけ`PASS`と出力先を表示します。合成ログを2回読み込み、2件の重複なしログを出力します。Cloudflareとの通信はありません。環境によって`py -3`の代わりに`python`を使用してください。

## Cloudflare APIから1回取得

まず対話形式でAccount IDを入力し、設定を作成できます（既存ファイルは上書きしません）。

```powershell
py -3 bridge.py setup
```

次にAPIトークンだけを非表示入力し、直近15分から最大5件を診断します。HMAC鍵はこの段階では不要です。

```powershell
py -3 bridge.py diagnose --config config.local.json --prompt-secrets
```

診断は生ログの保存・DB作成・チェックポイント更新を行いません。表示するのは件数と項目の有無です。

| status | 意味 |
|---|---|
| `api_reachable_no_events` | API応答は成功したがログは0件。取得成功とは扱わない |
| `events_received_http_fields_available` | APIからイベントを受信し、HTTP項目を確認できた |
| `events_received_adapter_or_logging_check_required` | イベントは届いたがHTTP項目が足りない。記録設定か変換器を調整する |

`worker_name_observed_events`は応答内で対象Worker名を確認できた件数、`http_events`は今回の変換でHTTPログとして出せる件数です。両方が1件以上なら終了コード0、それ以外は2です。HTTP/認証エラーは1です。`iwatobi_verified`は常にfalseで、iwatobiでの読み込み成功を意味しません。

0件の場合は対象Workerの名前、Observabilityの保存設定・サンプリング設定、直近15分にリクエストがあったかを確認してください。キャッシュや静的アセットだけの閲覧ではWorkerの実行ログが増えない場合もあります。

診断で対象WorkerのHTTPログを確認してから、以下の取得を実行します。

1. `setup`または`config.example.json`を元に`config.local.json`を作成する。
2. Account IDを設定する。Worker名は`kadaiinfo-web`。
3. 以下を実行し、非表示入力でAPIトークンとHMAC鍵を入力する。

```powershell
py -3 bridge.py collect --config config.local.json --prompt-secrets --cycles 1
```

APIトークンをコード・設定・チャット・コマンド引数に書かないでください。HMAC鍵は32文字以上で、継続取得では同じ値を使います。鍵を変更すると送信元IDが変わります。入力値は保存されません。プロセス環境変数`CF_API_TOKEN`と`CF_LOG_HMAC_KEY`での供給にも対応します。dotenvファイルは読みません。

APIトークンは対象アカウントに限定してください。公式query APIが要求する権限は`Workers Observability Write`です。プラン・保持期間・保存やサンプリング設定は実アカウントで確認してください。

APIは`$metadata.service == kadaiinfo-web`で絞ります。keys/valuesと実ログで値を検証してから継続運用します。間違ったフィルターは0件でも成功する可能性があります。

## 自動取得からiwatobi解析まで

現在の展開先を使って、一括処理を1回実行します。

```powershell
py -3 bridge.py collect --config config.local.json --prompt-secrets --cycles 1 --iwatobi "C:\Users\植村海翔\Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe"
```

APIトークンと以前と同じHMAC鍵を入力すると、取得→正規化→保存→ファイル出力→iwatobi起動→解析結果保存まで自動実行します。`--iwatobi`を省略した場合は従来どおり取得・変換までです。`--rules`で独自ルールディレクトリを指定でき、省略時はexeと同じ場所の`rules/`を使います。

5分待機して繰り返す場合:

```powershell
py -3 bridge.py collect --config config.local.json --prompt-secrets --interval-seconds 300 --cycles 0 --iwatobi "C:\Users\植村海翔\Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe"
```

端末を開いている間動き、Ctrl+Cで終了します。起動時に1回だけ秘密値を入力します。ネットワーク一時エラー、429、5xxは最大4回試行し、それでも失敗したら停止します。停止後は再実行してください。Windowsサービス・スケジュール登録は行っていません。

この短周期`collect`コマンドは従来互換用です。`Start-Collector.ps1`の既定動作は冒頭の日次モードに変更済みです。既定のexeはユーザープロファイル内の`Downloads/iwatobi-0.1.0-win-x64/`で、`-Iwatobi`引数で変更できます。

処理順:

```text
Workers API（固定時間窓・カーソルによるページ取得）
  → 許可リストによる正規化・秘密情報除去
  → SQLiteへイベントIDで重複排除保存
  → 全ページ成功後に取得時刻を記録
  → iwatobi用ログを新しいスナップショットへ出力
  → --iwatobi指定時に解析し、終了コードと件数を保存
```

初回は直近15分、次回以降は前回終了時刻から5分重ねて取得します。長い停止後は時間窓を15分以内に区切って追いつきます。5分を超える遅延到着やCloudflare保持期間を過ぎたログの完全回収は保証しません。ページ構造不明、未完了クエリ、繰り返しカーソル、API照会のサンプリング検出時には保存とチェックポイントをロールバックします。

## 出力とiwatobi入力

```text
data/iwatobi/<日時-UUID>/
├─ events.jsonl  正規化済み全イベント
├─ access.log    HTTP項目のそろったイベント
└─ analysis/     --iwatobi指定時
   ├─ detections.jsonl  検知タイムライン
   └─ analysis.json     実行結果・件数・終了コード
```

両ファイルを書き終えた後で`.partial`ディレクトリを正式名に変更します。`.partial`は入力に使わないでください。各スナップショットはDBの全保持イベントを含むため、iwatobiには1つだけ渡します。複数のスナップショットをまとめて解析すると二重計上されます。

解析件数も各スナップショット全体の結果なので、複数周期分を足し合わせないでください。現在は差分通知・検知の重複排除・保存期間の自動管理はありません。継続運転ではDBとスナップショットが増えるためディスク使用量を確認してください。

正常終了は`analysis.analysis_status: completed`、`analysis.iwatobi_exit_code: 0`で確認します。HTTPログが0行なら`skipped_no_http_events`となり解析は起動しません。検知0件は安全性の保証ではありません。

解析失敗時は`status: acquired_but_analysis_failed`を表示してループを停止します。取得済みログとDBは残し、解析の失敗内容を`analysis/analysis.json`に記録します。API取得チェックポイントは既に進んでいますが、再取得なしで保存ファイルを再解析できます（毎回新しい解析結果フォルダーへ出力）。

```powershell
py -3 bridge.py analyze --input "data/iwatobi/<日時-UUID>/access.log" --iwatobi "C:\Users\植村海翔\Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe"
```

子プロセスへAPIトークン・HMAC鍵は引き継ぎません。解析の制限時間は既定300秒で`--analysis-timeout`で変更できます。

iwatobiを直接実行する場合のコマンド:

```powershell
iwatobi dfir-timeline -f data/iwatobi/<日時-UUID>/access.log --custom-formats iwatobi-formats.yaml --log-format cloudflare-bridge -U -s -o data/timeline-001 -t jsonl,csv
```

`access.log`は時刻、`client_hash`、メソッド、パス、ステータスの5つをタブで区切ります。`iwatobi-formats.yaml`で取り込む設計です。`client_hash`をIP用の`c-ip`に偽装しません。相関ルールでは`client_hash`を指定し、不明値`-`を同一送信元として集約しないでください。

HTTPリクエスト情報のないconsoleイベントは、自由記述メッセージを取り除いてJSONLに保存し、access.logからは除外します。出力時に除外数を表示します。

## 個別コマンド

### iwatobi本体での入力検証

[公式Releases](https://github.com/Yamato-Security/iwatobi/releases)からWindows x64パッケージをダウンロードし、zip全体を展開します。`.exe`だけでなく同梱の`rules/`も必要です。変換器はPythonですが、解析本体はiwatobiの配布済み実行ファイルを使うため、Rustのビルドは不要です。

```powershell
py -3 check_iwatobi.py --input data/iwatobi/<日時-UUID>/access.log --iwatobi "C:\展開先\iwatobi-0.1.0-win-x64.exe"
```

実際の.exeファイル名とパスに置き換えてください。このスクリプトは、入力の形式検査→架空ログの既知ルール検知→実ログ全行の項目マッピング確認→同梱ルールで実ログ解析、の順に実行します。全行確認用ルールは攻撃判定ではありません。診断表示は件数だけで、生ログや検知詳細は表示しません。解析結果はローカルの`data/iwatobi-check-<UUID>/`に保存します。

実行ファイルが未導入なら`iwatobi_verified: false`を維持します。ここまでのPythonテスト成功は、iwatobi実機の検証成功を意味しません。

```powershell
py -3 bridge.py --help
py -3 bridge.py fetch --config config.local.json --prompt-secrets
py -3 bridge.py export --database data/events.sqlite --output data/manual-export-001
py -3 -m unittest discover -s tests -v
```

同じ出力先を上書きしません。SQLiteの構造は旧Rust版と同じなので、以前のDBもそのまま読み込めます。WorkerごとにDBを分けてください。

## 検証状況と制約

- Python 3.12.5で33件の単体テスト成功。日次処理では24時間分の窓分割取得、対象期間だけの出力、1回だけの解析、同日再実行のスキップ、取得中断・解析失敗からの再開、並列実行の防止を検証。API応答・iwatobi呼び出しはテスト用に差し替えています。
- 日次モードで実APIから24時間分を新規取得する実行・24時間の連続待機は、この変更後にはまだ確認していません。既存のログやチェックポイントを使うため、本番の取得状態をテスト用データで上書きしていません。
- 新しい`bridge.py analyze`から実際のiwatobi v0.1.0を起動し、既存の実ログ123行を解析。終了コード0・検知0件。結果: `data/iwatobi/20261031T083514-7ad704d446f540cca3c60935405c8c63/analysis-6dddc5f83bdb4af48852763fa89e273b/analysis.json`。
- 実APIから新規取得し、そのまま解析する一括処理と長時間の連続運転は、この変更後にはまだ実接続で確認していません。API認証情報を端末で入力し、上記`--cycles 1`から確認してください。
- テスト対象: ページ取得、429再試行、失敗時ロールバック、重複排除、匿名化、UTC変換、パストラバーサル痕跡保持、スナップショット出力。
- 2026-10-31に実Cloudflareログ取得後の`20261031T083514-7ad704d446f540cca3c60935405c8c63/access.log`をWindows版iwatobi v0.1.0で検証。架空ログの既知ルール検知、実ログ123行の全行マッピング確認、同梱ルールでの解析がすべて終了コード0で成功。同梱ルールの検知は0件。送信元不明の行は23件。
- 検証結果: `data/iwatobi-check-fb3f2c850ecc4c8a932e38b838e9d329/verification.json`。入力形式の互換性は確認済みですが、攻撃検知精度やKADAI INFO専用ルールの評価はまだ行っていません。検知0件は安全性の保証ではありません。
- 現在対応するイベント形は`$metadata.id`、整数ミリ秒またはタイムゾーン付き日時の`timestamp`、`$workers.event.request/response`または`source`内の同構造です。実レスポンスが異なる場合はアダプター調整が必要です。
- Cookie、認証ヘッダー、本文、クエリ、自由記述ログは保存しません。クエリ内のSQLi/XSSはこの出力では検知できません。URLパス自体に秘密情報がある独自ルートは別途マスクが必要です。
- WAFイベント、Workerに到達しない通信は取得対象外。Workers保存時のサンプリングや保持期間により、実トラフィック全件が取得できるとは限りません。

## 旧Rust版

`legacy-rust/`にRustソースとCargo.lockを保管しました。Python版の実行に使いません。既存の`target/`や生成データは削除していません。

## 参照仕様

- [Workers query API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/)
- [Workers Query Builder](https://developers.cloudflare.com/workers/observability/query-builder/)
- [iwatobi Custom log formats](https://github.com/Yamato-Security/iwatobi#custom-log-formats)
