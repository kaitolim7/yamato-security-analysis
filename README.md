# Yamato Security Analysis

KADAI INFOのCloudflare WorkersログをAPI経由で取得し、Pythonで整形・保存してiwatobiで解析するプロジェクトです。

## 発表資料

- [最終版PowerPoint](presentation/yamato_style_presentation.pptx)

## コード

- [使い方・設定・制約](code/README.md)
- `code/bridge.py`: API取得、秘密情報の除去、送信元の仮名化、SQLite保存、形式変換、iwatobi実行
- `code/daily.py`: 日次取得・解析と中断時の再開
- `code/check_iwatobi.py`: iwatobiの入力互換性を検証
- `code/tests/`: 外部APIと解析プロセスを差し替える単体テスト
- `code/fixtures/`: 実トラフィックを含まない合成サンプル

## ローカルでの確認

Python 3.10以降を使用します。Pythonコードは標準ライブラリで動作します。

```powershell
cd code
py -3 -m unittest discover -s tests -v
py -3 test_local.py
```

## 実ログの取得・解析

[iwatobi公式リリース](https://github.com/Yamato-Security/iwatobi/releases)からOSに合う配布物を展開してください。iwatobi本体と同梱ルールはこのリポジトリには含めていません。

```powershell
cd code
py -3 bridge.py setup
py -3 daily.py --prompt-secrets --iwatobi "C:\path\to\iwatobi.exe"
```

Cloudflare Account IDはローカルで設定し、APIトークンとHMAC鍵は実行時に非表示入力します。繰り返し実行する場合は同じHMAC鍵を使用してください。認証情報、ローカル設定、実ログ、データベース、実際の解析結果は公開対象に含めていません。

## 検証の範囲

正常終了は、ログの取り込みと解析処理が完了したことを示します。検知0件でも、攻撃がなかったことや検知精度は保証できません。同梱ルールの多くはPHP・Apache・Linux向けで、WorkersのHTTPログでは必要な項目がそろわないものがあります。

この変換器はクエリ文字列や本文を保存しないため、それらの内容に依存する攻撃はこの出力では検知できません。Cloudflare側のサンプリング・保持期間・記録対象によっても取得範囲が制限されます。攻撃検知の評価には、隔離環境の正常通信・攻撃ログとサイト向けルールを用いた検証が必要です。
