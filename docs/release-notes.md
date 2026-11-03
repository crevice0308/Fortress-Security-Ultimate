# Fortress Security Ultimate v1.0.0-dev.2 — Phase 1 Pre-release

ユーザー指定の修正版番号へ、プラグイン表示・パッケージ・文書の版を揃える更新です。機能・修正内容は公開済み `1.0.0-dev.1` と同じで、新たな不具合修正や追加監査を意味しません。旧 `v1.0.0-dev`・`v1.0.0-dev.1` のタグと配布物を維持し、新しいコミットのCI成功後に別のPre-releaseとして公開します。Stableや商用販売版ではありません。

## 1.0.0-dev.1 から引き継ぐ修正

| 対象 | 確認した問題 | 修正 |
| --- | --- | --- |
| 診断ZIPの容量判定 | 期限切れZIP・ログが残っていると、整理前の容量判定で出力を拒否 | 同じ保管ロック内で期限切れデータを先に整理してから容量を判定 |
| ZIPダウンロード | `headers_sent()` がfalseでも出力バッファーに文字列が残り、ZIPの前後へ混入 | ヘッダー前のバッファー・圧縮状態を確認。安全に処理できない状態では中止し、ZIP取得要求での追加出力を抑止 |
| 配布ZIP生成 | 出力シンボリックリンク、Windowsで危険になるメンバー名、検証失敗時の配布物混在 | 出力パス・アーカイブ名を検証し、4成果物を事前検証してから一時生成 |
| 開発版の公開 | 初回開発版だけを前提とする版と公開手順 | `1.0.0-dev.1` に対応。Draftへ添付して4ファイルを照合した後にPre-releaseとして公開 |

再現を確認した信頼性・ビルド整合性の修正です。未認証の遠隔悪用やCVEを確認したという報告ではありません。

## 検証の記録

`1.0.0-dev.1` の修正に対する回帰試験と、版表記を変更した `1.0.0-dev.2` のCI結果は [検証記録](verification.md) に記載します。過去の結果と今回の更新を区別します。

初回開発版 `1.0.0-dev` では、PHP 8.3.6・MariaDB 10.11.14・WordPress 7.1.4でローカル検証を行い、[過去のCI](https://github.com/crevice0308/Fortress-Security-Ultimate/actions/runs/41604028704) でPHP品質4件・WordPress互換性8組み合わせが成功しています。この記録を `1.0.0-dev.2` のCI合格結果として扱いません。最新の実行は [Actions](https://github.com/crevice0308/Fortress-Security-Ultimate/actions) を確認してください。

CI対象はPHP 8.2 / 8.3 / 8.4 / 8.5 × WordPress 7.0.8 / 7.1.4です。実ブラウザーでの描画検証は未完了です。

## 導入・再現手順

Releaseの `v1.0.0-dev.2` が公開されたら、Assetsの **`fortress-security-ultimate-1.0.0-dev.2.zip`** を隔離WordPressのプラグイン画面へアップロードします。`-source.zip` とGitHub自動生成のSource code ZIPは開発・参照用です。

ソースから生成する場合は、対象コミットを取得して次を実行します。

```sh
git clone https://github.com/crevice0308/Fortress-Security-Ultimate.git
cd Fortress-Security-Ultimate
composer install
composer check
python3 scripts/package.py
```

`dist/` へインストール用ZIP、ソースZIP、`SHA256SUMS`、`package-report.json` を生成します。Release作成時は、テストしたコミットとクリーンな作業ツリーを照合します。

## 継続する制約

- ログは1時間8 MiB、総量初期上限500 MiB。容量・同時処理・ディスク状態により記録が欠ける場合があります。
- 保持対象は168時間。時間ファイルの整理は書き込み・Cron実行時、境界ファイルの行単位整理は毎時Cron実行時です。無アクセス・Cron停止・セーフモードで削除が遅れる場合があります。
- ZIP内JSONLは最大16 MiB。打切りは `manifest.truncated` に記録します。作成後15分間は容量整理から保護し、取得後に削除します。
- ZIP生成用の空き容量が不足し、保持中ログを削除する必要がある場合は出力を中止します。ZIP作成のために現行入力を消去しません。
- 公開領域外の `FSU_PRIVATE_DIR` を推奨します。システム一時領域はホスティングの清掃で早期削除される場合があります。
- 既存PHPエラーハンドラーがある場合、FSUの通常警告取得は行いません。致命的エラーメタデータとWordPressエラーは別に扱います。
- マルチサイト、全診断文の英語翻訳、実ブラウザー描画確認は未対応・未完了です。

## 製品の範囲

日本語管理画面、読み取り専用環境診断、非公開ログ、診断ZIP、設定復元、セーフモードを提供します。WAF・攻撃遮断、コア整合性、既知脆弱性の照合、ファイル改ざん監視、Cloudflare、ルール更新、Stripe、ライセンス、自動アップデートは未実装です。

本番決済、正式販売、Stable公開は今回に含めません。
