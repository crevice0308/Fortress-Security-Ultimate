# Fortress Security Ultimate v1.0.0-dev — Phase 1 Pre-release

WordPress・PHPの診断、ログ、管理画面を提供する初回開発版です。公開区分は **Pre-release** で、Stableや商用販売版ではありません。

## 追加した機能

- 日本語管理ダッシュボードと、設定・ログ・実装状態の表示。
- PHP・WordPressの設定、HTTPS、権限、拡張などの読み取り専用診断。
- Web公開領域外へ保存する時間単位のJSONLログ。
- 固定イベントと型付きメタデータの許可リスト、ZIP出力時の再検査。
- 管理者権限とnonceを確認した1 / 24 / 168時間のZIP取得。
- 設定の1世代復元、ファイル設定によるセーフモード、管理画面外の復旧手順。
- 条件付き性能イベント、既存PHPエラーハンドラーを維持するエラー収集。
- PHPUnit、PHPStan、WordPress Coding Standards、依存監査、Actions、配布ZIP生成。

## 検証

PHP 8.3.6（ディストリビューション版）・MariaDB 10.11.14・WordPress 7.1.4で、単体テスト、実WordPressスモーク、HTTP管理画面とZIP取得、nonce不正時403、ZIPの版・チャネル・Gitコミット・環境情報を確認しました。静的解析、コーディング規約、依存監査、配布テストも実施しています。監査での修正と最終的なテスト件数・結果は [検証記録](verification.md) を参照してください。

[GitHub CI](https://github.com/crevice0308/Fortress-Security-Ultimate/actions/runs/41604028704)でPHP 8.2 / 8.3 / 8.4 / 8.5の品質チェック4件とWordPress 7.0.8 / 7.1.4の互換性8組み合わせがすべて成功しました。PHPUnit37件・232アサーション、配布テスト13件を実行しています。モバイル用CSSは実装済みですが、ブラウザー描画検証は未完了です。

## 導入・再現手順

公開されたReleaseのAssetsから `fortress-security-ultimate-1.0.0-dev.zip` を取得し、隔離WordPressのプラグイン画面からアップロードします。`-source.zip` とGitHub自動生成ZIPは開発・参照用です。

ソースから生成する場合は、PHPとComposerを用意して次を実行します。

```sh
git clone https://github.com/crevice0308/Fortress-Security-Ultimate.git
cd Fortress-Security-Ultimate
composer install
composer check
python3 scripts/package.py
```

`dist/` へインストール用ZIP、ソースZIP、`SHA256SUMS`、`package-report.json` を生成します。検証環境固有の手順とチェック結果は検証記録を参照してください。

## 既知の制約

- ログは1時間8 MiB、総量初期上限500 MiBです。上限・同時処理・ディスク状態により記録が欠ける場合があります。
- 保持対象は168時間です。削除は書き込み・Cron実行時のため、アクセスがない場合やセーフモード中は期限超過データが残る場合があります。
- ZIP内の再検査済みJSONLは最大16 MiBです。打切りは `manifest.truncated` に記録します。作成後15分間は容量整理から保護し、取得後に削除します。
- システム一時領域の保存先はホスティングの清掃で早期削除される場合があります。専用の `FSU_PRIVATE_DIR` を推奨します。
- 既存のPHPエラーハンドラーがある場合、FSUの通常警告取得は行いません。致命的エラーのメタデータとWordPressエラーは別に扱います。
- マルチサイトは未対応で、有効化を拒否します。全診断文の英語翻訳と実ブラウザーでの画面検証は未完了です。

## 今後の工程

WAF・攻撃遮断、コア整合性、既知脆弱性の照合、ファイル改ざん監視、Cloudflare、ルール更新、Stripe、ライセンス、自動アップデートは未実装です。Phase 1をこれらの保護機能として利用することはできません。

本番決済の有効化、正式販売、Stable公開は今回に含めません。将来の正式名称「Fortress Security Ultimate v1.0.0 Stable」は、品質ゲートと承認を満たした正式版に使用します。

## 公開前レビューによる修正

ZIPの読出し・後始末での警告による応答破損、7日境界ログの繰返し再解析、小容量ZIP予約時の入力消失を修正しました。通常要求では部分ログの全行解析を行わず、毎時Cronへ移しています。書込みだけで厳密な行単位の期限削除が常時完了する設計ではありません。ZIPでは行時刻を検査します。37件のPHPUnit、13件の配布テスト、PHPStan・WPCS・依存監査をローカルで実行し、公開はGitHub全CI成功後に限ります。
