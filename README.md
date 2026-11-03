# Fortress Security Ultimate

**WordPress・PHPの環境診断と、機密情報を最小化した開発者ログを備えるセキュリティ基盤。**

現在のバージョンは **1.0.0-dev.2 / Phase 1 / Pre-release** です。日本語の管理画面、読み取り専用診断、非公開JSONLログ、診断ZIP、設定復元・セーフモードを実装しています。隔離した検証環境で利用してください。

[ソースコード](https://github.com/crevice0308/Fortress-Security-Ultimate) · [Actions](https://github.com/crevice0308/Fortress-Security-Ultimate/actions) · [Releases](https://github.com/crevice0308/Fortress-Security-Ultimate/releases) · [検証記録](docs/verification.md) · [セキュリティ方針](SECURITY.md)

## 実装状況

| 機能 | Phase 1 の状態 |
| --- | --- |
| 日本語管理ダッシュボード | 実装済み。環境診断、設定、ログ出力、未実装機能の状態を表示 |
| WordPress・PHP環境診断 | 読み取り専用。バージョン、HTTPS、公開設定、権限、拡張などを点検 |
| 構造化ログ | UTCの1時間単位のJSONL。レベル・カテゴリーを設定可能 |
| ログの保護・整理 | 公開領域外へ保存。秘密情報を除外し、保持対象期間・容量・レコード長を制限 |
| 診断ZIPの取得 | 1 / 24 / 168時間。管理者権限とnonceを検証し、ログを再検査して出力 |
| 設定の復元 | 直前の設定を1世代保持し、管理画面から復元 |
| 管理画面外からの復旧 | `FSU_SAFE_MODE` とプラグインフォルダー名変更による復旧経路 |
| 開発・検証ツール | PHPUnit、PHPStan、WPCS、依存監査、Actions、配布ZIP生成 |
| WAF・攻撃遮断・レート制限 | **未実装**。Phase 2 |
| コア整合性・既知脆弱性・改ざん監視 | **未実装**。Phase 2・3 |
| Cloudflare・ルール自動更新・通知 | **未実装**。Phase 3 |
| Stripe・ライセンス・更新配信 | **未実装**。Phase 4。課金・外部API通信なし |

診断の合格は、その設定項目の確認結果です。攻撃防御や侵害がないことを保証する判定ではありません。Phase 1をWAFとして運用しないでください。PHP本体・OS・Webサーバーの脆弱性をプラグインだけで修正する機能もありません。

## 1.0.0-dev.2 の変更

ユーザー指定の修正版番号へ表示・パッケージ版を揃える更新です。機能と修正内容は公開済み `1.0.0-dev.1` と同じで、新しい不具合修正や追加監査を意味しません。旧タグ・配布物を維持し、新しいコミットのCI成功後に別のPre-releaseとして公開します。

## 1.0.0-dev.1 から引き継ぐ修正

再監査で確認した、診断ZIPと配布生成の不具合を修正する更新です。

- 期限切れZIP・ログの整理前に空き容量を判定し、出力できなくなる問題を修正。
- PHP出力バッファー内の文字列や終了処理の追加出力が、診断ZIPを破損させる問題を修正。
- ビルド出力のシンボリックリンク、Windowsで危険になるアーカイブ内パス、検証失敗時の配布物混在を対策。

これらは再現を確認した信頼性・ビルド整合性の修正です。未認証の遠隔悪用やCVEを確認したという報告ではありません。旧 `v1.0.0-dev` のタグ・配布物は上書きせず、新しいPre-releaseとして管理します。

## ZIPからインストール

1. [Releases](https://github.com/crevice0308/Fortress-Security-Ultimate/releases) で **v1.0.0-dev.2** の公開を確認し、Assetsの **`fortress-security-ultimate-1.0.0-dev.2.zip`** を取得します。ソース用の `-source.zip` やGitHub自動生成のSource code ZIPはインストール用ではありません。
2. WordPressの「プラグイン → 新規追加 → プラグインのアップロード」からZIPを選択します。
3. 有効化し、管理メニューの「Fortress Security」を開きます。
4. 環境診断、ログ保存先の状態、設定保存、ZIP取得を確認します。

配布前に手元で検証する場合は、後述のビルド手順で同じインストール用ZIPを生成できます。Phase 1はシングルサイト専用で、マルチサイトでの有効化を拒否します。

ログを継続保持する場合は、WordPressとWebサーバーの公開ディレクトリの外へ専用フォルダーを用意し、`wp-config.php` のWordPress読込より前へ追加してください。

```php
// 実環境に合わせた、Web公開領域外の専用パス。
define( 'FSU_PRIVATE_DIR', '/srv/private/fortress-security-ultimate' );
```

省略時はサイト別のシステム一時領域を使います。一時領域の清掃によってログが予定より早く消える場合があります。ディレクトリ0700・ファイル0600を使用し、公開領域内の保存先やシンボリックリンクは拒否します。

詳しくは [インストール・復旧手順](docs/installation.md) を参照してください。

## ログの仕様と上限

| 項目 | 動作 |
| --- | --- |
| 形式・分割 | JSONL、UTCの1時間単位 |
| 保持対象 | 直近168時間。削除は書込・Cron実行時 |
| 時間ファイルの上限 | 8 MiB。到達後、その時間の追加記録を停止 |
| 総容量の初期上限 | 500 MiB（524,288,000 bytes）。必要に応じて古いログを整理 |
| ZIPの出力範囲 | 直近1 / 24 / 168時間 |
| ZIPの内容上限 | 再検査済みJSONLが最大16 MiB。打切りは `manifest.truncated` へ記録 |
| ZIPの一時保護 | 作成後15分間は容量整理による削除から保護。取得後は削除 |

Cookie、パスワード、APIトークン、ライセンスキー、IP、メール、URL、要求本文、エラーメッセージ全文、絶対パスは記録しません。固定イベントと許可された数値・真偽値・バージョン情報だけを保存し、ZIP出力時にも再検査します。

通常のPHP警告はFSU内で発生したものを対象とします。既存のPHPエラーハンドラーがある場合はそのまま維持し、FSUによる通常警告の収集は行いません。終了時の致命的エラーメタデータと `WP_Error` は別に収集します。性能イベントは詳細ログ・performanceカテゴリーが有効、セーフモードが無効の場合のみ記録します。

アクセスのないサイトでWP-Cronが動かない間やセーフモード中は、期限超過データの削除が遅れる場合があります。システムCronから、適切なOSユーザーとWordPressパスで次を定期実行できます。

```sh
wp cron event run fsu_prune_logs --path=/absolute/path/to/wordpress
```

容量・同時実行・ディスク状態によって記録が欠ける場合があります。ログは全要求の完全な履歴ではありません。[ログ仕様](docs/logging.md) に制約をまとめています。

## 検証済み環境とCI対象

| 区分 | 環境・状態 |
| --- | --- |
| 初回開発版のローカル確認 | PHP 8.3.6（ディストリビューション版）・MariaDB 10.11.14・WordPress 7.1.4 |
| 初回開発版の実WordPress確認 | 有効化・管理画面・診断・設定・復旧・ZIPのスモーク、HTTP 200、nonce不正時403、ZIPメタデータ |
| CI設定上の対象 | PHP 8.2 / 8.3 / 8.4 / 8.5 × WordPress 7.0.8 / 7.1.4 |
| 初回開発版 `1.0.0-dev` のCI記録 | PHP品質4件・WordPress互換性8件が成功。[過去の実行記録](https://github.com/crevice0308/Fortress-Security-Ultimate/actions/runs/41604028704) |
| 今回の `1.0.0-dev.2` | バージョン表記を更新。新コミットのCI結果は検証記録へ記載し、過去の実行と区別する |
| ブラウザー表示 | モバイル用CSSは実装。実ブラウザーでの描画確認は未完了 |

PHPUnit、PHPStan、WordPress Coding Standards、依存監査、配布テストの件数・結果と監査での修正内容は [検証記録](docs/verification.md) を参照してください。CI設定の存在を、全環境での合格として扱いません。

対応方針は2026年11月3日時点の [PHP公式サポート期間](https://www.php.net/supported-versions.php)、[WordPressリリース一覧](https://wordpress.org/download/releases/)、[PHP互換性表](https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/) に基づきます。PHP 8.2の公式セキュリティサポート終了前に、最低対応版を再評価します。

## 開発・配布ZIPの生成

```sh
git clone https://github.com/crevice0308/Fortress-Security-Ultimate.git
cd Fortress-Security-Ultimate
composer install
composer check
python3 scripts/package.py
```

個別に実行する場合は次を使用します。

```sh
composer lint
composer test
composer stan
composer cs
composer audit:dependencies
python3 scripts/test_package.py
```

`dist/` にインストール用ZIP、`-source.zip`、`SHA256SUMS`、`package-report.json` を生成します。`--output /absolute/path` で出力先を変更できます。配布物は許可されたファイルだけで構成し、`vendor`、テスト、認証情報をインストール用ZIPへ含めません。

`build-info.json` には版、devチャネル、Gitコミット、未コミット変更の有無、ビルド基準時刻、`stable: false` を収録します。ビルドスクリプトは開発版の版形式のみを許可し、RC・Stableを生成しません。開発依存の脆弱性監査には外部への接続が必要です。

## 公開・ライセンス

ソースコードは [公開GitHubリポジトリ](https://github.com/crevice0308/Fortress-Security-Ultimate) で管理します。Phase 1は開発版Pre-releaseとして公開する対象です。**Stable認定・本番決済・商用販売は行っていません。** 公開する成果物とレビュー状況はReleases・Pull requests・Actionsで確認してください。

ソースコードは [GPL-2.0-or-later](LICENSE) です。将来のサブスクリプションは更新配信・サポート・サービス認証の契約として、コードのGPL上の権利とは別に扱います。予定価格は月額1,890円・年額18,900円（税込）、最大10サイト、機能差なしです。現在は決済機能自体がありません。

## 開発資料

- [開発者ガイド](docs/development.md)
- [アーキテクチャ](docs/architecture.md)
- [インストール・復旧](docs/installation.md)
- [ログ仕様](docs/logging.md)
- [将来の販売・ライセンス設計](docs/licensing.md)
- [将来API仕様](docs/api.md)
- [開発計画](docs/roadmap.md)
- [開発版リリースノート](docs/release-notes.md)
- [GitHub運用](docs/github-setup.md)
- [セキュリティ方針](SECURITY.md)
