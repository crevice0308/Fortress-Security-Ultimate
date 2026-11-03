=== Fortress Security Ultimate ===
Contributors: crevice0308
Tags: security, audit, logs
Requires at least: 7.0
Requires PHP: 8.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress・PHP環境診断と安全な構造化ログの基盤。1.0.0-dev・Phase 1 Pre-release。

== Description ==
開発版Pre-releaseです。日本語ダッシュボード、読み取り専用診断、秘密情報を除外するJSONLログ、管理者向け診断ZIP、設定復元・セーフモードを提供します。
WAF、攻撃遮断、コア整合性、既知脆弱性検出、改ざん監視、Cloudflare、Stripe、ライセンス認証、自動更新は未実装です。
Stable・本番防御・商用販売版ではありません。外部サービスへの通信や課金は行いません。

公開ソース・開発版配布:
https://github.com/crevice0308/Fortress-Security-Ultimate

== Installation ==
ReleaseのAssetsからfortress-security-ultimate-1.0.0-dev.zipを取得し、隔離WordPress環境のプラグイン画面へアップロードして有効化します。
-source.zipやGitHub自動生成のSource code ZIPは開発用です。
必要に応じてwp-config.phpのFSU_PRIVATE_DIRでWeb公開領域外の専用保存先を指定してください。
詳しい手順は公開リポジトリのREADME.mdと開発資料を参照してください。
マルチサイトはPhase 1対象外です。

== Logging limits ==
UTCの1時間単位でJSONLを保存します。1時間8 MiB、総量の初期上限500 MiBです。
保持対象は168時間で、期限超過データの削除は書込・Cron実行時です。WP-Cronが動かない間やセーフモード中は削除が遅れます。
ZIPのJSONL内容は最大16 MiBで、打切りはmanifestへ記録します。ZIPは作成後15分間容量整理から保護し、取得後に削除します。
ログは全イベントを損失なく記録するものではありません。

== Changelog ==
= 1.0.0-dev =
Phase 1基盤の初回Pre-release。診断・非公開ログ・管理画面・復旧・開発検証ツールを追加。
実行済みテスト・監査修正・未検証範囲はdocs/verification.mdを参照してください。
