# 開発者ガイド

## ローカル検証

```sh
composer install
composer lint
composer test
composer stan
composer cs
composer audit
python3 scripts/test_package.py
```

PHPUnitは純粋な診断器・ログ・管理操作の境界を検証します。WordPressスタブを使う単体テストは、実WordPress・DB・HTTPでの動作確認を置き換えません。実WordPressのスモークテストとPHP/WPマトリクスの結果は別に記録します。外部依存を取得できない環境では、未実行のPHPUnit・解析を成功扱いにせず、利用可能な検証を実施します。

`composer lint` はPHP構文、`composer stan` はPHPStan、`composer cs` はWordPress Coding Standardsの検査です。PSR-4による名前空間・クラスファイル構成のための規約調整は設定へ明記します。セキュリティ関連の検査を一括無効化して合格にしません。`composer audit` はロックされた依存の既知脆弱性を点検します。

## 設定

WordPress option `fsu_settings` に `debug`、`capture_errors`、`categories` のみを保存します。入力は許可値へ絞り、認識しないキーを保存しません。カテゴリーのうち `internal` / `admin` / `system` は基盤イベントのため残します。

設定変更前の値を `fsu_settings_previous` に1世代保持します。復元はそのスナップショットとの入れ替えであり、任意JSONファイルのアップロードではありません。秘密鍵やライセンスキーをこの設定へ追加しないでください。

`FSU_SAFE_MODE` はファイルシステムで設定する緊急スイッチです。Phase 1ではPHP・WordPressのエラー取得と定期整理を抑止するため、長期間の通常運用設定ではなく原因調査用として扱います。管理画面の読込、診断、設定操作を可能な範囲で維持します。

## PHP・WordPressエラーの扱い

既存のPHPエラーハンドラーがある場合は、未知の対象エラーレベルを変更しないため、そのハンドラーをそのまま維持してFSUの通常警告取得を行いません。既存ハンドラーがない場合の通常PHPエラーはFSU内で発生したものを対象とし、エラーメッセージ本文とファイルパスをログへ渡しません。終了時の致命的エラーは限定メタデータのみを記録し、WordPressのエラーイベントは固定コードへ変換します。捕捉できる範囲にはPHPの実行段階・終了状態・ディスク状態による制約があります。

詳細ログ・performanceカテゴリーが有効でセーフモードが無効の場合は、要求終了時に `performance.request` のDebugイベントを記録します。FSU起動からの経過時間とピークメモリーだけを含み、URLや本文は保存しません。

## ビルド

```sh
python3 scripts/package.py
python3 scripts/package.py --output /absolute/output/path
```

生成物はインストール用 `fortress-security-ultimate-1.0.0-dev.zip`、ソース用 `fortress-security-ultimate-1.0.0-dev-source.zip`、`SHA256SUMS`、`package-report.json` です。

許可リストに含まれるファイルのみを格納し、`.git`、`vendor`、ログ、秘密鍵、環境設定、生成済みZIP、Pythonキャッシュなどを配布へ含めません。シンボリックリンクと危険なアーカイブパスを拒否し、ZIPのCRCと各ファイルのSHA-256を検証します。単純な秘密値検出も行いますが、レビューとシークレット管理の代わりにはしません。

`build-info.json` には製品、版、チャネル、Gitコミット、未コミット変更の有無、再現用ビルド時刻、`stable: false` を埋め込みます。現スクリプトは `1.0.0-dev` のみを許可します。RC・Stableを配布する工程では、対応する品質ゲートを実装してから制限を変更します。

## GitHub・Pre-release

現在の公開リポジトリは[crevice0308/Fortress-Security-Ultimate](https://github.com/crevice0308/Fortress-Security-Ultimate)です。変更を作業ブランチとPRで確認し、品質・互換性チェックを通してから反映します。

CIの`release`ジョブは、このリポジトリのmainへのpushかつコミットメッセージに`[publish phase1]`がある場合だけ動作します。品質・WordPress互換性ジョブの成功後に、同じコミットから`v1.0.0-dev`をPre-releaseとして作成します。既存タグ・Release・配布物を上書きせず、Stable版や本番決済を公開しません。

CI設定が存在することとActionsが成功したことを分け、実行URL・結果を検証記録へ残します。再現・手動操作の詳細は[GitHub手順](github-setup.md)を参照してください。
