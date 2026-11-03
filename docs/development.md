# 開発者ガイド

## ローカル検証

```sh
composer install
composer lint
composer test
composer stan
composer cs
composer audit:dependencies
python3 scripts/test_package.py
```

PHPUnitは純粋な診断器・ログ・管理操作の境界を検証します。WordPressスタブを使う単体テストは、実WordPress・DB・HTTPでの動作確認を置き換えません。実WordPressのスモークテストとPHP/WPマトリクスの結果は別に記録します。外部依存を取得できない環境では、未実行のPHPUnit・解析を成功扱いにせず、利用可能な検証を実施します。

`composer lint` はPHP構文、`composer stan` はPHPStan、`composer cs` はWordPress Coding Standardsの検査です。PSR-4による名前空間・クラスファイル構成のための規約調整は設定へ明記します。セキュリティ関連の検査を一括無効化して合格にしません。`composer audit:dependencies` はロックされた依存の既知脆弱性を点検します。

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

生成物はインストール用 `fortress-security-ultimate-1.0.0-dev.2.zip`、ソース用 `fortress-security-ultimate-1.0.0-dev.2-source.zip`、`SHA256SUMS`、`package-report.json` です。

収録ファイルの事前検証、出力先のシンボリックリンク検査、Windowsでも安全なアーカイブ内パス検証を行います。4成果物を一時領域へ生成・照合した後に出力へ反映することで、ソース検証の失敗による新旧配布物の混在を防ぎます。

許可リストに含まれるファイルのみを格納し、`.git`、`vendor`、ログ、秘密鍵、環境設定、生成済みZIP、Pythonキャッシュなどを配布へ含めません。シンボリックリンクと危険なアーカイブパスを拒否し、ZIPのCRCと各ファイルのSHA-256を検証します。単純な秘密値検出も行いますが、レビューとシークレット管理の代わりにはしません。

`build-info.json` には製品、版、チャネル、Gitコミット、未コミット変更の有無、再現用ビルド時刻、`stable: false` を埋め込みます。現スクリプトは `1.0.0-dev` と `1.0.0-dev.1` のような連番の開発版を許可します。RC・Stableを配布する工程では、対応する品質ゲートを実装してから制限を変更します。

## GitHub・Pre-release

現在の公開リポジトリは[crevice0308/Fortress-Security-Ultimate](https://github.com/crevice0308/Fortress-Security-Ultimate)です。変更を作業ブランチとPRで確認し、品質・互換性チェックを通してから反映します。

CIの `phase1-prerelease` ジョブは、このリポジトリのmainへのpushかつコミットメッセージに`[publish phase1]`がある場合だけ動作します。品質・WordPress互換性ジョブの成功後に、対象コミットの版からタグ名を決め、現在は `v1.0.0-dev.2` を公開対象とします。Draft Releaseへ4成果物を添付し、名前・状態・サイズ・SHA-256を照合してからPre-releaseとして公開します。既存の `v1.0.0-dev`・`v1.0.0-dev.1` を含むタグ・Release・配布物は上書きせず、Stable版や本番決済を公開しません。

CI設定が存在することとActionsが成功したことを分け、実行URL・結果を検証記録へ残します。再現・手動操作の詳細は[GitHub手順](github-setup.md)を参照してください。

## 1.0.0-dev.1 のZIP回帰確認

期限切れZIP・ログが残った状態でのエクスポート、保持中ログの保存、出力バッファー内の文字列、解除できないバッファー・圧縮状態、終了時の追加出力を確認します。配布生成では出力先シンボリックリンク、Windows形式の危険パス、後半でのソース検証失敗、初回開発版との版の違いを回帰試験に含めます。実行結果は検証記録に残し、過去のCIを今回の合格扱いにしません。

出力整備は認可後かつZIP生成前に行います。削除可能・消去可能なバッファーはフラッシュせず破棄し、非互換状態は拒否します。ZIP転送後は当該要求でWordPressの通常フラッシュを抑止して追加文字列を破棄しますが、ほかの終了コールバックは停止しません。SAPIへの直接書き込み、意図的な出力制御変更、プロセス強制終了は保護の保証範囲外です。

## 1.0.0-dev.2 の版表記

現行の生成物は `1.0.0-dev.2` です。機能は `1.0.0-dev.1` と同じで、プラグイン表示・配布ZIP・ビルド情報・文書の版を揃えます。新しいコミットのCIを通して別のPre-releaseを公開し、旧版のタグ・添付物は変更しません。
