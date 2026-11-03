# GitHub運用

公開リポジトリ [crevice0308/Fortress-Security-Ultimate](https://github.com/crevice0308/Fortress-Security-Ultimate) を使用します。Phase 1ソースと開発版Pre-releaseの公開は承認済みです。Stable公開・本番決済・販売開始は対象外です。

## 開発の流れ

1. リモートの最新状態と既存ブランチ・PRを確認する。
2. 作業ブランチで修正・回帰試験・ドキュメントを管理する。
3. ローカル検証とセキュリティ・不具合レビューを行い、シークレットの混入を確認する。
4. レビュー可能なPRと実際のCI結果を記録する。
5. 品質・互換性チェック成功後に、対象コミットから開発版を公開する。

現在の更新は `1.0.0-dev.1`、予定タグは `v1.0.0-dev.1` です。初回の `v1.0.0-dev` は履歴として維持し、既存タグ・Release・添付ファイルを上書きしません。リモート履歴の強制上書きやリポジトリの再作成も行いません。

## 開発版の配布

```sh
composer install
composer check
python3 scripts/package.py
```

Releaseへ添付する4ファイルは次のとおりです。

- `fortress-security-ultimate-1.0.0-dev.1.zip`
- `fortress-security-ultimate-1.0.0-dev.1-source.zip`
- `SHA256SUMS`
- `package-report.json`

ローカル生成では、出力パスのシンボリックリンクと危険なアーカイブ内パスを拒否します。収録ファイルを事前検証し、4成果物を一時領域へ生成・照合してから出力先へ反映します。ソース検証の失敗で新旧の配布ファイルが混在する状態を防ぎます。

## 公開ジョブ

mainへのpushかつコミットメッセージに `[publish phase1]` がある場合のみ、品質・WordPress互換性ジョブの成功後に公開ジョブを実行します。版は対象コミットの開発版情報から取得し、RC・Stableは扱いません。

1. 作業ツリーがクリーンで、収録バイトとファイル名が対象コミットに一致することを確認する。
2. 同じタグ・Releaseが存在しないことと、対象コミットを確認する。
3. 新しいタグとDraft Releaseを作り、4成果物をアップロードする。
4. 添付ファイル名、完了状態、サイズ、SHA-256をローカル成果物と照合する。
5. 照合成功後にDraftを解除し、Pre-releaseとして公開する。Latest Stableには指定しない。

途中失敗時は、部分的なタグやDraftを既存オブジェクトとして残し、自動上書きせず状態を調べます。公開実施前に、予定URLだけを根拠として公開済みと記載しません。

- [ソース](https://github.com/crevice0308/Fortress-Security-Ultimate)
- [Pull requests](https://github.com/crevice0308/Fortress-Security-Ultimate/pulls)
- [Actions](https://github.com/crevice0308/Fortress-Security-Ultimate/actions)
- [Releases](https://github.com/crevice0308/Fortress-Security-Ultimate/releases)

## 記録

修正・ローカル実行結果・環境制約は `docs/verification.md`、変更履歴は `CHANGELOG.md` に記録します。過去のCI成功は、その版の記録として保持します。新しい版の結果は新しいActions実行が完了してから反映します。実在するPR番号・コミットSHA・実行URLを確認して報告します。
