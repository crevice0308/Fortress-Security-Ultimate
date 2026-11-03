# GitHub運用

ユーザーが作成した公開リポジトリ [crevice0308/Fortress-Security-Ultimate](https://github.com/crevice0308/Fortress-Security-Ultimate) を使用します。Phase 1ソースと開発版Pre-releaseの公開は承認済みです。これはStable公開・本番決済・販売開始の承認を意味しません。

## 開発の流れ

1. リモートの最新状態と既存ブランチ・PRを確認する。
2. 作業ブランチ `feat/phase-1-prerelease` でソース、テスト、ドキュメントを管理する。
3. シークレットを含めず、ローカル検証とセキュリティ・不具合レビューを実施する。
4. レビュー可能なPRを作成し、実際のCI結果と未検証範囲を記録する。
5. 開発版を公開するときは `v1.0.0-dev` のPre-releaseを使う。

リモート履歴の強制上書きや、公開リポジトリの再作成は行いません。PR番号・コミットSHA・Actions結果は、実在する値を確認して報告します。

## 開発版の配布

```sh
composer install
composer check
python3 scripts/package.py
```

Releaseへ添付する対象は、インストール用 `fortress-security-ultimate-1.0.0-dev.zip`、ソース用 `fortress-security-ultimate-1.0.0-dev-source.zip`、`SHA256SUMS`、`package-report.json` です。公開前にアーカイブの内容・版・コミット・秘密情報の混入を確認します。

`v1.0.0-dev` はPre-releaseとして扱い、Latest Stableに指定しません。リリース本文には実装範囲、検証結果、未実装機能、容量制限、対応環境を記載します。公開実施前に、予定URLだけを根拠として公開済みと記載しません。

- [ソース](https://github.com/crevice0308/Fortress-Security-Ultimate)
- [Pull requests](https://github.com/crevice0308/Fortress-Security-Ultimate/pulls)
- [Actions](https://github.com/crevice0308/Fortress-Security-Ultimate/actions)
- [Releases](https://github.com/crevice0308/Fortress-Security-Ultimate/releases)

## 記録

ローカルの実行結果と環境制約は `docs/verification.md`、変更内容は `CHANGELOG.md` に残します。CIマトリクス全体の結果は、Actionsが実際に完了してから反映します。ブラウザー描画、正式販売、外部API、本番決済など未実施の項目を、CIの合格とまとめないでください。
