# 認証基盤 migration

## 所有者

認証基盤の通常 schema migration は `postgres/auth-migrations/` が所有します。`rust-auth0-service` は migration を実行しません。旧 `uniauth` も migration 所有者ではありませんでした。

## 通常 migration

通常 migration はこのディレクトリ直下だけに置きます。

```text
postgres/auth-migrations/001_<purpose>.sql
postgres/auth-migrations/002_<purpose>.sql
```

ファイル名は `^[0-9]{3}_[a-z0-9_]+\.sql$` に従います。3 桁連番とし、数値 prefix は重複させません。`LC_ALL=C` の辞書順で適用します。サブディレクトリは通常 migration の対象外です。T05 の最初の配置先は `postgres/auth-migrations/001_create_authentication_tables.sql` です。

## 適用単位

通常 migration は全対象 SQL を 1 回の `psql` プロセスで、`ON_ERROR_STOP=1`、`--single-transaction`、順番に並べた複数の `-f` 引数を使って一括実行します。SQL ファイルごとに別々の `psql` は実行しません。途中の SQL が失敗した場合、同じ実行内の通常 migration 全体を rollback します。

## 履歴表と再実行契約

専用の migration 履歴表は採用しません。初期 migration 数が少なく、認証アプリケーションの状態・テーブルを増やさず、一括切替を前提とし、互換運用や複数系列の migration を扱わないためです。

履歴表を持たない代わりに、通常 migration SQL は次の契約に従います。

```text
対象が存在しない: 必要な構造を作成する
対象が期待どおり存在する: 安全に成功する
対象が部分的に存在する、または定義が異なる: 明示的に失敗する
```

単純な `CREATE TABLE IF NOT EXISTS` だけで構造差異を隠しません。具体的な DDL と前提検査は T05 で作成するため、ここでは SQL 例を作り込みません。

## 接続設定と空 DB 検証

適用スクリプトは標準の libpq 環境変数 `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER`、必要な場合の `PGPASSWORD` を使用します。Secret 値はこの README に記載しません。本番の対象 database は `auth0_accounts` ですが、ローカル検証では破棄可能な空 database を指定できます。

T05 以降は、ローカルで起動済みの破棄可能な空 PostgreSQL に標準の `PG*` 環境変数を設定して、次を実行します。

```bash
./postgres/apply-auth-migrations.sh
```

検証後は `psql` のカタログ照会で対象テーブルと制約を確認します。Docker、Kubernetes、特定のローカル DB 製品は必須にしません。

既存の `auth0_accounts` にも同じスクリプトを使用します。T05 の通常 migration は旧 `users` を変換・削除せず、新しい 3 テーブルだけを追加します。

## cutover との分離

T21 の一括切替成果物は `postgres/auth-migrations/cutover/` に置きます。このディレクトリは通常 migration 適用スクリプトの対象外です。one-shot SQL、Secret preparation、Cookie expiry、Redis identified-key invalidation、backup/restore と own rollback の正本は [cutover/README.md](cutover/README.md) です。通常 migration、通常起動、Pod再起動では実行しません。

## postgres-init-sql.yaml との関係

`postgres/postgres-init-sql.yaml` は旧 `users` を含む既存初期化資産です。通常 migration の入力ではなく、`apply-auth-migrations.sh` から実行しません。PostgreSQL Operator の自動 migration 機構でもありません。T21後も新schema初期化へ流用せず、legacy rollback baselineの入力としてだけ保持します。
