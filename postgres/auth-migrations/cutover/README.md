# T21 production cutover artifacts

このディレクトリは通常 migration の対象外である。T21 は T05 schema 適用後に一度だけ行う production initialization であり、legacy `public.users` を読取り・変換・削除しない。

## T21 の責務

1. `auth0_app_user` へ最小権限を付与し、`public.users` の権限を revoke する。
2. `portal-prod` を disabled で登録する。
3. portal service secret の SHA-256 digest、callback URI、logout URI を DB state として固定する。
4. read-only verifier で DB 登録値と Kubernetes Secret を照合する。

T05 は `../001_create_authentication_tables.sql` を通常 runner で適用する。T21 SQL は schema creation を複製せず、SQL 自身の `BEGIN` / `COMMIT` による一回の transaction として `psql -v ON_ERROR_STOP=1` で適用する。commit 前の失敗は T21 state を残さないため T21 を再試行できる。commit 後の失敗では T21 を再実行せず、`t21-verify-auth-foundation-state.sh` を read-only で実行して完全一致 state を確認し、最初の未完了の後続 step から再開する。不一致は STOP し、upsert/reconcile しない。

## Secret

`t21-prepare-portal-service-secret.sh` は protected external path に 32 raw bytes の unpadded base64url secret と SHA-256 digest を作成する。平文は stdout、stderr、argv、Git、docs、logs に出さない。plaintext は Kubernetes Secret `auth0/portal-prod-service-secret` の `service_secret` key にだけ配置し、digest だけを `portal_service_secret_sha256_hex` として SQL に渡す。

`t21-verify-auth-foundation-state.sh` は `T21_SERVICE_SECRET_SHA256_FILE` を入力に、disabled `portal-prod` の DB registration（service ID、URI、digest を含む）、required effective privileges、forbidden effective privileges、legacy `public.users` / `users_id_seq` への effective access がないことを read-only で照合する。PostgreSQL の `has_*_privilege` を使うため direct grant、role membership、`PUBLIC` を含む。`t21-verify-portal-service-registration.sh` は `T21_SECRET_FILE` を入力に、DB digest、callback URI、logout URI と Kubernetes Secret を read-only で照合する。成功しても enable しない。enable は新 runtime/routing 配備後に明示的に行う。

`t21-rehearse-portal-service-artifacts.sh` は Secret preparation と verifier の隔離 rehearsal である。`t21-rehearse-postgres.sh` は T21 の atomic failure、fresh execution、read-only completion/restart boundary、実効 least privilege、inherited / `PUBLIC` leakage detection を disposable PostgreSQL で検証する。

## 非対象

T21/T25/T26 は legacy user copy、Google identity copy、numeric ID preservation、sequence high-water、`users_id_seq`、legacy Redis invalidation、legacy Cookie physical expiry、pre-cutover backup/restore、rollback JWT、old runtime rollback を扱わない。`public.users` は残置され、新 runtime は grant も dependency も持たない。
