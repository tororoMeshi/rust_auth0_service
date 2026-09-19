# T21 production cutover artifacts

このディレクトリは通常 migration の対象外である。T21 は T05 schema 適用後に一度だけ行う production initialization であり、legacy `public.users` を読取り・変換・削除しない。

## T21 の責務

1. `auth0_app_user` へ最小権限を付与し、`public.users` の権限を revoke する。
2. `portal-prod` を disabled で登録する。
3. portal service secret の SHA-256 digest、callback URI、logout URI を DB state として固定する。
4. read-only verifier で DB 登録値と Kubernetes Secret を照合する。

T05 は `../001_create_authentication_tables.sql` を通常 runner で適用する。T21 SQL は schema creation を複製せず、SQL 自身の `BEGIN` / `COMMIT` による一回の transaction として `psql -v ON_ERROR_STOP=1` で適用する。commit 前の失敗は T21 state を残さないため T21 を再試行できる。commit 後の失敗では T21 を再実行せず、`t21-verify-auth-foundation-state.sh` を read-only で実行して完全一致 state を確認し、最初の未完了の後続 step から再開する。不一致は STOP し、upsert/reconcile しない。

## Secret

`t21-prepare-portal-service-secret.sh` は protected external path に 32 raw bytes の unpadded base64url secret と SHA-256 digest を作成する。平文は stdout、stderr、argv、Git、docs、logs に出さない。T05 後、T21 前に一つの operator shell で `T21_SECRET_FILE` と `T21_SERVICE_SECRET_SHA256_FILE` を export し、その同じ path を preparation、T21 の `portal_service_secret_sha256_hex`、Kubernetes Secret placement、verifier に使う。各依存 step の前に両変数と両 regular file を確認する。T21 の disabled registration 成功後にだけ plaintext を Kubernetes Secret `auth0/portal-prod-service-secret` の `service_secret` key に配置する。

`t21-verify-auth-foundation-state.sh` は `T21_SERVICE_SECRET_SHA256_FILE` を入力に、disabled `portal-prod` の DB registration（service ID、URI、digest を含む）、required effective privileges、forbidden effective privileges、legacy `public.users` / `users_id_seq` への effective access がないことを read-only で照合する。これは Boundary A の strict verifier であり、enabled=true を受け入れない。PostgreSQL の `has_*_privilege` を使うため direct grant、role membership、`PUBLIC` を含む。`t21-verify-portal-service-registration.sh` は `T21_SECRET_FILE` を入力に、DB digest、callback URI、logout URI と Kubernetes Secret を read-only で照合する。`T21_EXPECTED_ENABLED=false` が Boundary A、enable 後の `T21_EXPECTED_ENABLED=true` が Boundary B である。成功しても enable しない。

`t21-enable-portal-service.sh` は Boundary A の直後だけに使う一回限りの operator DB operation である。`auth0_accounts.public.registered_web_services` の `portal-prod` を `is_enabled=false` から `true` へ更新し、正確に一行の `portal-prod` を返さなければ失敗する。`t21-rehearse-portal-service-artifacts.sh` は同一 shell の Secret path を使う preparation と registration verifier の隔離 rehearsal であり、Boundary A false、exactly-one enable、Boundary B true、enabled=true の pre-enable rejection、enable rerun 非許容を検証する。`t21-rehearse-postgres.sh` は同じ exported digest path を preparation、T21、pre-enable verifier と実 DB の false→true transition に通し、T21 の atomic failure、fresh execution、read-only completion/restart boundary、実効 least privilege、inherited / `PUBLIC` leakage detection を disposable PostgreSQL で検証する。

`t25-validate-deployment-config.sh` は committed Kubernetes manifest の client-side render/parse と、new runtime/portal/backend の名前、Secret/config参照、frontend routing の最小 preflight である。T22--T24 が所有する runtime behavior、DB/Redis failure-stop、HTTP/browser flow を再実装しない。

## 非対象

T21/T25/T26 は legacy user copy、Google identity copy、numeric ID preservation、sequence high-water、`users_id_seq`、legacy Redis invalidation、legacy Cookie physical expiry、pre-cutover backup/restore、rollback JWT、old runtime rollback を扱わない。`public.users` は残置され、新 runtime は grant も dependency も持たない。
