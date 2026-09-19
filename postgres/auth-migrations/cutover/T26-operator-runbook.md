# T26 operator runbook

この runbook は Option C の fresh Auth Foundation cutover だけを記述する。production mutation は独立レビューの承認後だけに実行する。計画停止は許容され、切替中は service が一時的に利用不能になり得る。legacy user/identity/ID の保存、legacy state の cleanup、backup/restore、旧 runtime の再配備は行わない。

## 固定境界

- cutover-in-progress は writer-stop と新 runtime/routing への切替で表す。maintenance、operator bypass、特別な認証経路は使わない。
- writer-stop scope は namespace `auth0` の `deployment/uniauth` と `deployment/rust-auth0-service` だけである。`portal-backend-deployment` は含めない。
- legacy `public.users` は残置し、T05/T21/new runtime は読取り・書込み・変換・削除しない。
- operator は writer-stop の前に、production smoke に使える Google account へアクセスできることを確認する。email、Google subject、credential、token、固定 internal user ID を repository に記録しない。

## T05 前の operator shell setup

`postgres/apply-auth-migrations.sh` は `PGHOST`、`PGPORT`、`PGDATABASE`、`PGUSER` を必須とし、認証/TLS option を自ら設定しない。T05 の前に、次の block を **xtrace を無効にした一つの interactive operator shell** で実行する。これは `auth0_app` や application role を使わず、production CR で `auth0_accounts` の owner と定義されている `tororomeshi` の既存 credential Secret だけを利用する。password は stdout、stderr、argv、repository、SQL、log に出さない。

`auth0-account-db` Service は selector を持たないため、`kubectl port-forward service/...` は使わない。ready EndpointSlice が指す primary Pod を一意に解決して port-forward の対象にする。`LOCAL_PG_PORT` は既定値 `15432` が既に使用中の場合だけ、未使用の loopback port を明示して上書きできる。

```bash
set -euo pipefail
set +x
unset PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE PGSSLMODE PGOPTIONS

POSTGRES_NAMESPACE=auth0
POSTGRES_SERVICE=auth0-account-db
POSTGRES_REMOTE_PORT=5432
POSTGRES_DATABASE=auth0_accounts
POSTGRES_OWNER_SECRET="tororomeshi.${POSTGRES_SERVICE}.credentials.postgresql.acid.zalan.do"
export PGPORT="${LOCAL_PG_PORT:-15432}"

[[ "$(kubectl -n "${POSTGRES_NAMESPACE}" get service "${POSTGRES_SERVICE}" -o jsonpath='{.spec.ports[0].port}')" == "${POSTGRES_REMOTE_PORT}" ]]
POSTGRES_PRIMARY_POD="$({ kubectl -n "${POSTGRES_NAMESPACE}" get endpointslice -o json |
  jq -er --arg service "${POSTGRES_SERVICE}" '
    [.items[]
     | select(.metadata.labels["kubernetes.io/service-name"] == $service)
     | .endpoints[]
     | select(.conditions.ready == true and .targetRef.kind == "Pod")
     | .targetRef.name]
    | unique
    | if length == 1 then .[0] else error("expected exactly one ready primary endpoint") end'
  } )"

kubectl -n "${POSTGRES_NAMESPACE}" port-forward "pod/${POSTGRES_PRIMARY_POD}" "${PGPORT}:${POSTGRES_REMOTE_PORT}" &
POSTGRES_PORT_FORWARD_PID=$!
trap 'kill "${POSTGRES_PORT_FORWARD_PID}" 2>/dev/null || true; unset PGPASSWORD' EXIT

for _ in {1..30}; do
  pg_isready -h 127.0.0.1 -p "${PGPORT}" -d "${POSTGRES_DATABASE}" -t 1 >/dev/null 2>&1 && break
  sleep 1
done
pg_isready -h 127.0.0.1 -p "${PGPORT}" -d "${POSTGRES_DATABASE}" -t 1 >/dev/null

export PGHOST=127.0.0.1
export PGDATABASE="${POSTGRES_DATABASE}"
export PGUSER="$(kubectl -n "${POSTGRES_NAMESPACE}" get secret "${POSTGRES_OWNER_SECRET}" -o jsonpath='{.data.username}' | base64 --decode)"
[[ "${PGUSER}" == "tororomeshi" ]]
export PGPASSWORD="$(kubectl -n "${POSTGRES_NAMESPACE}" get secret "${POSTGRES_OWNER_SECRET}" -o jsonpath='{.data.password}' | base64 --decode)"

[[ "$(psql -X -v ON_ERROR_STOP=1 -Atqc 'SELECT current_database(), current_user;')" == "auth0_accounts|tororomeshi" ]]
printf 'Read-only PostgreSQL connection verified: %s as %s\n' "${PGDATABASE}" "${PGUSER}"
```

この block の `psql` は read-only の `SELECT current_database(), current_user` だけを実行する。`PGPASSWORD` は同じ shell の libpq authentication にだけ使用する。TLS option は runner にもこの block にも不要であり、cluster の libpq default を変更しない。T05 から Boundary B までこの shell と port-forward を維持する。cutover 完了または STOP 後にだけ `trap` を実行して port-forward と `PGPASSWORD` を破棄する。

同じ shell で、T21 の plaintext と digest の配置先を repository 外に作る。`/tmp` 配下の operator-owned 0700 directory を run 固有にし、T21/Boundary A/B で同じ path を保持する。ここではファイル内容を作らない。T21 の secret preparation が初めて内容を作る。

```bash
umask 077
CUTOVER_SECRET_DIR="$(mktemp -d /tmp/auth0-t26-cutover.XXXXXX)"
chmod 700 "${CUTOVER_SECRET_DIR}"
[[ "$(stat -c %U "${CUTOVER_SECRET_DIR}")" == "$(id -un)" ]]
[[ "$(stat -c %a "${CUTOVER_SECRET_DIR}")" == "700" ]]
export PORTAL_SERVICE_SECRET_FILE="${CUTOVER_SECRET_DIR}/portal-prod-service-secret"
export PORTAL_SERVICE_SECRET_DIGEST_FILE="${CUTOVER_SECRET_DIR}/portal-prod-service-secret.sha256"
export T21_SECRET_FILE="${PORTAL_SERVICE_SECRET_FILE}"
export T21_SERVICE_SECRET_SHA256_FILE="${PORTAL_SERVICE_SECRET_DIGEST_FILE}"
: "${PORTAL_SERVICE_SECRET_FILE:?}" "${PORTAL_SERVICE_SECRET_DIGEST_FILE:?}"
[[ ! -e "${PORTAL_SERVICE_SECRET_FILE}" && ! -e "${PORTAL_SERVICE_SECRET_DIGEST_FILE}" ]]
```

## 実行順序

上記 setup と 3--9 は一つの operator shell で続けて実行し、そこで保持した PostgreSQL environment、replica 数、Secret path を後続 command がそのまま使う。

1. 最終 clean/preflight を確認する。
2. 上記の Google account accessibility を人手で確認する。
3. writer の実際の desired replica 数を取得する。

   ```bash
   set -euo pipefail
   UNIAUTH_PRESTOP_REPLICAS="$(kubectl -n auth0 get deployment/uniauth -o jsonpath='{.spec.replicas}')"
   RUST_AUTH0_SERVICE_PRESTOP_REPLICAS="$(kubectl -n auth0 get deployment/rust-auth0-service -o jsonpath='{.spec.replicas}')"
   [[ "${UNIAUTH_PRESTOP_REPLICAS}" =~ ^[0-9]+$ ]]
   [[ "${RUST_AUTH0_SERVICE_PRESTOP_REPLICAS}" =~ ^[0-9]+$ ]]
   ```

4. 対象の二 Deployment だけを writer-stop し、desired zero と writer Pod absence を確認する。

   ```bash
   kubectl -n auth0 scale deployment/uniauth --replicas=0
   kubectl -n auth0 scale deployment/rust-auth0-service --replicas=0
   [[ "$(kubectl -n auth0 get deployment/uniauth -o jsonpath='{.spec.replicas}')" == 0 ]]
   [[ "$(kubectl -n auth0 get deployment/rust-auth0-service -o jsonpath='{.spec.replicas}')" == 0 ]]
   UNIAUTH_WRITER_PODS="$(kubectl -n auth0 get pods -l app=uniauth -o name)"
   RUST_AUTH0_SERVICE_WRITER_PODS="$(kubectl -n auth0 get pods -l app=rust-auth0-service -o name)"
   [[ -z "${UNIAUTH_WRITER_PODS}" ]]
   [[ -z "${RUST_AUTH0_SERVICE_WRITER_PODS}" ]]
   ```

   いずれかが失敗したら STOP する。T05/T21 の DB mutation 前に cutover を取りやめる場合だけ、同じ shell の保持値を使い writer-stop を undo する。

   ```bash
   kubectl -n auth0 scale deployment/uniauth --replicas="${UNIAUTH_PRESTOP_REPLICAS}"
   kubectl -n auth0 scale deployment/rust-auth0-service --replicas="${RUST_AUTH0_SERVICE_PRESTOP_REPLICAS}"
   ```

5. T05 `001_create_authentication_tables.sql` を通常 migration runner で適用する。
6. 上記 setup 済みの protected external path で service secret と digest を準備する。plaintext を repository、SQL、stdout、stderr、argv、logs に置かない。

   ```bash
   : "${T21_SECRET_FILE:?}" "${T21_SERVICE_SECRET_SHA256_FILE:?}"
   postgres/auth-migrations/cutover/t21-prepare-portal-service-secret.sh
   [[ -f "${T21_SECRET_FILE}" && -r "${T21_SECRET_FILE}" ]]
   [[ -f "${T21_SERVICE_SECRET_SHA256_FILE}" && -r "${T21_SERVICE_SECRET_SHA256_FILE}" ]]
   ```

7. 同じ path の prepared digest を入力に T21 を一度だけ実行し、disabled `portal-prod` registration を作る。

   ```bash
   : "${T21_SECRET_FILE:?}" "${T21_SERVICE_SECRET_SHA256_FILE:?}"
   [[ -f "${T21_SECRET_FILE}" && -r "${T21_SECRET_FILE}" ]]
   [[ -f "${T21_SERVICE_SECRET_SHA256_FILE}" && -r "${T21_SERVICE_SECRET_SHA256_FILE}" ]]
   psql -X -d auth0_accounts -v ON_ERROR_STOP=1 \
     -v portal_service_secret_sha256_hex="$(<"${T21_SERVICE_SECRET_SHA256_FILE}")" \
     -f postgres/auth-migrations/cutover/001_t21_auth_foundation_cutover.sql
   ```

8. T21 成功後にだけ、同じ protected plaintext path から Kubernetes Secret を配置する。

   ```bash
   : "${T21_SECRET_FILE:?}" "${T21_SERVICE_SECRET_SHA256_FILE:?}"
   [[ -f "${T21_SECRET_FILE}" && -r "${T21_SECRET_FILE}" ]]
   [[ -f "${T21_SERVICE_SECRET_SHA256_FILE}" && -r "${T21_SERVICE_SECRET_SHA256_FILE}" ]]
   kubectl -n auth0 create secret generic portal-prod-service-secret \
     --from-file=service_secret="${T21_SECRET_FILE}"
   ```

9. Boundary A（T21/pre-enable complete）を read-only で照合する。`portal-prod` は service ID、callback URI、logout URI、secret digest、effective DB privileges が完全一致で、`enabled=false` でなければならない。

   ```bash
   : "${T21_SECRET_FILE:?}" "${T21_SERVICE_SECRET_SHA256_FILE:?}"
   [[ -f "${T21_SECRET_FILE}" && -r "${T21_SECRET_FILE}" ]]
   [[ -f "${T21_SERVICE_SECRET_SHA256_FILE}" && -r "${T21_SERVICE_SECRET_SHA256_FILE}" ]]
   postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh
   T21_EXPECTED_ENABLED=false \
     postgres/auth-migrations/cutover/t21-verify-portal-service-registration.sh
   ```

10. 新 Auth Foundation runtime、portal configuration、routing を配備・設定し、旧 authentication runtime/routes を利用不能にする。ここからの production smoke は通常の intended production URL/path で行う。
11. **Boundary A が直前に PASS した場合にだけ**、PostgreSQL primary/operator access で次の一回限りの enable を実行する。対象 database は `auth0_accounts`、対象 table/row は `public.registered_web_services` の `portal-prod` だけである。`enabled=false` からの遷移が **exactly 1 row** でなければ STOP する。0 row を初回 enable の成功として扱わない。これは `auth0_app` を使用しない operator operation である。

   ```bash
   postgres/auth-migrations/cutover/t21-enable-portal-service.sh
   ```

   この command は `-d auth0_accounts` で `service_id = 'portal-prod' AND is_enabled = false` に限定した `UPDATE public.registered_web_services SET is_enabled = true ... RETURNING service_id` を実行し、戻り値が正確に `portal-prod` 一行でなければ失敗する。command failure は STOP し、smoke に進まない。

12. enable の直後に Boundary B（enable complete）を read-only で照合する。`portal-prod` は同じ service ID、callback URI、logout URI、secret digest を維持し、`enabled=true` でなければならない。失敗時は STOP し、T21 も enable も再実行せず、実際の DB state を診断する。

   ```bash
   : "${T21_SECRET_FILE:?}" "${T21_SERVICE_SECRET_SHA256_FILE:?}"
   [[ -f "${T21_SECRET_FILE}" && -r "${T21_SECRET_FILE}" ]]
   [[ -f "${T21_SERVICE_SECRET_SHA256_FILE}" && -r "${T21_SERVICE_SECRET_SHA256_FILE}" ]]
   T21_EXPECTED_ENABLED=true \
     postgres/auth-migrations/cutover/t21-verify-portal-service-registration.sh
   ```

13. 通常の production route で同じ Google account による初回 login を行い、Google authentication、fresh internal user 1件、Google external identity 1件、LocalSession、`/api/me` を確認する。固定 numeric ID は使わない。
14. 同じ account で二回目 login を行い、同じ internal user に解決され、internal user と external identity が増えず、LocalSession と API が引き続き成功することを確認する。
15. new runtime/routing active、old runtime/routes unavailable、Boundary B、初回 fresh smoke、二回目 reuse、LocalSession、`/api/me` が全て PASS なら cutover complete とする。

## 失敗時と再開境界

- T05/T21 DB mutation 前の abandonment では、上記 pre-stop undo で取得済み replica 数だけを戻せる。これは writer-stop の undo であり、legacy rollback ではない。
- T21 commit 前の失敗は SQL transaction が部分 T21 state を残さない。原因を診断して T21 を再実行できる。
- enable 前の失敗は STOP し、Boundary A を確認して、最初の未完了の pre-enable/post-T21 step から再開する。不一致は STOP であり、自動 reconcile はしない。
- Boundary B が既に completed の resume では enable を再実行しない。Boundary B を read-only で確認して、その後から再開する。enable 成功後に runtime または smoke が失敗した場合も同じであり、T21 を再実行せず、enable を盲目的に再実行しない。Boundary B を確認し、新しい runtime/smoke の問題を修正して post-enable smoke から再開する。不一致は STOP である。
- それ以降の失敗も STOP する。completed boundary は completed のまま残し、正確な completed state を確認して最初の incomplete/new-system failure を修正して再開する。legacy auth、DB、JWT、Secret、routing を復元しない。

## preflight 結果

- writer-stop: exact target、capture、stop、desired-zero、Pod absence、pre-DB undo を文書化済み。
- T05/T21: 同じ operator shell が保持する prepared digest を消費する fresh Auth Foundation schema と disabled `portal-prod` registration を使用する。
- service secret/verifier: Secret path は T21 前から Boundary B まで固定し、Boundary A は disabled と privileges、Boundary B は enabled を read-only で照合する。
- T25: committed deployment/configuration の最小 preflight を実行する。T22--T24 の behavior/failure evidence は再実装しない。
- independent review: any T26 production mutation の前に REQUIRED。
