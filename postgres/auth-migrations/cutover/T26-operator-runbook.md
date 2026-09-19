# T26 operator runbook

この runbook は Option C の fresh Auth Foundation cutover だけを記述する。production mutation は独立レビューの承認後だけに実行する。計画停止は許容され、切替中は service が一時的に利用不能になり得る。legacy user/identity/ID の保存、legacy state の cleanup、backup/restore、旧 runtime の再配備は行わない。

## 固定境界

- cutover-in-progress は writer-stop と新 runtime/routing への切替で表す。maintenance、operator bypass、特別な認証経路は使わない。
- writer-stop scope は namespace `auth0` の `deployment/uniauth` と `deployment/rust-auth0-service` だけである。`portal-backend-deployment` は含めない。
- legacy `public.users` は残置し、T05/T21/new runtime は読取り・書込み・変換・削除しない。
- operator は writer-stop の前に、production smoke に使える Google account へアクセスできることを確認する。email、Google subject、credential、token、固定 internal user ID を repository に記録しない。

## 実行順序

3--9 は一つの operator shell で続けて実行し、そこで保持した replica 数と Secret path を後続 command がそのまま使う。

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
6. T21 より先に protected external path を同じ operator shell へ export し、service secret と digest を準備する。plaintext を repository、SQL、stdout、stderr、argv、logs に置かない。

   ```bash
   export T21_SECRET_FILE=/protected/path/portal-prod-service-secret
   export T21_SERVICE_SECRET_SHA256_FILE=/protected/path/portal-prod-service-secret.sha256
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
