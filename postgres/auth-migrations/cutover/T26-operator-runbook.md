# T26 operator runbook

この runbook は Option C の fresh Auth Foundation cutover だけを記述する。production mutation は独立レビューの承認後だけに実行する。ここで legacy system、DB、Secret、Redis、routing の復元や cleanup は行わない。

## 固定境界

- maintenance: portal は切替中に maintenance を返す。
- writer-stop: `uniauth` と `rust-auth0-service` だけを停止する。
- 非停止: `portal-backend-deployment` は writer-stop scope に含めない。
- legacy `public.users`: 残置し、T05/T21/new runtime は読取り・書込み・変換・削除しない。

writer-stop の直後に、想定 replica 数が 0、対象 Pod が残っていないことを確認する。確認失敗時は STOP して maintenance を維持する。T26 は本 task では実行しない。

## 実行順序

1. repository が clean であり、Gate E と production preflight が承認済みであることを確認する。
2. portal を maintenance にし、`uniauth` と `rust-auth0-service` を writer-stop する。
3. T05 `001_create_authentication_tables.sql` を通常 migration runner で適用する。
4. `001_t21_auth_foundation_cutover.sql` を、protected digest file 由来の `portal_service_secret_sha256_hex` を指定し、`psql -v ON_ERROR_STOP=1` で適用する。SQL 自身が単一 transaction boundary を持つ。
5. portal service secret を protected external path に生成・配置する。平文を repository、SQL、ログ、argv に置かない。
6. `t21-verify-portal-service-registration.sh` を read-only で実行し、disabled `portal-prod` registration、URI、DB digest、Kubernetes Secret を照合する。
7. 新 Auth Foundation runtime、portal configuration、routing を配備・設定し、旧 authentication runtime/routes を利用不能にする。
8. `portal-prod` を明示的に enable する。
9. maintenance を維持したまま、fresh Google login を一度実行する。
10. operator は read-only DB 確認で internal user が1件、Google external identity がその user を指す1件であることを確認する。email、Google subject、OAuth token その他の個人識別子を repository に記録しない。
11. 同じ Google account で2回目 login を実行し、同じ external identity と internal user が解決され、internal user と external identity が増えないことを確認する。
12. portal LocalSession と `/api/me` を確認し、旧 route と旧 credential が新 runtime で拒否されることを確認する。
13. 全確認成功後だけ maintenance を解除する。

## 失敗時と T21 再開境界

各 mutation boundary で失敗したら STOP し、maintenance を維持する。T21 SQL は SQL 自身の single transaction である。

- T21 commit 前の失敗では、その transaction は T21 の部分状態を残さない。原因を診断してから T21 を再実行できる。
- T21 commit 後は T21 を再実行しない。`T21_SERVICE_SECRET_SHA256_FILE` を指定して `t21-verify-auth-foundation-state.sh` を read-only で実行し、disabled `portal-prod` の完全一致登録、最小の実効権限、legacy table/sequence への実効アクセスなしを確認する。
- この verifier が成功したら、最初の未完了の T21 後 step から再開する。たとえば Secret 配置前なら step 5、runtime/routing 前なら step 7 からである。
- `portal-prod` が存在しても URI、digest、disabled 状態、または実効権限が完全一致しなければ STOP する。手動で原因を診断・修正し、T21 INSERT による上書き・reconcile はしない。

部分的な新旧認証並行、legacy user migration、DB restore、rollback JWT、old runtime の再配備は行わない。

## fresh registration smoke の判定

- 最初の login 前に Auth Foundation identity state が空である。
- 最初の login 後に internal user が1件、Google external identity が1件だけある。
- その identity はその internal user を参照する。
- 2回目 login 後も件数は増えず、同じ internal user を解決する。
- fixed numeric ID は要求しない。
- portal LocalSession と `/api/me` が成功する。

## preflight 結果

- writer-stop: READY。対象は `uniauth` と `rust-auth0-service` に限定する。
- T05/T21: READY。fresh Auth Foundation schema、minimal grants、disabled `portal-prod` registration を使用する。
- service secret/verifier: READY。平文を記録せず、read-only 照合を行う。
- backup/restore、legacy-ID smoke、legacy Redis/Cookie cleanup、old-runtime rollback: NOT PART OF THIS CUTOVER。
- independent review: REQUIRED before any T26 production mutation.
