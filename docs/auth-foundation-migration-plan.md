# 認証基盤移行方針

## 1. 現行方針

本番の Auth Foundation は、計画停止を伴う一括切替で新構成だけを有効化する。legacy auth data は disposable であり、fresh registration を正本とする。互換性・データ保存は現在要件で正当化される場合だけに採用する。

`public.users` は残すが、新 Auth Foundation は読取り・書込み・変換・削除をしない。legacy user、numeric ID、Google identity、JWT、Cookie、Redis state、external consumer の互換性は引き継がない。新規の `internal_users` identity が唯一の採番 authority である。

切替失敗時は STOP する。完了済み boundary を確認し、新システムの最初の未完了または新規 failure を修正して再開する。legacy authentication system、DB、JWT、runtime を復元する rollback はサポートしない。

## 2. 新構成の対象

認証基盤が所有するアプリケーションテーブルは `internal_users`、`external_identities`、`registered_web_services` の3個である。T05 がこの schema を通常 migration として作成・検証する。T21 は schema を複製せず、T05 適用後の最小 grants と `portal-prod` の初期登録だけを行う。

新 runtime role `auth0_app_user` は `internal_users` と `external_identities` の `SELECT` / `INSERT`、`registered_web_services` の `SELECT`、`internal_users` identity sequence の `USAGE` だけを持つ。`public.users` への grant は持たない。

`portal-prod` は service secret の SHA-256 digest と完全一致 URI で `is_enabled = false` として登録する。Secret 平文は保護された外部の一時領域だけで扱い、DB、文書、ログ、URL、Cookie、frontend に記録しない。同じ operator shell が secret/digest path を preparation、T21、Kubernetes Secret placement、verifier に引き継ぐ。read-only Boundary A verifier が DB 登録値、Kubernetes Secret、effective privileges と `is_enabled = false` を照合してから、明示的な運用操作で enable する。enable 後の Boundary B verifier は同じ登録値と `is_enabled = true` を照合する。

## 3. 切替前提と境界

writer-stop は Auth Foundation の mutation 境界として `uniauth` と `rust-auth0-service` に限る。`portal-backend-deployment` は停止範囲を拡張しない。切替中は service が一時的に利用不能でよく、maintenance、operator bypass、特別な認証経路は要求しない。

Redis 6.2 の新 `auth:*` semantics と fail-closed behavior は維持する。legacy Redis key の物理削除、legacy Cookie の物理 expiry、旧 state の変換は認証正しさの要件ではない。必要な性質は、新 runtime が旧 credential、旧 Cookie、旧 route、legacy Redis format を受け付けないことである。

## 4. 一括切替

1. clean repository と production preflight を確認する。
2. operator が smoke 用 Google account にアクセスできることを確認する。
3. `uniauth` と `rust-auth0-service` の replica 数を capture し、writer-stop する。
4. T05 schema を適用する。
5. service secret と digest を一つの operator shell の固定 path に準備する。
6. T21 minimal grants と disabled `portal-prod` registration にその digest を適用する。
7. 同じ plaintext path から Kubernetes Secret を配置し、Boundary A を照合する。
8. 新 runtime と portal routing を配備・設定し、旧 runtime/routes を利用不能にする。
9. `portal-prod` を明示的に enable し、Boundary B を照合する。
10. 通常の production URL/path で fresh Google login を行い、internal user と Google external identity を各1件作成し、LocalSession と `/api/me` を確認する。
11. 同じ Google account の2回目 login が同じ identity と internal user を解決し、重複を作らないことを確認する。

enable 前の失敗は Boundary A を確認して最初の未完了の pre-enable/post-T21 step から再開する。enable 成功後に smoke が失敗した場合は T21 と enable を盲目的に再実行せず、Boundary B を確認し、新しい runtime/smoke の failure を修正して post-enable smoke から再開する。不一致は STOP し、自動 reconcile はしない。新旧の並行稼働、互換 layer、DB restore、旧 runtime の再配備は行わない。

## 5. 完了条件

- 新 API だけが公開され、旧 `/auth/google`、`/upsert_and_token`、`/sessions/verify`、旧 `/logout` は利用不能である。
- 新 runtime は legacy JWT、Cookie、Redis format、`public.users` を受け付けない。
- `auth0_app_user` は Auth Foundation の必要最小権限だけを持ち、legacy table / sequence への有効権限を持たない。
- `portal-prod` は exact URI、secret digest、Kubernetes Secret と一致し、enabled である。
- 最初の fresh Google registration が internal user 1件と Google external identity 1件を作る。
- 同じ Google identity の再 login は同じ internal user を解決し、二重作成しない。
- portal LocalSession と `/api/me` が成立する。
- legacy numeric ID、legacy identity、legacy DB/runtime rollback を前提にしない。
