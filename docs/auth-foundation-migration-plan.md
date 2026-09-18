# 認証基盤移行方針

## 1. 現行方針

本番の Auth Foundation は、計画停止を伴う一括切替で新構成だけを有効化する。legacy auth data は disposable であり、fresh registration を正本とする。互換性・データ保存は現在要件で正当化される場合だけに採用する。

`public.users` は残すが、新 Auth Foundation は読取り・書込み・変換・削除をしない。legacy user、numeric ID、Google identity、JWT、Cookie、Redis state、external consumer の互換性は引き継がない。新規の `internal_users` identity が唯一の採番 authority である。

切替失敗時はメンテナンスを維持し、新 Auth Foundation を診断・修正して再試行する。legacy authentication system、DB、JWT、runtime を復元する rollback はサポートしない。

## 2. 新構成の対象

認証基盤が所有するアプリケーションテーブルは `internal_users`、`external_identities`、`registered_web_services` の3個である。T05 がこの schema を通常 migration として作成・検証する。T21 は schema を複製せず、T05 適用後の最小 grants と `portal-prod` の初期登録だけを行う。

新 runtime role `auth0_app_user` は `internal_users` と `external_identities` の `SELECT` / `INSERT`、`registered_web_services` の `SELECT`、`internal_users` identity sequence の `USAGE` だけを持つ。`public.users` への grant は持たない。

`portal-prod` は service secret の SHA-256 digest と完全一致 URI で `is_enabled = false` として登録する。Secret 平文は保護された外部の一時領域だけで扱い、DB、文書、ログ、URL、Cookie、frontend に記録しない。read-only verifier が DB 登録値と Kubernetes Secret を照合してから、明示的な運用操作で enable する。

## 3. 切替前提と境界

writer-stop は Auth Foundation の mutation 境界として `uniauth` と `rust-auth0-service` に限る。`portal-backend-deployment` は停止範囲を拡張しない。旧 runtime/routes を新 runtime へ切り替える間は portal を maintenance に保つ。

Redis 6.2 の新 `auth:*` semantics と fail-closed behavior は維持する。legacy Redis key の物理削除、legacy Cookie の物理 expiry、旧 state の変換は認証正しさの要件ではない。必要な性質は、新 runtime が旧 credential、旧 Cookie、旧 route、legacy Redis format を受け付けないことである。

## 4. 一括切替

1. clean repository と production preflight を確認する。
2. portal を maintenance にし、`uniauth` と `rust-auth0-service` を writer-stop する。
3. T05 schema を適用する。
4. T21 minimal grants と disabled `portal-prod` registration を適用する。
5. portal service secret を準備・配置し、read-only verifier を実行する。
6. 新 runtime と portal routing を配備・設定し、旧 runtime/routes を利用不能にする。
7. `portal-prod` を明示的に enable する。
8. fresh Google login で internal user と Google external identity を各1件作成する。
9. 同じ Google account の2回目 login が同じ identity と internal user を解決し、重複を作らないことを確認する。
10. portal LocalSession と `/api/me` を確認して maintenance を解除する。

各 mutation boundary の失敗は STOP、maintenance 維持、diagnose/fix、new-system state から retry とする。新旧の並行稼働、互換 layer、DB restore、旧 runtime の再配備は行わない。

## 5. 完了条件

- 新 API だけが公開され、旧 `/auth/google`、`/upsert_and_token`、`/sessions/verify`、旧 `/logout` は利用不能である。
- 新 runtime は legacy JWT、Cookie、Redis format、`public.users` を受け付けず、依存もしない。
- 最初の fresh Google registration が internal user 1件と Google external identity 1件を作る。
- 同じ Google identity の再 login は同じ internal user を解決し、二重作成しない。
- portal LocalSession と `/api/me` が成立する。
- legacy numeric ID、legacy identity、legacy DB/runtime rollback を前提にしない。
