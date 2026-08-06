# 認証基盤現在状態

## 1. 確認基準

本書はリポジトリのマニフェスト、設定、ソース上の参照および確認済みKubernetes観測値を基礎にする。基準コミットは `ea160810824ade97709ee66cc5c89183f80e1f0d`（`ea16081 docs: define authentication implementation tasks`）である。Secretの平文、PostgreSQLのユーザー行、Redis valueは取得していない。確認時点の事実と切替時の状態は区別する。

## 2. リポジトリ構成

`rust-auth0-service` はGoogle認証開始・callbackと既存の認証処理を持つが、現在はPostgreSQLへ直接接続しない。`uniauth` は現在のPostgreSQL接続主体であり、JSONセッション、JWT、`/upsert_and_token`、`/sessions/verify`、旧`/logout` を持つ。`portal_backend` は現在JWT Cookieを検証するだけのbackendであり、`portal` はVite frontendである。主要な配置は `rust-auth0-service/yaml`、`uniauth/yaml`、`portal_backend/k8s`、`portal/k8s` にある。

## 3. ビルド・テスト・起動

確認できたbuild/deployスクリプトは `rust-auth0-service/run_docker.sh`、`rust-auth0-service/push_script.sh`、`uniauth/push_script.sh`、`portal_backend/push_to_dockerhub.sh`、`portal/push_script.sh`、`portal/scripts/deploy.sh` である。Rustの共通workspaceは確認できない。build/test/lintはT01では実行していない。Viteの開発ポートは5173で、browser-facing originは `http://localhost:5173` である。

## 4. 現在の認証フロー

ブラウザはportalからbackendへアクセスし、既存経路ではJWT Cookieとuniauthのセッション検証に依存する。rust-auth0-serviceはGoogleへのリダイレクトとcallbackを実行し、uniauthとの内部HTTPおよび旧認証状態が残る。正本では、認証コアをrust-auth0-serviceへ集約し、`LoginStart`、PKCE、handoff交換、`LocalSession`、portalローカルログアウトをportal_backendが所有する。portalはOAuth、service secret、JWT検証、認証DB・Redis参照を持たない。

旧Cookieは `jwt`、`session_id`、`Domain=.tororomeshi.net`、`Path=/` である。目標は `__Host-auth_session`、`__Host-portal_session`、`__Host-portal_login_ctx` のHttpOnly host-only Cookieと、HttpOnlyなしの `__Host-portal_csrf` に置換することである。

## 5. PostgreSQL・Redis

PostgreSQL CRは `auth0/auth0-account-db` で、databaseは `auth0_accounts` と `auth0_app` である。認証の復元単位はdatabase `auth0_accounts` とする。schemaは `metric_helpers`、`public`、`user_management`、認証アプリケーションテーブルは `public.users`、列は `id,email,google_id,name,icon_url,created_at` である。`auth0_app` を巻き戻さないため、cluster単位ではなくdatabase単位で復元する。

Redis接続先は `rfrm-redisfailover:6379`、DB番号は0である。参照ワークロードはuniauthとrust-auth0-serviceで、確認時点のkey総数は0だった。DB 0は認証用途のため、切替時の破棄対象はDB 0全体である。完全keyとvalueは取得していない。点検時点で空であることと、切替時点でも空であることは同一視しない。

## 6. portal・portal_backend

portalはViteを使用し、開発時に5173で起動する。現在のVite proxyは `/api` だけであり、browser-facing originは `http://localhost:5173` である。`/login`、`/auth/callback`、`/logout` のproxy、LoginStartとLocalSession、1 replica・Recreate、接続タイムアウト3秒・全体タイムアウト10秒は目標状態であり、第9章の正本との差分に属する。

## 7. Kubernetes配置

Kubernetes contextは `default`、namespaceは `auth0` である。rust-auth0-serviceは2 replicas、uniauthは1 replica、portal-backend-deploymentは1 replica、frontend-deploymentは2 replicasである。現在のIngressは `rust-auth0-ingress` の `auth.tororomeshi.net /` → `rust-auth0-service:8080`、`auth.tororomeshi.net /uniauth` → `uniauth:8081`、および `portal-ingress` の `portal.tororomeshi.net /` → `frontend-service:80` である。frontend-configのNginxは `/api/` を `portal-backend-service:3000` へ送る。portal_backendのNetworkPolicy selectorには不一致があり、PostgreSQLとRedisにはIngressがない。今回の調査ではKubernetes変更を行っていない。

## 8. 設定・Secret参照

rust-auth0-serviceは `google-auth-secrets` の `client_id`・`client_secret`、`session-secret` の `SESSION_SECRET_KEY` を参照し、GOOGLE_REDIRECT_URI、UNIAUTH_URL、REDIS_URL、APP_BASE_URL、POST_LOGIN_REDIRECT、ALLOWED_REDIRECT_ORIGINS、ALLOWED_CORS_ORIGINS、COOKIE_DOMAINを通常設定として持つ。uniauthは `auth0-app-user.auth0-account-db.credentials.postgresql.acid.zalan.do` の `username`・`password` と `uniauth-secrets` の `jwt_secret` を参照し、POSTGRES_HOST、DB_NAME、REDIS_URL、APP_BASE_URL、FRONTEND_ORIGINを通常設定として持つ。portal_backendは `backend-config` の FRONTEND_URL と `uniauth-secrets` の `jwt_secret` を参照し、PORT、RUST_LOGを通常設定として持つ。portalは `frontend-config` をnginx.confとしてvolume mountし、Secret環境変数参照はない。portal_backendのservice secretは目標構成で追加されるSecretである。Secret値自体は取得していない。

## 9. 正本との差分

現行はuniauth、JWT、旧Redisセッション、親ドメインCookie、内部HTTPに依存する。正本はrust-auth0-serviceを唯一の認証基盤とし、登録済みサービスの完全URI検証、PKCE S256、Redisの短期状態、host-only Cookie、handoff交換へ移行する。portalローカルログアウトは `__Host-portal_csrf` と `X-CSRF-Token` のdouble-submit方式、共通ログアウトはCommonLogoutTransactionとhidden field方式を使用する。

## 10. 未確認事項

`fac3387`、`cc09546`、`3e7b618` は存在するがtagとの対応候補であり、生成コミットとして確定していない。portal_backendの生成コミットは不明である。Gitコミット不明は追跡性の未確認事項として残す。T01は稼働PodのimageIDからdigestを取得し、ロールバック参照として固定済みとする。digest指定でレジストリからpullし、旧構成を再配備できることの実証はT21/T25で行う。切替時点のRedis DB 0のkey状態も再確認が必要である。
