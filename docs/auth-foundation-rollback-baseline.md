# 認証基盤ロールバック基準

## 1. 確認基準

本書はT01で固定する旧稼働構成の復元基準である。Secret平文、ユーザー行、Redis valueは含めない。可変tagではなく稼働Podで観測した不変digestと、現行Kubernetes構成・参照を復元可能な事実として残す。

## 2. 旧コンポーネント

| コンポーネント | namespace | Deployment | container | 設定image | 稼働image digest | replicas | strategy |
|---|---|---|---|---|---|---:|---|
| rust-auth0-service | auth0 | rust-auth0-service | rust-auth0-service | `tororomeshi/rust_auth0_service:20260506-fac3387` | `docker.io/tororomeshi/rust_auth0_service@sha256:60d3639013b279187706ea2106f8d6bae3868300cb022d4ad919db8f4722706a` | 2 | RollingUpdate（maxSurge 25%、maxUnavailable 25%） |
| uniauth | auth0 | uniauth | uniauth | `tororomeshi/uniauth:20260506-cc09546` | `docker.io/tororomeshi/uniauth@sha256:67186a16ca8b0e95874a3f45f3393f40c79e233fc813dba08457af1b2423538b` | 1 | RollingUpdate（maxSurge 25%、maxUnavailable 25%） |
| portal_backend | auth0 | portal-backend-deployment | portal-backend | `tororomeshi/portal-backend:latest` | `docker.io/tororomeshi/portal-backend@sha256:0992053e628b5b24e4d8d4081e79b689ab43d0a7d246a4e7c7f3efb2c7dcc0a0` | 1 | RollingUpdate（maxSurge 25%、maxUnavailable 25%） |
| portal | auth0 | frontend-deployment | frontend | `tororomeshi/portal-frontend:20260506-3e7b618` | `docker.io/tororomeshi/portal-frontend@sha256:b907b351753c2c4496211a75abb08fa7c89421a221c449d0cff12e9f267ded99` | 2 | RollingUpdate（maxSurge 25%、maxUnavailable 25%） |

## 3. 不変なコンテナイメージ

上表の稼働image digestをロールバック参照として固定する。T01は稼働PodのimageIDからdigestを取得し、ロールバック参照として固定済みとする。T21/T25はdigest指定でレジストリからpullし、旧構成を再配備できることを実証する。可変tagは補助情報であり、復元の識別子ではない。

## 4. Kubernetesリソース

rust-auth0-serviceはnamespace `auth0`、Service `rust-auth0-service`（port 8080）、Ingress `rust-auth0-ingress`（`auth.tororomeshi.net /`）、ServiceAccount `default`であり、readiness/liveness probeはない。uniauthはnamespace `auth0`、Service `uniauth`（port 8081）、Ingress `rust-auth0-ingress`（`auth.tororomeshi.net /uniauth`）、ServiceAccount `default`であり、readiness/liveness probeはない。

portal_backendはDeployment `portal-backend-deployment`、Service `portal-backend-service`（port 3000）、ConfigMap `backend-config`、ServiceAccount `default`、readiness/liveness `GET /health:3000`である。`backend-network-policy`のpodSelector `app=backend`はDeployment label `app=portal-backend`と不一致である。portalはDeployment `frontend-deployment`、Service `frontend-service`（Service port 80、target port 8080）、Ingress `portal-ingress`（`portal.tororomeshi.net /`）、ConfigMap `frontend-config`、ServiceAccount `default`、readiness/liveness `GET /healthz:8080`である。Kubernetesリソースの変更はこの調査では行わない。

## 5. 設定・Secret参照

rust-auth0-serviceは `google-auth-secrets` の `client_id`・`client_secret`、`session-secret` の `SESSION_SECRET_KEY` をSecret参照とし、GOOGLE_REDIRECT_URI、UNIAUTH_URL、REDIS_URL、APP_BASE_URL、POST_LOGIN_REDIRECT、ALLOWED_REDIRECT_ORIGINS、ALLOWED_CORS_ORIGINS、COOKIE_DOMAINを通常設定として持つ。現在、PostgreSQL credential Secretを直接参照しない。

uniauthは `auth0-app-user.auth0-account-db.credentials.postgresql.acid.zalan.do` の `username`・`password` と `uniauth-secrets` の `jwt_secret` をSecret参照とし、POSTGRES_HOST、DB_NAME、REDIS_URL、APP_BASE_URL、FRONTEND_ORIGINを通常設定として持つ。portal_backendは `backend-config` の FRONTEND_URL と `uniauth-secrets` の `jwt_secret` を参照し、PORT、RUST_LOGを通常設定として持つ。portalは `frontend-config` をnginx.confとしてvolume mountし、Secret環境変数参照はない。Secretの平文は記録しない。

## 6. Git・build・deploy

`fac3387`、`cc09546`、`3e7b618` は存在しtagとの対応候補だが、生成コミットとして確定していない。portal_backendの生成コミットは不明である。正確なGitコミットは追跡性の未確認事項として残す。build/deploy手順、manifest、CI成果物、image repository、tag、digest、配置に必要な成果物の所在を記録する。ソース追跡性は未解決だが、ロールバックは既存の不変image digestを使用し、旧ソースからの再buildを必要としない。

## 7. 復元に必要な成果物

復元には上表のdigest、旧Deployment・Service・Ingress・ConfigMap・Secret参照・NetworkPolicy・ServiceAccount・probeの構成、build/deploy成果物の所在、PostgreSQL復元範囲、Redis破棄範囲を用いる。PostgreSQLの認証復元単位は `auth0_accounts` databaseであり、`auth0_app` を巻き戻さない。active migration assumption では `rfrm-redisfailover:6379` の Redis DB0 は shared であり、DB0 全体を破棄範囲としない。forward migration / rollback とも `FLUSHDB` / `FLUSHALL` を使わず、安全に識別した key だけを削除する。分類不能 key が一件でもあれば削除せず cutover または rollback を停止する。

legacy uniauth JWT consumer として、`stateless-chat/nodejs-room`、`stateless-chat/websocket-chat-api`、`jamaica/play-matching`、`jamaica/matchmaking` が確認されている。各 workload は `uniauth-secrets` の `jwt_secret` を `JWT_SECRET` として参照し、旧 JWT を直接検証する。consumer の migration/retire 方針が未決定のため、auth0 namespace だけで十分とは決めず、cross-namespace rollback artifact scope は未確定である。同名 Secret だけを理由に他 workload へ Secret を同期しない。

## 8. 取得できなかった情報

Secret値、PostgreSQLのユーザー行、Redisの完全keyおよびvalueは取得していない。Redis DB 0は historical observation として点検時点でkey総数0だったが、切替時にも空である保証ではない。この過去記録は DB0 の active shared ownership と混同しない。正確な各imageの生成Gitコミット、特にportal_backendの生成コミットは未確定である。digest指定のpullと旧構成の実配備も未実証である。

## 9. T01完了判定

完了: digestと現行構成をロールバック基準として固定済み。

T21/T25で必要: digest指定でレジストリからpullし、旧構成を再配備できる実証。

T01では、旧4コンポーネントの稼働image digest、Kubernetes構成、Secret参照、PostgreSQL復元範囲、Redis破棄範囲、build/deploy成果物の所在を固定する。正確なGitコミットは望ましいが、単独ではT01の完了を妨げない。
