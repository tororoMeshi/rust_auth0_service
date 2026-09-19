# 認証基盤実装定数

## 1. 適用範囲

本書は `rust-auth0-service` の共通認証、`portal_backend` のローカル認証、portal のブラウザ経路に適用する。値は初期実装の固定値であり、Secret値そのものは記録しない。開発のbrowser-facing originは `http://localhost:5173`、開発サービスは `portal-dev`、callback は `http://localhost:5173/auth/callback`、logout return は `http://localhost:5173/` とする。

Auth Foundation production cutover は legacy JWT authentication consumer との互換性を維持しない。known legacy JWT consumer が切替後に動作しなくなることは accepted breaking change であり、consumer が migrated または retired 済みである証拠ではない。external consumer の migration、repair、retirement、owner confirmation は Gate E/T26 の prerequisite ではない。互換endpoint、adapter、bridge、dual auth、temporary fallback、migration shim は追加しない。

互換性やデータ保存は当然には前提にしない。現在の要件で正当化される場合だけを採用し、状態数、migration logic、rollback path、運用作業を実質的に増やすなら、より単純な breaking-change 案を operator/product owner に提示する。互換性を黙って捨てず、採否は operator/product owner が決める。

## 2. 認証基盤の期限

| 項目 | 値 | 意味 |
|---|---:|---|
| 外部認証トランザクションTTL | 600秒 | Googleへの開始からcallbackまで |
| 共通認証セッションTTL | 28,800秒 | 作成時からの絶対期限 |
| handoff TTL | 120秒 | 一回限りのサービス間引渡し |
| 共通ログアウト状態TTL | 600秒 | CommonLogoutTransaction |
| 参照値乱数 | OS乱数32バイト | Cookie、state、handoff等の平文参照値 |
| lookup | SHA-256の小文字16進 | RedisおよびDBの照合用 |
| PKCE | S256 | handoff交換のcode challenge方式 |
| service_id | `^[a-z0-9][a-z0-9_-]{0,63}$` | 1〜64文字 |

期限切れ状態は成功に使用せず、取得時に削除する。共通セッションのTTLはスライディング更新しない絶対期限とする。

## 3. portal_backendの期限と上限

| 項目 | 値 | 意味 |
|---|---:|---|
| LoginStart TTL | 600秒 | ログイン開始ブラウザ状態 |
| LocalSession TTL | 28,800秒 | 作成時からの絶対期限 |
| LoginStart保持件数上限 | 10,000件 | 上限時は新規開始を失敗させる |
| LocalSession保持件数上限 | 50,000件 | 上限時は新規セッションを作らない |
| 定期掃除 | 60秒 | 期限切れの粗い掃除間隔 |

portal_backend は `replicas: 1` と `Recreate` を前提にプロセスメモリで保持する。上限到達時に有効状態を追い出さない。

## 4. タイムアウト

| 項目 | 値 |
|---|---:|
| handoff交換接続タイムアウト | 3秒 |
| handoff交換全体タイムアウト | 10秒 |

通信失敗時に同じhandoffを自動再試行しない。成功・未成立を推測せず、ブラウザにログイン再開始を求める。

## 5. Cookie

新Cookieはすべてhost-onlyである。

| Cookie | 属性 | 用途 |
|---|---|---|
| `__Host-auth_session` | `Path=/`; `Secure`; `HttpOnly`; `SameSite=Lax`; Domainなし | 共通認証セッション参照 |
| `__Host-portal_session` | `Path=/`; `Secure`; `HttpOnly`; `SameSite=Lax`; Domainなし | LocalSession参照 |
| `__Host-portal_login_ctx` | `Path=/`; `Secure`; `HttpOnly`; `SameSite=Lax`; Domainなし | LoginStartのブラウザ結合 |
| `__Host-portal_csrf` | `Path=/`; `Secure`; HttpOnlyなし; `SameSite=Lax`; Domainなし | portalローカルログアウトCSRF平文 |

旧 Cookie の `jwt` と `session_id` は `Domain=.tororomeshi.net`、`Path=/` である。Option C はこれらの物理的な失効・削除成果物を要求しない。新 runtime は旧 Cookie を受け付けず、親ドメイン共有CookieおよびJWT Cookieに依存しない。

旧 Actix Cookie `id` は host-only `auth.tororomeshi.net`、`Path=/`、`Secure`、`HttpOnly`、`SameSite=Lax` である。Option C は旧 Actix Redis session の削除を要求しない。新 runtime は `id` を読まず、旧 credential と旧 runtime/routes を受け付けない。物理削除のためだけの新 route/component は追加しない。

## 6. CSRF

共通ログアウトは次の方式である。`GET /auth/logout` が `CommonLogoutTransaction` を作成し、OS乱数32バイトのCSRF値を生成する。RedisにはSHA-256 lookupだけを保存し、平文をform hidden fieldで渡す。`POST /auth/logout` は値をhash化して定数時間比較し、一致時だけ共通セッションを失効する。不一致、欠落、期限切れではセッションを変更しない。

portalローカルログアウトはdouble-submit方式である。LocalSession作成時、OS乱数32バイトから43文字のBase64url値を生成し、SHA-256 lookupだけをLocalSessionへ保存する。平文を `__Host-portal_csrf` に設定し、LocalSession CookieはHttpOnlyを維持する。`POST /logout` でJavaScriptがCookieを読み `X-CSRF-Token` に設定する。サーバーはLocalSession Cookieから状態を取得し、`__Host-portal_csrf` Cookieの平文値、`X-CSRF-Token` headerの平文値、LocalSessionに保存したSHA-256 lookupを照合する。Cookie値とheader値を定数時間比較し、一致した値をSHA-256化してLocalSession内hashと定数時間比較する。両方一致した場合だけLocalSessionと両Cookieを削除し、不一致・欠落・期限切れは403で状態を変更しない。

## 7. 入力上限

| 項目 | 上限 |
|---|---:|
| service_id | 64文字 |
| service state | 256文字 |
| OAuth state | 43文字 |
| OAuth code | 4,096文字 |
| handoff code | 43文字 |
| PKCE verifier | 43〜128文字 |
| PKCE challenge | 43文字 |
| provider | 16文字 |
| subject | 255文字 |
| post_login_path | 2,048文字 |
| CSRF値 | 43文字 |
| Authorization header | 8,192文字 |
| callback URI | 2,048文字 |
| logout return URI | 2,048文字 |
| HTTP body | 16,384バイト |

## 8. 定数と設定の分類

コード定数は、外部認証トランザクションTTL、共通認証セッションTTL、handoff TTL、共通ログアウト状態TTL、LoginStart TTL、LocalSession TTL、定期掃除間隔、Cookie名、Cookie属性、CSRF方式、入力上限、`service_id`形式、乱数バイト数、PKCE方式である。

通常設定は、公開URL、Google callback URI、PostgreSQL接続先、Redis接続先、portal_backendの`service_id`、認証基盤URL、LoginStart保持件数上限、LocalSession保持件数上限、handoff交換接続タイムアウト、handoff交換全体タイムアウト、HTTP body上限である。

Secretは、Google client secret、PostgreSQL credential、Redis credentialが存在する場合、portal_backendのservice secretである。平文を文書・ConfigMap・frontendへ置かない。登録済みcallback URIとlogout return URIはPostgreSQLの `registered_web_services` から取得し、要求値と完全一致で検証する。

## 9. 完了判定

すべての期限、上限、Cookie属性、CSRF比較、入力上限が実装・設定・検証で一致していること。開発オリジンに `localhost:8080` を残さず、`http://localhost:5173` を使用すること。共通ログアウトとportalローカルログアウトのCSRF方式を混同しないこと。Option C cutover は legacy runtime rollback を前提にしない。

## 10. 承認

本書の現行内容を、Gate Aの実装定数表として人間が承認した。

## 11. Gate B承認

T09〜T12により、production configuration boundary、Google/Redis/PostgreSQL起動設定、login、Google callback、handoff exchange、logout、および登録済みURI検証を含む認証基盤単体が成立したことを人間が承認した。browser単独で認証を成立させず、backend交換・service_id拘束・one-time handoff・PKCE S256を必須とし、アプリケーションには `internal_user_id` と `authenticated_at` のみを返す。CommonSessionはauth-host-onlyとし、親ドメインCookie、JWT置換フロー、provider subject/tokenの返却は行わない。callback claim、Redis/storage failure、logout GET/POST・CSRF、登録済みcallback/logout URIの扱いを含む主要不変条件を確認済みである。

独立レビュー結果は `APPROVE`、T12 commit可能およびGate B進行可能であり、`cargo fmt --check`、`cargo check`、`cargo test`、関連するPostgreSQL/Redis/HTTP integration、`git diff --check` はすべてPASSである。次の作業はT13以降とする。

## 12. Gate C承認

T13〜T15により、`portal_backend` 単体の認証経路が成立したことを人間が承認した。LoginStart / LocalSessionはprocess memoryで管理し、LoginStartのone-shot claim、handoffの自動retryなし、LocalSessionのみを認可根拠とする保護API、portalローカルログアウトのCSRF、JWT runtime認証の削除、および同一オリジンのbackend route境界を確認済みである。

独立レビュー結果は `APPROVE`、T15 commit可能およびGate C進行可能であり、25 tests、`cargo fmt --check`、`cargo check --locked`、`cargo test --locked`、`git diff --check` はすべてPASSである。次の作業はT16/T17およびT18とする。

## 13. T19本番routing・Secret・NetworkPolicy固定値

現行production edgeはCloudflare TunnelからKubernetes Serviceへ直接到達する。`portal.tororomeshi.net` は `frontend-service.auth0.svc.cluster.local:80`、`auth.tororomeshi.net` は `rust-auth0-service.auth0.svc.cluster.local:8080` が転送先であり、portal/authのKubernetes Ingressを経由しない。clusterに`cloudflared` IngressClass/controllerはない。したがって `portal/k8s/ingress.yaml` と `rust-auth0-service/yaml/ingress.yaml` のpath ruleをcurrent production routing enforcementの根拠にしない。

T19のproduction portal routing planeは `Cloudflare Tunnel -> frontend-service -> frontend Nginx` とする。frontend Nginxはexact matchの`/login`、`/auth/callback`、`/logout`と、末尾slashなしの`/api`および`/api/*`だけを`portal-backend-service:3000`へproxyする。既存の`location /api/`に加えて`/api`もbackendへ到達させ、`/login/*`や`/logout/*`へ範囲を広げない。`/`、SPA route、static fileはfrontend自身が処理する。T19で `portal/k8s/ingress.yaml`、Cloudflare設定、Ingress controller、path-aware Cloudflare routingを変更しない。

本番portal_backendの通常設定とSecret参照は次に固定する。

| 項目 | 固定値 |
|---|---|
| namespace | `auth0` |
| service ID | `PORTAL_SERVICE_ID=portal-prod` |
| 認証基盤URL | `PORTAL_AUTH_FOUNDATION_BASE_URL=https://auth.tororomeshi.net` |
| Secret resource | `portal-prod-service-secret` |
| Secret key | `service_secret` |
| consumer env | `PORTAL_SERVICE_SECRET` |

`backend-config`は通常設定2値だけを持ち、旧`NODE_ENV`、`PORT`、`FRONTEND_URL`は除去する。`PORT=3000`はDeploymentの既存literal値を維持する。Deploymentは`replicas: 1`、`strategy.type: Recreate`とし、旧`FRONTEND_URL`および`JWT_SECRET`/`uniauth-secrets`参照を削除する。LoginStartとLocalSessionはprocess memoryであるため、新旧Podを並存させない。

T19は `PORTAL_SERVICE_SECRET` を `secretKeyRef` のname `portal-prod-service-secret`、key `service_secret`へ配線するだけで、実Secret値、fake secret、plaintextを作成・commitしない。T26の同じoperator shellでprotected external pathにportal-prodの平文service_secretとそのSHA-256検証値を準備し、digestをT21の`registered_web_services`登録へ渡し、同じ平文を`auth0/portal-prod-service-secret`のkey `service_secret`として配置する。production Kubernetesへportal-devまたはportal-dev用Secretを置かず、developmentはT17/local設定に限定する。

portal_backendのNetworkPolicyは `podSelector.matchLabels.app: portal-backend` とする。ingressは同一namespaceの`app: frontend`からTCP 3000だけを許可し、`app: backend`自己許可やCloudflare Podからの直接許可を作らない。egressは、namespace `kube-system`かつ`k8s-app: kube-dns`へのUDP/TCP 53と、`ipBlock.cidr: 0.0.0.0/0`へのTCP 443だけを許可し、TCP 5432と6379のallow ruleを作らない。portal_backendはDB/Redis client自体を持たない。対象Podへ別のallow-allまたは加算的egress policyが存在しないことをT19で再確認する。

この標準NetworkPolicyが保証するのはDNSおよびTCP/443 outboundが可能で、PostgreSQL TCP/5432とRedis TCP/6379を許可しないことまでである。FQDN、TLS SNI、HTTP pathを認識しないため、`auth.tororomeshi.net`または`/auth/handoffs/exchange`専用とは主張しない。Cloudflare CIDR列挙はこの制約を解消せず外部可変設定を増やすため採用しない。接続先の真正性は `PORTAL_AUTH_FOUNDATION_BASE_URL=https://auth.tororomeshi.net` に対するreqwest/rustlsのTLS certificate・hostname検証で確保し、handoff交換の認可はHTTP Basicの`service_id=portal-prod`とservice_secretで確保する。平文service_secretを持つのはportal_backendだけとし、frontend/browserへ渡さない。

auth hostもCloudflare Tunnelからrust-auth0-serviceへ直接到達するため、T18のIngress path restrictionはcurrent production enforcementではない。T19ではauth側routingを変更せず、T20でlegacy Rust route/sourceを削除する。Gate Dはdead Ingress ruleの存在ではなく、portalの実経路とT20後のauth側actual route集合を検証する。T26は承認済み成果物を一括適用し、既存のCloudflare TunnelからServiceへのedge構成のまま新経路を公開する。
