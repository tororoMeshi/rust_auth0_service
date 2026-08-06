# 認証基盤物理コンポーネント設計

## 1. 採用構成

初期実装は認証基盤を `rust-auth0-service` の単一プロセス、単一コンテナ、1 Deployment、1 Kubernetes Serviceに集約する。認証基盤のGoogle接続、認証コア、PostgreSQLアクセス、RedisアクセスおよびRedis Lua操作は同一プロセス内の論理モジュールであり、物理サービスには分割しない。初期 `replica` 数は `rust-auth0-service`、`portal`、`portal_backend` ともに 1 replica とする。

```
Browser
  |
  +-- https://auth.tororomeshi.net
  |      |
  |      v
  |   rust-auth0-service
  |      +-- PostgreSQL
  |      +-- Redis
  |
  +-- https://portal.tororomeshi.net
         |
         +-- portal
         +-- portal_backend
```

本番の正規公開hostは `auth.tororomeshi.net` と `portal.tororomeshi.net` の二つだけとする。portalの現在のIngressは `portal.tororomeshi.net` の `/` をfrontendへ送っている。`portal` の既存画面ルートは `/` と `/dashboard` であり、認証用の `/login`、`/auth/callback`、`/logout`、`/api/*` と衝突しないため、これらを `portal_backend` に振り分ける。`app.tororomeshi.net` は本番の正規オリジンとして残さず、旧hostとして移行対象にする。

初期登録Webサービスはportalとportal_backendを合わせた単一サービスである。本番の登録値は `service_id = portal-prod`、`login_callback_uri = https://portal.tororomeshi.net/auth/callback`、`logout_return_uri = https://portal.tororomeshi.net/` とする。開発環境は `service_id = portal-dev` を別登録する。現在はVite port 5173で、proxyは `/api` のみである。目標構成では、開発環境でViteのポート5173を維持し、T17で `/login`、`/auth/callback`、`/logout`、`/api/*` を `http://localhost:3000` のportal_backendへproxyする。そのため登録値は `login_callback_uri = http://localhost:5173/auth/callback`、`logout_return_uri = http://localhost:5173/` とし、ブラウザが実際にアクセスするViteオリジンは `http://localhost:5173` である。

## 2. コンポーネントと責務

`rust-auth0-service` は新しい認証基盤の唯一の実行サービスである。`GET /auth/login`、Googleへのリダイレクトとcallback、`NormalizedExternalIdentity` への変換、`InternalUser` と `ExternalIdentity` の解決、共通認証セッション、`AuthenticationHandoff`、`POST /auth/handoffs/exchange`、`GET /auth/logout`、`POST /auth/logout`、`RegisteredWebService` の検証、PostgreSQL、RedisおよびRedis Lua操作を直接所有する。

`uniauth` は独立した実行サービスとして廃止する。uniauth Deployment、Kubernetes Service、専用Ingress、`rust-auth0-service` からの内部HTTP通信、`/upsert_and_token`、`/sessions/verify`、旧 `/logout`、独自JWT発行、独自Redisセッションを残さない。既存コードの吸収・削除順序は本書の対象外である。

`portal_backend` は登録済みWebサービスのバックエンドであり、LoginStart、PKCE verifier、Webサービス用 `state`、ブラウザコンテキストとの結び付き、認証後の相対遷移先、callback、handoffのバックチャネル交換、ローカルセッション、Webサービス側 `POST /logout`、保護APIを所有する。`service_id`、平文の `service_secret`、認証基盤のbackchannel URLを保持できるのは `portal_backend` だけである。これらをブラウザ、portalフロントエンド、JavaScript bundleへ渡さない。

`portal` は表示だけを担当する。Google OAuth、handoff交換、`service_secret` の保持、JWT検証、認証基盤DBまたはRedisへの参照、Cookie内の認証情報の解釈は行わない。ログイン開始は同一オリジンの `/login` へ遷移または要求し、portal_backendがLoginStartを作成して認証基盤へリダイレクトする。

## 3. 公開hostと通信経路

ブラウザは `https://portal.tororomeshi.net/login` を要求し、同一originのportal_backendがLoginStartを保存して `https://auth.tororomeshi.net/auth/login` へリダイレクトする。rust-auth0-serviceは共通認証セッションがなければGoogleへリダイレクトし、callback後に対象サービス用handoffを作成して `https://portal.tororomeshi.net/auth/callback` へ戻す。portal_backendはブラウザを経由させず、`https://auth.tororomeshi.net/auth/handoffs/exchange` に `POST` する。TLS終端は既存Ingressを利用し、HTTP Basicの `service_id:service_secret` はTLS内でだけ送信する。既存マニフェストからサービス間TLSまたは内部HTTPSの仕組みは確認できないため、初期実装で内部専用経路や新しいTLS基盤は追加しない。

portalのIngressまたは同等のルーティングは、`/` をportalへ、`/login`、`/auth/callback`、`/logout`、`/api/*` をportal_backendへ送る。`/auth/callback` は認証基盤のcallbackではなく、portalの登録済みWebサービスcallbackである。認証基盤のGoogle callbackは `auth.tororomeshi.net` 側にだけ置く。portalとportal_backendが同一オリジンなので、認証のためのCORS構成は不要である。

portal_backendのhandoff交換接続タイムアウトは3秒、handoff交換全体タイムアウトは10秒とする。HTTPレスポンスを正常に受信できなかった場合は、交換が成功したか未成立かを推測しない。同じhandoff codeを自動再試行しない。同じLoginStartを再利用せず、portalローカルセッションを作成せず、利用者には新しいログイン開始を要求する。これは、認証基盤がhandoffを使用済みにした後でレスポンスが失われる可能性があるためである。

## 4. Cookieとローカル状態

認証基盤の共通セッションCookieは `auth.tororomeshi.net` にだけ属するhost-only Cookieとする。`Domain` は設定せず、`Path=/`、`Secure`、`HttpOnly`、`SameSite=Lax` とし、値は共通セッション参照だけとする。

portalのローカルセッションCookieは `portal.tororomeshi.net` にだけ属するhost-only Cookieとする。`Domain` は設定せず、`Path=/`、`Secure`、`HttpOnly`、`SameSite=Lax` とし、値はportalローカルセッション参照だけとする。認証基盤Cookieとportal Cookieは名前も値も共有しない。

portalのローカルログアウトCSRF Cookieは `__Host-portal_csrf` とし、`Path=/`、`Secure`、`SameSite=Lax`、Domainなし、HttpOnlyなしとする。LocalSession作成時はOS乱数32バイトから43文字のBase64url値を生成し、LocalSessionにはそのSHA-256 lookupだけを保存して平文を `__Host-portal_csrf` に設定する。LocalSession CookieはHttpOnlyを維持する。`POST /logout` ではJavaScriptがCSRF Cookieを読み `X-CSRF-Token` に設定し、LocalSession Cookieから状態を取得する。`__Host-portal_csrf` Cookieの平文値、`X-CSRF-Token` headerの平文値、LocalSessionに保存したSHA-256 lookupを照合する。Cookie値とheader値を定数時間比較し、一致した値をSHA-256化してLocalSession内hashと定数時間比較し、両方一致した場合だけLocalSessionと両Cookieを削除する。不一致・欠落・期限切れは403で状態を変更しない。

portal_backendには所有可能な既存の安全な永続ストアは確認できない。したがって初期実装は `replicas = 1`、`Deployment strategy = Recreate` に固定し、LoginStartとLocalSessionを期限付きプロセスメモリに保存する。両方は作成時に絶対有効期限を持ち、取得時に期限を検査する。期限切れ状態は成功に使用せず、その場で削除し、定期掃除間隔 = 60秒で期限切れ状態を削除する。LoginStart保持件数上限 = 10,000件、LocalSession保持件数上限 = 50,000件とする。上限到達時は有効な既存状態を追い出さず、新しい状態の作成を拒否し、未認証やデータ不在として扱わない一時的な処理失敗とする。

Recreateを選ぶ理由は、LoginStartとLocalSessionをプロセスメモリに持ち、RollingUpdateでは新旧Podが一時的に同時稼働する可能性があり、新旧Pod間でメモリ状態を共有できないためである。Serviceから異なるPodへ振り分けられると認証状態が不安定になる。sticky sessionや共有セッションストアは導入せず、更新時に既存LoginStartとLocalSessionがすべて失効することを許容する。portal_backend再起動時も途中callbackを失敗させ、portal利用者には再ログインを要求する。認証基盤の共通セッションは維持されるため、再ログイン時にGoogle認証を省略できる場合がある。

## 5. データアクセスとSecret

PostgreSQLとRedisへ接続できるアプリケーションは `rust-auth0-service` だけである。PostgreSQLは `InternalUser`、`ExternalIdentity`、`RegisteredWebService` を含む永続状態の正本とし、Redisは短期の外部認証トランザクション、共通認証セッション、handoff、共通ログアウト一時状態の正本とする。Redisの一回限り処理はLuaで原子的に維持する。portal、portal_backend、ブラウザ、廃止後のuniauthはどちらにも接続しない。portal_backendはhandoff交換結果として `internal_user_id` と認証時刻を受け、ローカルセッション作成にだけ使う。

既存のportal_backend NetworkPolicyは存在するため、初期実装ではその最小方針を維持する。標準的なKubernetes NetworkPolicyではFQDNを直接宛先指定できるとは限らない。切替前に、portal_backendからcluster DNSへ名前解決できること、公開IngressのTCP 443へ接続できること、`auth.tororomeshi.net`を名前解決できること、TLS証明書とSNIの検証に成功すること、`POST /auth/handoffs/exchange`へ到達できること、現在のNetworkPolicyが必要なDNS通信とHTTPS通信を遮断しないことを検証する。NetworkPolicyの具体的な宛先は、現在のCNI、Ingressアドレス、既存Policyを確認して決める。PostgreSQLとRedisはIngressへ公開せず、認証基盤からだけ到達可能にする。認証基盤用NetworkPolicyが現在ないことを理由に、新設を初期実装の必須要素にはしない。

認証基盤はportal固有の `service_id` を環境変数に持たず、要求から受け取った `service_id` をPostgreSQLで検証する。認証基盤が保存する `service_secret` はPostgreSQLのSHA-256検証値だけであり、portal_backendは平文 `service_secret` をSecretから受け取る。Cookie名、Cookie属性、TTL、入力上限、CSRF方式、service_id形式は実装定数文書に従うコード定数とする。公開URL、Google callback URI、PostgreSQL接続先、Redis接続先、portal_backend自身の`service_id`、認証基盤URLは通常設定とする。portal_backendの `service_secret`、Google client secret、PostgreSQL credential、Redis credentialが存在する場合はSecretとする。`JWT_SECRET`、`ALLOWED_REDIRECT_ORIGINS`、`POST_LOGIN_REDIRECT`、uniauth接続先URL、uniauth専用Secret、親ドメインCookie設定、frontendへ注入された認証用Secretは削除対象である。

## 6. 配備・再起動・障害

rust-auth0-serviceは1 Deployment、1 Kubernetes Service、1コンテナ、1 replicaとするが、アプリケーションプロセス内に認証状態を保持しない。Pod再起動で永続ユーザーを失わず、Redis上の有効状態を失わず、Pod固有のsticky sessionを必要とせず、Luaによる一回限り処理を維持する。再起動後はPostgreSQLとRedisの状態で再開し、プロセスメモリの復旧は不要である。ブラウザの途中要求は失敗してよく、必要ならログインを再開始する。portal_backendは `replicas = 1` と `Deployment strategy = Recreate` を用い、更新時に新旧Podが並存しないようにする。更新でメモリ上のLoginStartとLocalSessionが全て失効することを許容し、共有状態やsticky sessionで補わない。

PostgreSQL障害時は新規外部本人の解決・作成に失敗させ、認証成功を返さず、portal_backendはローカルセッションを作成しない。Redis障害時は共通セッション不在として扱わず、Google認証へfallbackせず、handoffを発行・交換せず、認証成功を返さない。portal障害は認証基盤状態およびportal_backendのローカルセッションに影響させない。

portal_backend再起動時は、メモリ上のLoginStartとLocalSessionが消失し、既存callbackは失敗する。portal利用者には再ログインを要求し、認証基盤の共通セッションには影響しない。複数replica化の具体設計は行わない。

## 7. 現在実装との差分

現在のHEADは想定基準コミット `ea160810824ade97709ee66cc5c89183f80e1f0d`（`ea16081 docs: define authentication implementation tasks`）と一致している。T01は稼働PodのimageIDからdigestを取得し、ロールバック参照として固定済みとする。T21/T25はdigest指定でレジストリからpullし、旧構成を再配備できることを実証する。現在の作業ツリーにはリポジトリ変更を加えない。

| 現在 | 目標 | 物理的な変更 |
|---|---|---|
| rust-auth0-serviceは2 replicasでGoogle認証、親ドメインCookie、redirect設定を扱う | 認証基盤の唯一の実行サービス、1 replica | uniauthの認証コアを同一プロセスへ統合し、1 Deployment、1 Service、1コンテナへ固定する |
| uniauthは独立DeploymentとServiceでJWT、Redisセッション、`/upsert_and_token`、`/sessions/verify`、旧logoutを提供する | 独立実行サービスを廃止 | Deployment、Service、専用通信、旧endpoint、JWTと独自セッションを除去する |
| portal_backendはJWTを検証する既存backendで、1 replica | 登録済みWebサービスbackend、`replicas = 1`、`Deployment strategy = Recreate` | LoginStartとLocalSessionは期限付きかつ保持件数の上限付きプロセスメモリに置く。新旧Podの並存を許可せず、handoff交換の曖昧な通信失敗では自動再試行しない。 |
| portalは現在 `/` のIngress配下にあり、旧認証設定を持つ | 同一オリジンの表示frontend | 認証SecretとJWT解釈を除去し、`/login`等をportal_backendへ送る |
| Ingressはportalとauthのhostを個別に公開し、portal側は `/` をfrontendへ送る | 正規公開hostは二つ | `portal.tororomeshi.net` の認証・API経路をbackendへ追加し、開発時もVite proxyを通じてブラウザから見た同一オリジンを維持する。`app.tororomeshi.net` は移行対象にする |
| PostgreSQLはuniauth側の接続先として使われる | rust-auth0-serviceだけが接続する永続正本 | 認証基盤の永続識別子とサービス登録をrust-auth0-serviceへ集約する |
| Redisはuniauthの旧セッションとrust-auth0-service設定で使われる | rust-auth0-serviceだけが接続する短期状態の正本 | 共通セッション、handoff、Lua原子操作を認証基盤へ集約する |
| Cookieは親ドメイン共有とJWT依存がある | host-only Cookieを二種類に分離 | authとportalでDomainなし、別名・別参照値のCookieに置換する |
| JWT_SECRETが複数コンポーネントの設定に存在する | JWT共有認証を廃止 | JWT_SECRET、JWT検証、JWT発行を削除する |
| rust-auth0-serviceからuniauthへの内部HTTPがある | 認証基盤内HTTPを廃止 | 同一プロセス内の論理モジュール呼出へ置換する |

## 8. 採用しない構成

初期実装では、rust-auth0-serviceとuniauthの2サービス維持、認証コアのマイクロサービス分割、Google adapter専用Deployment、handoff交換専用Deployment、内部イベントバス、Kafka、RabbitMQ、Service Mesh、mTLS、API Gateway追加を採用しない。

portalとportal_backendの別オリジン運用、親ドメイン共有Cookie、portal専用Redis、portal専用PostgreSQL、sticky session、分散セッション、複数replicaの先行対応、sidecar、init containerによる業務処理、将来用の空Deploymentも採用しない。二種類のhandoff交換endpoint、uniauthへの内部HTTP、JWT client assertion、内部専用認証サービスまたは専用RPCも追加しない。
