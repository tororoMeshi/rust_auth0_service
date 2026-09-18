# 認証基盤実装タスクリスト

## 1. 実装方針

4つの正本を実装上の決定として扱い、現行実装との差分は設計変更ではなく変更対象にする。実装順序は、保存層、認証基盤、portal_backend、portal、配置、旧構成削除、移行成果物、検証、一括切替の順に固定する。各タスクは前タスクの完了条件と該当Gateを満たしてから着手する。

認証基盤は `rust-auth0-service` の単一プロセスへ集約する。Google接続と認証コアは同一サービス内の論理モジュールにとどめる。汎用暗号フレームワーク、providerプラグイン、ORM、汎用repository、汎用セッションライブラリ、新規インフラ製品、互換経路、二重書込み、fallback、feature flagは導入しない。

確認時のHEADは想定どおり `ea160810824ade97709ee66cc5c89183f80e1f0d`（`ea16081 docs: define authentication implementation tasks`）である。作業ツリーには未追跡の `docs/auth-current-state.md`、`docs/auth-foundation-design-condensed.md:Zone.Identifier`、`docs/back/` があり、本計画では変更しない。

## 2. 現在実装の変更範囲

現行の `rust-auth0-service/src/main.rs` は `/auth/google` とGoogle callbackを持ち、親ドメインCookie、任意redirect、`uniauth` HTTP clientに依存する。`uniauth/src/main.rs` は `users`、Redis JSONセッション、JWT、`/upsert_and_token`、`/sessions/verify`、旧`/logout`を持つ。`portal_backend/src/main.rs` はJWT Cookieを検証し、`portal/vite.config.js` は `/api` だけをproxyしている。

配置対象は主に `rust-auth0-service/yaml/deploy.yaml`、`rust-auth0-service/yaml/ingress.yaml`、`uniauth/yaml/deploy.yaml`、`portal/k8s/frontend-configmap.yaml`、`portal_backend/k8s/deploy.yaml`、`portal_backend/k8s/backend-networkpolicy.yaml`、`portal_backend/k8s/backend-configmap.yaml` である。PostgreSQLとRedisの既存配置候補は `postgres/` と `redis/create_redis.yaml` にある。新しいmigration、Lua、移行手順、テストの具体的な配置はT01で現在の管理方式に照らして確定する。

現行production edgeではCloudflare Tunnelがportal hostを`frontend-service.auth0.svc.cluster.local:80`へ、auth hostを`rust-auth0-service.auth0.svc.cluster.local:8080`へ直接転送し、Kubernetes Ingressを経由しない。clusterに`cloudflared` IngressClass/controllerはなく、portal/authのIngress path ruleをproduction routing enforcementの根拠にしない。

## 3. 依存関係とGate

依存関係は次の順に固定する。並列化は同じ段階で明示的に依存がないタスクだけに限り、Gateを跨がない。

```text
T01
├─ T02 → T03
└─ T04 → T05

T03 + T05 → T06
T03 → T07 → T08

T06 + T08 → Gate A
Gate A → T09 → T10 → T11 → T12 → Gate B
Gate B → T13 → T14 → T15 → Gate C
Gate C → T16 → T17
Gate C → T18
T15 + T17 + T18 → T19 → T20
T20 → Gate D → T21 → T22 → T23 → T24 → T25 → Gate E → T26
```

downstream legacy JWT consumer は後続調査で判明した既知consumerであり、本リポジトリの implementation task ではない。Auth Foundation の本番切替は legacy JWT consumer との互換性を維持しない。consumer の移行、修復、retirement は必要なら切替後に別途扱うものであり、Gate E または T26 の prerequisite ではない。external service implementation はこのリポジトリの task ownership の外である。

### Gate A: 保存層成立

- T01で現行の起動・検証・配置・正規URI・実スキーマを入力値として固定している。
- T01の実装定数表が承認済みである。
- 旧構成のイメージdigest、Kubernetesリソース、マニフェスト所在および設定参照がT01で固定されている。
- PostgreSQLの3テーブルと既存 `internal_user_id` 維持方針がmigrationとして検証可能である。
- サービス認証と本人解決がDB障害時に成功へ進まない。
- Redisキー種類が4個だけで、Hash、TTL、`expires_at`、使用済みhandoff保持を満たす。
- 5個のLua操作がRedis `TIME`、入力、戻り値、失敗分類を持つ。

### Gate B: 認証基盤単体成立

- `rust-auth0-service` がGoogle callbackから本人解決、共通session、handoff発行までを単独で実行できる。
- HTTP Basic、PKCE、登録済みcallback完全一致、host-only Cookieが実装されている。
- handoff交換と共通ログアウトは一回限り・期限・障害を正しく扱う。
- Secret、認可コード、handoff、Cookie値をログへ出さない。

### Gate C: portal単体成立

- `portal_backend` がLoginStart、PKCE、handoff交換、LocalSession、保護API、ローカルログアウトを所有する。
- LoginStartとLocalSessionは期限・件数上限・取得時削除・単一定期掃除を満たす。
- backend再起動でローカル状態が全失効し、同一handoffを再試行しない。
- portalが同一オリジンの `/login`、`/logout`、`/api/*` だけを使える。

### Gate D: 新構成統合成立

過去の review は、当時認識していた repo/auth0 scope の証拠に基づく完了記録であり、現在の canonical status は **PASS** である。T21 最終 blocker 調査で legacy uniauth JWT を直接検証する downstream workload が4件判明した事実と過去decisionは維持するが、これは Gate D の再判定理由でも T26 の external prerequisite でもない。最初から review が誤っていたとは扱わない。

判明した consumer は `stateless-chat/nodejs-room`、`stateless-chat/websocket-chat-api`、`jamaica/play-matching`、`jamaica/matchmaking` である。いずれも `uniauth-secrets` の `jwt_secret` を `JWT_SECRET` として参照し、旧 uniauth JWT（`jwt` Cookie、HS256、shared `JWT_SECRET`、`sub` / `exp` claims）を直接検証する。過去decisionは `nodejs-room` = **MIGRATE**、`websocket-chat-api` = **RETIRE**、`play-matching` = **RETIRE**、`matchmaking` = **RETIRE** であるが、これらは migrated または retired の完了記録ではない。切替後の互換性は unsupported とし、既存 JWT の互換発行、generic shared JWT、compatibility layer は採用しない。

`nodejs-room` は known legacy JWT consumer であり、過去decisionは **MIGRATE** である。migration は Auth Foundation cutover に不要であり、切替後の互換性は unsupported とする。local session design、source implementation、image、Deployment、および rollback は external owner が所有する。

`websocket-chat-api`、`play-matching`、`matchmaking` は known legacy JWT consumer であり、過去decisionはそれぞれ **RETIRE** である。retirement は Auth Foundation cutover に不要であり、切替後の互換性は unsupported とする。RETIRE 実装、外部リソース削除、および rollback は external owner が所有する。

- portalの実経路 `Cloudflare Tunnel -> frontend-service -> frontend Nginx -> portal_backend` が所定のpathだけをbackendへ渡すことを確認する。dead Kubernetes Ingress ruleの存在だけを証拠にしない。
- auth hostはrust-auth0-serviceへ直接到達し、T20後のactual source route集合がnew auth routesだけである。
- SecretKeyRef契約、Deployment、NetworkPolicyがT19の固定値と境界を満たす。
- `rust-auth0-service` は1 replica、`portal_backend` は1 replicaかつ `Recreate` である。
- rust_auth0_service repo/auth0 scope に uniauth、JWT、旧API、親ドメインCookie、旧Redis JSONセッション、不要依存が残っていない。known legacy JWT consumer が切替後に動作することは保証しない。
- Production cutover intentionally breaks compatibility with legacy JWT authentication consumers. これは accepted product decision であり、consumer が migrated または retired 済みである証拠ではない。external consumer の状態は Gate E/T26 の GO/NO-GO 条件にしない。
- PostgreSQLとRedisはIngressへ公開されていない。
- 旧構成を削除したリポジトリ状態でも、T01で固定した不変image digest、Kubernetes構成、旧マニフェストの所在を参照できる。

### Gate E: 一括移行可能

- T21〜T25が完了し、T21のmigration成果物、T25で検証した配備成果物、およびrollback成果物が準備済みである。
- T01で取得した旧構成情報を基に、T21でロールバック成果物が完成している。
- 旧イメージがdigest指定でpull可能である。
- 旧構成を新しいロールバック用JWT_SECRETで再配備するリハーサルが成功している。
- 単体、PostgreSQL、Redis、HTTP、ブラウザ、Kubernetes、リハーサルの代表検証が成功している。
- production prerequisite と一括切替チェックリストに、未解決の rust_auth0_service-owned cutover blocker がない。external consumer の移行、修復、retirement、owner confirmation はこの条件に含めない。

## 4. 実装タスク

### T01. 実装前成立条件の固定

**目的**

後続実装が参照する現行の運用・接続・配置値と、正本で未確定だった実装定数を、後続で判断不要な状態まで固定する。

**前提**

4つの正本と現行HEADを確認済みである。

**主な変更対象**

- `docs/auth-current-state.md`
- `docs/auth-foundation-implementation-values.md`（新規）
- `docs/auth-foundation-rollback-baseline.md`（新規）

**実施内容**

- 現在のビルド、テスト、各crate・アプリ起動、PostgreSQL・Redisローカル検証、Kubernetesマニフェスト配置を記録する。
- portalのViteポート・proxy、portal_backend公開ルート、`users`実スキーマ、Redis共有状況、PostgreSQL復元対象範囲を固定する。
- Google callback URI、本番・開発の正規URI、既存Secretと設定の配置を固定する。
- migration、Lua、移行手順、テストの配置先を現行管理方式から確定する。
- `docs/auth-foundation-rollback-baseline.md`へ、現在本番で稼働中の旧rust-auth0-service、旧uniauth、旧portal_backend、旧portalについて、コンテナイメージのrepository、tag、digestを記録する。可変tagだけでなくdigestを取得する。
- 同文書へ、現在適用されているDeployment、Service、Ingress、ConfigMap、Secret参照、NetworkPolicyの構成、image tag、Git履歴、Deployment annotation、CI/CD記録から生成Gitコミットを調査し、確認できた候補と根拠を記録する。確定できない場合は追跡性の未確認事項として残す。旧構成のbuildとdeployに必要な手順・成果物の所在を事実として記録する。Secretの平文値は記録せず、Secret名、key名、参照先だけを記録する。
- イメージdigestまたは旧構成の取得に失敗した場合は、後続実装を開始しない。ロールバック手順そのものや新しいJWT_SECRETはT21で作成する。
- `docs/auth-foundation-implementation-values.md`へ、正本で決定済みの外部認証トランザクションTTL、共通認証セッションTTL、handoff TTL、共通ログアウト状態TTLを転記する。
- 同文書へ、LoginStart TTL、LocalSession TTL、LoginStart・LocalSession保持件数上限、メモリ掃除間隔、handoff交換の接続・全体タイムアウト、認証基盤・portalローカルセッション・ブラウザコンテキスト用一時Cookie名、共通・ローカルログアウトのCSRF方式、各HTTP入力の最大長、HTTPリクエストボディ最大サイズ、旧Cookie削除に必要なCookie名とDomainを固定する。
- 未確定値は現在の実装、利用規模、標準仕様の範囲で最小値を選び、各値に一文の根拠を記録する。初期実装で変更不要な値は汎用設定化せず定数として扱う。

**検証**

- 記録値を現行設定・マニフェスト・実スキーマ確認手順と突合する。

**完了条件**

- 後続タスクが必要な現行入力値と配置先を参照でき、設計判断を含まない。
- 実装定数表がレビュー済みである。
- T02以降で新しい認証設計判断を行う必要がない。
- Cookie名、TTL、上限、掃除間隔、タイムアウト、CSRF方式が確定している。
- 旧構成4コンポーネントの不変なイメージdigestが記録済みである。
- 旧構成の稼働image digest、Kubernetes構成、マニフェスト所在が記録済みである。正確な生成Gitコミットの未特定だけではT01を未完了にしない。
- Secretの平文を記録していない。
- ロールバック元情報をT20の削除後に初めて探す必要がない。

### T02. 共通参照値と入力境界の実装

**目的**

認証基盤で使う短期参照値と外部入力の共通ルールを最小機能で実装する。

**前提**

T01で配置先と依存追加方法を確定している。

**主な変更対象**

- `rust-auth0-service/Cargo.toml`
- `rust-auth0-service/src/main.rs`

**実施内容**

- OS乱数32バイトからBase64url・パディングなし参照値を生成する。
- SHA-256 lookupと小文字16進表現を実装する。
- 外部入力ごとに正本に沿う長さ上限を境界で検査する。

**検証**

- 生成値の形式、lookupの安定性、上限超過拒否を単体で確認する。

**完了条件**

- 平文参照値をRedisへ保存しない前提の値生成・入力検査を呼出側が利用できる。

### T03. 共通暗号・時刻処理の実装

**目的**

サービスSecret、PKCE、Redis状態検証に必要な小さな共通処理を実装する。

**前提**

T02が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`

**実施内容**

- SHA-256値の定数時間比較、PKCE S256 challenge、Unix秒への変換と妥当性検証を実装する。
- 汎用trait階層や汎用暗号フレームワークを追加しない。

**検証**

- 既知のPKCE入力、異なるhash、境界時刻、不正時刻を単体で確認する。

**完了条件**

- service_secret検証、PKCE、Redis期限判定が同じ定義を利用できる。

### T04. PostgreSQL migration管理場所の確定

**目的**

認証スキーマと移行を一貫して適用・検証できる管理場所を確定する。

**前提**

T01で現行PostgreSQL管理方式を固定している。

**主な変更対象**

- `postgres/postgres-init-sql.yaml`

**実施内容**

- 現行方式に従い、認証用migrationの配置、適用順、ローカル検証手順を確定する。
- migration所有者を `rust-auth0-service` または現在の `postgres/` 配下にある一つの認証用配置のいずれかへ限定する。
- 新規ORMや汎用migration基盤を導入しない。

**検証**

- 空の検証DBへ管理対象を適用し、適用順を再現できることを確認する。

**完了条件**

- T05、T21が同じ管理場所と適用方式を参照できる。
- migrationの所有者がuniauthではない。

### T05. 認証用3テーブルの作成

**目的**

永続本人識別と登録サービスの正本を3テーブルに置き換える。

**前提**

T04が完了している。

**主な変更対象**

- 配置先はT01の確認結果で確定（新規）

**実施内容**

- `internal_users`、`external_identities`、`registered_web_services`の通常schema migrationを追加する。
- `users.id`を引き継ぐ`integer`の `internal_user_id`、一意制約、外部キー、最小の状態列と制約を作成する。
- 3テーブルの制約とインデックスを作成し、旧`users`が存在していても新3テーブルを安全に作成できるようにする。
- プロフィール列、履歴・監査・soft delete・`updated_at`・外部トークンを追加しない。

**検証**

- 空DBへの適用、旧`users`があるDBへの安全な適用、制約違反・外部キー違反の拒否を確認する。

**完了条件**

- 認証アプリケーションの目標永続テーブルが3個である。

### T06. PostgreSQL本人解決とサービス認証の実装

**目的**

登録サービスと外部本人を、DBを正本として安全に解決する。

**前提**

T03とT05が完了している。

**主な変更対象**

- `rust-auth0-service/Cargo.toml`
- `rust-auth0-service/src/main.rs`

**実施内容**

- `RegisteredWebService`読取り、`service_secret`のhash・定数時間検証、`is_enabled`検査を実装する。
- `(provider, subject)`で既存本人を解決し、不在時は `InternalUser` と `ExternalIdentity` を同一トランザクションで作成する。
- 一意性競合では確定済み本人を再読込みし、DB障害時は認証成功へ進ませない。
- repository層または同等の最小分離だけを設ける。

**検証**

- 既存本人、新規本人、競合、無効ユーザー、無効サービス、DB障害を統合で確認する。

**完了条件**

- メールやプロフィールに依存せず、永続本人とサービスを確定できる。

### T07. Redis Hash状態とキー生成の実装

**目的**

期限付き認証状態を4種類のRedis Hashだけで表現する。

**前提**

T02、T03、T06が完了している。

**主な変更対象**

- `rust-auth0-service/Cargo.toml`
- `rust-auth0-service/src/main.rs`

**実施内容**

- `auth:external`、`auth:session`、`auth:handoff`、`auth:logout` のキー生成とHash読書きを実装する。
- 各状態のTTLと論理的`expires_at`を同じ絶対期限で扱う。
- Redis障害とキー不在・期限切れを区別し、使用済みhandoffを期限まで保持する。

**検証**

- 4キー形式、Hashフィールド、TTL、`expires_at`、不在・期限切れ・接続失敗の扱いを確認する。

**完了条件**

- Redis値がJSONや追加prefixを使わない4種類のHashだけである。

### T08. Redis Lua原子操作の実装

**目的**

一回限りの認証状態遷移を5個のLua操作で原子的に実行する。

**前提**

T07が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- 配置先はT01の確認結果で確定（新規）

**実施内容**

- 外部callback claim、SSO handoff発行、初回sessionとhandoff作成、handoff交換、共通ログアウトを実装する。
- 各操作の入力、戻り値、キー不在・期限・使用済み・不整合・Redis障害の分類を固定する。
- scriptのロードまたは実行方式を実装し、各実行内で一度だけRedis `TIME`を使う。
- 分散ロック、Redlock、WATCH再試行、Cluster対応、PostgreSQLへの短期状態複製を追加しない。

**検証**

- 同時callback claim、同時handoff交換、同時ログアウトをRedis統合試験で確認する。

**完了条件**

- 5操作がHashの期限・状態を原子的に遷移し、部分成功を返さない。

### T09. 認証基盤設定とSecret境界の整理

**目的**

新しい認証基盤が必要最小限の設定だけを受け取るようにする。

**前提**

Gate Aを通過している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- `rust-auth0-service/Cargo.toml`
- `rust-auth0-service/yaml/deploy.yaml`

**実施内容**

- Google、PostgreSQL、Redis、公開URLに必要な通常設定とSecretを整理する。Cookie名、Cookie属性、TTL、入力上限、CSRF方式は実装定数文書に従うコード定数として扱う。`service_id`はブラウザまたはHTTP Basic要求から受け取り、PostgreSQLの`registered_web_services`で検証し、認証基盤の環境変数へportal固有値を持たせない。
- `UNIAUTH_URL`、任意redirect、親ドメインCookie、JWTに関する設定を認証基盤から除く準備を行う。
- Secret、コード、Cookie値のログマスキングを共通化する。

**検証**

- 必須設定欠落、Secretを含む異常系ログ、旧設定混入を確認する。

**完了条件**

- 認証基盤が平文service_secretやJWT_SECRETを要求しない。

### T10. Login要求とGoogle認証開始の実装

**目的**

登録サービスから受けたログイン要求を外部認証トランザクションへ安全に変換する。

**前提**

T08、T09が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`

**実施内容**

- `GET /auth/login`でサービス、service state、PKCE challengeを検証し、共通sessionがあればその `internal_user_id` を得てPostgreSQLで `InternalUser` が存在し `is_enabled = true` であることを確認してからSSO handoffへ進める。
- ユーザーが無効・存在しない、またはDB確認に失敗した場合はhandoffを発行しない。DB障害を共通セッション不在として扱わず、DB障害時にGoogle認証へfallbackしない。
- 共通sessionがなければRedis外部トランザクションを作成し、Google認証開始へ遷移する。
- Google callback用stateとWebサービスstateを混用せず、登録済みcallback URIだけを使う。

**検証**

- 正常開始、SSO開始、無効サービス、不正state・challenge、期限切れsession、共通セッション存在中のユーザー無効化、DB障害をHTTP統合で確認する。

**完了条件**

- 任意redirectやWebサービスからのGoogle直接処理を使わずにログイン開始できる。

### T11. Google callbackと認証成功発行の実装

**目的**

Google本人確認から内部本人解決、共通session、handoff発行までを一貫して実行する。

**前提**

T10が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`

**実施内容**

- Google callbackを一回だけclaimし、応答を `NormalizedExternalIdentity` に変換する。
- T06の本人解決後にT08の初回session・handoff操作を実行し、登録済みcallbackへ戻す。
- callback二重処理、Google失敗、PostgreSQL障害、Redis障害を成功として扱わない。

**検証**

- 正常callback、新規・既存本人、二重callback、無効ユーザー、各依存障害を確認する。

**完了条件**

- JWTや旧Redisセッションを発行せず、handoffだけをブラウザへ渡す。

### T12. handoff交換・共通ログアウト・HTTP防御の実装

**目的**

Webサービスとの認証結果交換と共通ログアウトを完結させる。

**前提**

T11が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`

**実施内容**

- `POST /auth/handoffs/exchange`にHTTP Basic、PKCE、service一致、使用済み判定を実装する。
- `GET /auth/logout`と`POST /auth/logout`でlogout一時状態と共通session失効を実装する。POSTではT01で固定したCSRF方式により `CommonLogoutTransaction` とCSRF検証情報を照合する。
- GETだけではsessionを失効せず、CSRF不一致では共通セッションを削除しない。
- auth hostだけのhost-only Cookie、`Cache-Control`、`Referrer-Policy`、外部エラー表現を実装する。

**検証**

- PKCE不一致、期限切れ・再利用・同時交換、Basic失敗、GET/POST logout、CSRF不一致、Cookie属性とレスポンスheaderを確認する。

**完了条件**

- 認証基盤の公開経路が新しいログイン、交換、共通ログアウトだけで完結する。

### T13. portal_backendの設定と一時状態モデルの実装

**目的**

portal_backendが認証基盤利用に必要な最小状態をプロセスメモリに持つ。

**前提**

Gate Bを通過している。

**主な変更対象**

- `portal_backend/Cargo.toml`
- `portal_backend/src/main.rs`
- `portal_backend/k8s/deploy.yaml`

**実施内容**

- `service_secret`、service ID、認証基盤URL、ローカルCookie設定を整理する。
- LoginStartモデル、ブラウザコンテキスト参照、PKCE verifier、安全な相対post-login path、絶対期限を実装する。
- LocalSessionモデル、保持件数上限、取得時削除、単一定期掃除を実装する。LocalSession作成時にCSRF値を生成し、SHA-256 lookupだけをLocalSessionへ保存して、平文を`__Host-portal_csrf`へ設定する。
- 上限到達時は既存状態を追い出さず、新規作成を一時失敗として拒否する。

**検証**

- 期限、別ブラウザ、件数上限、掃除、再起動時全失効を確認する。

**完了条件**

- JWTやRedisを使わずにLoginStartとLocalSessionを管理できる。

### T14. portal_backendのログインcallbackとhandoff交換の実装

**目的**

portalの同一オリジンログインを、認証基盤とのバックチャネル交換へ接続する。

**前提**

T13が完了している。

**主な変更対象**

- `portal_backend/src/main.rs`

**実施内容**

- `/login`でLoginStartを作成して認証基盤の`/auth/login`へ遷移する。
- `/auth/callback`では、browser context確認、`state`確認、絶対有効期限確認、未使用確認、LoginStartを再利用不能にする、handoff交換を一度だけ実行する、成功時だけLocalSessionを作成する、`code`と`state`を含まない安全な`post_login_path`へリダイレクトする、の順序を守る。
- T01で固定した接続タイムアウトとリクエスト全体タイムアウトを設定する。handoff交換がタイムアウト、通信失敗、認証基盤エラーとなった場合も、同じLoginStartを未使用へ戻さず、同じLoginStart、code、handoffを自動再試行せず新しいログイン開始を要求する。
- 成功時だけhost-onlyローカルCookieとLocalSessionを作成する。

**検証**

- 正常ログイン、LoginStart不一致、別ブラウザ、PKCE不一致、交換応答喪失をHTTP統合で確認する。

**完了条件**

- browserはservice_secret、PKCE verifier、handoff交換応答を受け取らず、callbackの最終URLに`code`または`state`を残さない。

### T15. portal_backendの保護APIとローカルログアウト実装

**目的**

portal用の認証済みAPIとローカルログアウトをLocalSessionへ切り替える。

**前提**

T14が完了している。

**主な変更対象**

- `portal_backend/src/main.rs`

**実施内容**

- 保護APIをhost-only LocalSession Cookieで認可し、最小の`internal_user_id`と認証状態だけを返す。
- `POST /logout`では、`__Host-portal_csrf` Cookieの平文値、`X-CSRF-Token` headerの平文値、LocalSessionに保存したSHA-256 lookupを照合する。Cookie値とheader値を定数時間比較し、一致値をSHA-256化し、LocalSession内hashと定数時間比較し、両方一致時だけLocalSessionと両Cookieを削除する。GETによるローカルログアウトは作らず、不一致・欠落・期限切れは403で状態を変更しない。
- JWT解釈、CORS認証依存、旧Cookieの受理を削除する。

**検証**

- 有効・期限切れ・欠落・旧JWT・旧Cookie、ローカルログアウト、CSRF不一致、再起動後失効を確認する。

**完了条件**

- portal_backendがJWTを検証せず、ローカル状態だけを認可根拠にする。

### T16. portalの認証経路切替

**目的**

portal画面を新しい同一オリジン認証経路だけへ切り替える。

**前提**

Gate Cを通過している。

**主な変更対象**

- `portal/src/App.vue`
- `portal/src/main.js`
- `portal/src/router/index.js`
- `portal/src/utils/axios.js`

**実施内容**

- ログイン開始を`/login`、ローカルログアウトを`/logout`、保護APIを`/api/*`に切り替える。
- JWT解釈、email・name・picture必須表示、`app.tororomeshi.net`依存、認証用CORS依存を削除する。
- `internal_user_id`と認証状態だけで最小表示を行う。

**検証**

- 未認証、ログイン後、ログアウト後、旧JWT非依存をブラウザ相当の画面検証で確認する。

**完了条件**

- frontendは認証情報を解釈せず、同一オリジンbackendだけを利用する。

### T17. portal開発proxyの認証経路対応

**目的**

開発時にもportalとportal_backendの認証経路を同一オリジンに保つ。

**前提**

T16が完了している。

**主な変更対象**

- `portal/vite.config.js`

**実施内容**

- Viteの5173番ポートを維持し、`/login`、`/auth/callback`、`/logout`、`/api/*`をportal_backendへproxyする。
- T01で固定した開発callback URIとlogout URIに一致させる。

**検証**

- ブラウザから見た `http://localhost:5173` の経路とbackend到達先を確認する。

**完了条件**

- 開発環境で認証のための別オリジンまたはCORSを必要としない。

### T18. 認証基盤Kubernetes設定の切替

**目的**

認証基盤を唯一の認証サービスとして公開・設定する。

**前提**

T12が完了している。

**主な変更対象**

- `rust-auth0-service/yaml/deploy.yaml`
- `rust-auth0-service/yaml/ingress.yaml`

**実施内容**

- rust-auth0-serviceを1 replicaにし、auth host、Google callback URI、PostgreSQL・Redis・Google Secretだけを設定する。
- `JWT_SECRET`、uniauth URL、親ドメインCookie、任意redirect設定を削除する。
- PostgreSQLとRedisをIngressへ公開しないことを確認する。
- auth hostのCloudflare Tunnelはrust-auth0-serviceへ直接到達する。T18で新しいIngress controllerやCloudflare routingを追加せず、Ingress path restrictionをcurrent production enforcementとして扱わない。

**検証**

- manifestレビューでreplica、公開host、不要環境変数、Ingress公開範囲を確認する。ただしproduction routingはCloudflare Tunnelの実転送先も確認し、Ingress ruleだけで判定しない。

**完了条件**

- auth hostはrust-auth0-serviceへ到達する。new auth routesだけへの限定はIngressではなく、T20でlegacy Rust route/sourceを削除したactual route集合によってGate Dまでに成立させる。

### T19. portal Kubernetes経路と配備条件の切替

**目的**

portalをfrontendとbackendの同一オリジン構成へ配置する。

**前提**

T15、T17、T18が完了している。

**主な変更対象**

- `portal/k8s/frontend-configmap.yaml`
- `portal_backend/k8s/deploy.yaml`
- `portal_backend/k8s/backend-networkpolicy.yaml`
- `portal_backend/k8s/backend-configmap.yaml`

**実施内容**

- production portal routing planeを `Cloudflare Tunnel -> frontend-service -> frontend Nginx` に固定する。frontend Nginxはexact matchの`/login`、`/auth/callback`、`/logout`と、`/api`および`/api/*`だけを`portal-backend-service:3000`へproxyする。既存`location /api/`に末尾slashなしの`/api`を加え、`/login/*`や`/logout/*`へ広げない。`/`、SPA route、static fileはfrontend自身で処理する。
- portal_backendを`replicas: 1`・`strategy.type: Recreate`とし、process memoryのLoginStart/LocalSessionを持つ新旧Podを並存させない。
- `backend-config`を`PORTAL_SERVICE_ID=portal-prod`と`PORTAL_AUTH_FOUNDATION_BASE_URL=https://auth.tororomeshi.net`だけへ置換する。旧`NODE_ENV`、`PORT`、`FRONTEND_URL`をConfigMapから除去し、`PORT=3000`はDeploymentの既存literal値を維持する。
- Deploymentの`PORTAL_SERVICE_SECRET`をnamespace `auth0`のSecret `portal-prod-service-secret`、key `service_secret`への`secretKeyRef`で配線する。旧`FRONTEND_URL`と`JWT_SECRET`設定、および`uniauth-secrets`の`jwt_secret` `SecretKeyRef`を削除する。T19では実Secret値やfake secretを作らず、plaintextをcommitしない。
- production Kubernetesへportal-devまたはportal-dev用Secretを置かない。developmentはT17/local設定を使用する。
- NetworkPolicy selectorを`app: portal-backend`へ修正し、ingressは同一namespaceの`app: frontend`からTCP 3000だけを許可する。`app: backend`自己許可とCloudflare Podからの直接許可は作らない。
- egressはnamespace `kube-system`かつ`k8s-app: kube-dns`へのUDP/TCP 53と、`ipBlock.cidr: 0.0.0.0/0`へのTCP 443だけを許可する。portal_backendはDB/Redis client自体を持たず、TCP 5432/6379のallow ruleを作らない。
- T19で `portal/k8s/ingress.yaml`、Cloudflare設定、legacy Rust routeを変更せず、新しいIngress controller、service mesh、egress proxy、FQDN NetworkPolicy製品、Cloudflare CIDR管理を追加しない。

**検証**

- actual production chainでNginxのexact 3 path、`/api`、`/api/*`だけがbackendへ届き、`/login/*`、`/logout/*`、SPA route、static fileがbackendへ広がらないことを確認する。dead Ingress ruleだけをrouting成立の証拠にしない。
- 1 replica/Recreate、通常設定2値、`PORT=3000` literal、SecretKeyRef、旧env削除をmanifestで確認する。
- NetworkPolicyのselector、frontendだけのingress、DNSとTCP/443のegressを確認する。TCP/5432 PostgreSQLとTCP/6379 Redisのallow rule、および対象Podへ適用される別のallow-all/additive egress policyがないことを確認する。
- `PORTAL_AUTH_FOUNDATION_BASE_URL`に対するreqwest/rustlsのTLS certificate・hostname検証、HTTP Basicの`service_id=portal-prod`とservice_secret、および平文secretをportal_backendだけが持つことを確認する。

**完了条件**

- portalのactual production chain、配備設定、Secret参照、NetworkPolicyが固定値どおりであり、portal-dev用Secretを本番clusterへ配置しない。
- NetworkPolicyの保証はportal_backendからDNSとTCP/443 outboundが可能で、TCP/5432とTCP/6379を許可しないことまでとする。標準NetworkPolicyはFQDN、TLS SNI、HTTP pathを認識しないため、auth hostまたはhandoff endpoint専用とは主張しない。
- 認証先の真正性・認可はTLS certificate/hostname検証とHTTP Basicのportal-prod資格情報を合わせて成立させ、frontend/browserへservice_secretを渡さない。

### T20. 旧uniauth・JWT・旧APIの完全削除

**目的**

新経路の単体実装後に、rust_auth0_service repo 内の旧認証経路を残さず除去する。

**前提**

T16–T19が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- `rust-auth0-service/Cargo.toml`
- `uniauth/src/main.rs`
- `uniauth/Cargo.toml`
- `uniauth/yaml/deploy.yaml`
- `portal_backend/src/main.rs`
- `portal_backend/Cargo.toml`
- `portal_backend/k8s/deploy.yaml`

**実施内容**

- `/auth/google`、任意redirect、`ALLOWED_REDIRECT_ORIGINS`、`POST_LOGIN_REDIRECT`、`/upsert_and_token`、`/sessions/verify`、旧`/logout`を削除する。
- JWT発行・検証・JWT_SECRET、親ドメインCookie、旧Redis JSONセッション、rust-auth0-serviceからuniauthへのHTTP client、uniauth実行バイナリ・Deployment・Service・不要crate依存を削除する。
- コメントアウト、feature flag、互換API、fallbackとして残さない。
- auth hostはCloudflare Tunnelからrust-auth0-serviceへ直接到達するため、legacy Rust route/sourceの削除をactual production route集合のenforcementとする。T20でCloudflare設定を変更しない。
- 新しい一括切替リリース内で旧経路が存在しない状態をリポジトリ上で作り、統合検証とリハーサルを行う。現在稼働中の旧本番環境はT26まで変更しない。
- T18、T19、T20の成果物を個別に本番へ順次適用せず、本番への新マニフェスト適用、uniauth停止、旧API停止はT26の一括切替で同時に行う。
- T01でロールバック元情報が固定されていなければ、旧コードや旧マニフェストを削除しない。T20でリポジトリから旧構成を削除しても、T01に記録した不変image digest、Kubernetes構成、旧マニフェストの所在、設定・Secret参照から旧構成を復元するための基準を維持する。
- T20 の完了は rust_auth0_service repo 内の legacy uniauth/JWT/session/API/deployable artifacts の除去である。system 全体から legacy JWT dependency が消えたことを意味しない。known external consumer の migrated/retired 確認は不要であり、T26 で旧認証を停止するための release condition として扱わない。

**検証**

- 旧endpoint、`jsonwebtoken`、JWT_SECRET、旧Cookie、uniauth参照、旧Redis JSON形式が残らないことを検索とHTTP確認で検証する。

**完了条件**

- uniauthが独立サービスとして存在せず、rust-auth0-serviceが唯一の認証基盤サービスである。ロールバック元情報の取得を現在稼働中のPodだけに依存しない。

### T21. 一括移行成果物の作成

**目的**

本番切替前にデータ移行・失効・復旧を再現できる成果物を揃える。

**前提**

T04で管理場所を確定し、**PASS** の Gate D を通過している。T21 は external consumer を理由には BLOCK しない。Redis version blockerは解消済みであり、T21 は **READY** である。本番の基準Redis 6.2.6で、保存した`expires_at`とRedis `TIME`を論理期限authorityとする。

**主な変更対象**

- `postgres/confirmation-users.sh`
- `postgres/postgres-init-sql.yaml`
- `redis/create_redis.yaml`

**実施内容**

- 現行users事前検査、usersから`internal_users`への変換、usersから`external_identities`への変換、件数・ID・外部ID検査、identity sequence調整、旧users削除を、一括切替専用のSQLまたは手順として作成する。
- `registered_web_services`初期登録、service_secret生成、旧Redisキー安全識別・削除、PostgreSQLバックアップ・復元確認、旧Cookie失効、ロールバック用の新しいJWT_SECRET生成の成果物を作成する。portal-prodのservice_secretはSHA-256検証値を`registered_web_services`へ登録し、同じ平文を`auth0/portal-prod-service-secret`のkey `service_secret`としてcutover成果物へ配置する。具体的なscript/file名はT21実装時に既存管理方式へ合わせて決める。
- T01で記録したイメージdigestを再確認し、T01で記録した不変image digest、Kubernetes構成、旧マニフェストの所在、設定・Secret参照をロールバック成果物として固定する。必要なイメージがレジストリからpull可能であることを確認する。
- T01で記録した設定参照を使い、ロールバック用の新しいJWT_SECRETを組み込む手順と、旧構成を不変な成果物から再配備するチェックリストを作成する。可変タグだけをロールバック根拠にせず、T21で稼働中Podを唯一の情報源として初めてdigestを取得しない。
- legacy user ID を再利用しない。`internal_users` identity sequence の次値は、writer 停止後に観測した `max(users.id) + 1` と legacy `users_id_seq` の実 next value の大きい方にする。現在の観測値は `max(users.id) = 36`、legacy sequence next = `125` であり、例示値は125である。ただし production script に125を hardcode しない。
- cutover 成果物で runtime role `auth0_app_user` へ最小権限を付与する。`internal_users` は `SELECT` / `INSERT`、`external_identities` は `SELECT` / `INSERT`、`registered_web_services` は `SELECT`、`internal_users` identity sequence は `USAGE` とする。service registration / enable 等の運用 write 権限は付与しない。既存 schema migration `001` をこの時点で変更するとは決めない。
- Redis DB0 は authentication 専用ではなく shared である。確認済み consumer は少なくとも `auth0/rust-auth0-service`、`auth0/uniauth`、`stateless-chat/nodejs-room`、`stateless-chat/websocket-chat-api` である。forward migration と rollback のいずれでも `FLUSHDB` / `FLUSHALL` を禁止し、安全に識別した key だけを削除する。分類不能 key が一件でもあれば削除せず cutover を停止し、script で推測、自動修復、自動削除をしない。
- legacy Redis auth state の識別対象は、uniauth の prefix なし24文字 ASCII 英数字 key（string JSON、`user_id` / `expires_at`、TTL 約24h）と、old rust-auth0-service Actix session の prefix なし64文字 ASCII 英数字 key（string JSON map、`oauth_state` 必須、`redirect` 任意、TTL 約24h）である。`auth:external:`、`auth:session:`、`auth:handoff:`、`auth:logout:` は forward 削除対象外である。
- `jwt` と `session_id` の parent-domain legacy Cookie は `Domain=.tororomeshi.net; Path=/` であり、T21/T25/T26 に browser expiry artifact を含める。旧 Actix Cookie `id`（host-only `auth.tororomeshi.net`; `Path=/`; `Secure`; `HttpOnly`; `SameSite=Lax`）は、旧 Actix Redis session 削除・旧 runtime 停止・新 runtime が読まないことにより server-side invalidation を成立させる。`id` を物理削除するだけの新 route/component は追加しない。
- production Redis 6.2.6を使用する。論理期限は保存した`expires_at`とRedis `TIME`で判定し、`EXPIREAT`による物理期限はcleanupと早期消滅時のfail-closed defense-in-depthとして扱う。shared Redisまたはoperatorのupgrade、manifest image pin追加はT21の要件ではない。
- external consumer の rollback は external owner の責務である。cutover により external consumer が動作しなくなっても、それだけを理由に rust_auth0_service rollback を自動発動しない。rust_auth0_service rollback は external consumer を自動復元せず、同名 Secret の存在だけを理由に他 workloadへ Secret を同期しない。
- 一括切替チェックリストを作成し、SQL本文やShell本文を本タスクリストへ転記しない。

**検証**

- 隔離したリハーサル対象で成果物の順序、入力、出力、失敗停止点をレビューする。

**完了条件**

- 既存internal_user_id維持、全旧ログイン状態無効、全体ロールバックだけを明示できる。上記の sequence high-water、runtime DB grants、shared Redis safety、Cookie expiry、Redis version decision、`nodejs-room` migration rollback scopeを成果物として検証できる。RETIRE consumerの復元参照はauthentication rollback成果物へ混在させない。データ変換、sequence調整、旧users削除は通常migrationに含めず、通常起動、Pod再起動、アプリ更新によって再実行されない。

### T22. 単体検証の整備

**目的**

認証処理の不変条件を最小の代表テストで固定する。

**前提**

T02–T17が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- `portal_backend/src/main.rs`

**実施内容**

- 参照値、hash、定数時間比較、PKCE、Unix秒、入力上限、LoginStart、LocalSessionの代表単体テストを追加する。
- テスト件数を目的化せず、境界ごとの不変条件をまとめる。

**検証**

- 各crateのT01で固定したテスト方法で実行する。

**完了条件**

- 認証の基本入力・期限・状態遷移の回帰を単体で検出できる。

### T23. PostgreSQL・Redis統合検証の整備

**目的**

保存層の正本・原子性・障害停止を実環境相当で確認する。

**前提**

T06–T08、T20が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- `postgres/postgres-init-sql.yaml`
- `redis/create_redis.yaml`

**実施内容**

- PostgreSQL本人解決、競合再読込み、無効サービス・無効ユーザー、DB障害を代表ケースで検証する。
- Redis期限、callback二重処理、handoff再利用・同時交換、Redis障害を代表ケースで検証する。

**検証**

- T01で固定したローカルPostgreSQL・Redis検証方法で実行する。

**完了条件**

- DB・Redisの失敗が認証成功、Googleへのfallback、LocalSession作成へ進まない。

### T24. HTTP・ブラウザフロー統合検証の整備

**目的**

新しいサービス境界を越える認証フローを確認する。

**前提**

T12、T15–T20が完了している。

**主な変更対象**

- `rust-auth0-service/src/main.rs`
- `portal_backend/src/main.rs`
- `portal/src/App.vue`

**実施内容**

- 正常ログイン、SSO、LoginStart不一致、別ブラウザ、PKCE不一致、期限切れ、handoff交換レスポンス喪失、ローカルログアウト、共通ログアウトを検証する。
- Cookie属性、Cache-Control、Referrer-Policy、旧JWT拒否、旧Cookie拒否、旧API不存在、uniauth不存在を確認する。

**検証**

- HTTP統合とブラウザフローで、portalのログインから保護APIまでを確認する。

**完了条件**

- 新経路だけで認証・SSO・失効が成立し、旧クライアント状態は利用できない。

### T25. Kubernetes配置と一括移行リハーサル

**目的**

本番と同じ構成で配置条件と移行手順の成立を確認する。

**前提**

T21–T24が完了している。

**主な変更対象**

- `rust-auth0-service/yaml/deploy.yaml`
- `rust-auth0-service/yaml/ingress.yaml`
- `portal/k8s/frontend-configmap.yaml`
- `portal_backend/k8s/deploy.yaml`
- `portal_backend/k8s/backend-networkpolicy.yaml`
- `portal_backend/k8s/backend-configmap.yaml`

**実施内容**

- 1 replica、Recreate、Secret、NetworkPolicy、DB・Redis非公開と、`Cloudflare Tunnel -> frontend-service -> frontend Nginx -> portal_backend`のactual portal chainを配置検証する。Ingress path ruleの存在だけをroutingの証拠にせず、auth側はT20後のactual route集合を確認する。
- T21のバックアップ、データ変換、登録、旧状態失効、復元確認、ロールバック手順を一括移行リハーサルで検証する。
- 旧イメージdigestを使った全体ロールバック、新しいロールバック用JWT_SECRETで旧JWT認証機能が起動すること、移行前JWTが新しいJWT_SECRETで拒否されること、ロールバック後も全利用者へ再ログインを要求することを確認する。

**検証**

- Kubernetes配置とリハーサル中の正常ログイン、SSO、再起動、障害停止を確認する。

**完了条件**

- Gate Eの全条件を満たし、本番一括切替の入力が確定している。

### T26. 一括切替の実施

**目的**

承認済み成果物を本番へ適用する運用タスクとして、新認証基盤へ一度で切り替える。

**前提**

Gate Eを通過している。

**主な変更対象**

- T21で作成した一括切替チェックリスト
- T21で作成したデータ移行成果物
- T18〜T20で完成し、T25で検証済みの配備成果物

**実施内容**

- T21の一括切替チェックリストを順に実行し、バックアップ、migration、初期登録、配備、旧状態無効化、公開後確認を行う。
- T18〜T20の承認済み成果物を一括適用し、Cloudflare TunnelからServiceへの既存edge構成のまま新経路を公開する。T26でCloudflare routingを再設計しない。
- T26は唯一のproduction一括切替境界である。rust_auth0_service は Auth Foundation、portal deployment/config、auth DB migration、RegisteredWebService、own Secret、auth Redis migration/invalidation、own routing、legacy auth shutdown、および own rollback を一括適用する。T26 は rust_auth0_service-owned scope のみを対象とし、external workload を直接 mutation しない。
- known external legacy JWT consumer の migration、repair、retirement、external owner completion confirmation、coordinated external cutover confirmation は T26 の prerequisite ではない。legacy auth shutdown は、legacy JWT consumer との互換性を意図して破る accepted breaking change として実施する。
- 問題時はT21で定義した全体ロールバックだけを行い、部分互換や二重運用を開始しない。
- T26実施中に新しいコード、SQL、Lua、YAMLをその場で修正しない。問題が見つかった場合は作業を止め、承認済みの全体ロールバックを行う。

**検証**

- T25と同じ公開後代表フロー、旧状態拒否、監視対象を確認する。

**完了条件**

- 新構成だけが稼働し、旧認証状態と旧経路が利用不能である。

## 5. 統合検証

検証はT22の単体、T23のPostgreSQL統合・Redis統合、T24のHTTP統合・ブラウザフロー、T25のKubernetes配置・一括移行リハーサルに分ける。正常ログイン、SSO、LoginStart不一致、別ブラウザ、PKCE不一致、無効サービス、無効ユーザー、handoff期限切れ・再利用・同時交換、callback二重処理、Redis障害、PostgreSQL障害、portal_backend再起動、handoff交換レスポンス喪失、ローカルログアウト、共通ログアウト、旧JWT・旧Cookie・旧API・uniauthの拒否を、該当タスクの最小代表ケースとして確認する。

## 6. 一括移行

T05の通常schema migrationで新3テーブルを作成する。T21では事前検査、users変換、sequence調整、users削除、サービス初期登録、Secret生成、旧Redisキー処理、バックアップ・復元、Cookie失効、不変なロールバック成果物、一括切替チェックリストを成果物化する。T25で同じ順序をリハーサルし、Gate E通過後にだけT26で一括切替する。移行中の障害に対して互換経路、二重書込み、部分ロールバックは使わない。

## 7. 完了条件

- rust-auth0-serviceが唯一の認証基盤サービスである。
- uniauthが独立サービスとして存在しない。
- PostgreSQLの認証アプリケーションテーブルが3個である。
- Redisキー種類が4個で、Lua操作が5個である。
- JWT発行・検証およびJWT_SECRETが存在しない。
- 親ドメイン共有Cookieが存在しない。
- portalとportal_backendが同一オリジンである。
- portal_backendが1 replica・Recreateであり、再起動でローカル状態が失効する。
- 旧API、旧usersテーブル、旧ログイン状態が存在せず、既存internal_user_idが維持される。
- 互換コード、二重書込み、fallback、feature flagが存在しない。
