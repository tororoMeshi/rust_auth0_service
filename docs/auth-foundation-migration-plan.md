# 認証基盤移行方針

## 1. 移行原則

本移行は、計画停止を伴う一括切替で実施する。切替時点を境に旧認証を完全に停止し、新構成だけを稼働させる。既存のログイン状態は失われることを受け入れ、全利用者に再ログインを要求する。

互換処理は採用しない。新旧 API・Cookie・JWT・ローカルセッション・Redis キー・DB テーブルの併用、二重書込み、読込み fallback、段階的ユーザー移行、長期間の feature flag、compatibility adapter、旧エンドポイント用ラッパー、旧セッション変換、旧 JWT の継続利用を行わない。旧版と新版が混在して認証処理を行う時間を設計しない。

正本は `docs/auth-foundation-spec.md` および `docs/auth-foundation-storage-design.md` とする。現行実装との差分は、正本を変更する根拠ではなく移行対象として扱う。認証基盤の永続正本は PostgreSQL、期限付き認証処理状態の正本は Redis とし、認証基盤が所有するアプリケーションテーブルは、`internal_users`、`external_identities`、`registered_web_services` の3個だけである。これはマイグレーション管理用メタデータなど、フレームワークが所有する管理テーブルを数える意味ではない。

停止範囲は、移行中にログインまたは認証状態が変化しないことを優先して決める。現行では `portal` が認証サービスへ直接遷移し、`portal_backend` が JWT Cookie を保護 API の認証に用いるため、最も単純で安全な切替は認証を利用する Web サービス全体をメンテナンス状態にすることである。業務機能だけを残す場合も、旧認証への新規アクセス、保護 API、ログアウトを確実に停止できることを事前確認の条件とし、新旧認証の並行稼働を理由に停止範囲を縮小しない。

## 2. 現在実装の移行対象

確認対象は現行ブランチの `rust-auth0-service`、`uniauth`、`portal_backend`、`portal` と、これらの関連設定である。現行の `rust-auth0-service` は `GET /auth/google` と Google callback を提供し、任意 redirect と `ALLOWED_REDIRECT_ORIGINS`、`POST_LOGIN_REDIRECT` を扱い、`.tororomeshi.net` の `session_id`・`jwt` Cookie を発行する。`uniauth` は `/upsert_and_token` で `users` を Google ID で upsert し、JWT とランダム `session_id` を発行して、Redis に session ID をキーとする JSON を保存する。`/sessions/verify` と旧 `/logout` はこの旧セッションを扱う。`portal_backend` は `jwt` Cookie と `JWT_SECRET` による HS256 検証を行う。これらはすべて削除または新構成へ置換する移行対象である。

| コンポーネント | 旧責務 | 新責務 | 切替時に削除するもの |
|---|---|---|---|
| rust-auth0-service | Google 認証開始・callback、共有 Cookie 発行、`uniauth` 呼出、旧 `/auth/logout` | 認証基盤のブラウザ向け論理責務の仮配置。`GET /auth/login`、Google callback、登録済み callback、共通セッション、`GET /auth/logout` と `POST /auth/logout` を担当 | `/auth/google`、任意 redirect、`ALLOWED_REDIRECT_ORIGINS`、`POST_LOGIN_REDIRECT`、親ドメイン Cookie、`session_id`・`jwt` Cookie、`uniauth` の旧 API 呼出 |
| uniauth | `users` upsert、JWT 発行、旧 Redis JSON セッション、`/sessions/verify`、旧 `/logout` | 認証基盤の永続データ・サービス資格情報・Redis 原子操作の論理責務の仮配置。`POST /auth/handoffs/exchange` を担当 | `/upsert_and_token`、`/sessions/verify`、旧 `/logout`、JWT 発行、`JWT_SECRET`、旧 JSON セッション読み書き |
| portal_backend | `jwt` Cookie を検証して保護 API の利用者情報を返す | Web サービスの LoginStart、handoff 交換、host-only ローカルセッション、保護 API、`POST /logout` を担当 | JWT 検証、`JWT_SECRET`、共有 `jwt` Cookie 依存 |
| portal | 認証サービスの `/auth/google?redirect=...` へ直接遷移し、共有 Cookie を前提に `/api/me` を利用 | 登録済み Web サービスとして `GET /auth/login` を開始し、Web サービスのローカルログアウトを使う | `/auth/google` への遷移、任意 redirect、共有 Cookie 前提 |

`rust-auth0-service` と `uniauth` を物理的に統合するかは本計画で決めない。上表の仮配置は、必要な論理責務を漏れなく実装・配備・検査するためのものに限る。

初期登録サービスは少なくとも `portal` と `portal_backend` を一つの Web サービスとして確認する。現行の外部認証 host は `https://auth.tororomeshi.net`、Google callback は `https://auth.tororomeshi.net/auth/google/callback`、本番 portal は主に `https://portal.tororomeshi.net` である。一方、現行フロントエンドには `https://app.tororomeshi.net/dashboard` への redirect 記述もあり、開発時は `localhost` の認証・フロントエンド・バックエンド既定値がある。このため、登録する本番 login callback URI と logout 後 URI は推測せず、portal の実配信 host、backend の callback 受信経路、開発環境の host・port ごとに完全一致 URI を確定して登録する。Google 側の callback URI も新構成の確定値へ更新する。

`portal` の Dashboard は email、name、picture を表示し、現行では JWT の claims を使う `portal_backend` の `/api/me` がその値を返す。初期の新構成では、プロフィール用 DB、プロフィール移行、外部属性保存を追加しない。`portal_backend` の認証後レスポンスは認証状態、`internal_user_id`、`authenticated_at`だけを基準にし、旧JWT Claimsに由来する email、name、picture への依存を削除する。`portal` の Dashboard から email、name、picture の必須表示を削除する。プロフィールが必要になった場合は将来 portal 側の独立した機能として設計し、認証基盤の `internal_users` または `external_identities` へプロフィール列を追加しない。

## 3. 事前検査

T21 を開始する前に、legacy uniauth JWT を直接検証する4 consumerの canonical decision を実装完了する。`stateless-chat/nodejs-room` は **MIGRATE**、`stateless-chat/websocket-chat-api`、`jamaica/play-matching`、`jamaica/matchmaking` は **RETIRE** であり、UNKNOWN は0件である。これは新番号付きtaskではなく、(A) nodejs-room auth migration、(B) unpublished stateless-chat branch retirement、(C) Jamaica legacy matching retirement の3論理作業である。依存は `T20 -> A/B/C -> final Gate D -> T21` とし、A/B/Cがすべて完了するまで Gate D は **REOPENED / BLOCKED**、T21 implementation readiness は **BLOCKED** とする。新 Auth Foundation は legacy JWT を発行せず、既存 JWT の互換発行、generic shared JWT、compatibility layer は採用しない。

`nodejs-room` は `chat.tororomeshi.net -> Cloudflare Tunnel -> nodejs-room` の実公開chat経路であり、live static clientも `/socket.io/` を使用するためMIGRATEとする。chat appは自身のlocal sessionを、Auth Foundationはcommon SSO sessionを所有し、legacy parent-domain JWTを使わない。現状の2 replicasとprocess-memory room/message stateは移行前提として記録するが、1 replica化またはRedis local sessionの採用は実装前調査で最小構成を決めるまで固定しない。

`websocket-chat-api` はDNSが存在してもCloudflare Tunnel hostname設定、有効IngressClass、Ingress status/addressがなく、外部到達経路を持たない。参照する`chat-frontend`も公開されておらず、直近720h request evidence、Redis DB0 state、nodejs-room置換完了の明示証拠もないためRETIREとする。Deploymentだけを削除せず、`chat-frontend`、`stateless-chat.tororomeshi.net`用Ingress、websocket-chat-apiのService/Deployment/config等を含む未公開系統のexact retirement scopeを実装前調査で決める。本書ではactual file一覧を推測しない。

`play-matching` はcurrent caller、external route、persistent state、直近720h request evidenceがなく、current Jamaica frontend/proxyにも接続されていないためRETIREとする。`matchmaking` は `browser -> POST /api/matchmaking/get_matches -> jamaica-game -> http://matchmaking:8081/get_matches` に対し、実serviceが `matchmaking:8080 -> Pod:8080` でcurrent intended pathが成立せず、CPU player runtime、cluster-wide direct consumer、720h request evidence、persistent stateもないためRETIREとする。Deployment/Serviceだけを削除せず、`jamaica-game`のruntime proxy、frontend/template、config/env、manifest、source/build referenceを含むexact deletion scopeを実装前調査で確定し、壊れた`MATCHMAKING_SERVICE_URL`、`/api/matchmaking/*`、5秒polling等を意図的に残さない。本書では具体fileを推測しない。

切替開始前に、PostgreSQL の切替前バックアップ取得方法と同じバックアップからの復元手順を、対象環境で確認する。復元安全性について、認証データが専用データベースまたは専用スキーマに分離されていること、または復元対象範囲へ書き込むすべてのコンポーネントを停止していることのいずれかを保証する。認証以外の処理が同じ復元対象へ書き込み続けている状態で PostgreSQL バックアップを復元しない。復元によって認証以外のデータを巻き戻す可能性がある場合は、一括切替を開始しない。部分的な新旧認証移行や二重書込みによってこの問題を回避しない。既存 `users` 件数を記録し、切替用 DDL、変換手順、Redis Lua の検証を完了する。実行可能な移行 SQL、Redis 削除スクリプト、Lua 本文は本書には記載しない。

`users` の事前検査では、対象件数、最小・最大 `users.id`、ID の NULL・非正・重複、同じユーザー行の重複、`google_id` の NULL・空文字・重複を検査する。`google_id` は trim 後の空文字も異常として扱う。変換対象件数、作成予定の `internal_users` 件数、作成予定の `external_identities` 件数が元 `users` 件数と一致することも検査する。異常が一件でもあれば仮値で補完せず、移行を開始せずに事前修正を必要とする。

現行コードは `users` から `created_at` を返すが、今回確認した範囲には既存 `users` DDL と値の由来を保証する資料がない。そのため、`created_at` を信頼できる既存作成時刻として利用する前にスキーマ・値品質を確認する。確認できない場合の既定は、すべての `internal_users.created_at` を移行時刻にすることである。

サービス登録について、`portal` と `portal_backend` の本番・開発それぞれの `service_id`、login callback URI、logout 後 URI、認証サービス URL、Google callback URI を実環境設定と照合する。初回登録では、(1) `service_secret` を生成して Web サービスの Secret 管理領域へ配置し、(2) `registered_web_services` へ SHA-256 検証値と完全一致 URI を `is_enabled = false`で登録し、(3) Web サービス側の Secret、`service_id`、callback URI、logout 後 URI の設定値を静的に照合し、(4) 認証基盤側と Web サービス側の設定値が一致したことを確認し、(5) メンテナンス状態を維持したまま `is_enabled = true`へ変更し、(6) 移行済みの既存Googleアカウントで実際の疎通確認を行い、(7) 疎通確認成功後だけ一般利用を再開する。`is_enabled = false` の状態で実際のログインまたは handoff 交換を成功させる設計にはしない。疎通確認のための特別なエンドポイント、管理 API、feature flag は追加しない。平文 Secret を SQL、ログ、文書、URL、Cookie、フロントエンドに記載しない。管理画面、汎用管理 CLI、複数世代 Secret は追加せず、初回登録の最小手段だけを後続実装事項とする。

Redis DB0 は authentication 専用ではなく shared である。確認済み consumer は少なくとも `auth0/rust-auth0-service`、`auth0/uniauth`、`stateless-chat/nodejs-room`、`stateless-chat/websocket-chat-api` である。forward migration と rollback の双方で `FLUSHDB` と `FLUSHALL` を使わず、安全に識別した旧 auth key だけを削除する。uniauth は prefix なし24文字 ASCII 英数字 key（string JSON、`user_id` / `expires_at`、TTL 約24h）、old rust-auth0-service Actix session は prefix なし64文字 ASCII 英数字 key（string JSON map、`oauth_state` 必須、`redirect` 任意、TTL 約24h）として識別する。新しい `auth:external:`、`auth:session:`、`auth:handoff:`、`auth:logout:` は forward 削除対象外である。分類不能 key が一件でもあれば削除せず cutover を停止し、推測・自動修復・自動削除をしない。

production Redis は6.2.6だが canonical storage design は Redis 7+ である。T21 の blocker は、7+ が必要な機能的不変条件を確認して upgrade すること、または単なる選択 baseline なら minimum version requirement を再評価することのいずれかである。shared infrastructure の `redis:7.4.11-alpine` への upgrade は今回固定しない。

次の全項目が満たされない限り一括切替を開始しない。

- PostgreSQL バックアップ取得方法と復元手順が確認済みである。
- 既存 `users` 件数、ID 範囲、`google_id` の NULL・空・重複ゼロ、ID 保持可能性、件数一致が確認済みである。
- 新 DDL、データ変換手順、Redis Lua が検証済みである。
- 新サービス Secret が配置済みで、登録済み callback URI と Google callback URI が設定済みである。
- portal と portal_backend から旧JWT Claimsのemail、name、picture依存が削除され、新しい最小レスポンスで画面が成立することを確認済みである。
- 新コンポーネントの同時配備、旧コンポーネントの停止、最小疎通確認手順が準備済みである。

## 4. PostgreSQL移行

停止中に、切替前バックアップ取得後の `users` を一度だけ `internal_users` と `external_identities` へ変換する。`registered_web_services` はユーザーデータ変換とは別に登録する。`users.id` を新しい `internal_users.internal_user_id` としてそのまま保持し、新しいユーザー ID を発行し直さない。各正常ユーザーについて `internal_users` には `internal_user_id = users.id`、`is_enabled = true`、`created_at = 信頼できる既存時刻、なければ移行時刻` を作成する。

同じユーザーごとに `external_identities` へ `provider = google`、`subject = users.google_id`、`internal_user_id = users.id`、`linked_at = 移行時刻` を一件作成する。`(provider, subject)` の一意性と、各 external identity が有効な internal user を参照することを検証する。email、name、image URL、Google トークン、Google 応答は新しい認証基盤 DB に保存しない。

`internal_users.internal_user_id` は identity を持つ設計であるため、legacy user ID を再利用しない。writer 停止後に、次の採番値を `max(max(users.id) + 1, legacy users_id_seq の実 next value)` として設定する。現在の観測値は `max(users.id) = 36`、legacy sequence next = `125` であるため例示値は125だが、production script に125を hardcode しない。これを実施しないと、将来の新規ユーザー作成が移行済み ID と衝突する。sequence 調整後に次の採番値がこの high-water rule を満たすことを検証する。

新 Auth Foundation runtime role `auth0_app_user` の grant は cutover 成果物で付与する。`internal_users` は `SELECT` / `INSERT`、`external_identities` は `SELECT` / `INSERT`、`registered_web_services` は `SELECT`、`internal_users` identity sequence は `USAGE` に限る。service registration / enable などの運用 write 権限は付与しない。既存 schema migration `001` を変更するかは、この時点で決めない。

`registered_web_services` はデータ変換の副産物にせず、事前検査で確定した初期利用サービスをユーザーデータ変換とは別に一度だけ登録する。登録行には有効な `service_id`、完全一致の login callback URI、完全一致の logout 後 URI、SHA-256 の `service_secret` 検証値を持たせ、接続確認が終わるまでは `is_enabled = false` とする。Secret 平文は DB、ログ、文書、URL、Cookie、フロントエンドに保存しない。

変換後、件数、ID、外部 ID、一意制約、外部キーを検証し、identity sequence を調整して次の採番値を検証する。その後、旧`users`テーブルを切替中に削除する。旧 `users` テーブルを読取り専用、退避名、互換用として DB 内へ残さない。旧データが必要な場合は切替前の PostgreSQL バックアップだけを使用し、ロールバックはバックアップ復元で行う。新 DB の一部データを旧 DB へ逆変換するロールバック方式は作成しない。

## 5. Redis・Cookie・JWTの破棄

旧 Redis セッションを新方式へ変換しない。旧 `session_id` を `auth:session:` へ変換せず、旧 JSON セッションを Redis Hash へ変換せず、旧 OAuth 途中状態も引き継がない。旧ログイン途中の利用者は最初からやり直す。切替時は安全に識別した旧認証キーを削除し、新構成の `auth:external:*`、`auth:session:*`、`auth:handoff:*`、`auth:logout:*` は空から開始する。旧キーが残存しても新方式はそれを読まないため、残存と Redis 障害を混同しない。

新 Redis の値は設計書どおりの Hash とし、認証基盤の短期状態だけを保存する。Redis 障害時や Lua の検証失敗時は認証を成功扱いにしない。新旧 Redis キーの二重書込み、読込み fallback、変換処理は行わない。

切替時に `.tororomeshi.net` の親ドメイン共有 Cookie `jwt` と `session_id`（いずれも `Domain=.tororomeshi.net; Path=/`）、旧 JWT、`JWT_SECRET` による認証経路、`portal_backend` の旧 JWT 検証を無効化する。T21/T25/T26 の browser expiry artifact は必要だが、これだけを目的とする新しい恒久 runtime endpoint は追加しない。旧 Actix Cookie `id` は host-only `auth.tororomeshi.net; Path=/; Secure; HttpOnly; SameSite=Lax` であり、旧 Actix Redis session 削除、旧 runtime 停止、新 runtime が読まないことにより server-side invalidation を成立させる。新構成が使用する Cookie は、認証基盤 host-only 共通セッション Cookie と、各 Web サービス host-only ローカルセッション Cookie だけである。いずれも正本設計に従い `HttpOnly`、`Secure`、`SameSite=Lax` とし、親ドメインを設定しない。

旧 Cookie の明示削除は、親ドメイン Cookie を発行した host と Domain 属性に対してのみ有効であるため、対象ブラウザに確実に届けられる通常の新版レスポンスで一回限りに失効できるかを切替前に確認する。必要な場合も、旧 Cookie 削除だけを目的とする互換エンドポイントは作らず、通常の新版ログイン開始、callback、logout またはエラー応答で失効を返す方式を検討する。旧 Cookie が残っていても、新構成が参照しないことで認証成功にならないことを不変条件とする。

## 6. 一括切替手順

1. 事前検査の全ゲートを満たし、切替責任者、停止開始時刻、復元判断時刻を確定する。新コンポーネント、サービス登録、Secret、Google callback URI、メンテナンス表示を配備可能な状態にするが、旧認証と同時に有効化しない。
2. 旧認証への新規アクセスを停止する。認証を利用する Web サービスをメンテナンス状態にし、旧 `/auth/google`、`/upsert_and_token`、`/sessions/verify`、旧 `/logout`、保護 API 経由の認証状態変更を受け付けない。
3. PostgreSQL の切替前バックアップを取得し、取得結果と復元対象を記録する。
4. 停止状態の `users` を事前検査済みの手順で `internal_users` と `external_identities` へ一括変換する。件数、ID、外部 ID、一意制約、外部キーを検証し、identity sequence を調整して検証する。異常または不一致ならサービスを再開せず、ロールバック判断へ進む。
5. 検証後、旧`users`テーブルを切替中に削除する。旧表を DB 内へ残さず、旧データを必要とする場合は切替前 PostgreSQL バックアップだけを用いる。
6. shared Redis DB0 から安全に識別した旧認証 key だけを削除する。`FLUSHDB` / `FLUSHALL`、認証専用領域の一括破棄、旧状態の変換は行わない。分類不能 key が一件でもあれば削除せず cutover を停止する。
7. 新しい全コンポーネントを一括配備し、旧コンポーネントを一括停止したままにする。新 API だけを公開し、旧 API、JWT 発行・検証、`JWT_SECRET`、親ドメイン Cookie 設定、任意 redirect、`ALLOWED_REDIRECT_ORIGINS` を残さない。
8. `portal` と `portal_backend` の Web サービス Secret、PostgreSQL の SHA-256 検証値、完全一致 URI を静的に照合し、認証基盤側と Web サービス側の設定値が一致したことを確認する。設定が一つでも欠ければ有効化しない。
9. サービス再開前の疎通確認として、メンテナンス状態を維持したまま `registered_web_services` を `is_enabled = true`へ変更する。第7章の最小疎通確認だけを実施し、Google ログイン試験には移行済みの既存Googleアカウントを使用する。そのアカウントが `external_identities` に既に存在することを事前確認する。ロールバック判断が完了するまで、未登録 Google アカウントによるログインを許可せず、疎通確認によって新しい `internal_users` または `external_identities` を作成しない。新規登録を一時的に制御する feature flag は設けず、メンテナンス中に検査用の既存アカウントだけを使う運用手順とする。
10. 疎通確認成功とロールバック不要の判断後、Web サービスのメンテナンスを解除してサービスを再開する。全利用者には新構成での再ログインを要求する。

## 7. 疎通確認とロールバック

サービス再開前の最小疎通確認は次だけとする。

Google ログインを含む確認には移行済みの既存Googleアカウントだけを使用し、対象が `external_identities` に既に存在することを開始前に確認する。ロールバック判断が完了するまで未登録 Google アカウントのログインは許可せず、疎通確認によって新しい `internal_users` または `external_identities` を作成しない。

1. 未ログイン状態で保護 API が拒否される。
2. Google ログインを開始できる。
3. Google callback を処理できる。
4. handoff を一回だけ交換できる。
5. Web サービス側ローカルセッションが作成される。
6. ページ再読込後もログイン状態を維持する。
7. SSO により Google 再認証を省略できる。
8. ローカルログアウトが当該サービスだけを終了する。
9. 共通ログアウト後に新しい handoff を取得できない。
10. 使用済み handoff を再交換できない。
11. 旧 JWT と旧 Cookie で認証できない。

確認中に失敗した場合、または完了条件を満たせない場合は、互換処理や部分ロールバックを行わず、全体ロールバックだけを許可する。PostgreSQL 復元は、認証データが専用データベースまたは専用スキーマに分離されていること、または復元対象範囲へ書き込むすべてのコンポーネントを停止していることを確認してから行う。認証以外の処理が同じ復元対象へ書き込み続けている状態で復元せず、認証以外のデータを巻き戻す可能性がある場合は切替を開始しない。部分的な新旧認証移行や二重書込みによってこの問題を回避しない。

ロールバック手順は次の順とする。

1. 新コンポーネントを停止する。
2. PostgreSQL を切替前バックアップへ復元する。
3. shared Redis DB0 から安全に識別した新認証 state だけを削除する。`FLUSHDB` / `FLUSHALL` は使わず、分類不能 key が一件でもあれば rollback を停止する。
4. ロールバック用の新しい`JWT_SECRET`を生成して Secret 管理領域へ配置する。
5. 旧コンポーネントを、新しい `JWT_SECRET` で一括再配備する。
6. 全利用者へ再ログインを要求する。

旧構成へ戻す場合も、移行前の`JWT_SECRET`を再利用しない。ブラウザに移行前の旧 JWT が残っていても、新しい `JWT_SECRET` では検証に成功しないようにする。Redis セッションの削除だけで旧 JWT が失効するとは扱わない。新旧混在状態での部分ロールバック、新 DB の一部データから旧 DB への逆変換、旧セッションまたは旧 JWT の継続利用を禁止する。MIGRATEである`nodejs-room`のrollback scopeは移行実装とともに確定する。RETIRE consumerは通常のAuth Foundation rollbackで自動復活させず、retirement decision自体を戻す場合にだけpre-retirement manifest、image digest、source commitを参照して扱う。これはT21のauthentication rollbackへ混在させない。ロールバックは旧認証機能を復旧するものであり、移行前のログイン状態を復元するものではない。

ロールバック判断は、新構成で新しいユーザーが作成される前に完了する。この順序により、バックアップ復元後の新規ユーザー差分を扱う必要を作らない。ロールバック後は旧構成へ一括復帰するため、再切替は新しい停止計画としてあらためて実施する。

## 8. 完了条件

移行完了は、次のすべてを満たす状態とする。

- 新 API だけが存在し、旧 `/auth/google`、`/upsert_and_token`、`/sessions/verify`、旧 `/logout` は呼出不能である。
- rust_auth0_service repo/auth0 scope で JWT 発行・検証コードと `JWT_SECRET` が不要であり、親ドメイン共有 Cookie を設定しない。system 全体の legacy JWT dependency の不存在は、全 downstream consumer resolution 完了後にだけ主張できる。
- `nodejs-room` がnew Auth Foundation flowで認証可能であり、`websocket-chat-api`、`play-matching`、`matchmaking` がretiredである。runtime全体でlegacy `JWT_SECRET` consumer、legacy `jwt` Cookie verifier、HS256 legacy auth verifierが0件である。
- 旧 Redis 認証キーが存在せず、新 Redis は `auth:external:*`、`auth:session:*`、`auth:handoff:*`、`auth:logout:*` の新しい短期状態だけを扱う。
- 旧`users`テーブルが存在しない。
- 認証基盤が所有するアプリケーションテーブルは `internal_users`、`external_identities`、`registered_web_services` の3個だけである。
- 全既存ユーザーの `internal_user_id` が元の `users.id` と一致し、全既存 Google ID が `external_identities` に一対一で対応する。
- Web サービスが handoff 交換後に host-only ローカルセッションを作成し、共通認証 Cookie と Web サービス Cookie を共有しない。
- すべての旧ログイン状態が無効であり、利用者は次回アクセス時に新構成での再ログインを要求される。
- rust_auth0_service repo/auth0 scope に移行前の `JWT_SECRET` が残っておらず、ロールバック時も移行前 JWT を再び有効にしない。
- 疎通確認は移行済み既存ユーザーで完了しており、新規ユーザー作成を許可する前にロールバック判断が完了している。
- portal と portal_backend が旧JWT Claimsのemail、name、pictureへ依存していない。
- 互換コード、feature flag、二重書込み、読込み fallback、新旧並行稼働が残っていない。
