# 認証基盤設計仕様

## 1. 目的と範囲

認証の責務と、Webサービスの責務を分離する。

この認証基盤は、複数の独立したWebサービスに共通の本人確認とSSOを提供する。現在接続する外部認証プロバイダーはGoogleだけとする。

認証基盤が担当する範囲は次のとおりである。

- Googleによる本人確認
- 外部の本人と内部ユーザーの対応付け
- 共通認証セッション
- Webサービスへの一回限りの認証引き渡し
- Webサービス登録とバックチャネル認証
- 共通ログアウトと認証基盤側の失効

各Webサービスが担当する範囲は次のとおりである。

- ログイン開始状態
- Webサービス固有のローカルセッション
- Webサービス固有のプロフィール、ロール、権限、業務データ
- ローカルログアウト
- 認証後の画面と業務処理

初期実装では、次を作らない。

- Google以外の外部プロバイダー
- 動的なWebサービス登録
- 管理画面
- アカウント統合UI
- 汎用OIDC Provider
- refresh token
- 一般的な失効照会API
- 全Webサービスへのログアウト通知
- 将来利用するかもしれない機能の空実装

## 2. システム境界

公開契約だけを共有し、内部状態は共有しない。

```text
Google
  |
  v
+------------------------------+
| 共通認証基盤                 |
|                              |
|  外部プロバイダー接続        |
|          |                   |
|          v                   |
|  内部認証コア                |
|                              |
|  PostgreSQL / Redis          |
+------------------------------+
          |
          | 公開API
          v
+------------------------------+
| 各Webサービス               |
|                              |
|  バックエンド                |
|  ローカルセッション          |
|  フロントエンド              |
+------------------------------+
```

外部プロバイダー接続と内部認証コアは、論理的に分離する。別プロセス、別Pod、別Deploymentにするかは、この設計では固定しない。

各Webサービスは次を行わない。

- Google OAuthを直接処理する
- 認証基盤のPostgreSQLまたはRedisを直接参照する
- 認証基盤の共通認証セッションを直接利用する
- 認証基盤のCookieを共有する
- 認証結果を発行できる秘密鍵を保持する
- 外部プロバイダーのトークンを受け取る
- 認証基盤の内部データ構造へ依存する

`portal`と`portal_backend`は、認証基盤を利用する参照Webサービスであり、認証基盤そのものではない。

## 3. 永続的な識別モデル

本人識別は、外部IDと内部ユーザーを分ける。

### 3.1 InternalUser

`InternalUser`は、認証基盤が発行する内部ユーザーである。

概念上、次を持つ。

```text
InternalUser
- internal_user_id
- status
- created_at
```

`internal_user_id`は、Google ID、メールアドレス、WebサービスIDと兼用しない。

初期状態は、少なくとも`active`と`disabled`を区別できればよい。詳細なユーザーライフサイクルは後続で決める。

### 3.2 ExternalIdentity

`ExternalIdentity`は、外部プロバイダー上の本人と`InternalUser`の対応である。

```text
ExternalIdentity
- provider
- subject
- internal_user_id
- linked_at
```

外部本人は`(provider, subject)`で一意に識別する。

- `subject`単独では一意とみなさない
- 一つの`ExternalIdentity`を複数の`InternalUser`へ結び付けない
- メールアドレスで自動統合しない
- 外部アクセストークンとリフレッシュトークンを標準では永続保存しない

Googleから得たメールアドレス、確認状態、表示名、画像URLは任意の観測属性である。本人識別の主キーには使用しない。保存するかは後続で決める。

### 3.3 NormalizedExternalIdentity

外部プロバイダー接続から内部認証コアへ渡す境界入力である。永続テーブルそのものではない。

```text
NormalizedExternalIdentity
- provider
- subject
- email?
- email_verification
- display_name?
- picture_url?
```

`provider`と`subject`だけを必須とする。`email_verification`は`verified`、`unverified`、`unknown`を区別し、未取得を`unverified`として扱わない。任意値を取得できない場合に空文字や架空値で補完しない。

### 3.4 RegisteredWebService

初期実装では、一つの登録サービスに一つのログインcallback URIと一つのログアウト後URIを登録する。

```text
RegisteredWebService
- service_id
- status
- login_callback_uri
- logout_return_uri
- service_secret_verifier
```

- `service_id`は認証基盤が管理する安定した識別子とする
- `status`は少なくとも`active`と`disabled`を区別する
- URIは完全なURIを登録し、実行時に部分一致やワイルドカード判定を行わない
- 開発環境と本番環境でURIが異なる場合は、別の`service_id`として登録してよい
- `service_secret`の平文は認証基盤へ保存せず、不可逆な検証情報だけを保存する
- 平文の`service_secret`は各WebサービスのSecret管理領域だけに置く
- `service_secret`は認証結果の署名鍵ではない
- 初期実装では一つのサービスにつき一つの有効な`service_secret`だけを持つ

## 4. 状態モデル

状態は、所有者と正本が異なる単位に分ける。

| 状態 | 所有者 | 正本 | 最小状態 |
|---|---|---|---|
| Webサービス側ログイン開始状態 | 各Webサービス | 各Webサービス | 未使用、使用済み、期限切れ |
| 外部認証トランザクション | 認証基盤 | Redis | 待機中、処理中 |
| 共通認証セッション | 認証基盤 | Redis | 有効 |
| AuthenticationHandoff | 認証基盤 | Redis | 未使用、使用済み |
| 共通ログアウト一時状態 | 認証基盤 | Redis | 未使用、使用済み |
| Webサービス側ローカルセッション | 各Webサービス | 各Webサービス | 有効 |

`不在`、`未認証`、`終了`は、必ずしも保存レコードを意味しない。レコードが不要になった場合は削除または期限切れで表現する。

### 4.1 Webサービス側ログイン開始状態

Webサービスバックエンドが所有する。

```text
LoginStart
- state
- browser_context_reference
- code_verifier
- post_login_path
- created_at
- expires_at
- usage_status
```

`LoginStart`は、ログインを開始したブラウザの一時セッションへ結び付ける。`state`が存在しても、別のブラウザコンテキストからは利用させない。

`post_login_path`は、Webサービス内の安全な相対パスだけを保存する。認証基盤へ渡さない。

### 4.2 外部認証トランザクション

認証基盤がGoogle callbackを一回だけ処理するための短期状態である。

```text
ExternalAuthTransaction
- provider_transaction_id
- service_id
- service_state
- handoff_code_challenge
- provider
- provider_callback_state
- provider_verification_data
- created_at
- expires_at
- processing_status
```

Webサービスの`state`と、Google callback用の内部stateを兼用しない。

### 4.3 共通認証セッション

認証基盤が所有するSSO状態である。

```text
CommonSession
- session_reference
- internal_user_id
- authenticated_at
- created_at
- expires_at
```

共通認証セッションは絶対有効期限を持つ。アクセスのたびに期限を延長しない。

### 4.4 AuthenticationHandoff

特定のWebサービスへ認証結果を一回だけ渡す短期状態である。

```text
AuthenticationHandoff
- code_lookup_key
- service_id
- internal_user_id
- common_session_reference
- code_challenge
- authenticated_at
- issued_at
- expires_at
- usage_status
```

ブラウザへ渡す`handoff_code`の平文は保存せず、不可逆に導出した検索用キーを保存する。

交換失敗だけでは使用済みにしない。正規の交換が成功した場合だけ使用済みにする。使用済みの検索用キーは、少なくとも元の有効期限までは残し、重複交換を使用済みとして判定できるようにする。

### 4.5 共通ログアウト一時状態

GETで検証したログアウト先と、POSTによる実行を結び付ける。

```text
CommonLogoutTransaction
- logout_transaction_reference
- service_id
- logout_return_uri
- csrf_verification_data
- created_at
- expires_at
- usage_status
```

### 4.6 Webサービス側ローカルセッション

各Webサービスが所有する期限付き状態である。

```text
LocalSession
- local_session_reference
- internal_user_id
- authenticated_at
- created_at
- expires_at
```

Cookieには`local_session_reference`だけを保存する。ユーザーID、ロール、権限をCookieへ直接格納しない。

## 5. 認証フロー

認証基盤はSSOを管理し、Webサービスは自サービスのログイン状態を管理する。

```text
Webサービスバックエンド
  | stateとPKCE verifier/challengeを生成
  | LoginStartを保存
  v
ブラウザ
  | GET /auth/login
  v
認証基盤
  | 有効な共通認証セッションあり
  |   -> Google認証を省略
  | 有効な共通認証セッションなし
  |   -> Google認証を実行
  v
AuthenticationHandoffを発行
  | codeとstateを登録済みcallbackへ返す
  v
Webサービスバックエンド
  | stateを検証してLoginStartを使用済みにする
  | codeとcode_verifierをバックチャネル交換
  v
認証基盤
  | Webサービス、code、PKCE、期限、共通セッションを検証
  | handoffを原子的に使用済みにする
  v
Webサービスバックエンド
  | internal_user_idを受領
  | LocalSessionを作成
  v
ブラウザ
  | Webサービス固有Cookieを保持
```

### 5.1 ログイン開始

Webサービスバックエンドは、次を生成して`LoginStart`へ保存する。

- 推測困難な`state`
- 推測困難な`code_verifier`
- `code_verifier`からS256で導出した`code_challenge`
- 認証後の安全なWebサービス内遷移先
- ログインを開始したブラウザコンテキストとの結び付き
- 有効期限

ブラウザを次へ遷移させる。

```http
GET /auth/login?service_id=...&state=...&code_challenge=...&code_challenge_method=S256
```

認証基盤は`service_id`から登録済み`login_callback_uri`を取得する。ブラウザからcallback URIを受け取らない。

### 5.2 SSO

認証基盤Cookieから有効な共通認証セッションを正常に読み取れた場合、Google認証を省略して新しい`AuthenticationHandoff`を発行する。

共通認証セッションが存在しない場合だけGoogle認証へ進む。

Redisの読込失敗は、セッション不在として扱わない。一時障害として終了する。

### 5.3 Google認証

共通認証セッションがない場合、認証基盤は`ExternalAuthTransaction`を作成してGoogle認証を開始する。

Google callbackでは、対応するトランザクションを原子的に`処理中`へ変更してから処理する。同じcallbackを二回成功させない。

Googleから得た情報を検証し、`provider=google`と`subject`を含む`NormalizedExternalIdentity`へ変換してから内部ユーザーを解決する。解決された`InternalUser`が`disabled`なら認証を成立させない。

### 5.4 callback

認証成功後、認証基盤は登録済み`login_callback_uri`へ次だけを返す。

```text
code
state
```

次は返さない。

- `internal_user_id`
- 外部providerとsubject
- メール、表示名、画像URL
- Googleのトークン
- 共通認証セッションID
- JWT
- `service_secret`

Webサービスバックエンドは`state`とブラウザコンテキストを検証する。該当する`LoginStart`が存在しない、不一致、別ブラウザ、期限切れ、使用済みの場合は交換しない。

`state`検証後、`LoginStart`を再利用不能にする。

### 5.5 バックチャネル交換

Webサービスバックエンドは、TLS上で次を呼び出す。

```http
POST /auth/handoffs/exchange
Authorization: Basic base64(service_id:service_secret)
Content-Type: application/json
```

```json
{
  "code": "opaque-handoff-code",
  "code_verifier": "pkce-code-verifier"
}
```

認証基盤は次を検証する。

1. Webサービス資格情報が正しい
2. Webサービスが有効
3. handoffが存在する
4. handoffが期限内かつ未使用
5. handoffの`service_id`が認証済みWebサービスと一致する
6. `code_verifier`が保存済み`code_challenge`と一致する
7. 対応する共通認証セッションが有効
8. 必要な値をすべて正常に取得できた

成功時、handoffの使用済み化と交換結果の確定を一つの原子的処理として扱う。同時交換では一つだけ成功する。

成功レスポンスは次の最小情報とする。

```json
{
  "internal_user_id": "stable-internal-user-id",
  "authenticated_at": "timestamp"
}
```

交換結果は認証トークンとして保存せず、ローカルセッションの作成にだけ使用する。

## 6. 公開API

| 操作 | 呼出主体 | 役割 |
|---|---|---|
| `GET /auth/login` | ブラウザ | SSOまたはGoogle認証の開始 |
| Google callback | Google | 外部プロバイダー接続の内部API |
| Webサービスcallback | ブラウザ | 登録済みWebサービスへの`code`と`state`の返却 |
| `POST /auth/handoffs/exchange` | Webサービスバックエンド | handoffの一回限り交換 |
| Webサービスの`POST /logout` | ブラウザ | Webサービス固有のローカルログアウト |
| `GET /auth/logout` | ブラウザ | 共通ログアウト確認の開始 |
| `POST /auth/logout` | 認証基盤上のページ | 共通ログアウトの実行 |

Google callbackのパスは、Webサービス向けの安定した公開契約ではない。

### 6.1 エラー

バックチャネル交換では、少なくとも次を扱う。

| 状況 | HTTP |
|---|---:|
| JSONまたは必須項目の不備 | 400 |
| Webサービス認証失敗 | 401 |
| Webサービス停止中 | 403 |
| 無効、期限切れ、使用済み、対象不一致、PKCE不一致 | 400 |
| 認証基盤の一時障害 | 503 |

外部へ返すエラーは、攻撃者がコードやサービスの存在を探索できない粒度にまとめてよい。内部DB、Redis、Secret、外部プロバイダーの生エラーは公開しない。

ログイン開始時に`service_id`が不明、停止中、または登録情報を取得できない場合は、認証基盤上で安全に終了する。未検証の外部URIへエラーを返さない。

サービスとcallback URIの確認後に、Google拒否、期限切れ、認証未完了が発生した場合は、登録済みcallback URIへ必要最小限の`error`と元の`state`を返してよい。Googleの生エラーと内部障害の詳細は返さない。

## 7. Cookieとセッション

Cookieはサーバー側状態への参照であり、認証状態そのものではない。

### 7.1 認証基盤Cookie

- host-only
- `Domain`を設定しない
- `Path=/`
- `Secure`
- `HttpOnly`
- `SameSite=Lax`
- 不透明な共通認証セッション参照だけを保存
- JWT、ユーザー属性、権限を保存しない

### 7.2 WebサービスCookie

- 対象Webサービスのhost-only
- `Domain`を設定しない
- `Path=/`
- `Secure`
- `HttpOnly`
- `SameSite=Lax`
- 不透明なローカルセッション参照だけを保存
- 認証基盤Cookieと名前や値を共有しない

### 7.3 JWT

初期方式では次にJWTを使用しない。

- ブラウザへの認証引き渡し
- 認証基盤とWebサービス間の交換結果
- `portal_backend`のローカルセッション

JWTが不要な場所へ署名鍵、Claims、失効規則を追加しない。

## 8. ログアウトと失効

ローカルログアウトと共通ログアウトを分ける。

### 8.1 ローカルログアウト

各Webサービスが`POST /logout`を所有する。

- ローカルセッションを終了する
- WebサービスCookieを削除する
- 認証基盤Cookieを変更しない
- 共通認証セッションを終了しない
- Webサービス自身のCSRF対策を行う

### 8.2 共通ログアウト

共通ログアウトは認証基盤が所有する。

```text
GET /auth/logout?service_id=...
  -> 登録済みlogout_return_uriを取得
  -> CommonLogoutTransactionを作成
  -> 認証基盤上の確認ページを表示

POST /auth/logout
  -> CSRFとCommonLogoutTransactionを検証
  -> 一時状態を使用済みにする
  -> 共通認証セッションを終了
  -> 認証基盤Cookieを削除
  -> 登録済みlogout_return_uriへ戻る
```

GETだけで共通認証セッションを終了しない。

すでに共通認証セッションが存在しない場合も、POSTは安全な冪等操作として完了してよい。

### 8.3 失効の反映

共通認証セッション終了後、新しいhandoffは発行または交換できない。

既存のWebサービス側ローカルセッションは、初期実装では即時に一斉終了させない。各サービスの有効期限またはローカルログアウトによって終了する。

一般的な失効照会API、Webhook、全サービス通知は初期実装へ追加しない。

## 9. 保存先と原子性

PostgreSQL、Redis、Webサービスの保存領域を混在させない。

| 正本 | 保存対象 |
|---|---|
| PostgreSQL | `InternalUser`、`ExternalIdentity`、`RegisteredWebService`、`service_secret`の検証情報 |
| Redis | 外部認証トランザクション、共通認証セッション、AuthenticationHandoff、共通ログアウト一時状態 |
| 各Webサービス | LoginStart、ローカルセッション、プロフィール、認可、業務データ |

Redisは、ここに挙げた短期状態についてキャッシュではなく正本である。同じ短期状態をPostgreSQLへ二重保存しない。

### 9.1 PostgreSQL

新しい外部本人を登録する場合、次を一つのトランザクションで行う。

1. `(provider, subject)`の一意性確認
2. `InternalUser`の作成
3. `ExternalIdentity`の作成
4. 両者の関連付け

一意性競合が発生した場合は、確定済みの対応関係を再読込する。読込または書込に失敗した場合は認証成功にしない。

### 9.2 Redis

次を原子的な論理処理とする。

- Google callbackの処理開始
- 共通認証セッション確認とhandoff作成
- 初回認証時の共通認証セッションとhandoff作成
- handoff検証と使用済み化
- 共通ログアウト一時状態の使用済み化と共通認証セッション終了

具体的なRedisコマンド、トランザクション、Luaの要否は後続で決める。

### 9.3 PostgreSQLとRedisをまたぐ失敗

分散トランザクション、二相コミット、汎用Sagaを導入しない。

基本順序は次とする。

1. 外部認証トランザクションを処理中にする
2. Googleの結果を検証する
3. PostgreSQLで内部ユーザーを解決する
4. Redisで共通認証セッションとhandoffを作成する
5. Cookieとリダイレクトを返す

PostgreSQL成功後にRedisが失敗した場合、作成済みの永続本人データは残す。ただしログイン成功は返さない。再試行時は同じ`ExternalIdentity`から同じ`internal_user_id`を取得する。

Redis成功後にブラウザが応答を受け取れなかった場合、短期状態は期限切れまで残ってよい。配信確認や再送保証は追加しない。

handoff交換後にWebサービスがローカルセッションを保存できなかった場合、handoffは使用済みのままとする。ユーザーは新しいログインを開始する。

### 9.4 期限切れと障害

Redis上のすべての短期状態は、論理的な有効期限とTTLを持つ。

- 物理的に残っていても期限切れなら無効
- Redis読込失敗とエントリ不在を区別
- Redis状態喪失時は認証をやり直す
- 短期状態をPostgreSQLから復元しない
- Redis再起動後の完全復元を初期要件にしない
- 短期状態失敗の補償として永続本人データを削除しない

## 10. セキュリティ不変条件

- 必要な値を取得または検証できない場合は成功にしない
- 保存先障害をデータ不在として扱わない
- 未検証のブラウザ入力を本人情報として扱わない
- callback URIとログアウト後URIは登録済みの完全URIから取得する
- `state`、外部プロバイダー用state、`handoff_code`、PKCE verifierを兼用しない
- LoginStartをログイン開始ブラウザの一時セッションへ結び付ける
- `handoff_code`を対象`service_id`とPKCE challengeへ結び付ける
- 他サービス向けhandoffを交換させない
- 期限切れまたは使用済みhandoffを交換させない
- 正規の交換成功だけがhandoffを消費する
- 同時交換では一つだけ成功させる
- Webサービスへ認証結果の発行権限を渡さない
- `service_secret`をブラウザ、Cookie、URL、ログへ渡さない
- 共通認証CookieとWebサービスCookieを共有しない
- 親ドメイン共有Cookieを使用しない
- Cookie削除だけをサーバー側失効とみなさない
- callback後は`code`を早期に処理し、コードを含まないURLへ遷移する
- 認証関連レスポンスを共有キャッシュへ保存させない
- セッション参照、handoff code、service secret、外部トークン、Google client secretを平文ログへ記録しない
- ログを認証状態の正本にしない
- 不明な状態を成功側へ倒さない

## 11. 現在の実装からの変更方向

| 現在 | 目標 |
|---|---|
| `/auth/google`をWebサービスが直接利用 | Webサービスは`GET /auth/login`を利用し、Google接続を内部化 |
| 任意の`redirect`と`ALLOWED_REDIRECT_ORIGINS` | `service_id`から固定の登録済みcallback URIを取得 |
| `.tororomeshi.net`共有Cookie | 認証基盤と各Webサービスのhost-only Cookie |
| `jwt` Cookie | 一回限りの不透明なhandoff code |
| ブラウザへ`session_id`を共有 | 認証基盤ホストだけの共通セッション参照 |
| `JWT_SECRET`とHS256をサービス間共有 | サービスごとの`service_secret`による交換認証 |
| `/upsert_and_token` | 本人解決、共通セッション作成、handoff作成を責務分離 |
| `/sessions/verify` | 一回限りの`POST /auth/handoffs/exchange` |
| `portal_backend`がJWTを直接検証 | 交換後に自サービスのローカルセッションを作成 |
| 一つの`/logout`で状態を混在 | ローカルログアウトと共通ログアウトを分離 |
| Google固有の`users.google_id` | `InternalUser`と`ExternalIdentity(provider, subject)` |

移行手順と互換期間は別工程で決める。

## 12. 採用しない設計

初期実装では次を採用しない。

- 親ドメイン共有Cookie
- ブラウザへJWTを渡す方式
- Webサービスへ共有署名鍵を配布する方式
- 認証基盤への全リクエスト都度照会
- フロントエンドから交換APIを直接呼ぶ方式
- 外部プロバイダーのトークンをWebサービスへ渡す方式
- mTLS
- JWT client assertion
- 動的クライアント登録
- refresh token
- 複数回取得可能なhandoff
- 交換結果の再取得API
- 複雑な冪等性基盤
- 分散トランザクション
- 汎用Saga
- 全Webサービスへのログアウト通知
- Webhook
- 専用の永続監査DB
- 将来の外部プロバイダー用プラグイン機構

## 13. 後続工程

次の具体値と物理設計は、本文の境界を変えない範囲で後続に決める。

- PostgreSQLのテーブル、列、型、主キー、外部キー、一意制約、インデックス
- Redisのキー、値形式、原子操作、Luaの要否
- 各識別子とコードの生成方式
- 各状態の有効期限
- 使用済みhandoffの保持期間
- `service_secret`の生成、ハッシュ、ローテーション
- Cookie名
- Webサービス側ローカルセッションの保存製品
- CSRFの具体方式
- キャッシュ制御ヘッダーとReferrer-Policy
- ログマスキング
- Redisの永続化、可用性、アクセス制御
- Secret管理
- 物理コンポーネント構成とKubernetes配置
- 監査要件
- 移行計画
- 実装タスク
