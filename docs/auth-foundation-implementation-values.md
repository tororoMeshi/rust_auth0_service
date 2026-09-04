# 認証基盤実装定数

## 1. 適用範囲

本書は `rust-auth0-service` の共通認証、`portal_backend` のローカル認証、portal のブラウザ経路に適用する。値は初期実装の固定値であり、Secret値そのものは記録しない。開発のbrowser-facing originは `http://localhost:5173`、開発サービスは `portal-dev`、callback は `http://localhost:5173/auth/callback`、logout return は `http://localhost:5173/` とする。

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

旧Cookie情報は `jwt`、`session_id`、`Domain=.tororomeshi.net`、`Path=/` である。親ドメイン共有CookieおよびJWT Cookieは移行完了時に残さない。

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

すべての期限、上限、Cookie属性、CSRF比較、入力上限が実装・設定・検証で一致していること。開発オリジンに `localhost:8080` を残さず、`http://localhost:5173` を使用すること。共通ログアウトとportalローカルログアウトのCSRF方式を混同しないこと。T01は稼働PodのimageIDからdigestを取得し、ロールバック参照として固定済みとする。T21/T25はdigest指定でレジストリからpullし、旧構成を再配備できることを実証する。

## 10. 承認

本書の現行内容を、Gate Aの実装定数表として人間が承認した。

## 11. Gate B承認

T09〜T12により、production configuration boundary、Google/Redis/PostgreSQL起動設定、login、Google callback、handoff exchange、logout、および登録済みURI検証を含む認証基盤単体が成立したことを人間が承認した。browser単独で認証を成立させず、backend交換・service_id拘束・one-time handoff・PKCE S256を必須とし、アプリケーションには `internal_user_id` と `authenticated_at` のみを返す。CommonSessionはauth-host-onlyとし、親ドメインCookie、JWT置換フロー、provider subject/tokenの返却は行わない。callback claim、Redis/storage failure、logout GET/POST・CSRF、登録済みcallback/logout URIの扱いを含む主要不変条件を確認済みである。

独立レビュー結果は `APPROVE`、T12 commit可能およびGate B進行可能であり、`cargo fmt --check`、`cargo check`、`cargo test`、関連するPostgreSQL/Redis/HTTP integration、`git diff --check` はすべてPASSである。次の作業はT13以降とする。

## 12. Gate C承認

T13〜T15により、`portal_backend` 単体の認証経路が成立したことを人間が承認した。LoginStart / LocalSessionはprocess memoryで管理し、LoginStartのone-shot claim、handoffの自動retryなし、LocalSessionのみを認可根拠とする保護API、portalローカルログアウトのCSRF、JWT runtime認証の削除、および同一オリジンのbackend route境界を確認済みである。

独立レビュー結果は `APPROVE`、T15 commit可能およびGate C進行可能であり、25 tests、`cargo fmt --check`、`cargo check --locked`、`cargo test --locked`、`git diff --check` はすべてPASSである。次の作業はT16/T17およびT18とする。
