# Rust Auth0 Service

Google OAuth2を利用する共通認証基盤と、portal固有のローカル認証・セッションを提供するサービス群です。

## アーキテクチャ

```text
[Browser]
   | HTTPS (portal host, same origin)
   v
[portal: Vue/Vite + Nginx] ---> [portal_backend: app local auth/session]
                                          |
                                          | HTTPS + handoff exchange
                                          v
[Google OAuth] <--- [rust-auth0-service: common auth foundation]
                                          |
                                          +-- PostgreSQL (identity/service registry)
                                          +-- Redis (external auth/common session/handoff/logout state)
```

`rust-auth0-service` が共通認証基盤、`portal_backend` がportal固有の認証・セッション、`portal` が同一オリジンのfrontendです。

## 本番環境に必要なコンポーネント

### フロントエンド
- **portal/** - Vue.js製ポータルサイト
  - Viteでbuildした静的frontend
  - Nginxで静的配信し、認証/API経路を同一オリジンの`portal_backend`へproxy

### バックエンドサービス
- **portal_backend/** - Rust製APIサーバー
  - LoginStartとportalローカルセッションをprocess memoryで管理
  - 認証handoffを共通認証基盤とserver-to-serverで交換
  - host-only Cookieで`/api/me`を認証
  - ポート: 3000

- **rust-auth0-service/** - 共通認証基盤 (Rust)
  - Google OAuth2認証、外部identity解決、共通セッション管理
  - 登録済みservice callback/logout URIとone-time handoffを管理
  - ポート: 8080

### インフラストラクチャ
- **PostgreSQL** - ユーザーデータ永続化
  - Zalando Postgres Operator使用
- **Redis** - セッション・キャッシュ管理
  - Redis Failover使用
- **Cloudflare Tunnel** - 外部アクセス・SSL終端

## テスト・開発用コンポーネント

### 開発支援ファイル
- **portal/lint.sh** - コードリンター
- **portal/.eslintrc.\*** - ESLint設定
- **portal/Dockerfile.nginx** - 代替Dockerファイル
- **portal/scripts/** - デプロイスクリプト

## 環境変数

### rust-auth0-service
```bash
GOOGLE_CLIENT_ID=<Google OAuth2クライアントID>
GOOGLE_CLIENT_SECRET=<Google OAuth2クライアントシークレット>
GOOGLE_REDIRECT_URI=https://auth.example.com/auth/google/callback
REDIS_URL=redis://redis:6379
PGHOST=auth0-account-db
PGPORT=5432
PGDATABASE=auth0_accounts
PGUSER=<PostgreSQLユーザー名>
PGPASSWORD=<PostgreSQLパスワード>
```

### 置き換えが必要な値
- `portal.tororomeshi.net` / `auth.tororomeshi.net` は現在の本番値です。別環境ではGoogle callback、認証基盤URL、Ingress host、登録済みcallback/logout URIを一貫して差し替えてください。
- `rust-auth0-service` が参照する Google OAuth の Secret 名は `google-auth-secrets`、data key は `client_id` と `client_secret` です。

### portal_backend
```bash
PORT=3000
PORTAL_SERVICE_ID=portal-prod
PORTAL_SERVICE_SECRET=<登録済みservice secretの平文値>
PORTAL_AUTH_FOUNDATION_BASE_URL=https://auth.example.com
PORTAL_LOGIN_START_CAPACITY=10000       # optional
PORTAL_LOCAL_SESSION_CAPACITY=50000     # optional
RUST_LOG=info
```

## デプロイ手順

### 1. 前提条件
- Kubernetes クラスター
- PostgreSQL Operator (Zalando)
- Redis Operator
- Cloudflare Tunnel設定

### 2. Secretsの作成

Secret名とdata keyはDeployment YAMLと一致させてください。Secret値をREADME、ConfigMap、frontendへ置かないでください。

1. Google OAuth Secret を作成する
   ```bash
   ./rust-auth0-service/yaml/secret.sh client_secret.json
   ```
   生成される Secret:
   - `google-auth-secrets`
   - data key: `client_id`, `client_secret`

2. PostgreSQL credentialはPostgres Operatorが作成するSecretを`rust-auth0-service/yaml/deploy.yaml`から参照します。

3. `portal_backend`用の`portal-prod-service-secret`（data key: `service_secret`）を、`registered_web_services`に登録したSHA-256検証値と対になる平文値で用意します。

### 3. サービスのデプロイ
```bash
# Common Auth Foundation
kubectl apply -f rust-auth0-service/yaml/deploy.yaml \
  -f rust-auth0-service/yaml/service.yaml \
  -f rust-auth0-service/yaml/ingress.yaml

# Portal Backend
kubectl apply -f portal_backend/k8s/

# Frontend
kubectl apply -k portal/k8s/
```

## 認証フロー

以下の `portal.tororomeshi.net` / `auth.tororomeshi.net` は現在の本番例です。別プロジェクトへ流用する時は、対応するホスト名と URL をまとめて置き換えてください。

1. ユーザーが `https://portal.tororomeshi.net/` にアクセス
2. 「Login with Google」クリック
3. `portal_backend` がLoginStartとPKCEを作成し、共通認証基盤の`/auth/login`へリダイレクト
4. 共通認証基盤が登録済みcallback URIを検証し、Google OAuth2認証を開始
5. `/auth/google/callback`でGoogle token/userinfoを取得し、PostgreSQLで外部identityを解決
6. Redisに共通セッションとone-time handoffを作成し、`__Host-auth_session`を設定
7. 登録済みのportal callbackへcode/stateを返し、`portal_backend`がhandoffを交換
8. `portal_backend`がhost-onlyのportalローカルセッションCookieを設定し、固定した相対pathへリダイレクト
9. frontendが同一オリジンの`/api/me`でユーザー情報を取得

## APIエンドポイント

### Portal Backend (`portal_backend`)
- `GET /login` - portalログイン開始
- `GET /auth/callback` - 共通認証handoff callback
- `GET /api/me` - portalローカルセッションで現在のユーザー情報を取得
- `POST /logout` - portalローカルセッションを削除
- `GET /health` - ヘルスチェック

### Auth Service (`rust-auth0-service`)
- `GET /auth/login` - 登録済みservice向けGoogle認証開始
- `GET /auth/google/callback` - Google OAuth2 callback
- `POST /auth/handoffs/exchange` - 認証済みserviceによるone-time handoff交換
- `GET /auth/logout` - 共通ログアウト開始
- `POST /auth/logout` - CSRF検証後に共通セッションを削除

## 開発・テスト

### ローカル開発
```bash
# ポートフォワードでサービスにアクセス
kubectl port-forward -n auth0 services/frontend-service 8080:80
kubectl port-forward -n auth0 services/portal-backend-service 3001:3000
```

### ログ確認
```bash
# サービスログ
kubectl logs -n auth0 -l app=portal-backend
kubectl logs -n auth0 -l app=rust-auth0-service  
kubectl logs -n auth0 -l app=frontend
```

## トラブルシューティング

### よくある問題

1. **Google callbackエラー** - Google OAuth clientのcallback URIと`GOOGLE_REDIRECT_URI`が一致していることを確認
2. **handoff交換エラー** - `PORTAL_SERVICE_ID`、service secret、登録済みcallback URIが同じservice recordに対応することを確認
3. **保存先接続エラー** - `rust-auth0-service`のPostgreSQL/Redis設定と到達性を確認

### デバッグ手順

1. Ingressが正しく動作しているか確認:
   ```bash
   kubectl get ingress -n auth0
   ```

2. 共通認証基盤への到達性を確認:
   ```bash
   kubectl exec -n auth0 <portal-backend-pod> -- \
     curl -I https://auth.tororomeshi.net/auth/login
   ```

## セキュリティ考慮事項

- 共通認証Cookieはauth host限定の`__Host-auth_session`とし、portal Cookieもhost-onlyにする
- Cookieは`Secure`、適切な`HttpOnly`/`SameSite`属性を付け、親domainへ共有しない
- service callback/logout URIは`registered_web_services`の固定値と完全一致で検証する
- handoffはserviceに拘束したone-time値とし、portal backendだけがservice secretを保持する
- PostgreSQL認証情報は Postgres Operator により自動管理
- すべての通信はHTTPS（Cloudflare Tunnel経由）

## ライセンス

MIT License
