# Rust Auth0 Service

OAuth2認証とJWT管理を提供するRust製マイクロサービス群です。Google OAuth2を使用したユーザー認証とセッション管理機能を提供します。

## アーキテクチャ

```
[User Browser] 
    ↓ HTTPS
[Cloudflare Tunnel] 
    ↓ HTTP (Kubernetes内)
[Frontend (Vue.js/Nginx)] ←→ [Portal Backend (Rust)] ←→ [Auth Service (Rust)] ←→ [Uniauth Service (Rust)]
    (静的ファイル配信)  HTTP (Pod間通信)        HTTP (Pod間通信)             HTTP (Pod間通信)
                                                                ↓ HTTPS (外部API)             ↓ Pod間通信
                                                            [Google OAuth2]          [PostgreSQL + Redis]
```

## 本番環境に必要なコンポーネント

### フロントエンド
- **portal/** - Vue.js製ポータルサイト
  - ユーザーログイン画面
  - ダッシュボード画面
  - Nginx (8080ポート) でホスティング

### バックエンドサービス
- **portal_backend/** - Rust製APIサーバー
  - JWT認証エンドポイント (`/api/me`)
  - ヘルスチェック (`/healthz`)
  - ポート: 3000

- **rust-auth0-service/** - OAuth2認証サービス (Rust)
  - Google OAuth2認証フロー
  - ユーザー情報取得とセッション管理
  - ポート: 8080

- **uniauth/** - 認証・トークン管理サービス (Rust)
  - JWT生成・検証
  - セッション管理 (Redis)
  - ユーザー情報管理 (PostgreSQL)
  - ポート: 8081

### インフラストラクチャ
- **PostgreSQL** - ユーザーデータ永続化
  - Zalando Postgres Operator使用
- **Redis** - セッション・キャッシュ管理
  - Redis Failover使用
- **Cloudflare Tunnel** - 外部アクセス・SSL終端

## テスト・開発用コンポーネント

### 旧実装（参考用・削除済み）
- **~~portal-backend/~~** - Express.js版バックエンド（削除済み）
- **uniauth/src/ok_main.rs** - 旧バージョン実装（参考用）
- **rust-auth0-service/src/ver2_auth_main.rs** - 旧認証フロー（参考用）

### 開発支援ファイル
- **portal/lint.sh**, **uniauth/lint.sh** - コードリンター
- **portal/.eslintrc.\*** - ESLint設定
- **portal/Dockerfile.nginx** - 代替Dockerファイル
- **portal/scripts/** - デプロイスクリプト

## 環境変数

### 共通
```bash
JWT_SECRET=<JWT署名用シークレット>
```

### rust-auth0-service
```bash
GOOGLE_CLIENT_ID=<Google OAuth2クライアントID>
GOOGLE_CLIENT_SECRET=<Google OAuth2クライアントシークレット>
GOOGLE_REDIRECT_URI=https://auth.example.com/auth/google/callback
APP_BASE_URL=https://app.example.com
ALLOWED_REDIRECT_ORIGINS=https://app.example.com
ALLOWED_CORS_ORIGINS=https://app.example.com,https://auth.example.com
UNIAUTH_URL=http://uniauth:8081
COOKIE_DOMAIN=.example.com
```

### uniauth
```bash
POSTGRES_HOST=auth0-account-db
POSTGRES_USER=<PostgreSQLユーザー名>
POSTGRES_PASSWORD=<PostgreSQLパスワード>
DB_NAME=auth0_accounts
REDIS_URL=redis://rfrm-redisfailover:6379
COOKIE_DOMAIN=.tororomeshi.net
COOKIE_SECURE=true
POST_LOGIN_REDIRECT=https://portal.tororomeshi.net/dashboard
```

### portal_backend
```bash
PORT=3000
FRONTEND_URL=http://frontend-service.auth0.svc.cluster.local:80
JWT_SECRET=<JWT検証用シークレット（uniauthと同一）>
RUST_LOG=info
```

## デプロイ手順

### 1. 前提条件
- Kubernetes クラスター
- PostgreSQL Operator (Zalando)
- Redis Operator
- Cloudflare Tunnel設定

### 2. Secretsの作成
```bash
kubectl create secret generic uniauth-secrets -n auth0 \
  --from-literal=JWT_SECRET="<共通JWTシークレット>" \
  --from-literal=FAUNA_SECRET="<任意>"
```

### 3. サービスのデプロイ
```bash
# Uniauth
kubectl apply -f uniauth/yaml/deploy.yaml

# Auth Service  
kubectl apply -f rust-auth0-service/yaml/

# Portal Backend
kubectl apply -f portal_backend/k8s/

# Frontend
kubectl apply -k portal/k8s/
```

## 認証フロー

1. ユーザーが `https://portal.tororomeshi.net/` にアクセス
2. 「Login with Google」クリック
3. `auth.tororomeshi.net/auth/google` にリダイレクト
4. Google OAuth2認証
5. コールバックで `uniauth` にユーザー情報送信
6. JWTトークン生成、Cookieに設定
7. `portal.tororomeshi.net/dashboard` にリダイレクト
8. フロントエンドが `/api/me` でユーザー情報取得
9. JWTトークン検証後、ユーザー情報表示

## APIエンドポイント

### Portal Backend (`portal_backend`)
- `GET /api/me` - 現在のユーザー情報取得（JWT認証必須）
- `GET /healthz` - ヘルスチェック

### Auth Service (`rust-auth0-service`)
- `GET /auth/google` - Google OAuth2認証開始
- `GET /callback` - OAuth2コールバック

### Uniauth (`uniauth`)
- `POST /upsert_and_token` - ユーザー登録・JWT発行
- `POST /logout` - ログアウト・セッション削除

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
kubectl logs -n auth0 -l app=uniauth
kubectl logs -n auth0 -l app=frontend
```

## トラブルシューティング

### よくある問題

1. **JWT署名エラー** - `uniauth` と `portal_backend` のJWT_SECRETが一致していることを確認
2. **DNS解決エラー** - Cloudflare DNSでCNAMEレコードが正しく設定されていることを確認
3. **Cookie設定エラー** - `COOKIE_DOMAIN` と `COOKIE_SECURE` の設定を確認

### デバッグ手順

1. Ingressが正しく動作しているか確認:
   ```bash
   kubectl get ingress -n auth0
   ```

2. サービス間通信を確認:
   ```bash
   kubectl exec -n auth0 <pod-name> -- curl http://uniauth:8081/health
   ```

3. JWT_SECRET一致確認:
   ```bash
   kubectl get secret -n auth0 uniauth-secrets -o jsonpath='{.data.JWT_SECRET}' | base64 -d | sha256sum
   ```

## セキュリティ考慮事項

- JWTシークレットはKubernetes Secretで管理
- Cookieは `HttpOnly`, `Secure`, `SameSite=None` 設定
- PostgreSQL認証情報は Postgres Operator により自動管理
- すべての通信はHTTPS（Cloudflare Tunnel経由）

## 旧Cloudflare設定（参考）

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: cloudflare
  name: cloudflared
  labels:
    app: cloudflared
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cloudflared
  template:
    metadata:
      labels:
        app: cloudflared
    spec:
      containers:
      - name: cloudflared
        image: cloudflare/cloudflared:latest
        command: ["cloudflared", "tunnel", "--no-autoupdate", "run"]
        env:
        - name: TUNNEL_TOKEN
          valueFrom:
            secretKeyRef:
              name: cloudflared-token
              key: token
```

## ライセンス

MIT License
