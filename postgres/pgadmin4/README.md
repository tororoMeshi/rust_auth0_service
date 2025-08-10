# pgAdmin4 セットアップ

## デプロイ
```bash
kubectl apply -f postgres/pgadmin4/deploy.yaml
```

## アクセス方法
NodePortでアクセス可能：
- URL: http://node-ip:30080
- Email: admin@tororomeshi.net
- Password: admin123

## PostgreSQL接続設定
pgAdmin4内でPostgreSQLサーバーを追加：

1. **General**:
   - Name: auth0-account-db

2. **Connection**:
   - Host name/address: `auth0-account-db`
   - Port: `5432`
   - Username: `tororomeshi` (管理ユーザー)
   - Password: PostgreSQL operatorで生成されたパスワード

## パスワード取得方法
```bash
# PostgreSQL管理ユーザーのパスワード取得
kubectl get secret tororomeshi.auth0-account-db.credentials.postgresql.acid.zalan.do \
  -n auth0 -o jsonpath='{.data.password}' | base64 -d
```