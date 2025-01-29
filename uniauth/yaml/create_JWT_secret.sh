#!/bin/bash
# ファイル名: create_uniauth_secret.sh
# 用途: OpenSSLでランダム文字列を生成し、Kubernetes Secret (jwt_secret) を作成/更新

# 使用例: ./create_uniauth_secret.sh

# 作成先のNamespace
NAMESPACE="auth0"
# Secret名
SECRET_NAME="uniauth-secrets"
# Secret中のキー名
SECRET_KEY_NAME="jwt_secret"

# ランダムな文字列を生成 (32バイト=256bit)
RANDOM_SECRET=$(openssl rand -hex 32)

echo "Generated random secret: $RANDOM_SECRET"

# Secret を --dry-run=client + -o yaml で出力した上で、kubectl apply -f - で作成または更新
kubectl create secret generic "$SECRET_NAME" \
  --namespace "$NAMESPACE" \
  --from-literal="$SECRET_KEY_NAME"="$RANDOM_SECRET" \
  --dry-run=client -o yaml \
| kubectl apply -f -

echo "Kubernetes Secret '$SECRET_NAME' has been created/updated in namespace '$NAMESPACE'"
