#!/bin/bash
# ファイル名: create_uniauth_secret.sh
# 用途: OpenSSLでランダム文字列を生成し、Kubernetes Secret (jwt_secret) を
#       auth0 および stateless-chat の両方のNamespaceに作成/更新する
#
# 使用例:
#   ./create_uniauth_secret.sh

# 対象とする Namespace のリスト
NAMESPACES=("auth0" "stateless-chat" "jamaica")

# Secret 名と Secret 中のキー名
SECRET_NAME="uniauth-secrets"
SECRET_KEY_NAME="jwt_secret"

# ランダムな文字列を生成 (32バイト=256bit)
RANDOM_SECRET=$(openssl rand -hex 32)
echo "Generated random secret: $RANDOM_SECRET"

# 各 Namespace に対して Secret を作成/更新する
for NAMESPACE in "${NAMESPACES[@]}"; do
  echo "Creating/updating secret '$SECRET_NAME' in namespace '$NAMESPACE'..."
  kubectl create secret generic "$SECRET_NAME" \
    --namespace "$NAMESPACE" \
    --from-literal="$SECRET_KEY_NAME"="$RANDOM_SECRET" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo "Kubernetes Secret '$SECRET_NAME' has been created/updated in namespaces: ${NAMESPACES[*]}"
