#!/usr/bin/env bash
set -euo pipefail

# ファイル名: create_uniauth_secret.sh
# 用途: 同一 JWT シークレットを複数 Namespace に作成/更新
# Secret 名は `uniauth-secrets`、data key は `jwt_secret`

NAMESPACES=("auth0" "stateless-chat" "jamaica")
SECRET_NAME="uniauth-secrets"
SECRET_KEY_NAME="jwt_secret"

# 32バイト(=256bit)のランダムHEX
RANDOM_SECRET="$(openssl rand -hex 32)"

# ログには値を出さず、指紋だけ出す
FINGERPRINT="$(printf '%s' "$RANDOM_SECRET" | sha256sum | cut -d' ' -f1)"
echo "Generated new JWT secret (sha256 fingerprint): $FINGERPRINT"

for NAMESPACE in "${NAMESPACES[@]}"; do
  echo "Applying secret '$SECRET_NAME' to namespace '$NAMESPACE'..."
  kubectl create secret generic "$SECRET_NAME" \
    --namespace "$NAMESPACE" \
    --from-literal="$SECRET_KEY_NAME=$RANDOM_SECRET" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo "✅Done. Remember to rollout restart the deployments that consume this secret."
