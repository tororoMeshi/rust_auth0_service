#!/bin/bash
# create_google_auth_secret.sh
# Usage: ./create_google_auth_secret.sh path/to/client_secret.json
#   例:   ./create_google_auth_secret.sh client_secret.json
#
# 1. Debian/Ubuntuベースで jq が無い場合、apt-get でインストールする
# 2. client_secret.json から client_id, client_secret を取り出す
# 3. `google-auth-secrets` (data key: `client_id`, `client_secret`) を作成・更新する

set -eu

# -- 0. apt-get と jq のチェック ---
if ! command -v jq > /dev/null 2>&1; then
  echo "[INFO] 'jq' is not installed. Installing via apt-get..."
  if command -v apt-get > /dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y jq
  else
    echo "[ERROR] 'apt-get' not found. Cannot install jq automatically."
    exit 1
  fi
else
  echo "[INFO] 'jq' is already installed."
fi

# -- 1. 引数チェック --
if [ $# -lt 1 ]; then
  echo "Usage: $0 <client_secret.json>"
  exit 1
fi

JSON_FILE="$1"

# -- 2. JSON から必要なフィールドを抽出 --
CLIENT_ID=$(jq -r '.web.client_id' "$JSON_FILE")
CLIENT_SECRET=$(jq -r '.web.client_secret' "$JSON_FILE")

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
  echo "Error: Could not extract client_id or client_secret from $JSON_FILE"
  exit 1
fi

echo "Extracted client_id: $CLIENT_ID"
echo "Extracted client_secret: $CLIENT_SECRET"

# -- 3. Secret名や Namespace は必要に応じて変更 --
SECRET_NAME="google-auth-secrets"
NAMESPACE="auth0"

# -- 4. kubectl で Secret 作成or更新 (dry-run で yaml 出力→apply) --
kubectl create secret generic "$SECRET_NAME" \
  --namespace "$NAMESPACE" \
  --from-literal=client_id="$CLIENT_ID" \
  --from-literal=client_secret="$CLIENT_SECRET" \
  --dry-run=client -o yaml \
| kubectl apply -f -

echo "Kubernetes Secret '$SECRET_NAME' has been created/updated in namespace '$NAMESPACE'."
