#!/bin/bash
# create_session_secret.sh
# Usage: ./create_session_secret.sh
#
# このスクリプトは、openssl を利用してランダムな SESSION_SECRET_KEY を生成し、
# Kubernetes の Secret (namespace: auth0, secret名: session-secret) を作成・更新します.
#
# ※ SECRET_KEY はセッションの署名に使用されるため、十分な乱数（32バイト以上）を利用してください。
#
set -eu

# --- 1. openssl のチェック ---
if ! command -v openssl > /dev/null 2>&1; then
  echo "[ERROR] openssl がインストールされていません。openssl をインストールしてください。"
  exit 1
else
  echo "[INFO] openssl は既にインストールされています。"
fi

# --- 2. SESSION_SECRET_KEY の生成 ---
# 32 バイト（256ビット）のランダムなキーを16進数で生成（64文字）
SESSION_SECRET_KEY=$(openssl rand -hex 32)

if [ -z "$SESSION_SECRET_KEY" ]; then
  echo "[ERROR] SESSION_SECRET_KEY の生成に失敗しました。"
  exit 1
fi

echo "生成された SESSION_SECRET_KEY: $SESSION_SECRET_KEY"

# --- 3. Secret 名と Namespace の設定 ---
SECRET_NAME="session-secret"
NAMESPACE="auth0"

# --- 4. Kubernetes Secret の作成または更新 ---
kubectl create secret generic "$SECRET_NAME" \
  --namespace "$NAMESPACE" \
  --from-literal=SESSION_SECRET_KEY="$SESSION_SECRET_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Kubernetes Secret '$SECRET_NAME' が Namespace '$NAMESPACE' に作成/更新されました。"
