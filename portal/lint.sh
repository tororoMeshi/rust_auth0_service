#!/usr/bin/env bash
set -euo pipefail

# ===== logging =====
LOG_DIR="${LOG_DIR:-logs}"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${LOG_DIR}/lint-${TS}.log"

exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Lint & Security Check Started at $(date) ==="

# ===== config =====
DOCKERHUB_USER="${DOCKERHUB_USER:?Set DOCKERHUB_USER}"
LINT_IMAGE="vite-lint"
APP_IMAGE="${DOCKERHUB_USER}/vite-spa"   # ← プロダクト名に合わせて変更
NODE_IMAGE="${NODE_IMAGE:-node:20-bullseye}"

# ===== ① devDeps 自動整備（未導入なら package.json/lock のみ更新）=====
need=0
node -e 'const p=require("./package.json"); process.exit(p.devDependencies && p.devDependencies.vite ? 0 : 1)' || need=1
node -e 'const p=require("./package.json"); process.exit(p.devDependencies && p.devDependencies["@vitejs/plugin-vue"] ? 0 : 1)' || need=1
node -e 'const p=require("./package.json"); process.exit(p.devDependencies && p.devDependencies["eslint-plugin-vue"] ? 0 : 1)' || need=1

if [ "$need" -eq 1 ]; then
  ./npm.sh pkg set \
    "devDependencies.vite=latest" \
    "devDependencies.@vitejs/plugin-vue=latest" \
    "devDependencies.eslint-plugin-vue=latest"
  ./npm.sh install --package-lock-only
fi

# ===== ② builder image（依存インストール & Vite build）=====
docker build -t "$LINT_IMAGE" -f - . <<'DOCKERFILE'
# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE
FROM ${NODE_IMAGE:-node:20-bullseye} AS builder
WORKDIR /app

COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    if [ -f package-lock.json ]; then \
      npm ci || (echo "Lock out-of-sync → fallback to npm install" >&2; rm -rf node_modules && npm i); \
    else \
      npm i; \
    fi

COPY . .
RUN npm run build
DOCKERFILE

# ===== ③ lint / outdated =====
docker run --rm "$LINT_IMAGE" bash -lc '
  cd /app;
  npm run lint || true;
  npm outdated || true;
'

# ===== ④ 本番イメージ（Nginx静的配信）をビルド =====
# Dockerfile を nginx 用に固定
docker build -t "${APP_IMAGE}:lint-temp" -f Dockerfile.nginx .

# ===== ⑤ Trivy: 結果をホスト logs へ保存 =====
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${HOME}/.cache/trivy":/root/.cache/trivy \
  -v "$PWD/$LOG_DIR":"$PWD/$LOG_DIR" \
  -w "$PWD" \
  aquasec/trivy:latest image \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --format json \
  --output "$PWD/${LOG_DIR}/trivy-${TS}.json" \
  "${APP_IMAGE}:lint-temp"

# 後片付け
docker rmi "${APP_IMAGE}:lint-temp" || true

echo "✅ Done: log=${LOG_FILE}, trivy=${LOG_DIR}/trivy-${TS}.json"
