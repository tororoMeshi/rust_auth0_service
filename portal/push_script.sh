#!/usr/bin/env bash
set -euo pipefail

# ========================
# Config
# ========================
: "${DOCKERHUB_USER:?Set DOCKERHUB_USER}"   # 例: export DOCKERHUB_USER=tororomeshi
APP_NAME="${APP_NAME:-portal-frontend}"            # リポジトリ名（lint.sh に合わせた既定）
IMAGE="${DOCKERHUB_USER}/${APP_NAME}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.nginx}"
CONTEXT_DIR="${CONTEXT_DIR:-.}"

# TAG は引数 or git の短SHA or 日時フォールバック
TAG="${1:-$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M)}"

# Multi-arch を使う場合は MULTIARCH=1 をセット
MULTIARCH="${MULTIARCH:-0}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

echo "==> IMAGE:        ${IMAGE}"
echo "==> DOCKERFILE:   ${DOCKERFILE}"
echo "==> CONTEXT:      ${CONTEXT_DIR}"
echo "==> TAG:          ${TAG}"
echo "==> MULTIARCH:    ${MULTIARCH} (platforms: ${PLATFORMS})"

# ちょっとした安全策: Dockerfile 存在チェック
[[ -f "${DOCKERFILE}" ]] || { echo "Dockerfile not found: ${DOCKERFILE}" >&2; exit 1; }

# ========================
# Build & Push
# ========================
if [[ "${MULTIARCH}" == "1" ]]; then
  # buildx でそのまま push（ビルド済みローカルイメージは残らない）
  echo "==> Using buildx (multi-arch) build & push..."
  docker buildx inspect >/dev/null 2>&1 || docker buildx create --use
  docker buildx build \
    --platform "${PLATFORMS}" \
    -f "${DOCKERFILE}" \
    -t "${IMAGE}:${TAG}" \
    -t "${IMAGE}:latest" \
    --push \
    "${CONTEXT_DIR}"

  echo "==> Inspect pushed image manifest:"
  docker buildx imagetools inspect "${IMAGE}:${TAG}" || true
else
  # 通常の docker build -> push
  echo "==> Building (single arch) image..."
  DOCKER_BUILDKIT=1 docker build \
    -f "${DOCKERFILE}" \
    -t "${IMAGE}:${TAG}" \
    -t "${IMAGE}:latest" \
    "${CONTEXT_DIR}"

  echo "==> Pushing ${IMAGE}:${TAG} ..."
  docker push "${IMAGE}:${TAG}"

  echo "==> Pushing ${IMAGE}:latest ..."
  docker push "${IMAGE}:latest"
fi

echo "✅ Done. Pushed:"
echo "   - ${IMAGE}:${TAG}"
echo "   - ${IMAGE}:latest"
