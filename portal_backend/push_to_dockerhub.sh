#!/usr/bin/env bash
set -euo pipefail

DOCKERHUB_USER="${DOCKERHUB_USER:?Set DOCKERHUB_USER environment variable. (例: DOCKERHUB_USER=yourname ./push_to_dockerhub.sh)}"
PROJECT_NAME="portal-backend"
IMAGE_TAG=$(date +%Y%m%d%H%M)
if [ $# -ge 1 ]; then IMAGE_TAG="$1"; fi

IMAGE_NAME="${DOCKERHUB_USER}/${PROJECT_NAME}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ -f "Cargo.lock" ]; then
  echo "Removing Cargo.lock..."
  rm Cargo.lock
fi

echo "==> Building and pushing multi-arch Docker image..."
docker buildx create --use --name multiarch-builder >/dev/null 2>&1 || true

docker buildx build   --platform linux/amd64,linux/arm64   --tag "${IMAGE_NAME}:${IMAGE_TAG}"   --tag "${IMAGE_NAME}:latest"   --push   .

echo "✅ Multi-arch Docker image pushed: ${IMAGE_NAME}:${IMAGE_TAG} (also tagged latest)"
