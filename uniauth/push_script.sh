#!/bin/bash
# This script builds a Docker image and pushes it to Docker Hub.
# Usage: ./push_docker.sh <IMAGE_TAG>
# Make sure you are logged in to Docker Hub before running this script.

set -eu

IMAGE_NAME="tororomeshi/uniauth"
if [ $# -ne 1 ]; then
  echo "Usage: $0 <IMAGE_TAG>" >&2
  exit 1
fi

IMAGE_TAG="$1"

# Check script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# Build image
echo "Building Docker image..."
if ! docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .; then
  echo "Docker build failed." >&2
  exit 1
fi

# Function to push image and handle authentication errors
push_image() {
  local TAG=$1
  echo "Pushing Docker image with tag ${TAG}..."
  if ! docker push "${IMAGE_NAME}:${TAG}"; then
    echo "Docker push failed for tag ${TAG}." >&2
    echo "Please make sure you are logged in to Docker Hub by running 'docker login'." >&2
    exit 1
  fi
}

push_image "${IMAGE_TAG}"

echo "Docker image pushed successfully."
