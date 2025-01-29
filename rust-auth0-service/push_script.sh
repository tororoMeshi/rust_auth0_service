#!/bin/bash
# This script builds a Docker image and pushes it to Docker Hub.
# Usage: ./push_docker.sh [IMAGE_TAG]
# Make sure you are logged in to Docker Hub before running this script.

set -eu

IMAGE_NAME="tororomeshi/rust_auth0_service"
IMAGE_TAG="${1:-0.1}"

# Check script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# Build image
echo "Building Docker image..."
if ! docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" .; then
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

# Push image with specific tag
push_image "${IMAGE_TAG}"

# Push image with latest tag
push_image "latest"

echo "Docker image pushed successfully."
