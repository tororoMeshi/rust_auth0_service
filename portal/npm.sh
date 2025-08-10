#!/usr/bin/env bash
set -euo pipefail
NODE_IMAGE="${NODE_IMAGE:-node:20-bullseye}"
WORKDIR="/work"
UIDGID="$(id -u):$(id -g)"

docker run --rm -u "$UIDGID" \
  -e HOME=/home/node \
  -v "$PWD":"$WORKDIR" \
  -v "$HOME/.npm":/home/node/.npm \
  -w "$WORKDIR" "$NODE_IMAGE" \
  npm "$@"
