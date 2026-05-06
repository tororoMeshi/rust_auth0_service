#!/bin/bash
set -eux

kubectl create configmap google-auth-config -n auth0 \
  --from-literal=GOOGLE_REDIRECT_URI="https://auth.tororomeshi.net/auth/google/callback" \
  --from-literal=APP_BASE_URL="https://portal.tororomeshi.net" \
  --from-literal=ALLOWED_REDIRECT_ORIGINS="https://portal.tororomeshi.net" \
  --from-literal=ALLOWED_CORS_ORIGINS="https://portal.tororomeshi.net,https://auth.tororomeshi.net"
