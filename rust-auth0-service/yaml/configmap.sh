#!/bin/bash
set -eux

kubectl create configmap google-auth-config -n auth0 \
  --from-literal=GOOGLE_REDIRECT_URI="https://auth.tororomeshi.net/auth/google/callback"
