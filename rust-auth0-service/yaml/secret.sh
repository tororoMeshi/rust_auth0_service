#!/bin/bash
set -eux

kubectl create secret generic google-auth-secrets -n auth0 \
  --from-env-file=google-auth-secrets.env