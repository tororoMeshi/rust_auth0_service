#!/usr/bin/env bash
set -euo pipefail

# This is an isolated rehearsal of the four rust_auth-owned rollback images.
# Their immutable image references remain owned by the rollback baseline document.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
baseline_doc="${repo_root}/docs/auth-foundation-rollback-baseline.md"
legacy_manifest_commit="37b5876"
run_id="t25-legacy-rollback-${RANDOM}-$$"
network="${run_id}-network"
rehearsal_dir="$(mktemp -d)"
fresh_secret_file="${rehearsal_dir}/fresh-rollback-jwt-secret"
previous_secret_file="${rehearsal_dir}/previous-jwt-secret"
postgres_container="${run_id}-postgres"
redis_container="${run_id}-redis"
uniauth_container="${run_id}-uniauth"
rust_auth_container="${run_id}-rust-auth"
backend_container="${run_id}-backend"
frontend_container="${run_id}-frontend"

cleanup() {
    docker rm -f "${frontend_container}" "${backend_container}" "${rust_auth_container}" \
        "${uniauth_container}" "${redis_container}" "${postgres_container}" >/dev/null 2>&1 || true
    docker network rm "${network}" >/dev/null 2>&1 || true
    rm -rf -- "${rehearsal_dir}"
}
trap cleanup EXIT
umask 077
chmod 700 "${rehearsal_dir}"

require_status() {
    local expected="$1"
    shift
    local actual
    actual="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 5 "$@")"
    if [[ "${actual}" != "${expected}" ]]; then
        printf 'expected HTTP %s, got %s\n' "${expected}" "${actual}" >&2
        exit 1
    fi
}

wait_for_status() {
    local expected="$1"
    shift
    local actual="no response"
    for attempt in $(seq 1 30); do
        if actual="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 "$@" 2>/dev/null)" \
            && [[ "${actual}" == "${expected}" ]]; then
            return 0
        fi
        sleep 1
    done
    printf 'timed out waiting for HTTP %s (last status: %s)\n' "${expected}" "${actual}" >&2
    exit 1
}

published_port() {
    docker inspect --format "{{(index (index .NetworkSettings.Ports \"$2/tcp\") 0).HostPort}}" "$1"
}

image_from_baseline() {
    local component="$1"
    local image
    image="$(sed -n "/| ${component} |/p" "${baseline_doc}" | sed -nE 's/.*`(docker\.io\/tororomeshi\/[^`]+@sha256:[0-9a-f]{64})`.*/\1/p')"
    [[ "${image}" =~ ^docker\.io/tororomeshi/.+@sha256:[0-9a-f]{64}$ ]] || {
        printf 'rollback baseline has no immutable digest for %s\n' "${component}" >&2
        exit 1
    }
    printf '%s\n' "${image}"
}

make_jwt() {
    python3 - "$1" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time

secret = open(sys.argv[1], "rb").read().strip()
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps(
    {
        "sub": "rollback-rehearsal",
        "email": "rollback-rehearsal@example.test",
        "name": "rollback-rehearsal",
        "picture": "",
        "exp": int(time.time()) + 300,
    },
    separators=(",", ":"),
).encode()).rstrip(b'=')
signed = header + b'.' + payload
signature = base64.urlsafe_b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).rstrip(b'=')
print((signed + b'.' + signature).decode())
PY
}

[[ -r "${baseline_doc}" ]] || { printf 'missing rollback baseline: %s\n' "${baseline_doc}" >&2; exit 1; }
git -C "${repo_root}" rev-parse --verify --quiet "${legacy_manifest_commit}^{commit}" >/dev/null || {
    printf 'missing legacy manifest commit %s\n' "${legacy_manifest_commit}" >&2
    exit 1
}

rust_auth_image="$(image_from_baseline rust-auth0-service)"
uniauth_image="$(image_from_baseline uniauth)"
backend_image="$(image_from_baseline portal_backend)"
frontend_image="$(image_from_baseline portal)"
for image in "${rust_auth_image}" "${uniauth_image}" "${backend_image}" "${frontend_image}"; do
    docker pull "${image}" >/dev/null
done

T21_ROLLBACK_JWT_SECRET_FILE="${fresh_secret_file}" \
    "${repo_root}/postgres/auth-migrations/cutover/t21-prepare-rollback-jwt-secret.sh"
T21_ROLLBACK_JWT_SECRET_FILE="${previous_secret_file}" \
    "${repo_root}/postgres/auth-migrations/cutover/t21-prepare-rollback-jwt-secret.sh"
fresh_jwt="$(make_jwt "${fresh_secret_file}")"
previous_jwt="$(make_jwt "${previous_secret_file}")"

git -C "${repo_root}" show "${legacy_manifest_commit}:portal/k8s/frontend-configmap.yaml" \
    | awk '/^  nginx.conf: \|$/ { nginx=1; next } nginx { if ($0 ~ /^    }apiVersion:/) { print "}"; exit }; if ($0 != "" && $0 !~ /^    /) exit; sub(/^    /, ""); print }' >"${rehearsal_dir}/nginx.conf"
[[ -s "${rehearsal_dir}/nginx.conf" ]] || { printf 'failed to extract legacy frontend configuration\n' >&2; exit 1; }
chmod 644 "${rehearsal_dir}/nginx.conf"
mkdir -p "${rehearsal_dir}/nginx-cache" "${rehearsal_dir}/nginx-run" "${rehearsal_dir}/nginx-tmp"
chmod 777 "${rehearsal_dir}/nginx-cache" "${rehearsal_dir}/nginx-run" "${rehearsal_dir}/nginx-tmp"

{
    printf 'PORT=3000\nFRONTEND_URL=http://frontend:8080\nJWT_SECRET='
    cat "${fresh_secret_file}"
    printf '\nRUST_LOG=warn\n'
} >"${rehearsal_dir}/backend.env"
{
    printf 'POSTGRES_HOST=postgres\nPOSTGRES_USER=postgres\nPOSTGRES_PASSWORD=fixture-only\nDB_NAME=auth0_accounts\nREDIS_URL=redis://redis:6379\nAPP_BASE_URL=http://frontend:8080\nFRONTEND_ORIGIN=http://frontend:8080\nJWT_SECRET='
    cat "${fresh_secret_file}"
    printf '\n'
} >"${rehearsal_dir}/uniauth.env"
{
    printf 'GOOGLE_CLIENT_ID=rollback-rehearsal\nGOOGLE_CLIENT_SECRET=rollback-rehearsal\nGOOGLE_REDIRECT_URI=http://rust-auth0-service:8080/auth/google/callback\nUNIAUTH_URL=http://uniauth:8081\nREDIS_URL=redis://redis:6379\nAPP_BASE_URL=http://frontend:8080\nPOST_LOGIN_REDIRECT=/\nALLOWED_REDIRECT_ORIGINS=http://frontend:8080\nALLOWED_CORS_ORIGINS=http://frontend:8080\nSESSION_SECRET_KEY=0123456789012345678901234567890123456789012345678901234567890123\n'
} >"${rehearsal_dir}/rust-auth.env"

docker network create "${network}" >/dev/null
docker run -d --name "${postgres_container}" --network "${network}" --network-alias postgres \
    -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=auth0_accounts postgres:17-alpine >/dev/null
for attempt in $(seq 1 30); do
    if docker exec "${postgres_container}" psql -X -U postgres -d auth0_accounts -c 'SELECT 1' >/dev/null 2>&1; then
        break
    fi
    [[ "${attempt}" != 30 ]] || { printf 'fixture PostgreSQL readiness timed out\n' >&2; exit 1; }
    sleep 1
done
docker run -d --name "${redis_container}" --network "${network}" --network-alias redis redis:6.2.6-alpine >/dev/null
for attempt in $(seq 1 30); do
    if docker exec "${redis_container}" redis-cli ping >/dev/null 2>&1; then
        break
    fi
    [[ "${attempt}" != 30 ]] || { printf 'fixture Redis readiness timed out\n' >&2; exit 1; }
    sleep 1
done

docker run -d --name "${uniauth_container}" --network "${network}" --network-alias uniauth \
    --env-file "${rehearsal_dir}/uniauth.env" -p 127.0.0.1::8081 "${uniauth_image}" >/dev/null
uniauth_port="$(published_port "${uniauth_container}" 8081)"
[[ -n "${uniauth_port}" ]] || { printf 'uniauth port was not published\n' >&2; exit 1; }
wait_for_status 200 "http://127.0.0.1:${uniauth_port}/health"

docker run -d --name "${rust_auth_container}" --network "${network}" --network-alias rust-auth0-service \
    --env-file "${rehearsal_dir}/rust-auth.env" -p 127.0.0.1::8080 "${rust_auth_image}" >/dev/null
rust_auth_port="$(published_port "${rust_auth_container}" 8080)"
[[ -n "${rust_auth_port}" ]] || { printf 'rust-auth0-service port was not published\n' >&2; exit 1; }
wait_for_status 302 "http://127.0.0.1:${rust_auth_port}/auth/google?redirect=/"

docker run -d --name "${backend_container}" --network "${network}" --network-alias portal-backend-service \
    --env-file "${rehearsal_dir}/backend.env" "${backend_image}" >/dev/null
docker run --rm --network "${network}" -v "${rehearsal_dir}/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${rehearsal_dir}/nginx-cache:/var/cache/nginx" -v "${rehearsal_dir}/nginx-run:/var/run" \
    -v "${rehearsal_dir}/nginx-tmp:/tmp" \
    "${frontend_image}" nginx -t >/dev/null
docker run -d --name "${frontend_container}" --network "${network}" --network-alias frontend \
    -v "${rehearsal_dir}/nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "${rehearsal_dir}/nginx-cache:/var/cache/nginx" -v "${rehearsal_dir}/nginx-run:/var/run" \
    -v "${rehearsal_dir}/nginx-tmp:/tmp" -p 127.0.0.1::8080 "${frontend_image}" >/dev/null
frontend_port="$(published_port "${frontend_container}" 8080)"
[[ -n "${frontend_port}" ]] || { printf 'frontend port was not published\n' >&2; exit 1; }
wait_for_status 401 "http://127.0.0.1:${frontend_port}/api/me"

require_status 200 -H "Cookie: jwt=${fresh_jwt}" "http://127.0.0.1:${frontend_port}/api/me"
require_status 401 -H "Cookie: jwt=${previous_jwt}" "http://127.0.0.1:${frontend_port}/api/me"
require_status 401 "http://127.0.0.1:${frontend_port}/api/me"
printf 'T25 legacy rollback runtime rehearsal PASS: old images started; frontend-to-backend JWT validation requires re-login\n'
