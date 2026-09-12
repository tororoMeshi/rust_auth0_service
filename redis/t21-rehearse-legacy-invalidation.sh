#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="t21-redis-$RANDOM-$$"
report_dir="$(mktemp -d)"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${report_dir}"; }
trap cleanup EXIT
docker run --rm -d --name "${container}" -p 127.0.0.1::6379 redis:6.2.6-alpine >/dev/null
until docker exec "${container}" redis-cli ping | grep -qx PONG; do sleep 1; done
port="$(docker port "${container}" 6379/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')"
u_key=AbCdEfGhIjKlMnOpQrStUvWx
a_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB
docker exec "${container}" redis-cli SETEX "${u_key}" 3600 '{"user_id":36,"expires_at":2000000000}' >/dev/null
docker exec "${container}" redis-cli SETEX "${a_key}" 3600 '{"oauth_state":"state","redirect":"/"}' >/dev/null
docker exec "${container}" redis-cli HSET auth:session:keep field value >/dev/null
python3 "${repo_root}/redis/t21_legacy_key_invalidation.py" --host 127.0.0.1 --port "${port}" --report "${report_dir}/dry.json"
python3 "${repo_root}/redis/t21_legacy_key_invalidation.py" --host 127.0.0.1 --port "${port}" --report "${report_dir}/execute.json" --execute
[[ "$(docker exec "${container}" redis-cli EXISTS "${u_key}" "${a_key}" auth:session:keep)" == 1 ]]
python3 "${repo_root}/redis/t21_legacy_key_invalidation.py" --host 127.0.0.1 --port "${port}" --report "${report_dir}/rollback.json" --rollback-auth-foundation --execute
[[ "$(docker exec "${container}" redis-cli EXISTS auth:session:keep)" == 0 ]]
docker exec "${container}" redis-cli SET unrelated-key unrelated >/dev/null
if python3 "${repo_root}/redis/t21_legacy_key_invalidation.py" --host 127.0.0.1 --port "${port}" --report "${report_dir}/ambiguous.json"; then
    printf 'ambiguous-key STOP rule did not fail\n' >&2
    exit 1
fi
printf 'Redis 6.2.6 classifier rehearsal PASS: exact legacy deletion, new-key exclusion, ambiguous STOP\n'
