#!/usr/bin/env bash
set -euo pipefail

# T21 own-rollback input only. This is a new legacy JWT verification secret;
# it must never be an old JWT_SECRET value and must remain outside the repo.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
secret_file="${T21_ROLLBACK_JWT_SECRET_FILE:?T21_ROLLBACK_JWT_SECRET_FILE must be an external protected path}"
resolved="$(realpath -m "${secret_file}")"
case "${resolved}" in
    "${repo_root}"|"${repo_root}"/*) printf 'protected rollback secret must be outside this repository\n' >&2; exit 2 ;;
esac
[[ ! -e "${resolved}" ]] || { printf 'refusing to overwrite protected rollback secret\n' >&2; exit 2; }
umask 077
openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n' >"${secret_file}"
[[ "$(wc -c <"${secret_file}")" == 43 ]] || { rm -f -- "${secret_file}"; printf 'unexpected encoded secret length\n' >&2; exit 1; }
chmod 600 -- "${secret_file}"
