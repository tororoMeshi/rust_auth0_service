#!/usr/bin/env bash
set -euo pipefail

# T21 only. Generates 32 CSPRNG bytes as unpadded base64url (43 ASCII bytes).
# SHA-256 is over this exact PORTAL_SERVICE_SECRET plaintext representation.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
secret_file="${T21_SECRET_FILE:?T21_SECRET_FILE must be an external protected path}"
digest_file="${T21_SERVICE_SECRET_SHA256_FILE:?T21_SERVICE_SECRET_SHA256_FILE must be an external protected path}"
declare -a destinations=()
for candidate in "${secret_file}" "${digest_file}"; do
    candidate_parent="$(realpath -e -- "$(dirname -- "${candidate}")")" || {
        printf 'protected artifact parent directory must already exist\n' >&2
        exit 2
    }
    [[ -d "${candidate_parent}" ]] || {
        printf 'protected artifact parent must be a directory\n' >&2
        exit 2
    }
    resolved="$(realpath -m -- "${candidate_parent}/$(basename -- "${candidate}")")"
    case "${resolved}" in
        "${repo_root}"|"${repo_root}"/*) printf 'protected T21 artifacts must be outside this repository\n' >&2; exit 2 ;;
    esac
    [[ ! -e "${resolved}" && ! -L "${resolved}" ]] || {
        printf 'refusing to overwrite or follow protected artifact target\n' >&2
        exit 2
    }
    destinations+=("${resolved}")
done
if [[ "${destinations[0]}" == "${destinations[1]}" ]]; then
    printf 'plaintext and digest destinations must differ\n' >&2
    exit 2
fi

umask 077
secret_tmp=''
digest_tmp=''
secret_tmp="$(mktemp "$(dirname -- "${destinations[0]}")/.t21-portal-secret.XXXXXX")"
digest_tmp="$(mktemp "$(dirname -- "${destinations[1]}")/.t21-portal-digest.XXXXXX")"
completed=false
cleanup() {
    if [[ "${completed}" == false ]]; then
        # Remove only links we placed; never remove a destination another actor
        # created after an exclusive link(2) attempt failed.
        [[ -n "${secret_tmp}" && -e "${secret_tmp}" && -e "${destinations[0]}" && "${secret_tmp}" -ef "${destinations[0]}" ]] && rm -f -- "${destinations[0]}"
        [[ -n "${digest_tmp}" && -e "${digest_tmp}" && -e "${destinations[1]}" && "${digest_tmp}" -ef "${destinations[1]}" ]] && rm -f -- "${destinations[1]}"
    fi
    [[ -z "${secret_tmp}" ]] || rm -f -- "${secret_tmp}"
    [[ -z "${digest_tmp}" ]] || rm -f -- "${digest_tmp}"
}
trap cleanup EXIT

openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n' >"${secret_tmp}"
if [[ "$(wc -c <"${secret_tmp}")" != 43 ]]; then
    printf 'unexpected encoded secret length\n' >&2
    exit 1
fi
sha256sum "${secret_tmp}" | awk '{print $1}' >"${digest_tmp}"
chmod 600 -- "${secret_tmp}" "${digest_tmp}"

# link(2) is an exclusive no-overwrite placement: an existing file, directory,
# or symlink makes it fail and is never followed or replaced.
ln -T -- "${secret_tmp}" "${destinations[0]}"
ln -T -- "${digest_tmp}" "${destinations[1]}"
rm -f -- "${secret_tmp}" "${digest_tmp}"
completed=true
trap - EXIT
printf 'prepared secret artifacts successfully\n'
