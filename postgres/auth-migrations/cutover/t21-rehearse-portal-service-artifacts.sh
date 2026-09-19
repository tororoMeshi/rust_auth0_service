#!/usr/bin/env bash
set -euo pipefail
set +x

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
prepare_script="${repo_root}/postgres/auth-migrations/cutover/t21-prepare-portal-service-secret.sh"
verify_script="${repo_root}/postgres/auth-migrations/cutover/t21-verify-portal-service-registration.sh"
enable_script="${repo_root}/postgres/auth-migrations/cutover/t21-enable-portal-service.sh"
workdir="$(mktemp -d)"
cleanup() { rm -rf -- "${workdir}"; }
trap cleanup EXIT
chmod 700 "${workdir}"

secret_file="${workdir}/portal-secret"
digest_file="${workdir}/portal-digest.sha256"
export T21_SECRET_FILE="${secret_file}"
export T21_SERVICE_SECRET_SHA256_FILE="${digest_file}"
"${prepare_script}" >/dev/null
[[ "${T21_SECRET_FILE}" == "${secret_file}" ]]
[[ "${T21_SERVICE_SECRET_SHA256_FILE}" == "${digest_file}" ]]
[[ -f "${secret_file}" && -f "${digest_file}" ]]
[[ "$(stat -c '%a' -- "${secret_file}")" == 600 ]]
[[ "$(stat -c '%a' -- "${digest_file}")" == 600 ]]
[[ "$(wc -c <"${secret_file}")" == 43 ]]
LC_ALL=C grep -Eq '^[A-Za-z0-9_-]{43}$' "${secret_file}"
[[ "$(sha256sum -- "${secret_file}" | awk '{print $1}')" == "$(<"${digest_file}")" ]]
printf 'portal secret rehearsal PASS: distinct secure artifacts\n'

same_path="${workdir}/same"
if T21_SECRET_FILE="${same_path}" T21_SERVICE_SECRET_SHA256_FILE="${same_path}" \
    "${prepare_script}" >/dev/null 2>&1; then
    printf 'same-path rejection unexpectedly succeeded\n' >&2
    exit 1
fi
[[ ! -e "${same_path}" && ! -L "${same_path}" ]]

mkdir "${workdir}/equivalent"
canonical_path="${workdir}/canonical"
if T21_SECRET_FILE="${workdir}/equivalent/../canonical" T21_SERVICE_SECRET_SHA256_FILE="${canonical_path}" \
    "${prepare_script}" >/dev/null 2>&1; then
    printf 'canonical-equivalent-path rejection unexpectedly succeeded\n' >&2
    exit 1
fi
[[ ! -e "${canonical_path}" && ! -L "${canonical_path}" ]]

existing_secret="${workdir}/existing-secret"
existing_digest="${workdir}/existing-digest"
printf 'protected-existing-content' >"${existing_secret}"
existing_before="$(sha256sum -- "${existing_secret}" | awk '{print $1}')"
if T21_SECRET_FILE="${existing_secret}" T21_SERVICE_SECRET_SHA256_FILE="${existing_digest}" \
    "${prepare_script}" >/dev/null 2>&1; then
    printf 'existing-target rejection unexpectedly succeeded\n' >&2
    exit 1
fi
[[ "${existing_before}" == "$(sha256sum -- "${existing_secret}" | awk '{print $1}')" ]]
[[ ! -e "${existing_digest}" && ! -L "${existing_digest}" ]]

symlink_target="${workdir}/symlink-target"
symlink_secret="${workdir}/symlink-secret"
symlink_digest="${workdir}/symlink-digest"
printf 'protected-symlink-target' >"${symlink_target}"
symlink_before="$(sha256sum -- "${symlink_target}" | awk '{print $1}')"
ln -s "${symlink_target}" "${symlink_secret}"
if T21_SECRET_FILE="${symlink_secret}" T21_SERVICE_SECRET_SHA256_FILE="${symlink_digest}" \
    "${prepare_script}" >/dev/null 2>&1; then
    printf 'symlink-target rejection unexpectedly succeeded\n' >&2
    exit 1
fi
[[ "${symlink_before}" == "$(sha256sum -- "${symlink_target}" | awk '{print $1}')" ]]
[[ ! -e "${symlink_digest}" && ! -L "${symlink_digest}" ]]
printf 'portal secret rehearsal PASS: collision and existing-target rejection\n'

race_bin="${workdir}/race-bin"
mkdir "${race_bin}"
race_target="${workdir}/race-target"
race_secret="${workdir}/race-secret"
race_digest="${workdir}/race-digest"
cat >"${race_bin}/ln" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${4:-}" == "${T21_RACE_DESTINATION}" ]]; then
    mkdir -- "${T21_RACE_TARGET}"
    /usr/bin/ln -s -- "${T21_RACE_TARGET}" "${T21_RACE_DESTINATION}"
fi
exec /usr/bin/ln "$@"
EOF
chmod 700 "${race_bin}/ln"
[[ ! -e "${race_secret}" && ! -L "${race_secret}" ]]
[[ ! -e "${race_target}" && ! -L "${race_target}" ]]
if PATH="${race_bin}:${PATH}" T21_RACE_DESTINATION="${race_secret}" \
    T21_RACE_TARGET="${race_target}" T21_SECRET_FILE="${race_secret}" \
    T21_SERVICE_SECRET_SHA256_FILE="${race_digest}" \
    "${prepare_script}" >/dev/null 2>&1; then
    printf 'directory-symlink race unexpectedly succeeded\n' >&2
    exit 1
fi
[[ -L "${race_secret}" ]]
[[ -d "${race_target}" ]]
[[ -z "$(find "${race_target}" -mindepth 1 -maxdepth 1 -print -quit)" ]]
[[ -z "$(find "${workdir}" -maxdepth 1 -type f \( -name '.t21-portal-secret.*' -o -name '.t21-portal-digest.*' \) -print -quit)" ]]
[[ ! -e "${race_digest}" && ! -L "${race_digest}" ]]
printf 'portal secret rehearsal PASS: directory-symlink race rejection and cleanup\n'

fake_bin="${workdir}/bin"
mkdir "${fake_bin}"
cat >"${fake_bin}/psql" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ " $* " == *' -d auth0_accounts '* ]] || exit 97
if [[ "$*" == *'UPDATE public.registered_web_services'* ]]; then
    [[ "$*" == *"service_id = 'portal-prod'"* ]] || exit 97
    [[ "$*" == *'is_enabled = false'* ]] || exit 97
    [[ "$*" == *'RETURNING service_id'* ]] || exit 97
    [[ "$(<"${T21_FAKE_ENABLED_FILE}")" == false ]] || exit 0
    printf 'true\n' >"${T21_FAKE_ENABLED_FILE}"
    printf 'portal-prod\n'
    exit 0
fi
[[ "$*" == *"service_id = 'portal-prod'"* ]] || exit 97
expected_enabled="${T21_EXPECTED_ENABLED:-false}"
[[ "$*" == *"is_enabled = ${expected_enabled}"* ]] || exit 97
[[ "$(<"${T21_FAKE_ENABLED_FILE}")" == "${expected_enabled}" ]] || exit 0
[[ "$*" == *"login_callback_uri = 'https://portal.tororomeshi.net/auth/callback'"* ]] || exit 97
[[ "$*" == *"logout_return_uri = 'https://portal.tororomeshi.net/'"* ]] || exit 97
case "${T21_VERIFIER_CASE}:${expected_enabled}" in
    all_match:false|all_match:true|wrong_kubernetes_secret:false) printf '%s\n' "${T21_EXPECTED_HASH}" ;;
    wrong_db_hash) printf '%064d\n' 0 ;;
    wrong_callback|wrong_logout_uri) exit 0 ;;
    *) exit 98 ;;
esac
EOF
cat >"${fake_bin}/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *'get secret portal-prod-service-secret -n auth0'* ]] || exit 97
case "${T21_VERIFIER_CASE}" in
    missing_secret_or_key) exit 1 ;;
    wrong_kubernetes_secret) printf 'different fixture value' | base64 | tr -d '\n' ;;
    *) base64 <"${T21_KUBERNETES_SECRET_FILE}" | tr -d '\n' ;;
esac
EOF
chmod 700 "${fake_bin}/psql" "${fake_bin}/kubectl"
export PATH="${fake_bin}:${PATH}"
export T21_EXPECTED_HASH="$(<"${digest_file}")"
export T21_KUBERNETES_SECRET_FILE="${secret_file}"
export T21_FAKE_ENABLED_FILE="${workdir}/enabled"
printf 'false\n' >"${T21_FAKE_ENABLED_FILE}"

run_verifier_case() {
    local test_case="$1" expected="$2" expected_enabled="${3:-false}"
    if T21_VERIFIER_CASE="${test_case}" T21_EXPECTED_ENABLED="${expected_enabled}" \
        "${verify_script}" >/dev/null 2>&1; then
        [[ "${expected}" == pass ]] || {
            printf 'verifier %s unexpectedly succeeded\n' "${test_case}" >&2
            exit 1
        }
    else
        [[ "${expected}" == fail ]] || {
            printf 'verifier %s unexpectedly failed\n' "${test_case}" >&2
            exit 1
        }
    fi
}

run_verifier_case all_match pass
run_verifier_case wrong_db_hash fail
run_verifier_case wrong_callback fail
run_verifier_case wrong_logout_uri fail
run_verifier_case wrong_kubernetes_secret fail
run_verifier_case missing_secret_or_key fail
printf 'true\n' >"${T21_FAKE_ENABLED_FILE}"
run_verifier_case all_match fail
printf 'false\n' >"${T21_FAKE_ENABLED_FILE}"
T21_PSQL=psql "${enable_script}" | grep -Fx 'portal-prod enable PASS (updated rows=1)'
run_verifier_case all_match pass true
if T21_PSQL=psql "${enable_script}" >/dev/null 2>&1; then
    printf 'initial enable unexpectedly succeeded after Boundary B\n' >&2
    exit 1
fi
printf 'portal registration verifier rehearsal PASS: Boundary A false, exact one-row enable, Boundary B true, strict false rejection, and no enable rerun\n'
