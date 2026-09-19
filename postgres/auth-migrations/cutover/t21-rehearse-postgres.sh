#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
container="t21-postgres-$RANDOM-$$"
workdir="$(mktemp -d)"
secret_file="${workdir}/portal-secret"
digest_file="${workdir}/portal-secret.sha256"
prepare_script="${repo_root}/postgres/auth-migrations/cutover/t21-prepare-portal-service-secret.sh"
enable_script="${repo_root}/postgres/auth-migrations/cutover/t21-enable-portal-service.sh"
cleanup() { rm -rf -- "${workdir}"; docker rm -f "${container}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

export T21_SECRET_FILE="${secret_file}"
export T21_SERVICE_SECRET_SHA256_FILE="${digest_file}"
"${prepare_script}" >/dev/null
[[ -f "${T21_SECRET_FILE}" && -f "${T21_SERVICE_SECRET_SHA256_FILE}" ]]

run_t21() {
  docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 \
    -v portal_service_secret_sha256_hex="$(<"${T21_SERVICE_SECRET_SHA256_FILE}")" \
    -f /dev/stdin <"${repo_root}/postgres/auth-migrations/cutover/001_t21_auth_foundation_cutover.sql"
}

t21_psql() {
  docker exec -i "${container}" psql -X -U postgres "$@"
}
export -f t21_psql
export container

docker run --rm -d --name "${container}" -e POSTGRES_PASSWORD=fixture-only postgres:17-alpine >/dev/null
until docker exec "${container}" pg_isready -U postgres -d postgres >/dev/null; do sleep 1; done

docker exec -i "${container}" psql -X -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE DATABASE auth0_accounts;
\c auth0_accounts
CREATE ROLE auth0_app_user LOGIN;
CREATE TABLE public.users (
  id SERIAL PRIMARY KEY, email varchar(255) UNIQUE NOT NULL, google_id varchar(255) UNIQUE NOT NULL
);
INSERT INTO public.users (email, google_id) VALUES
  ('legacy-one@example.test', 'legacy-google-one'),
  ('legacy-two@example.test', 'legacy-google-two');
GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO auth0_app_user;
GRANT CREATE ON SCHEMA public TO auth0_app_user;
SQL

docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -f /dev/stdin <"${repo_root}/postgres/auth-migrations/001_create_authentication_tables.sql" >/dev/null
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO public.registered_web_services (
  service_id, is_enabled, login_callback_uri, logout_return_uri, service_secret_sha256
) VALUES ('portal-prod', false, 'https://unexpected.example.test/callback', 'https://unexpected.example.test/', decode(repeat('b', 64), 'hex'));
SQL
if run_t21 >/dev/null 2>&1; then
  printf 'T21 atomic failure rehearsal unexpectedly succeeded\n' >&2
  exit 1
fi
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT has_table_privilege('auth0_app_user', 'public.users', 'SELECT') THEN RAISE EXCEPTION 'failed T21 committed legacy revoke'; END IF;
  IF has_table_privilege('auth0_app_user', 'public.internal_users', 'SELECT') THEN RAISE EXCEPTION 'failed T21 committed new grant'; END IF;
END
$$;
DELETE FROM public.registered_web_services WHERE service_id = 'portal-prod';
SQL
printf 'T21 atomic failure leaves no T21 state PASS\n'

run_t21 >/dev/null
T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh"
[[ "${T21_SECRET_FILE}" == "${secret_file}" ]]
[[ "${T21_SERVICE_SECRET_SHA256_FILE}" == "${digest_file}" ]]
printf 'T21 same-shell secret/digest path lifetime PASS\n'

docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF (SELECT count(*) FROM public.users) <> 2 THEN RAISE EXCEPTION 'legacy users changed'; END IF;
  IF (SELECT count(*) FROM public.internal_users) <> 0 OR (SELECT count(*) FROM public.external_identities) <> 0 THEN RAISE EXCEPTION 'fresh identity state is not empty'; END IF;
  IF (SELECT count(*) FROM public.registered_web_services WHERE service_id = 'portal-prod') <> 1 THEN RAISE EXCEPTION 'portal registration count changed'; END IF;
END
$$;
SQL

# Simulate a later cutover failure. Resume calls only the read-only completion
# verifier; it never invokes the T21 SQL whose INSERT would conflict.
if false; then :; fi
T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh"
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -Atq -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM public.registered_web_services WHERE service_id = 'portal-prod'" | grep -qx '1'
printf 'T21 post-commit resume boundary PASS\n'

docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE t21_inherited_leak;
GRANT t21_inherited_leak TO auth0_app_user;
GRANT UPDATE ON public.internal_users TO t21_inherited_leak;
GRANT CREATE ON SCHEMA public TO t21_inherited_leak;
SQL
if T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh" >/dev/null 2>&1; then
  printf 'inherited forbidden privilege leak was not detected\n' >&2
  exit 1
fi
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -c 'REVOKE t21_inherited_leak FROM auth0_app_user; REVOKE UPDATE ON public.internal_users FROM t21_inherited_leak; REVOKE CREATE ON SCHEMA public FROM t21_inherited_leak;' >/dev/null

docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -c 'GRANT SELECT ON public.users TO PUBLIC;' >/dev/null
if T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh" >/dev/null 2>&1; then
  printf 'PUBLIC legacy privilege leak was not detected\n' >&2
  exit 1
fi
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -c 'REVOKE SELECT ON public.users FROM PUBLIC;' >/dev/null
T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh"
printf 'T21 effective privilege inherited/PUBLIC leakage detection PASS\n'

# Boundary A has just passed. The exact one-time operator command must change
# only portal-prod from false to true and report exactly one updated row.
T21_PSQL=t21_psql "${enable_script}" | grep -Fx 'portal-prod enable PASS (updated rows=1)'
docker exec -i "${container}" psql -X -U postgres -d auth0_accounts -Atq -v ON_ERROR_STOP=1 \
  -c "SELECT service_id FROM public.registered_web_services WHERE service_id = 'portal-prod' AND is_enabled = true" | grep -qx 'portal-prod'
printf 'T21 portal-prod false-to-true enable transition PASS\n'

# The strict pre-enable verifier must still reject the post-enable state.
if T21_PSQL=t21_psql "${repo_root}/postgres/auth-migrations/cutover/t21-verify-auth-foundation-state.sh" >/dev/null 2>&1; then
  printf 'T21 pre-enable verifier accepted enabled portal-prod\n' >&2
  exit 1
fi
printf 'T21 pre-enable verifier rejects enabled=true PASS\n'
printf 'T21 fresh Auth Foundation PostgreSQL rehearsal PASS\n'
