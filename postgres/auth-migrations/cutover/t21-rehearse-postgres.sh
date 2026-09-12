#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
container="t21-postgres-$RANDOM-$$"
rehearsal_dir="$(mktemp -d)"
cleanup() {
    docker rm -f "${container}" >/dev/null 2>&1 || true
    rm -rf -- "${rehearsal_dir}"
}
trap cleanup EXIT
chmod 700 "${rehearsal_dir}"

docker run --rm -d --name "${container}" -e POSTGRES_HOST_AUTH_METHOD=trust \
    -e POSTGRES_DB=auth0_accounts -v "${repo_root}:/work:ro" postgres:17-alpine >/dev/null
until docker exec "${container}" pg_isready -U postgres -d auth0_accounts >/dev/null 2>&1; do sleep 1; done

run_sql() { docker exec -i "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts; }
run_case() {
    local label="$1" sequence_last="$2" expected_next="$3"
    run_sql <<SQL
CREATE ROLE auth0_app_user LOGIN;
CREATE TABLE public.users (
  id SERIAL PRIMARY KEY, email varchar(255) UNIQUE NOT NULL, google_id varchar(255) UNIQUE NOT NULL,
  name varchar(255), icon_url text, created_at timestamp without time zone NOT NULL
);
INSERT INTO public.users (id, email, google_id, name, created_at) VALUES
  (1, 'one-${label}@example.test', 'google-${label}-one', 'one', '2024-01-02 03:04:05'),
  (36, 'thirtysix-${label}@example.test', 'google-${label}-36', 'thirty-six', '2024-05-06 07:08:09');
SELECT setval('public.users_id_seq', ${sequence_last}, true);
SQL
    docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts \
        -f /work/postgres/auth-migrations/001_create_authentication_tables.sql >/dev/null
    local backup_file="${rehearsal_dir}/auth0_accounts-${label}.dump"
    local checksum_file="${backup_file}.sha256"
    # This is intentionally host-side durable storage, not the Pod filesystem.
    docker exec "${container}" pg_dump -U postgres -Fc -d auth0_accounts >"${backup_file}"
    [[ -s "${backup_file}" ]]
    (
        cd "${rehearsal_dir}"
        sha256sum "$(basename "${backup_file}")" >"$(basename "${checksum_file}")"
        sha256sum -c "$(basename "${checksum_file}")" >/dev/null
    )
    docker run --rm -v "${rehearsal_dir}:/backup:ro" postgres:17-alpine \
        pg_restore --list "/backup/$(basename "${backup_file}")" >/dev/null
    docker cp "${backup_file}" "${container}:/tmp/pre-cutover.dump"
    docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts \
        -v portal_service_secret_sha256_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        -f /work/postgres/auth-migrations/cutover/001_t21_auth_foundation_cutover.sql >/dev/null
    run_sql <<SQL
DO \$\$
BEGIN
  IF (SELECT array_agg(internal_user_id ORDER BY internal_user_id) FROM public.internal_users) <> ARRAY[1,36] THEN RAISE EXCEPTION 'ID preservation failed'; END IF;
  IF (SELECT count(*) FROM public.external_identities WHERE provider = 'google') <> 2 THEN RAISE EXCEPTION 'external identities failed'; END IF;
  IF (SELECT created_at AT TIME ZONE 'UTC' FROM public.internal_users WHERE internal_user_id = 1) <> timestamp '2024-01-02 03:04:05' THEN RAISE EXCEPTION 'UTC conversion failed'; END IF;
  IF (SELECT nextval(pg_get_serial_sequence('public.internal_users','internal_user_id'))) <> ${expected_next} THEN RAISE EXCEPTION 'high-water failed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.registered_web_services WHERE service_id = 'portal-prod' AND NOT is_enabled) THEN RAISE EXCEPTION 'disabled service failed'; END IF;
  IF has_table_privilege('auth0_app_user','public.internal_users','UPDATE') OR has_table_privilege('auth0_app_user','public.registered_web_services','INSERT') THEN RAISE EXCEPTION 'grant minimum failed'; END IF;
END \$\$;
SQL
    docker exec "${container}" pg_restore --clean --if-exists -U postgres -d auth0_accounts /tmp/pre-cutover.dump >/dev/null
    run_sql <<SQL
DO \$\$
DECLARE restored_last bigint; restored_called boolean;
BEGIN
  IF (SELECT count(*) FROM public.users) <> 2 THEN RAISE EXCEPTION 'legacy users were not restored'; END IF;
  SELECT last_value, is_called INTO restored_last, restored_called FROM public.users_id_seq;
  IF restored_last <> ${sequence_last} OR NOT restored_called THEN RAISE EXCEPTION 'legacy sequence was not restored'; END IF;
  IF (SELECT count(*) FROM public.internal_users) <> 0 OR (SELECT count(*) FROM public.external_identities) <> 0 OR (SELECT count(*) FROM public.registered_web_services) <> 0 THEN RAISE EXCEPTION 'T05 tables were not restored to empty state'; END IF;
END \$\$;
SQL
    printf 'PostgreSQL rehearsal PASS: %s (next ID %s)\n' "${label}" "${expected_next}"
}

# max(users.id)+1 > legacy sequence next; and the converse. No production value is hardcoded.
run_case max_wins 9 37
docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts -c 'DROP SCHEMA public CASCADE; DROP ROLE auth0_app_user; CREATE SCHEMA public;' >/dev/null
run_case sequence_wins 124 125
docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts -c 'DROP SCHEMA public CASCADE; DROP ROLE auth0_app_user; CREATE SCHEMA public;' >/dev/null

# The migration must reject a privilege reachable only through role membership.
run_sql <<'SQL'
CREATE ROLE auth0_app_user LOGIN;
CREATE ROLE t21_forbidden_helper NOLOGIN;
CREATE TABLE public.users (
  id SERIAL PRIMARY KEY, email varchar(255) UNIQUE NOT NULL, google_id varchar(255) UNIQUE NOT NULL,
  name varchar(255), icon_url text, created_at timestamp without time zone NOT NULL
);
INSERT INTO public.users (email, google_id, created_at)
VALUES ('inherited@example.test', 'google-inherited', '2024-01-02 03:04:05');
SQL
docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts \
    -f /work/postgres/auth-migrations/001_create_authentication_tables.sql >/dev/null
run_sql <<'SQL'
GRANT TRUNCATE ON public.internal_users TO t21_forbidden_helper;
GRANT t21_forbidden_helper TO auth0_app_user;
SQL
if docker exec "${container}" psql -X -v ON_ERROR_STOP=1 -U postgres -d auth0_accounts \
    -v portal_service_secret_sha256_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    -f /work/postgres/auth-migrations/cutover/001_t21_auth_foundation_cutover.sql >/dev/null 2>&1; then
    printf 'inherited forbidden privilege rehearsal unexpectedly succeeded\n' >&2
    exit 1
fi
run_sql <<'SQL'
DO $$
BEGIN
  IF to_regclass('public.users') IS NULL THEN RAISE EXCEPTION 'failed migration did not roll back legacy users'; END IF;
  IF EXISTS (SELECT 1 FROM public.registered_web_services WHERE service_id = 'portal-prod') THEN RAISE EXCEPTION 'failed migration committed portal bootstrap'; END IF;
END
$$;
SQL
printf 'PostgreSQL rehearsal PASS: inherited TRUNCATE rejected\n'
