#!/usr/bin/env bash
set -euo pipefail
set +x

# Read-only T21 completion verifier. It uses PostgreSQL effective privilege
# functions, so direct grants, role membership, and PUBLIC are all considered.
digest_file="${T21_SERVICE_SECRET_SHA256_FILE:?T21_SERVICE_SECRET_SHA256_FILE must name the protected digest artifact}"
[[ -f "${digest_file}" && ! -L "${digest_file}" && -r "${digest_file}" ]] || {
    printf 'protected digest artifact is not a readable regular file\n' >&2
    exit 2
}

expected_hash="$(<"${digest_file}")"
[[ "${expected_hash}" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'protected digest artifact must contain one lowercase SHA-256 hexadecimal digest\n' >&2
    exit 2
}

psql_command="${T21_PSQL:-psql}"
failed_checks="$("${psql_command}" -X -Atq -v ON_ERROR_STOP=1 -d auth0_accounts \
    -v expected_hash="${expected_hash}" <<'SQL'
WITH checks(check_name, ok) AS (
    VALUES
        ('portal-prod exact disabled registration', (
            SELECT count(*) = 1
              FROM public.registered_web_services
             WHERE service_id = 'portal-prod'
               AND is_enabled = false
               AND login_callback_uri = 'https://portal.tororomeshi.net/auth/callback'
               AND logout_return_uri = 'https://portal.tororomeshi.net/'
               AND service_secret_sha256 = decode(:'expected_hash', 'hex')
        )),
        ('public schema usage', has_schema_privilege('auth0_app_user', 'public', 'USAGE')),
        ('public schema CREATE absent', NOT has_schema_privilege('auth0_app_user', 'public', 'CREATE')),
        ('internal_users SELECT', has_table_privilege('auth0_app_user', 'public.internal_users', 'SELECT')),
        ('internal_users INSERT', has_table_privilege('auth0_app_user', 'public.internal_users', 'INSERT')),
        ('external_identities SELECT', has_table_privilege('auth0_app_user', 'public.external_identities', 'SELECT')),
        ('external_identities INSERT', has_table_privilege('auth0_app_user', 'public.external_identities', 'INSERT')),
        ('registered_web_services SELECT', has_table_privilege('auth0_app_user', 'public.registered_web_services', 'SELECT')),
        ('internal_users identity sequence USAGE', has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'USAGE')),
        ('forbidden Auth Foundation table privileges absent', NOT EXISTS (
            SELECT 1
              FROM (VALUES
                  ('public.internal_users', 'UPDATE'), ('public.internal_users', 'DELETE'),
                  ('public.internal_users', 'TRUNCATE'), ('public.internal_users', 'REFERENCES'),
                  ('public.internal_users', 'TRIGGER'), ('public.internal_users', 'MAINTAIN'),
                  ('public.external_identities', 'UPDATE'), ('public.external_identities', 'DELETE'),
                  ('public.external_identities', 'TRUNCATE'), ('public.external_identities', 'REFERENCES'),
                  ('public.external_identities', 'TRIGGER'), ('public.external_identities', 'MAINTAIN'),
                  ('public.registered_web_services', 'INSERT'), ('public.registered_web_services', 'UPDATE'),
                  ('public.registered_web_services', 'DELETE'), ('public.registered_web_services', 'TRUNCATE'),
                  ('public.registered_web_services', 'REFERENCES'), ('public.registered_web_services', 'TRIGGER'),
                  ('public.registered_web_services', 'MAINTAIN')
              ) AS forbidden(relation_name, privilege_name)
             WHERE has_table_privilege('auth0_app_user', relation_name, privilege_name)
        )),
        ('forbidden new identity sequence privileges absent',
            NOT has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'SELECT')
            AND NOT has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'UPDATE')),
        ('legacy public.users effective access absent', NOT EXISTS (
            SELECT 1
              FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN']) AS privilege_name
             WHERE has_table_privilege('auth0_app_user', 'public.users', privilege_name)
        )),
        ('legacy users_id_seq effective access absent', NOT EXISTS (
            SELECT 1
              FROM unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS privilege_name
             WHERE has_sequence_privilege('auth0_app_user', 'public.users_id_seq', privilege_name)
        ))
)
SELECT check_name FROM checks WHERE NOT ok ORDER BY check_name;
SQL
)" || {
    printf 'T21 Auth Foundation database completion verification failed\n' >&2
    exit 1
}

if [[ -n "${failed_checks}" ]]; then
    printf 'T21 Auth Foundation database completion verification failed: %s\n' "${failed_checks//$'\n'/, }" >&2
    exit 1
fi

printf 'T21 Auth Foundation database completion verification PASS\n'
