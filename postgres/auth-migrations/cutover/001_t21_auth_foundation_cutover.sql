\set ON_ERROR_STOP on
\if :{?portal_service_secret_sha256_hex}
\else
\echo 'portal_service_secret_sha256_hex must be supplied from the protected digest file' stderr
\quit 3
\endif

-- T21 one-shot only: run after writers stop, a database-scoped backup, and
-- the normal T05 schema migration. This directory is excluded from normal migration runs.
BEGIN;
CREATE TEMP TABLE t21_parameters ON COMMIT DROP AS
SELECT :'portal_service_secret_sha256_hex'::text AS service_secret_sha256_hex;
LOCK TABLE public.users IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    legacy_count bigint;
    distinct_ids bigint;
    distinct_google_ids bigint;
    max_legacy_id integer;
    target_count bigint;
    sequence_last bigint;
    sequence_called boolean;
    sequence_increment bigint;
    sequence_next bigint;
    target_next bigint;
    dependency_detail text;
    secret_hash text;
BEGIN
    IF to_regclass('public.users') IS NULL THEN
        RAISE EXCEPTION 'legacy public.users is required';
    END IF;
    IF to_regclass('public.internal_users') IS NULL
       OR to_regclass('public.external_identities') IS NULL
       OR to_regclass('public.registered_web_services') IS NULL THEN
        RAISE EXCEPTION 'T05 authentication schema must be applied first';
    END IF;
    SELECT service_secret_sha256_hex INTO secret_hash FROM t21_parameters;
    IF secret_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'portal service secret digest must be 64 lowercase hexadecimal characters';
    END IF;

    SELECT count(*), count(DISTINCT id), count(DISTINCT google_id), max(id)
      INTO legacy_count, distinct_ids, distinct_google_ids, max_legacy_id FROM public.users;
    IF legacy_count <> distinct_ids
       OR EXISTS (SELECT 1 FROM public.users WHERE id IS NULL OR id < 1) THEN
        RAISE EXCEPTION 'legacy users.id is not a positive unique migration key';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.users
         WHERE google_id IS NULL OR btrim(google_id) = ''
    ) THEN
        RAISE EXCEPTION 'legacy users.google_id has a NULL or blank value; STOP for manual repair';
    END IF;
    IF distinct_google_ids <> legacy_count THEN
        RAISE EXCEPTION 'legacy users.google_id is not unique; STOP for manual repair';
    END IF;
    IF (SELECT atttypid FROM pg_attribute
         WHERE attrelid = 'public.users'::regclass AND attname = 'created_at' AND NOT attisdropped)
            <> 'timestamp without time zone'::regtype
       OR EXISTS (SELECT 1 FROM public.users WHERE created_at IS NULL OR NOT isfinite(created_at)) THEN
        RAISE EXCEPTION 'legacy users.created_at is not a finite timestamp without time zone';
    END IF;
    SELECT count(*) INTO target_count FROM public.internal_users;
    IF target_count <> 0 THEN RAISE EXCEPTION 'internal_users must be empty; found %', target_count; END IF;
    SELECT count(*) INTO target_count FROM public.external_identities;
    IF target_count <> 0 THEN RAISE EXCEPTION 'external_identities must be empty; found %', target_count; END IF;
    SELECT count(*) INTO target_count FROM public.registered_web_services;
    IF target_count <> 0 THEN RAISE EXCEPTION 'registered_web_services must be empty; found %', target_count; END IF;

    SELECT last_value, is_called INTO sequence_last, sequence_called FROM public.users_id_seq;
    SELECT increment_by INTO sequence_increment FROM pg_sequences
     WHERE schemaname = 'public' AND sequencename = 'users_id_seq';
    IF sequence_increment IS NULL OR sequence_increment <= 0 THEN
        RAISE EXCEPTION 'users_id_seq must have a positive increment';
    END IF;
    sequence_next := CASE WHEN sequence_called THEN sequence_last + sequence_increment ELSE sequence_last END;
    target_next := GREATEST(COALESCE(max_legacy_id::bigint + 1, 1), sequence_next);
    IF target_next < 1 OR target_next > 2147483647 THEN
        RAISE EXCEPTION 'calculated next internal user ID % is outside integer range', target_next;
    END IF;
    SELECT string_agg(pg_describe_object(classid, objid, objsubid), '; ')
      INTO dependency_detail FROM pg_depend
     WHERE refobjid = 'public.users'::regclass AND deptype = 'n';
    IF dependency_detail IS NOT NULL THEN
        RAISE EXCEPTION 'legacy users has dependencies; DROP CASCADE is forbidden: %', dependency_detail;
    END IF;
END
$$;

INSERT INTO public.internal_users (internal_user_id, is_enabled, created_at)
SELECT id, true, created_at AT TIME ZONE 'UTC' FROM public.users ORDER BY id;
INSERT INTO public.external_identities (provider, subject, internal_user_id, linked_at)
SELECT 'google', google_id, id, CURRENT_TIMESTAMP FROM public.users ORDER BY id;

DO $$
DECLARE
    legacy_count bigint;
    copied_users bigint;
    copied_identities bigint;
    id_mismatches bigint;
    max_legacy_id integer;
    sequence_last bigint;
    sequence_called boolean;
    sequence_increment bigint;
    target_next bigint;
BEGIN
    SELECT count(*), max(id) INTO legacy_count, max_legacy_id FROM public.users;
    SELECT count(*) INTO copied_users FROM public.internal_users;
    SELECT count(*) INTO copied_identities FROM public.external_identities WHERE provider = 'google';
    SELECT count(*) INTO id_mismatches
      FROM public.users AS legacy FULL JOIN public.internal_users AS target
        ON target.internal_user_id = legacy.id
     WHERE legacy.id IS NULL OR target.internal_user_id IS NULL;
    IF copied_users <> legacy_count OR copied_identities <> legacy_count OR id_mismatches <> 0 THEN
        RAISE EXCEPTION 'copy verification failed (legacy %, users %, identities %, mismatches %)',
            legacy_count, copied_users, copied_identities, id_mismatches;
    END IF;
    SELECT last_value, is_called INTO sequence_last, sequence_called FROM public.users_id_seq;
    SELECT increment_by INTO sequence_increment FROM pg_sequences
     WHERE schemaname = 'public' AND sequencename = 'users_id_seq';
    target_next := GREATEST(
        COALESCE(max_legacy_id::bigint + 1, 1),
        CASE WHEN sequence_called THEN sequence_last + sequence_increment ELSE sequence_last END
    );
    PERFORM setval(
        pg_get_serial_sequence('public.internal_users', 'internal_user_id')::regclass,
        target_next,
        false
    );
END
$$;

-- Intentionally no CASCADE. A dependency aborts this transaction.
DROP TABLE public.users;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.internal_users FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.external_identities FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.registered_web_services FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON SEQUENCE public.internal_users_internal_user_id_seq FROM auth0_app_user;
GRANT USAGE ON SCHEMA public TO auth0_app_user;
GRANT SELECT, INSERT ON TABLE public.internal_users TO auth0_app_user;
GRANT SELECT, INSERT ON TABLE public.external_identities TO auth0_app_user;
GRANT SELECT ON TABLE public.registered_web_services TO auth0_app_user;
GRANT USAGE ON SEQUENCE public.internal_users_internal_user_id_seq TO auth0_app_user;

INSERT INTO public.registered_web_services (
    service_id, is_enabled, login_callback_uri, logout_return_uri, service_secret_sha256
)
SELECT 'portal-prod', false,
       'https://portal.tororomeshi.net/auth/callback',
       'https://portal.tororomeshi.net/',
       decode(service_secret_sha256_hex, 'hex')
  FROM t21_parameters;

DO $$
DECLARE
    supplied_hash text;
    checked_table text;
    forbidden_privilege text;
BEGIN
    SELECT service_secret_sha256_hex INTO supplied_hash FROM t21_parameters;
    IF (SELECT is_called FROM public.internal_users_internal_user_id_seq) THEN
        RAISE EXCEPTION 'internal_users sequence must remain uncalled until the first new user';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.registered_web_services
         WHERE service_id = 'portal-prod' AND is_enabled = false
           AND login_callback_uri = 'https://portal.tororomeshi.net/auth/callback'
           AND logout_return_uri = 'https://portal.tororomeshi.net/'
           AND encode(service_secret_sha256, 'hex') = supplied_hash
    ) THEN RAISE EXCEPTION 'portal-prod disabled bootstrap verification failed'; END IF;
    IF NOT has_table_privilege('auth0_app_user', 'public.internal_users', 'SELECT')
       OR NOT has_table_privilege('auth0_app_user', 'public.internal_users', 'INSERT')
       OR NOT has_table_privilege('auth0_app_user', 'public.external_identities', 'SELECT')
       OR NOT has_table_privilege('auth0_app_user', 'public.external_identities', 'INSERT')
       OR NOT has_table_privilege('auth0_app_user', 'public.registered_web_services', 'SELECT')
       OR NOT has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'USAGE') THEN
        RAISE EXCEPTION 'auth0_app_user minimum grants verification failed';
    END IF;
    IF NOT has_schema_privilege('auth0_app_user', 'public', 'USAGE')
       OR has_schema_privilege('auth0_app_user', 'public', 'CREATE')
       OR has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'SELECT, UPDATE') THEN
        RAISE EXCEPTION 'auth0_app_user has a privilege beyond the T21 runtime minimum';
    END IF;
    -- has_table_privilege checks privileges auth0_app_user can actually exercise,
    -- including privileges inherited through membership in another role.
    FOREACH checked_table IN ARRAY ARRAY[
        'public.internal_users',
        'public.external_identities',
        'public.registered_web_services'
    ] LOOP
        FOREACH forbidden_privilege IN ARRAY ARRAY[
            'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'MAINTAIN'
        ] LOOP
            IF has_table_privilege('auth0_app_user', checked_table, forbidden_privilege) THEN
                RAISE EXCEPTION
                    'auth0_app_user has forbidden effective % privilege on %',
                    forbidden_privilege, checked_table;
            END IF;
        END LOOP;
    END LOOP;
    IF has_table_privilege('auth0_app_user', 'public.registered_web_services', 'INSERT') THEN
        RAISE EXCEPTION
            'auth0_app_user has forbidden effective INSERT privilege on public.registered_web_services';
    END IF;
END
$$;

SELECT
    (SELECT count(*) FROM public.internal_users) AS migrated_users,
    (SELECT count(*) FROM public.external_identities WHERE provider = 'google') AS migrated_google_identities,
    (SELECT last_value FROM public.internal_users_internal_user_id_seq) AS next_internal_user_id,
    (SELECT is_enabled FROM public.registered_web_services WHERE service_id = 'portal-prod') AS portal_prod_enabled;
COMMIT;
