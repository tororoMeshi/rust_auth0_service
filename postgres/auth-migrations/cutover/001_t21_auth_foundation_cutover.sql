\set ON_ERROR_STOP on
\if :{?portal_service_secret_sha256_hex}
\else
\echo 'portal_service_secret_sha256_hex must be supplied from the protected digest file' stderr
\quit
\endif

-- Run once after T05. This initializes only the new Auth Foundation state.
-- public.users is deliberately left untouched and is not a new-runtime dependency.
-- This file owns one transaction boundary: failure commits no T21 state.
BEGIN;

CREATE TEMP TABLE t21_parameters ON COMMIT DROP AS
SELECT :'portal_service_secret_sha256_hex'::text AS service_secret_sha256_hex;

DO $$
DECLARE
    secret_hash text;
BEGIN
    IF to_regclass('public.internal_users') IS NULL
       OR to_regclass('public.external_identities') IS NULL
       OR to_regclass('public.registered_web_services') IS NULL THEN
        RAISE EXCEPTION 'T05 authentication schema must be applied before T21';
    END IF;
    SELECT service_secret_sha256_hex INTO secret_hash FROM t21_parameters;
    IF secret_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'portal service secret digest must be 64 lowercase hexadecimal characters';
    END IF;
    IF EXISTS (SELECT 1 FROM public.internal_users)
       OR EXISTS (SELECT 1 FROM public.external_identities) THEN
        RAISE EXCEPTION 'fresh Auth Foundation identity state must be empty before T21';
    END IF;
END
$$;

REVOKE ALL PRIVILEGES ON TABLE public.users FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.internal_users FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.external_identities FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON TABLE public.registered_web_services FROM auth0_app_user;
REVOKE ALL PRIVILEGES ON SEQUENCE public.internal_users_internal_user_id_seq FROM auth0_app_user;
REVOKE CREATE ON SCHEMA public FROM auth0_app_user;
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
BEGIN
    SELECT service_secret_sha256_hex INTO supplied_hash FROM t21_parameters;
    IF NOT EXISTS (
        SELECT 1 FROM public.registered_web_services
         WHERE service_id = 'portal-prod' AND is_enabled = false
           AND login_callback_uri = 'https://portal.tororomeshi.net/auth/callback'
           AND logout_return_uri = 'https://portal.tororomeshi.net/'
           AND encode(service_secret_sha256, 'hex') = supplied_hash
    ) THEN
        RAISE EXCEPTION 'portal-prod disabled bootstrap verification failed';
    END IF;
    IF NOT has_table_privilege('auth0_app_user', 'public.internal_users', 'SELECT')
       OR NOT has_table_privilege('auth0_app_user', 'public.internal_users', 'INSERT')
       OR NOT has_table_privilege('auth0_app_user', 'public.external_identities', 'SELECT')
       OR NOT has_table_privilege('auth0_app_user', 'public.external_identities', 'INSERT')
       OR NOT has_table_privilege('auth0_app_user', 'public.registered_web_services', 'SELECT')
       OR NOT has_sequence_privilege('auth0_app_user', 'public.internal_users_internal_user_id_seq', 'USAGE')
       OR has_table_privilege('auth0_app_user', 'public.users', 'SELECT')
       OR has_table_privilege('auth0_app_user', 'public.users', 'INSERT') THEN
        RAISE EXCEPTION 'auth0_app_user minimum grants verification failed';
    END IF;
END
$$;

COMMIT;
