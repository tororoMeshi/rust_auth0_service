#!/usr/bin/env bash
set -euo pipefail
set +x

# Read-only pre-enable verifier. It neither changes PostgreSQL nor Kubernetes.
secret_file="${T21_SECRET_FILE:?T21_SECRET_FILE must name the protected plaintext artifact}"
[[ -f "${secret_file}" && ! -L "${secret_file}" && -r "${secret_file}" ]] || {
    printf 'protected plaintext artifact is not a readable regular file\n' >&2
    exit 2
}

expected_hash="$(sha256sum -- "${secret_file}" | awk '{print $1}')"
db_hash="$(psql -X -At -v ON_ERROR_STOP=1 -d auth0_accounts -c "
SELECT encode(service_secret_sha256, 'hex')
  FROM public.registered_web_services
 WHERE service_id = 'portal-prod'
   AND is_enabled = false
   AND login_callback_uri = 'https://portal.tororomeshi.net/auth/callback'
   AND logout_return_uri = 'https://portal.tororomeshi.net/';
")" || {
    printf 'portal service database verification failed\n' >&2
    exit 1
}
[[ "${db_hash}" =~ ^[0-9a-f]{64}$ && "${db_hash}" == "${expected_hash}" ]] || {
    printf 'portal service database verification failed\n' >&2
    exit 1
}

kubernetes_hash="$(kubectl get secret portal-prod-service-secret -n auth0 \
    -o jsonpath='{.data.service_secret}' | base64 -d | sha256sum | awk '{print $1}')" || {
    printf 'portal service Kubernetes Secret verification failed\n' >&2
    exit 1
}
[[ "${kubernetes_hash}" == "${expected_hash}" ]] || {
    printf 'portal service Kubernetes Secret verification failed\n' >&2
    exit 1
}

printf 'portal service registration verification PASS\n'
