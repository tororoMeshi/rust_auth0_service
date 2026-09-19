#!/usr/bin/env bash
set -euo pipefail

# One-time operator transition after Boundary A; an already-enabled row is a
# resume boundary, never an upsert/reconcile case.
psql_command="${T21_PSQL:-psql}"
updated_service_id="$("${psql_command}" -X -Atq -v ON_ERROR_STOP=1 -d auth0_accounts -c "
UPDATE public.registered_web_services
   SET is_enabled = true
 WHERE service_id = 'portal-prod'
   AND is_enabled = false
RETURNING service_id;
")"

# The key permits at most one target row. Exact psql output proves the one
# permitted false -> true transition; zero rows is not an initial-enable success.
if [[ "${updated_service_id}" != "portal-prod" ]]; then
    printf 'portal-prod enable failed: expected exactly 1 updated row returning portal-prod; got %q\n' "${updated_service_id}" >&2
    exit 1
fi

printf 'portal-prod enable PASS (updated rows=1)\n'
