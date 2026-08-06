#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
migration_dir="${script_dir}/auth-migrations"

export LC_ALL=C
shopt -s dotglob nullglob

migrations=()
for candidate in "${migration_dir}"/*.sql; do
  [[ -f "${candidate}" ]] || continue

  basename="$(basename "${candidate}")"
  if [[ ! "${basename}" =~ ^[0-9]{3}_[a-z0-9_]+\.sql$ ]]; then
    printf 'Invalid migration filename: %s\n' "${basename}" >&2
    exit 1
  fi

  migrations+=("${candidate}")
done

if (( ${#migrations[@]} == 0 )); then
  printf 'No auth migrations found; nothing to apply.\n'
  exit 0
fi

declare -A seen_prefixes=()
for migration in "${migrations[@]}"; do
  basename="$(basename "${migration}")"
  prefix="${basename:0:3}"
  if [[ -v "seen_prefixes[${prefix}]" ]]; then
    printf 'Duplicate migration prefix: %s\n' "${prefix}" >&2
    exit 1
  fi
  seen_prefixes["${prefix}"]=1
done

if ! command -v psql >/dev/null 2>&1; then
  printf 'psql command is required to apply auth migrations.\n' >&2
  exit 1
fi

for required_variable in PGHOST PGPORT PGDATABASE PGUSER; do
  if [[ -z "${!required_variable:-}" ]]; then
    printf '%s must be set to apply auth migrations.\n' "${required_variable}" >&2
    exit 1
  fi
done

printf 'Applying auth migrations:\n'
for migration in "${migrations[@]}"; do
  printf '  %s\n' "$(basename "${migration}")"
done

psql_args=(psql -X -v ON_ERROR_STOP=1 --single-transaction)
for migration in "${migrations[@]}"; do
  psql_args+=(-f "${migration}")
done

"${psql_args[@]}"
