# T26 operator runbook

これはT26の既存順序を変更せず、writer-stop、`auth0_accounts` backup/restore、
Google smokeの事前条件を固定するためのoperator runbookである。ここにない
production mutationは追加しない。`auth0_app`、external workload、route、Secretは
writer-stopの対象外である。

## Fixed scope and order

順序は canonical T26 のまま、`writer-stop` → actual high-water確認 → durable
backup → T05 schema → T21 migration → service secret → verifier / Redis
classification → legacy invalidation → deployment/routing cutover → portal-prod enable
→ smoke → maintenance release とする。

namespace と対象は次だけである。

```bash
t26_context=default
t26_namespace=auth0
t26_uniauth_replicas=1
t26_rust_auth_replicas=2
```

`auth0_app`、`stateless-chat/*`、`jamaica/*`、その他external consumerは、この
runbookの対象外であり、wildcard又はnamespace-wideのscale-downは使わない。

## Writer definition and writer-stop

| runtime | T26時点の状態変更 | store | T26競合writerか | 処置 |
| --- | --- | --- | --- | --- |
| `uniauth` | legacy user upsertと旧JSON sessionの作成・失効 | `auth0_accounts` のlegacy `public.users`、Redis DB0 | はい | 停止 |
| `rust-auth0-service` | Google callbackを受け、`uniauth`を通じたlegacy loginを起動し得る。旧OAuth/session stateもRedis接続を持つ | `uniauth`経由のPostgreSQL、Redis DB0、process-local | はい（callback競合を閉じるため） | 停止 |
| `portal-backend-deployment` | portalのLocalSessionはprocess-local。現行pre-cutoverではlegacy PostgreSQL/Redisへ直接書込しない | process-localのみ | いいえ | 停止しない |
| `frontend-deployment` | `/login`、`/auth/callback`、`/logout`、`/api/` のproxy | なし | いいえ | 停止しない |

最小maintenance mechanismは、`auth0` namespaceの上記2 Deploymentだけを
scale-to-zeroする方式である。routeを変更せず、Google callback とlegacy writerの
実行主体をなくす。frontend/portalがこの間に返すエラーはmaintenance boundaryの
副作用であり、route変更で補わない。

### Before state and exact commands

以下は**T26本番でだけ**実行する。今回のpreflightでは実行しない。

```bash
kubectl --context "$t26_context" -n "$t26_namespace" get deployment uniauth rust-auth0-service \
  -o jsonpath='{range .items[*]}{.metadata.name}{" spec="}{.spec.replicas}{" available="}{.status.availableReplicas}{"\n"}{end}'

[[ "$(kubectl --context "$t26_context" -n "$t26_namespace" get deployment uniauth -o jsonpath='{.spec.replicas}')" == "$t26_uniauth_replicas" ]] || exit 1
[[ "$(kubectl --context "$t26_context" -n "$t26_namespace" get deployment rust-auth0-service -o jsonpath='{.spec.replicas}')" == "$t26_rust_auth_replicas" ]] || exit 1

kubectl --context "$t26_context" -n "$t26_namespace" scale deployment/uniauth --replicas=0
kubectl --context "$t26_context" -n "$t26_namespace" scale deployment/rust-auth0-service --replicas=0
kubectl --context "$t26_context" -n "$t26_namespace" wait --for=delete pod -l app=uniauth --timeout=90s
kubectl --context "$t26_context" -n "$t26_namespace" wait --for=delete pod -l app=rust-auth0-service --timeout=90s
```

Expected after stateは両Deploymentの`.spec.replicas=0`かつ両selectorにRunning Podが
ないこと。`kubectl scale`のtargetは明示した2 Deploymentだけである。

### Verification: writers stopped = VERIFIED

次がすべてPASSしたときだけ `writers stopped = VERIFIED` とする。

```bash
[[ "$(kubectl --context "$t26_context" -n "$t26_namespace" get deployment uniauth -o jsonpath='{.spec.replicas}')" == 0 ]]
[[ "$(kubectl --context "$t26_context" -n "$t26_namespace" get deployment rust-auth0-service -o jsonpath='{.spec.replicas}')" == 0 ]]
[[ -z "$(kubectl --context "$t26_context" -n "$t26_namespace" get pod -l app=uniauth --field-selector=status.phase=Running -o name)" ]]
[[ -z "$(kubectl --context "$t26_context" -n "$t26_namespace" get pod -l app=rust-auth0-service --field-selector=status.phase=Running -o name)" ]]
```

その後のactual high-water readで使用するprimary `psql` session以外に、legacy DBの
application sessionが残っていないこともread-onlyで確認する。意図しないwriter session、
Pod残存、またはreplica数不一致はSTOPである。

### Undo before database migration

T05/T21のdatabase mutation前に限り、writer-stopを戻してcutoverを中止できる。

```bash
kubectl --context "$t26_context" -n "$t26_namespace" scale deployment/uniauth --replicas="$t26_uniauth_replicas"
kubectl --context "$t26_context" -n "$t26_namespace" scale deployment/rust-auth0-service --replicas="$t26_rust_auth_replicas"
kubectl --context "$t26_context" -n "$t26_namespace" rollout status deployment/uniauth --timeout=180s
kubectl --context "$t26_context" -n "$t26_namespace" rollout status deployment/rust-auth0-service --timeout=180s
```

### Rollback restore writer-stop (rollback only)

通常cutover開始時のwriter-stopは上記の`uniauth`と`rust-auth0-service`だけであり、
`portal-backend-deployment`を追加しない。`auth0_accounts`のbackupをrollback restore
する直前だけ、canonical rollback baselineに従って次の3 Deploymentを停止する。

```bash
kubectl scale -n auth0 deployment/uniauth --replicas=0
kubectl scale -n auth0 deployment/rust-auth0-service --replicas=0
kubectl scale -n auth0 deployment/portal-backend-deployment --replicas=0
```

restore開始前に、次のread-only guardが3つすべての`.spec.replicas=0`を確認する。
1つでも残っていればSTOPであり、`T21_RESTORE_WRITERS_STOPPED=confirmed`を設定してはならない。

```bash
t21_restore_writer_replicas="$(kubectl --context "$t26_context" -n "$t26_namespace" \
  get deployment uniauth rust-auth0-service portal-backend-deployment \
  -o jsonpath='{range .items[*]}{.metadata.name}={.spec.replicas}{"\n"}{end}')"
for t21_restore_writer in uniauth rust-auth0-service portal-backend-deployment; do
  printf '%s\n' "$t21_restore_writer_replicas" \
    | grep -qx "${t21_restore_writer}=0" \
    || { echo "rollback restore writer not stopped: $t21_restore_writer" >&2; exit 1; }
done
export T21_RESTORE_WRITERS_STOPPED=confirmed
```

restore後の旧runtime再配備と`portal-backend-deployment`の復帰は、既存の
`docs/auth-foundation-rollback-baseline.md`に定めたlegacy runtime再配備順序に従う。
このrunbookでは新しいrollback sequencingを追加しない。

## Durable `T21_BACKUP_DIR`

`T21_BACKUP_DIR` は次のoperator確認済み値に固定する。

```text
T21_BACKUP_DIR=/home/tororomeshi/backups/rust_auth0_service/t26
```

このdirectoryはrepo外のoperator host filesystem（`/dev/sdd`, `ext4`）にあり、Pod-local
filesystemではない。owner/groupは`tororomeshi:tororomeshi`、modeは`0700`、free spaceは
approximately 891 GiBであり、operator-ownedかつsufficient free space verifiedである。
この確認済みdestination以外を暗黙に選択してはならない。

```bash
export T21_BACKUP_DIR=/home/tororomeshi/backups/rust_auth0_service/t26
```

固定後に使用するbackup手順は、primaryがちょうど1 Podであることを確認してから、
`auth0_accounts`だけを`pg_dump -Fc`で作成し、既存destinationを拒否し、SHA-256と
`pg_restore --list`を成功させるものとする。`auth0_app`、cluster-wide dump、
all-databases dumpは使わない。destination unavailable / non-persistent / file exists /
dump failure / checksum failure / list failure / unexpected primary countはすべてSTOPである。

```bash
mapfile -t t21_primary_pods < <(kubectl --context "$t26_context" -n "$t26_namespace" get pods \
  -l application=spilo,cluster-name=auth0-account-db,spilo-role=master \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#t21_primary_pods[@]} -eq 1 ]] || exit 1
t21_primary_pod=${t21_primary_pods[0]}
[[ "$(kubectl --context "$t26_context" -n "$t26_namespace" get pod "$t21_primary_pod" -o jsonpath='{.metadata.labels.spilo-role}')" == master ]] || exit 1

t21_repo_root="$(git rev-parse --show-toplevel)"
t21_backup_dir="$(realpath -e "$T21_BACKUP_DIR")"
[[ -d "$t21_backup_dir" && "$t21_backup_dir" != "$t21_repo_root" && "$t21_backup_dir" != "$t21_repo_root"/* ]] || exit 1
t21_backup_file="$t21_backup_dir/auth0_accounts-pre-t21-$(date -u +%Y%m%dT%H%M%SZ).dump"
t21_checksum_file="${t21_backup_file}.sha256"
[[ -d "$t21_backup_dir" && ! -e "$t21_backup_file" && ! -L "$t21_backup_file" ]] || exit 1
[[ ! -e "$t21_checksum_file" && ! -L "$t21_checksum_file" ]] || exit 1

# pg_dump bytes are written directly to the operator host filesystem; do not use a Pod-local path.
t21_dump_tmp="$(mktemp "$t21_backup_dir/.t21-backup.XXXXXX")"
kubectl --context "$t26_context" -n "$t26_namespace" exec "$t21_primary_pod" -- \
  pg_dump -U postgres -Fc -d auth0_accounts >"$t21_dump_tmp"
ln -T -- "$t21_dump_tmp" "$t21_backup_file" || { echo 'backup dump destination appeared; STOP' >&2; exit 1; }
rm -f -- "$t21_dump_tmp"
[[ -s "$t21_backup_file" ]] || exit 1
t21_checksum_tmp="$(mktemp "$t21_backup_dir/.t21-checksum.XXXXXX")"
sha256sum "$t21_backup_file" >"$t21_checksum_tmp"
ln -T -- "$t21_checksum_tmp" "$t21_checksum_file" || { echo 'backup checksum destination appeared; STOP' >&2; exit 1; }
rm -f -- "$t21_checksum_tmp"
sha256sum -c "$t21_checksum_file"
pg_restore --list "$t21_backup_file" >/dev/null
```

dumpとchecksum sidecarは一組のartifactとして扱う。preflightでどちらか一方でも
既存（regular file、directory、symlinkを含む）ならSTOPする。`ln -T`によるexclusive
placementが既存destinationで失敗する場合もSTOPであり、dumpまたは`.sha256`を上書きしない。
checksumにはdumpのSHA-256行だけを保存し、秘密情報を含めない。backup後はdump存在、sidecar存在、
`sha256sum -c`成功、`pg_restore --list`成功の全てを確認する。

同じartifactのrestoreはrollback operatorが明示的に意図した場合だけ、writers stoppedを
再確認してから行う。restore targetは`auth0_accounts`だけであり、`auth0_app`には接続・
restore・検証をしない。

```bash
: "${t21_backup_file:?use the verified auth0_accounts backup}"
: "${T21_RESTORE_WRITERS_STOPPED:?set only after rollback-only three-writer stop verification}"
: "${T21_RESTORE_INTENT:?set only when rollback is intended}"
[[ "$T21_RESTORE_WRITERS_STOPPED" == confirmed && "$T21_RESTORE_INTENT" == rollback ]] || exit 1
[[ -s "$t21_backup_file" && -s "${t21_backup_file}.sha256" ]] || exit 1
sha256sum -c "${t21_backup_file}.sha256"
pg_restore --list "$t21_backup_file" >/dev/null
kubectl --context "$t26_context" -n "$t26_namespace" exec -i "$t21_primary_pod" -- \
  pg_restore --clean --if-exists -U postgres -d auth0_accounts <"$t21_backup_file"
```

本番restoreはこのpreflightで行わない。disposable PostgreSQL 17 rehearsal
`postgres/auth-migrations/cutover/t21-rehearse-postgres.sh` は、host-side custom-format
`pg_dump`、SHA-256、`pg_restore --list`、`auth0_accounts`への`--clean --if-exists` restoreを
実行し、2026-09-18にPASSした。これはdump/restore procedureの証明であり、上記のdurable
destination STOPを解除するものではない。

## Google smoke account

productionのread-only queryで、legacy `public.users`にはnon-empty `google_id`を持つ既存
candidateが3件あり、個人情報/provider subjectを出さずIDだけを確認した。T26 candidateは
次に固定する。

```bash
T26_SMOKE_LEGACY_USER_ID=2
EXPECTED_MIGRATED_INTERNAL_USER_ID=2
```

T21はlegacy `users.id`をinternal user IDとして保持するため、expected IDは同じ`2`である。
Google accountは既存identityを使い、新規identityをsmoke目的で作成しない。

```text
Operator confirmation:
[x] The Google account corresponding to legacy user ID 2 is currently accessible.
```

cutover後のsmokeは、既存Google identityでloginが成功し、既存migrated identityが解決され、
`internal_user_id=2`となること、duplicate internal user / external identityが作られないこと、
portal LocalSessionの確立、`/api/me`の成功を確認する。email、name、Google subject、provider
tokenはrepoへ記録しない。

smoke後のread-only DB verificationは、同じ`auth0_accounts`へのoperator-host接続で次を実行し、
legacy user IDを保持したmigrated `internal_users` row（ID 2）が1件だけ存在し、Google external
identityが1件だけであることを確認する。migration後はlegacy `public.users`がcanonicalどおり
dropされるため、legacy user ID 2 → migrated `internal_user_id=2`の対応は保持されたIDで確認する。
subject値は表示しない。

```bash
kubectl --context "$t26_context" -n "$t26_namespace" exec -i "$t21_primary_pod" -- \
  psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -At -c \
  "SELECT count(iu.internal_user_id) AS migrated_internal_user_rows,
          max(iu.internal_user_id) AS migrated_internal_user_id,
          count(e.internal_user_id) AS google_identity_count
     FROM public.internal_users AS iu
     LEFT JOIN public.external_identities AS e
       ON e.internal_user_id = iu.internal_user_id AND e.provider = 'google'
    WHERE iu.internal_user_id = 2;"
```

期待値は`1|2|1`の1行である。0行、複数row、異なるID、またはcount不一致はSTOPとする。

## Preflight result

- writer-stop: READY。exact commands、verification、pre-migration undoを上記に固定した。
- durable backup: READY。`T21_BACKUP_DIR`はrepo外・operator host persistent filesystem上で、
  mode 0700、operator-owned、sufficient free space verified。exact backup/restore procedure、
  checksum、list検証、`auth0_app` exclusionを固定した。
- Google smoke account: READY。legacy user ID 2、expected migrated `internal_user_id=2`、
  operator account access confirmationを固定した。
- このpreflightではproduction mutationを実行せず、独立レビューapproveまではT26 production
  executionを開始してはならない。
- T26 preflight: READY。上記3 blockerはすべて解消済みである。
- independent review: REQUIRED before any T26 production mutation.
