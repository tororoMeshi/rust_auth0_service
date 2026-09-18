# T21 production cutover artifacts

## T25 legacy rollback runtime rehearsal

`./t25-rehearse-legacy-rollback-runtime.sh` は、`docs/auth-foundation-rollback-baseline.md` の不変digestで指定された rust-auth0-service、uniauth、portal_backend、portal frontend を一時 Docker network 上で起動する。production のDB、Redis、Secret、network、routingには接続しない。

このscriptは既存の `t21-prepare-rollback-jwt-secret.sh` で外部一時領域に fresh rollback JWT secret を生成し、旧frontendの `/api/` proxy 経由で旧 `portal_backend` の `/api/me` を検証する。fresh JWT は200、別の一時secretで署名したpre-migration相当JWTと認証なしは401でなければ失敗する。成功・失敗のどちらでもcontainer、network、secret/JWTを含む一時ファイルをcleanupする。

```bash
postgres/auth-migrations/cutover/t25-rehearse-legacy-rollback-runtime.sh
```

このディレクトリは通常migrationの対象外です。T21は成果物準備と隔離rehearsalだけであり、production mutation、external workload mutation、`auth0_app`の操作を行いません。

## Secret

`t21-prepare-portal-service-secret.sh` は OS CSPRNG の32 raw bytesを unpadded base64url（43 ASCII bytes）へ一度だけ符号化する。既存の `PORTAL_SERVICE_SECRET` は文字列環境変数で、実装はその exact string bytes の SHA-256 をDBにある `service_secret_sha256` と比較するため、この表現を採用する。

T26担当者はrepo外の保護一時領域に未作成の `T21_SECRET_FILE` と `T21_SERVICE_SECRET_SHA256_FILE` を指定する。scriptは両destinationをcanonical pathへ正規化して一致を拒否し、既存のregular file・directory・symlinkを一切follow/overwriteしない。同一directory内のtemporary fileからhard linkによるexclusive placementを行い、両artifactを0600で作る。plaintextをstdout、stderr、argv、Git、docs、logへ出さない。plaintext file を唯一の入力として Kubernetes Secret `auth0/portal-prod-service-secret` の `service_secret` key を作り、同じfile由来のdigest fileの64桁lowercase hexだけを `portal_service_secret_sha256_hex` としてSQLに渡す。SQLは `decode(..., 'hex')` で64文字hexを32 raw bytesの `bytea` に変換する。Kubernetes manifestを生成する場合も `--from-file=service_secret="$T21_SECRET_FILE"` とし、manifestも保護一時領域だけに置く。

DB bootstrapはdisabledのままであり、Secret creationは後続cutover phaseの明示操作である。Secret/configを作成後、enable前に必ず `T21_SECRET_FILE=/operator/protected/portal-secret ./t21-verify-portal-service-registration.sh` を実行する。このread-only verifierは `auth0_accounts` の単一 `portal-prod` row、callback、logout return、`is_enabled=false`、DB SHA-256、Kubernetes Secret `auth0/portal-prod-service-secret` の `service_secret` を同じprotected plaintextと照合する。一つでも不一致ならnon-zeroでSTOPし、自動修正しない。PASS後だけ別の明示enable操作を許可し、T21自体はenableしない。cutoverまたはrollback終了後にplaintext、digest、生成manifestを保護領域の手順に従い破棄する。

## T26 only ordering

1. writersを停止しmaintenance boundaryを確立する。known external legacy JWT consumer は Gate E または T26 の prerequisite ではなく、external owner confirmation も prerequisite ではない。切替後の互換性は unsupported とする。過去の MIGRATE / RETIRE decision は移行または retirement の完了を意味しない。T26 は external consumer workload を変更しない。
2. writer停止後にlegacy `users` と `users_id_seq` のactual stateを読む。新identityの次値は `max(users.id)+1` と `last_value` / `is_called` / incrementから算出するactual next値のmaxであり、125をhardcodeしない。
3. [Backup / own rollback](#backup--own-rollback) のprimary確認とdurable backupを完了・検証する。`auth0_app`をbackup/restore対象へ混在させない。
4. 既存T05 schemaを通常runnerで適用してから `001_t21_auth_foundation_cutover.sql` を一度だけ適用する。SQLはtarget empty、users.id / google_id / created_at、high-water、dependencyを検証し、異常ならtransactionをSTOPする。
5. SQLは `users.id` を保持し、`created_at AT TIME ZONE 'UTC'` で移す。`google_id`はnormalize・rewrite・mergeせず、exact valueを `('google', google_id, users.id)` として移す。email/name/icon_urlは移さない。`DROP TABLE users` はCASCADEなしの不可逆境界である。
6. runtime grantは `internal_users`と`external_identities`のSELECT/INSERT、`registered_web_services`のSELECT、identity sequenceのUSAGEだけである。`portal-prod` は `https://portal.tororomeshi.net/auth/callback` と `https://portal.tororomeshi.net/` でdisabled bootstrapする。
7. Secret creation後に `t21-verify-portal-service-registration.sh` をread-onlyでPASSさせ、Redis classifierをdry-runする。ambiguous keyが一件でもあれば削除せずcutover/rollback stepをSTOPする。`FLUSHDB`、`FLUSHALL`、shared Redis upgradeは禁止する。
8. `t21-legacy-cookie-expiry.http` を承認済みHTTPS maintenance/cutover pathで一度だけ配信してparent-domain `jwt` と `session_id` を失効する。恒久endpointは追加しない。host-only old Actix `id` はlegacy Redis state削除、old runtime停止、新runtime無視によるserver-side invalidationだけである。
9. すべて確認後だけ、verifier PASSを根拠に別の明示操作で `portal-prod` をenableし、T26配備・公開確認へ進む。T21ではenableしない。

## Redis DB0

`redis/t21_legacy_key_invalidation.py` はshared DB0（Redis 6.2.6）をSCANする。削除候補は、string JSONの exact `user_id`/`expires_at` をもつ24 ASCII alnum uniauth keyと、string JSONの`oauth_state`とoptional `redirect`をもつ64 ASCII alnum old Actix keyだけである。`auth:external:`、`auth:session:`、`auth:handoff:`、`auth:logout:`はforward deletion対象外である。他のkey、TTL/TYPE/JSON shape不一致、非ASCIIは `AMBIGUOUS` であり、reportを残してexit 3、削除0件とする。

最初は `--report <operator protected report>` だけで候補listを作る。`READY_FOR_EXPLICIT_DELETE` の場合だけ同じwriter-stop windowで `--execute` を追加する。executeは再分類後にcandidateだけを`DEL`し、FLUSH系commandを実装・呼出しない。rollbackでは、新runtime停止後かつ新規user許可前の同じ境界で `--rollback-auth-foundation` を明示し、4個の `auth:*` familyだけをmigration-created stateとして候補にする。legacy/unrelated keyは削除しない。ambiguousはforward/rollbackのどちらでもSTOPである。

## Backup / own rollback

対象databaseは固定で `auth0_accounts` だけである。`auth0_app`、cluster-wide dump、all-databases dumpは使用しない。backup artifactはrepo外かつPod再作成後にも残るoperator-controlled persistent filesystemへ置く。Podの`/tmp`等だけをrollback sourceにしてはならず、既存artifactは絶対に上書きしない。

切替直前に、read-onlyで現在のZalando primaryを確認する。確認済み環境の実metadataは `application=spilo`、`cluster-name=auth0-account-db`、`spilo-role=master` であり、次のcommandがちょうど1 Podを返さなければSTOPする。

```bash
mapfile -t t21_primary_pods < <(kubectl get pods -n auth0 \
  -l application=spilo,cluster-name=auth0-account-db,spilo-role=master \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#t21_primary_pods[@]} -eq 1 ]] || { echo 'expected exactly one auth0-account-db primary' >&2; exit 1; }
t21_primary_pod=${t21_primary_pods[0]}
[[ "$(kubectl get pod -n auth0 "$t21_primary_pod" -o jsonpath='{.metadata.labels.spilo-role}')" == master ]] || exit 1
```

`T21_BACKUP_DIR` は事前に作成済みのrepo外durable directoryを指す。次はprimary Pod内でcustom-format dumpを生成し、bytesを`kubectl exec`のstdout経由でhost側durable fileへ直接置く。`pg_restore --list` とchecksumが成功するまで不可逆境界へ進まない。

```bash
: "${T21_BACKUP_DIR:?set an operator-controlled persistent directory outside the repository}"
t21_repo_root="$(git rev-parse --show-toplevel)"
t21_backup_dir="$(realpath -e "$T21_BACKUP_DIR")"
[[ -d "$t21_backup_dir" ]] || { echo 'invalid durable backup directory' >&2; exit 1; }
case "$t21_backup_dir" in "$t21_repo_root"|"$t21_repo_root"/*) echo 'backup must be outside the repository' >&2; exit 1 ;; esac
t21_backup_file="$t21_backup_dir/auth0_accounts-pre-t21-$(date -u +%Y%m%dT%H%M%SZ).dump"
[[ ! -e "$t21_backup_file" && ! -L "$t21_backup_file" ]] || { echo 'refusing to overwrite backup' >&2; exit 1; }
kubectl exec -n auth0 "$t21_primary_pod" -- pg_dump -U postgres -Fc -d auth0_accounts >"$t21_backup_file"
[[ -s "$t21_backup_file" ]] || { echo 'empty backup' >&2; exit 1; }
( cd "$t21_backup_dir" && sha256sum "$(basename "$t21_backup_file")" >"$(basename "$t21_backup_file").sha256" && sha256sum -c "$(basename "$t21_backup_file").sha256" )
pg_restore --list "$t21_backup_file" >/dev/null
```

restoreはrollback operatorが明示的に意図し、application/auth writers停止をread-only確認してからだけ行う。確認なしのrestoreは禁止する。以下のguardは自由なDB名を受け付けず、`auth0_accounts`だけへrestoreする。

```bash
t21_writer_replicas="$(kubectl get deployment -n auth0 rust-auth0-service uniauth portal-backend-deployment \
  -o jsonpath='{range .items[*]}{.metadata.name}={.spec.replicas}{"\n"}{end}')"
for t21_writer in rust-auth0-service uniauth portal-backend-deployment; do
  printf '%s\n' "$t21_writer_replicas" | grep -qx "${t21_writer}=0" || { echo "writer not stopped: $t21_writer" >&2; exit 1; }
done
: "${T21_RESTORE_WRITERS_STOPPED:?set to confirmed only after the operator verified all application/auth writers stopped}"
: "${T21_RESTORE_INTENT:?set to rollback only when restore is intended}"
[[ "$T21_RESTORE_WRITERS_STOPPED" == confirmed && "$T21_RESTORE_INTENT" == rollback ]] || exit 1
: "${t21_backup_file:?use the durable auth0_accounts backup above}"
[[ -s "$t21_backup_file" ]] || exit 1
sha256sum -c "${t21_backup_file}.sha256"
pg_restore --list "$t21_backup_file" >/dev/null
kubectl exec -i -n auth0 "$t21_primary_pod" -- \
  pg_restore --clean --if-exists -U postgres -d auth0_accounts <"$t21_backup_file"
```

restore後はread-onlyでlegacy `users` row数、`users_id_seq`の`last_value`/`is_called`（backup直前の記録と一致）、およびT05 target tablesがbackup時点の期待状態（今回の切替前backupでは空）であることを確認する。`auth0_app`にはtouchしない。新tableの逆変換はしない。

```bash
kubectl exec -n auth0 "$t21_primary_pod" -- psql -X -U postgres -d auth0_accounts -v ON_ERROR_STOP=1 -c \
  "SELECT count(*) AS legacy_users FROM public.users; SELECT last_value, is_called FROM public.users_id_seq; SELECT count(*) AS internal_users FROM public.internal_users; SELECT count(*) AS external_identities FROM public.external_identities; SELECT count(*) AS registered_web_services FROM public.registered_web_services;"
```

`DROP TABLE public.users` はCASCADEなしでも不可逆である。durable backupのsize、checksum、`pg_restore --list`が確認されるより前に、rollback sourceを失う処理へ進まない。

own rollbackは新runtime停止、`auth0_accounts` restore、安全に識別したmigration-created `auth:*`だけのindividual cleanup、`t21-prepare-rollback-jwt-secret.sh`によるrepo外の新しいrollback JWT secret生成、`docs/auth-foundation-rollback-baseline.md`のcommit `37b5876`・固定image digest・legacy manifest参照によるown legacy再配備、全利用者再loginの順である。old JWT secretのreuse、`auth0_app`、external workload、external rollbackは対象外である。
