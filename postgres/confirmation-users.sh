#!/bin/bash
set -eux

# operatorが生成したシークレットなどを参照しつつ
kubectl exec -it pod/auth0-account-db-0 -n auth0 -- psql -U tororomeshi -d auth0_accounts

# \dt でテーブル一覧
# \dt

# # \d users で schema を確認
# \d users

# select * from users;