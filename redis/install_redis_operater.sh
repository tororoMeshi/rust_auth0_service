#!/bin/bash
set -eux

REDIS_OPERATOR_VERSION=v1.2.4
kubectl create -f https://raw.githubusercontent.com/spotahome/redis-operator/${REDIS_OPERATOR_VERSION}/manifests/databases.spotahome.com_redisfailovers.yaml
kubectl apply -f https://raw.githubusercontent.com/spotahome/redis-operator/${REDIS_OPERATOR_VERSION}/example/operator/all-redis-operator-resources.yaml