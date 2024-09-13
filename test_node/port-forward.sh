#!/bin/bash
set -eux

kubectl port-forward svc/login-test 8088:3005 -n auth0
