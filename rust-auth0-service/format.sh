#!/bin/bash
set -eux

cargo fmt
docker build -t rust-auth0-service-check:local -f rust-check .
docker run --rm rust-auth0-service-check:local
