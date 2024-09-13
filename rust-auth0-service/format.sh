#!/bin/bash
set -eux

cargo fmt
docker build -t rust-check -f rust-check .
docker run --rm rust-check