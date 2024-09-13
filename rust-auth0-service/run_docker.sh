#!/bin/bash
set -eux

docker build -t rust-auth0-service .
docker run --rm -p 8080:8080 rust-auth0-service
# docker run --rm -p 8080:8080 --env-file .env rust-auth0-service
