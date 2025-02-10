#!/bin/bash
set -eux

docker build -t nuxt-check -f nuxt-check .
docker run --rm nuxt-check