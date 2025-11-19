#!/bin/bash
#
# Builds LockBox with the latest commit hash (short)
# E.g.: ./lockbox-node -v --> LockBox 75316fe

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

commit_hash=$(git rev-parse --short HEAD)
CGO_ENABLED=1 go build -o lockbox-node -ldflags="-s -w -X github.com/dueldanov/lockbox/v2/components/app.Version=${commit_hash}" -tags rocksdb,external_libs
