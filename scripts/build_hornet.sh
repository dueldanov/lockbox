#!/bin/bash
#
# Builds LockBox with the latest commit hash (short)
# E.g.: ./lockbox-node -v --> LockBox 75316fe

DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

commit_hash=$(git rev-parse --short HEAD)
go build -o lockbox-node -ldflags="-s -w -X github.com/dueldanov/lockbox/v2/components/app.Version=${commit_hash}"

# Code signing for macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Applying macOS code signature..."
    codesign --force --deep --sign - ./lockbox-node
fi
