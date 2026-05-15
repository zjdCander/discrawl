#!/usr/bin/env bash
set -euo pipefail

go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
