#!/usr/bin/env bash
set -euo pipefail

git fetch --no-tags --depth=1 origin 385d23a330158ae78ff3fd55df2eac3a74cb2aec
chmod +x scripts/pg_dump_test_container.sh
echo "PG_DUMP=$GITHUB_WORKSPACE/scripts/pg_dump_test_container.sh" >> "$GITHUB_ENV"
