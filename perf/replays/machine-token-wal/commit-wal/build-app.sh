#!/usr/bin/env bash
# Build both arms in one pinned toolchain with identical release options.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p out
work=$(mktemp -d)
builder=nazo-wal-replay-build-$$
trap 'rm -rf -- "$work"' EXIT
git -C "$1" archive f6f1f9a08d1614f9af42088292d07598ad5073d7 | tar -x -C "$work"
python3 ../transaction-comparison/observe-commits.py "$work"
docker run -d --name "$builder" -e RUSTUP_TOOLCHAIN=1.100.0 -e CARGO_BUILD_JOBS=12 \
  rust@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe sleep infinity >/dev/null
trap 'docker rm -f "$builder" >/dev/null; rm -rf -- "$work"' EXIT
docker exec "$builder" mkdir -p /bench/src
for variant in control candidate http-timing; do
  if [[ $variant == candidate ]]; then
    (cd "$work" && git apply - < "$OLDPWD/one-statement.patch")
  elif [[ $variant == http-timing ]]; then
    (cd "$work" && git apply -R - < "$OLDPWD/one-statement.patch")
    python3 response-timing.py "$work"
  fi
  tar -C "$work" -cf - . | docker exec -i "$builder" tar -xf - -C /bench/src
  docker exec "$builder" touch /bench/src/crates/persistence-postgres/src/repositories/{audit_ledger,token_issuance,token_principals}.rs
  docker exec -w /bench/src "$builder" cargo build --locked --release -p nazo-server --bin nazoauth
  docker cp "$builder:/bench/src/target/release/nazoauth" "out/$variant"
done
sha256sum out/{control,candidate,http-timing}
