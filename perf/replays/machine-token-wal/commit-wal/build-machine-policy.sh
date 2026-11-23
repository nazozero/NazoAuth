#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
repo=$(git -C "$1" rev-parse --show-toplevel)
revision=$(git -C "$repo" rev-parse "${2:-HEAD}^{commit}")
base=5a2de27de35041a751c020224f3601f4a2fc4ffa
work=$(mktemp -d)
builder=machine-policy-build-$$
cleanup() {
  docker rm -f "$builder" >/dev/null 2>&1 || :
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -p out
docker run -d --name "$builder" -e RUSTUP_TOOLCHAIN=1.100.0 -e CARGO_BUILD_JOBS=14 \
  rust@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe sleep infinity >/dev/null
docker exec "$builder" mkdir -p /bench/src
arms=(control revised)
if [[ ${BENCH_BUILD_SNAPSHOT_TIMING:-0} == 1 ]]; then arms+=(diagnostic); fi
for arm in "${arms[@]}"; do
  commit=$base; if [[ $arm != control ]]; then commit=$revision; fi
  mkdir "$work/$arm"
  git -C "$repo" archive "$commit" | tar -x -C "$work/$arm"
  python3 ../transaction-comparison/observe-commits.py "$work/$arm"
  if [[ $arm == diagnostic ]]; then python3 machine-snapshot-timing.py "$work/$arm"; fi
  tar -C "$work/$arm" -cf - . | docker exec -i "$builder" tar --touch -xf - -C /bench/src
  docker exec -w /bench/src "$builder" cargo build --locked --release -p nazo-server --bin nazoauth
  docker cp "$builder:/bench/src/target/release/nazoauth" "out/$arm"
  printf '%s %s\n' "$arm" "$commit"
  sha256sum "out/$arm"
done
