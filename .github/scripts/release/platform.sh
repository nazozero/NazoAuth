#!/usr/bin/env bash
set -euo pipefail

bind_musl() {
  target="$RELEASE_TARGET"
  cc_variable="CC_${target//-/_}"
  linker_variable="CARGO_TARGET_${target^^}_LINKER"
  linker_variable="${linker_variable//-/_}"
  {
    echo "$cc_variable=musl-gcc"
    echo "$linker_variable=musl-gcc"
  } >> "$GITHUB_ENV"
}

check_linux() {
  binary="target/$RELEASE_TARGET/release/nazoauth"
  dynamic="$(readelf -d "$binary")"
  if grep -Eiq 'NEEDED.*(libpq|libssl|libcrypto)' <<<"$dynamic"; then
    echo "$binary depends on a non-system database or TLS library" >&2
    exit 1
  fi
  if [[ "$RELEASE_LIBC" = musl ]]; then
    if grep -q '(NEEDED)' <<<"$dynamic"; then
      echo "$binary is not fully static" >&2
      exit 1
    fi
  fi
}

check_macos() {
  binary="target/$RELEASE_TARGET/release/nazoauth"
  if otool -L "$binary" | grep -Eiq '(libpq|libssl|libcrypto)'; then
    echo "$binary depends on a non-system database or TLS library" >&2
    exit 1
  fi
}

case "${1:-}" in
  bind-musl) bind_musl ;;
  check-linux) check_linux ;;
  check-macos) check_macos ;;
  *) echo "Usage: $0 {bind-musl|check-linux|check-macos}" >&2; exit 2 ;;
esac
