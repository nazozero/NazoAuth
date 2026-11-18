#!/usr/bin/env bash
set -euo pipefail

package_protocol() {
  cargo package --locked --package nazo-crypto --package nazo-operator-protocol
  mkdir -p target/release-protocol
  version="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "nazo-operator-protocol") | .version')"
  for name in nazo-crypto nazo-operator-protocol; do
    cp -- "target/package/${name}-${version}.crate" target/release-protocol/
  done
  (cd target/release-protocol && sha256sum ./*.crate > SHA256SUMS)
}

verify_protocol() {
  package="target/release-protocol/nazo-operator-protocol-${GITHUB_REF_NAME#v}.crate"
  test -f "$package"
  test -f "target/release-protocol/nazo-crypto-${GITHUB_REF_NAME#v}.crate"
  (cd target/release-protocol && sha256sum --check SHA256SUMS)
  echo "path=target/release-protocol/*.crate" >> "$GITHUB_OUTPUT"
}

publish() {
  test "$(find target/release-binaries -maxdepth 1 -type f | wc -l)" -eq 8
  for target in \
    x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
    x86_64-apple-darwin aarch64-apple-darwin; do
    test -f "target/release-binaries/nazoauth-$target"
  done
  for target in x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
    test -f "target/release-binaries/nazoauth-$target.exe"
  done
  protocol_asset="nazo-operator-protocol-${GITHUB_REF_NAME#v}.crate"
  crypto_asset="nazo-crypto-${GITHUB_REF_NAME#v}.crate"
  test -f "target/release-protocol/$protocol_asset"
  test -f "target/release-protocol/$crypto_asset"
  (cd target/release-protocol && sha256sum --check SHA256SUMS)
  allowed_names="$(mktemp)"
  find target/release-binaries -maxdepth 1 -type f -printf '%f\n' \
    | sort > "$allowed_names"
  printf '%s\n' "$protocol_asset" "$crypto_asset" >> "$allowed_names"
  sort -u -o "$allowed_names" "$allowed_names"
  test "$(wc -l < "$allowed_names")" -eq 10
  gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1 ||
    gh release create "$GITHUB_REF_NAME" \
      --repo "$GITHUB_REPOSITORY" --verify-tag --generate-notes
  remote_names="$(mktemp)"
  gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" \
    --json assets --jq '.assets[].name' > "$remote_names"
  while IFS= read -r name; do
    test -z "$name" || grep -Fxq "$name" "$allowed_names" || {
      echo "GitHub Release contains an unexpected asset: $name" >&2
      exit 1
    }
  done < "$remote_names"
  existing="$(mktemp -d)"
  for asset in target/release-binaries/* "target/release-protocol/$protocol_asset" "target/release-protocol/$crypto_asset"; do
    name="$(basename "$asset")"
    if grep -Fxq "$name" "$remote_names"; then
      gh release download "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" \
        --pattern "$name" --dir "$existing"
      cmp --silent "$asset" "$existing/$name" || {
        echo "existing GitHub Release asset differs: $name" >&2
        exit 1
      }
      echo "GitHub Release already has the exact asset: $name"
    else
      gh release upload "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" "$asset"
    fi
  done
  gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" \
    --json assets --jq '.assets[].name' > "$remote_names"
  test "$(wc -l < "$remote_names")" -eq 10
  diff -u "$allowed_names" <(sort "$remote_names")
}

case "${1:-}" in
  package-protocol) package_protocol ;;
  verify-protocol) verify_protocol ;;
  publish) publish ;;
  *) echo "Usage: $0 {package-protocol|verify-protocol|publish}" >&2; exit 2 ;;
esac
