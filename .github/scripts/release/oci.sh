#!/usr/bin/env bash
set -euo pipefail

stage_binaries() {
  install -Dm755 \
    target/release-container/source-amd64/nazoauth-x86_64-unknown-linux-gnu \
    target/release-container/amd64/nazoauth
  install -Dm755 \
    target/release-container/source-arm64/nazoauth-aarch64-unknown-linux-gnu \
    target/release-container/arm64/nazoauth
  test "$(find target/release-container/amd64 target/release-container/arm64 -type f -name nazoauth | wc -l)" -eq 2
}

scan() {
  archive="$RUNNER_TEMP/nazoauth-image.oci.tar"
  layout="$(mktemp -d "${RUNNER_TEMP}/nazoauth-image.oci.XXXXXX")"
  mkdir -p target/release-evidence/oci
  python3 scripts/validate_release_oci.py \
    --archive "$archive" \
    --layout "$layout" \
    --expected-index-digest "$EXPECTED_INDEX_DIGEST" \
    --repository "ghcr.io/nazozero/nazoauth" \
    --output target/release-evidence/oci/descriptor.json
  chmod -R go+rX "$layout"
  for platform in linux/amd64 linux/arm64; do
    docker run --rm \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      -v "$layout:/image:ro" \
      "$TRIVY_IMAGE" image \
        --format table \
        --exit-code 1 \
        --severity CRITICAL,HIGH \
        --ignore-unfixed \
        --platform "$platform" \
        --input /image
  done
}

record_descriptor() {
  descriptor="target/release-evidence/oci/descriptor.json"
  index_digest="$(jq -er .index_digest "$descriptor")"
  [[ "$index_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  test "$index_digest" = "$EXPECTED_INDEX_DIGEST"
  amd64_digest="$(jq -er '.platform_manifests["linux/amd64"]' "$descriptor")"
  arm64_digest="$(jq -er '.platform_manifests["linux/arm64"]' "$descriptor")"
  [[ "$amd64_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  [[ "$arm64_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  {
    echo "index_digest=$index_digest"
    echo "amd64_digest=$amd64_digest"
    echo "arm64_digest=$arm64_digest"
  } >> "$GITHUB_OUTPUT"
}

publish() {
  archive="target/release-evidence/oci/nazoauth-image.oci.tar"
  descriptor="target/release-evidence/oci/descriptor.json"
  test -f "$archive"
  test "$(jq -r .index_digest "$descriptor")" = "$EXPECTED_INDEX_DIGEST"
  destination="docker://ghcr.io/nazozero/nazoauth:${GITHUB_REF_NAME}"
  if existing="$(skopeo inspect "$destination" 2>/dev/null | jq -er .Digest)"; then
    if [[ "$existing" != "$EXPECTED_INDEX_DIGEST" ]]; then
      echo "existing OCI tag has a different digest: $existing" >&2
      exit 1
    fi
    echo "OCI tag already names the exact scanned index; resuming publication"
  else
    skopeo copy --all "oci-archive:$archive" "$destination"
  fi
  published="$(skopeo inspect "$destination" | jq -r .Digest)"
  test "$published" = "$EXPECTED_INDEX_DIGEST"
}

case "${1:-}" in
  stage-binaries) stage_binaries ;;
  scan) scan ;;
  record-descriptor) record_descriptor ;;
  publish) publish ;;
  *) echo "Usage: $0 {stage-binaries|scan|record-descriptor|publish}" >&2; exit 2 ;;
esac
