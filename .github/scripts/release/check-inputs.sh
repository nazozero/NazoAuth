#!/usr/bin/env bash
set -euo pipefail

verify_ci() {
  basic_auth="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w 0)"
  git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic_auth" fetch \
    --no-tags origin \
    refs/heads/main:refs/remotes/origin/main
  python3 scripts/check_release_ci.py
}

validate_version() {
  if [[ "$GITHUB_REF_TYPE" = tag ]]; then
    [[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
    release_version="${GITHUB_REF_NAME#v}"
    workspace_version="$(python3 - <<'PY'
import tomllib
from pathlib import Path

manifest = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))
print(manifest["workspace"]["package"]["version"])
PY
    )"
    if [[ "$workspace_version" != "$release_version" ]]; then
      echo "tag $GITHUB_REF_NAME does not match workspace version $workspace_version" >&2
      exit 1
    fi
    metadata="$(cargo metadata --locked --no-deps --format-version 1)"
    mismatches="$(jq -r --arg version "$release_version" '
      [.workspace_members[] as $member
        | .packages[]
        | select(.id == $member and .version != $version)
        | "\(.name)=\(.version)"]
      | join(", ")
    ' <<<"$metadata")"
    if [[ -n "$mismatches" ]]; then
      echo "tag $GITHUB_REF_NAME does not match workspace package versions: $mismatches" >&2
      exit 1
    fi
  fi
}

case "${1:-}" in
  verify-ci) verify_ci ;;
  validate-version) validate_version ;;
  *) echo "Usage: $0 {verify-ci|validate-version}" >&2; exit 2 ;;
esac
