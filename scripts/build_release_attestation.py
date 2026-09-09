#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "nazozero/NazoAuth"
OCI_REPOSITORY = "ghcr.io/nazozero/nazoauth"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*"
    r"))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}


def load_closed_json(path: Path, keys: set[str], name: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{name} must be a regular non-symlink file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{name} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict) or set(value) != keys:
        raise SystemExit(f"{name} has an unexpected closed schema")
    return value


def local_artifact(path: Path, expected_name: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.name != expected_name:
        raise SystemExit(f"release artifact must be the expected regular file: {expected_name}")
    size = path.stat().st_size
    if size <= 0:
        raise SystemExit(f"release artifact must not be empty: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "repository": REPOSITORY,
        "name": expected_name,
        "sha256": digest.hexdigest(),
        "size": size,
    }


def validate_oci(path: Path) -> dict[str, Any]:
    value = load_closed_json(
        path,
        {"repository", "index_digest", "platform_manifests"},
        "OCI descriptor",
    )
    if value["repository"] != OCI_REPOSITORY:
        raise SystemExit(f"OCI repository must be {OCI_REPOSITORY}")
    if not isinstance(value["index_digest"], str) or not SHA256.fullmatch(value["index_digest"]):
        raise SystemExit("OCI index digest must be a lowercase sha256 digest")
    manifests = value["platform_manifests"]
    expected_platforms = {"linux/amd64", "linux/arm64"}
    if not isinstance(manifests, dict) or set(manifests) != expected_platforms:
        raise SystemExit("OCI platform manifests must contain exactly linux/amd64 and linux/arm64")
    if any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in manifests.values()):
        raise SystemExit("OCI platform manifest digest must be lowercase sha256")
    return {
        "repository": OCI_REPOSITORY,
        "index_digest": value["index_digest"],
        "platform_manifests": {platform: manifests[platform] for platform in sorted(manifests)},
    }


def operator_protocol_version() -> int:
    source = (ROOT / "crates" / "operator-protocol" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    versions = re.findall(r"(?m)^pub const PROTOCOL_VERSION: u32 = ([0-9]+);$", source)
    if len(versions) != 1:
        raise SystemExit("operator protocol must declare exactly one numeric PROTOCOL_VERSION")
    return int(versions[0])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--oci", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        raise SystemExit("version must be an immutable vSemVer tag")
    if args.target not in TARGETS:
        raise SystemExit("target is not in the closed supported Release target set")
    extension = ".exe" if "windows" in args.target else ""
    binary_name = f"nazoauth-{args.target}{extension}"
    manifest = {
        "schema": 7,
        "version": args.version,
        "target": args.target,
        "release_identity": (
            "https://github.com/nazozero/NazoAuth/"
            f".github/workflows/release-security.yml@refs/tags/{args.version}"
        ),
        "operator_protocol": operator_protocol_version(),
        "artifacts": {
            "binary": local_artifact(args.binary, binary_name),
        },
        "oci": validate_oci(args.oci),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
