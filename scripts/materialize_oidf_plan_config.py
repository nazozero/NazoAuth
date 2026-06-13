#!/usr/bin/env python3
"""Materialize OIDF plan config templates with secret patches."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def secret_patch_from_env(prefix: str) -> dict[str, Any]:
    parts: list[str] = []
    for index in range(1, 21):
        value = os.environ.get(f"{prefix}_{index:02d}", "").strip()
        if value:
            parts.append(value)
    if not parts:
        raise SystemExit(f"{prefix}_01 secret patch chunk is required")
    payload = gzip.decompress(base64.b64decode("".join(parts)))
    patch = json.loads(payload.decode("utf-8"))
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch must be a JSON object")
    return patch


def secret_patch_from_file(path: Path) -> dict[str, Any]:
    patch = read_json(path)
    if not isinstance(patch, dict):
        raise SystemExit("OIDF secret patch file must contain a JSON object")
    return patch


def materialize(value: Any, patch: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        secret = value.get("$secret")
        if isinstance(secret, str):
            if set(value) != {"$secret"}:
                raise SystemExit(f"secret placeholder has unexpected keys: {secret}")
            if secret not in patch:
                raise SystemExit(f"missing secret patch value for {secret}")
            return patch[secret]
        return {key: materialize(child, patch) for key, child in value.items()}
    if isinstance(value, list):
        return [materialize(child, patch) for child in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--secret-patch-file",
        type=Path,
        default=None,
        help="read the secret patch JSON object from this file",
    )
    parser.add_argument(
        "--secret-prefix",
        default="OIDF_PLAN_CONFIG_SECRET_PATCH_GZ_B64",
        help="environment variable prefix for gzip+base64 secret patch chunks",
    )
    args = parser.parse_args()

    template = read_json(args.template)
    patch = (
        secret_patch_from_file(args.secret_patch_file)
        if args.secret_patch_file is not None
        else secret_patch_from_env(args.secret_prefix)
    )
    rendered = materialize(template, patch)
    args.output.write_text(json.dumps(rendered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
