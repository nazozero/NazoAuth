#!/usr/bin/env python3
"""Apply production-delivered client identifiers to private OIDF runner input."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import urllib.parse
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {path}: {error}")


def canonical_origin(value: str, label: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} must be an HTTPS origin")
    authority = (
        parsed.hostname.lower()
        if parsed.port in {None, 443}
        else f"{parsed.hostname.lower()}:{parsed.port}"
    )
    return f"https://{authority}"


def replace_client(value: Any, logical_id: str, actual_id: str, secret: str | None) -> int:
    replacements = 0
    if isinstance(value, dict):
        if value.get("client_id") == logical_id:
            value["client_id"] = actual_id
            if secret is None:
                value.pop("client_secret", None)
            else:
                value["client_secret"] = secret
            replacements += 1
        for child in value.values():
            replacements += replace_client(child, logical_id, actual_id, secret)
    elif isinstance(value, list):
        for child in value:
            replacements += replace_client(child, logical_id, actual_id, secret)
    return replacements


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--material-json-file", type=Path, required=True)
    parser.add_argument("--config-json-file", type=Path, required=True)
    parser.add_argument("--expected-target-issuer", required=True)
    parser.add_argument("--expected-suite-base-url", required=True)
    args = parser.parse_args()
    material = read_json(args.material_json_file)
    if not isinstance(material, dict) or material.get("schema") != 1:
        fail("delivered client material must be a schema-1 object")
    if canonical_origin(str(material.get("target_issuer", "")), "target issuer") != canonical_origin(
        args.expected_target_issuer, "expected target issuer"
    ):
        fail("delivered client material target issuer does not match this run")
    if canonical_origin(str(material.get("suite_base_url", "")), "suite base URL") != canonical_origin(
        args.expected_suite_base_url, "expected suite base URL"
    ):
        fail("delivered client material suite base URL does not match this run")
    clients = material.get("clients")
    if not isinstance(clients, list) or not clients:
        fail("delivered client material contains no clients")
    document = read_json(args.config_json_file)
    if not isinstance(document, dict) or not isinstance(document.get("configs"), dict):
        fail("plan config document must contain a configs object")
    seen: set[str] = set()
    total = 0
    for index, item in enumerate(clients):
        if not isinstance(item, dict):
            fail(f"clients[{index}] must be an object")
        logical_id = item.get("logical_client_id")
        actual_id = item.get("client_id")
        secret = item.get("client_secret")
        if (
            not isinstance(logical_id, str)
            or not logical_id
            or logical_id in seen
            or not isinstance(actual_id, str)
            or not actual_id
            or (secret is not None and (not isinstance(secret, str) or not secret))
        ):
            fail(f"clients[{index}] contains invalid delivered material")
        seen.add(logical_id)
        total += replace_client(document, logical_id, actual_id, secret)
    if total == 0:
        fail("delivered client material does not match any runner client")
    temporary = args.config_json_file.with_suffix(args.config_json_file.suffix + ".new")
    temporary.write_text(
        json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    temporary.replace(args.config_json_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
