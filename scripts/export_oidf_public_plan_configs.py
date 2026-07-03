#!/usr/bin/env python3
"""Export public-only OIDF plan configs for server-side client seeding."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from collections.abc import Sequence
from typing import Any


PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
SEED_NAZO_FIELDS = {
    "fapi_auth_method",
    "fapi_profile",
    "fapi_request_method",
    "fapi_sender_constrain",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def public_jwk(value: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(child) for key, child in value.items() if key not in PRIVATE_JWK_FIELDS}


def strip_private_jwks(value: Any) -> Any:
    if isinstance(value, dict):
        if isinstance(value.get("keys"), list):
            stripped = copy.deepcopy(value)
            stripped["keys"] = [
                public_jwk(key) if isinstance(key, dict) else copy.deepcopy(key)
                for key in value["keys"]
            ]
            return stripped
        return {key: strip_private_jwks(child) for key, child in value.items()}
    if isinstance(value, list):
        return [strip_private_jwks(child) for child in value]
    return copy.deepcopy(value)


def public_seed_client(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for key in ("client_id", "scope"):
        if key in value:
            result[key] = copy.deepcopy(value[key])
    if "jwks" in value:
        result["jwks"] = strip_private_jwks(value["jwks"])
    return result or None


def public_seed_mtls(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or "cert" not in value:
        return None
    return {"cert": copy.deepcopy(value["cert"])}


def public_seed_nazo(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {key: copy.deepcopy(value[key]) for key in SEED_NAZO_FIELDS if key in value}
    return result or None


def public_seed_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    result: dict[str, Any] = {}
    if "alias" in config:
        result["alias"] = copy.deepcopy(config["alias"])
    for key in ("client", "client2"):
        public_client = public_seed_client(config.get(key))
        if public_client is not None:
            result[key] = public_client
    for key in ("mtls", "mtls2"):
        public_mtls = public_seed_mtls(config.get(key))
        if public_mtls is not None:
            result[key] = public_mtls
    public_nazo = public_seed_nazo(config.get("nazo"))
    if public_nazo is not None:
        result["nazo"] = public_nazo
    return result


def main_with_args_for_test(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-json-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    rendered = read_json(args.config_json_file)
    configs = rendered.get("configs") if isinstance(rendered, dict) else None
    if not isinstance(configs, dict):
        raise SystemExit("rendered OIDF config must contain a configs object")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for file_name, config in configs.items():
        if Path(file_name).name != file_name or not file_name.endswith(".json"):
            raise SystemExit(f"invalid OIDF config file name: {file_name}")
        public_config = public_seed_config(config)
        args.output_dir.joinpath(file_name).write_text(
            json.dumps(public_config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 0


def main() -> int:
    return main_with_args_for_test()


if __name__ == "__main__":
    raise SystemExit(main())
