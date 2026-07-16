#!/usr/bin/env python3
"""Materialize the bounded OpenID4VC Final/HAIP OIDF regression matrix."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path


VCI_STANDARD = "oid4vci-1_0-issuer-test-plan"
VCI_HAIP = "oid4vci-1_0-issuer-haip-test-plan"
VP_STANDARD = "oid4vp-1final-verifier-test-plan"
VP_HAIP = "oid4vp-1final-verifier-haip-test-plan"


def matrix_cases() -> list[tuple[str, str, dict[str, str]]]:
    return [
        (VCI_STANDARD, "vci-sd-wallet-plain", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-mdoc-wallet-encrypted", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"mdoc","vci_credential_encryption":"encrypted"}),
        (VCI_STANDARD, "vci-sd-issuer-encrypted", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"encrypted"}),
        (VCI_STANDARD, "vci-mdoc-issuer-plain", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-sd-preauth", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"pre_authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc","vci_credential_encryption":"plain"}),
        (VCI_STANDARD, "vci-mdoc-preauth", {"fapi_profile":"vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_request_method":"unsigned","authorization_request_type":"simple","openid":"plain_oauth","fapi_response_mode":"plain_response","vci_grant_type":"pre_authorization_code","vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc","vci_credential_encryption":"encrypted"}),
        (VCI_HAIP, "vci-haip-sd-wallet", {"vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"sd_jwt_vc"}),
        (VCI_HAIP, "vci-haip-mdoc-wallet", {"vci_authorization_code_flow_variant":"wallet_initiated","credential_format":"mdoc"}),
        (VCI_HAIP, "vci-haip-sd-issuer", {"vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"sd_jwt_vc"}),
        (VCI_HAIP, "vci-haip-mdoc-issuer", {"vci_authorization_code_flow_variant":"issuer_initiated","credential_format":"mdoc"}),
        (VP_STANDARD, "vp-sd-redirect-query", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"redirect_uri","request_method":"url_query","response_mode":"direct_post"}),
        (VP_STANDARD, "vp-mdoc-redirect-query-jwt", {"vp_profile":"plain_vp","credential_format":"iso_mdl","client_id_prefix":"redirect_uri","request_method":"url_query","response_mode":"direct_post.jwt"}),
        (VP_STANDARD, "vp-sd-x509dns-signed", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"x509_san_dns","request_method":"request_uri_signed","response_mode":"direct_post"}),
        (VP_STANDARD, "vp-mdoc-x509dns-signed-jwt", {"vp_profile":"plain_vp","credential_format":"iso_mdl","client_id_prefix":"x509_san_dns","request_method":"request_uri_signed","response_mode":"direct_post.jwt"}),
        (VP_STANDARD, "vp-sd-x509hash-signed-jwt", {"vp_profile":"plain_vp","credential_format":"sd_jwt_vc","client_id_prefix":"x509_hash","request_method":"request_uri_signed","response_mode":"direct_post.jwt"}),
        (VP_STANDARD, "vp-mdoc-x509hash-signed", {"vp_profile":"plain_vp","credential_format":"iso_mdl","client_id_prefix":"x509_hash","request_method":"request_uri_signed","response_mode":"direct_post"}),
        (VP_HAIP, "vp-haip-sd", {"credential_format":"sd_jwt_vc","response_mode":"direct_post.jwt"}),
        (VP_HAIP, "vp-haip-mdoc", {"credential_format":"iso_mdl","response_mode":"direct_post.jwt"}),
    ]


def plan_expression(plan: str, variants: dict[str, str], filename: str) -> str:
    return plan + "".join(f"[{name}={value}]" for name, value in variants.items()) + f" {filename}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-config-json-file", required=True)
    parser.add_argument("--driver-config-json-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--conformance-server")
    parser.add_argument("--target-origin")
    args = parser.parse_args()
    base = json.loads(Path(args.base_config_json_file).read_text(encoding="utf-8"))
    driver = json.loads(Path(args.driver_config_json_file).read_text(encoding="utf-8"))
    if args.conformance_server:
        driver["conformance_server"] = args.conformance_server
    if args.target_origin:
        driver["target_origin"] = args.target_origin
    if not driver.get("conformance_server") or not driver.get("target_origin"):
        raise SystemExit("driver configuration requires conformance_server and target_origin")
    required = {"vci", "vci_haip", "vp", "vp_haip"}
    if set(base) != required or not all(isinstance(base[name], dict) for name in required):
        raise SystemExit(f"base configuration must contain exactly {sorted(required)}")
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    configs: dict[str, object] = {}
    expressions: list[str] = []
    aliases: list[str] = []
    for plan, slug, variants in matrix_cases():
        key = "vci_haip" if plan == VCI_HAIP else "vci" if plan == VCI_STANDARD else "vp_haip" if plan == VP_HAIP else "vp"
        config = copy.deepcopy(base[key])
        if plan in (VCI_STANDARD, VCI_HAIP):
            issuer = driver.get("issuer")
            if not isinstance(issuer, dict):
                raise SystemExit("driver configuration requires issuer settings")
            configuration_ids = issuer.get("credential_configuration_ids")
            if not isinstance(configuration_ids, dict):
                raise SystemExit("driver issuer requires credential_configuration_ids")
            format_name = variants["credential_format"]
            configuration_id = configuration_ids.get(format_name)
            if not isinstance(configuration_id, str) or not configuration_id:
                raise SystemExit(f"driver issuer lacks credential configuration for {format_name}")
            vci = config.get("vci")
            if not isinstance(vci, dict):
                raise SystemExit(f"{key} base configuration requires a vci object")
            vci["credential_issuer_url"] = str(driver["target_origin"])
            vci["credential_configuration_id"] = configuration_id
            if variants.get("vci_grant_type") == "pre_authorization_code":
                tx_code = issuer.get("tx_code")
                if isinstance(tx_code, str) and tx_code:
                    vci["static_tx_code"] = tx_code
        prefix = str(config.get("alias", "nazo-openid4vc"))
        alias = f"{prefix}-{slug}"
        config["alias"] = alias
        config["description"] = f"NazoAuth {slug} OpenID4VC Final regression"
        filename = f"openid4vc-{slug}.json"
        configs[filename] = config
        aliases.append(alias)
        expressions.append(plan_expression(plan, variants, filename))
    driver["aliases"] = aliases
    (output / "openid4vc-plan-configs.json").write_text(json.dumps({"configs": configs}, indent=2) + "\n", encoding="utf-8")
    (output / "openid4vc-plan-set.json").write_text(json.dumps(expressions, indent=2) + "\n", encoding="utf-8")
    (output / "openid4vc-driver.json").write_text(json.dumps(driver, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
