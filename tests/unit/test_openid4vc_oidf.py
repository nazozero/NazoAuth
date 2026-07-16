import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class Openid4vcOidfTests(unittest.TestCase):
    def test_tokenless_openid4vc_driver_is_restricted_to_local_suite(self):
        module = load("run_openid4vc_conformance.py")
        local = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "conformance_no_api_token": True,
                "aliases": [],
            },
            module.threading.Event(),
        )
        with patch.object(module, "module_entries", return_value=[]):
            local.drive_once()

        public = module.Openid4vcDriver(
            {
                "conformance_server": "https://www.certification.openid.net",
                "conformance_no_api_token": True,
                "aliases": [],
            },
            module.threading.Event(),
        )
        with self.assertRaisesRegex(RuntimeError, "restricted to loopback"):
            public.drive_once()

    def test_credential_issuer_metadata_is_registered_inside_the_single_well_known_scope(self):
        routes = (ROOT / "crates" / "authorization-server" / "src" / "bootstrap" / "routes.rs").read_text(
            encoding="utf-8"
        )

        self.assertEqual(routes.count('web::scope("/.well-known")'), 1)
        self.assertIn('"/openid-credential-issuer"', routes)
        self.assertNotIn('"/.well-known/openid-credential-issuer"', routes)

    def test_matrix_is_bounded_and_covers_each_final_role_format(self):
        module = load("materialize_openid4vc_oidf_config.py")
        cases = module.matrix_cases()
        self.assertEqual(len(cases), 17)
        self.assertEqual({plan for plan, _, _ in cases}, {
            module.VCI_STANDARD, module.VCI_HAIP, module.VP_STANDARD, module.VP_HAIP
        })
        for plan in (module.VCI_STANDARD, module.VCI_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "mdoc"})
        for plan in (module.VP_STANDARD, module.VP_HAIP):
            self.assertEqual({v["credential_format"] for p, _, v in cases if p == plan}, {"sd_jwt_vc", "iso_mdl"})
        self.assertFalse(any("wallet" in plan for plan, _, _ in cases))

    def test_registry_is_alpha_evidence_not_certification_claim(self):
        registry = json.loads((ROOT / "tests" / "contracts" / "openid4vc-oidf-matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(registry["status"], "alpha-regression-not-certification")
        self.assertEqual(registry["roles"], ["issuer", "verifier"])

    def test_verifier_driver_emits_format_specific_dcql_meta(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://auth.nazo.run",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        cases = {
            "sd_jwt_vc": ("dc+sd-jwt", {"vct_values": ["urn:eudi:pid:1"]}),
            "iso_mdl": ("mso_mdoc", {"doctype_value": "org.iso.18013.5.1.mDL"}),
        }
        for credential_format, (expected_format, expected_meta) in cases.items():
            with self.subTest(credential_format=credential_format), patch.object(
                module,
                "request_json",
                return_value={"authorization_url": "https://localhost:8443/authorize"},
            ) as request, patch.object(module, "get_url"):
                driver.drive_verifier(
                    "module-id",
                    {"alias": "vp-alias", "testName": "oid4vp-1final-verifier-happy-flow"},
                    {
                        "credential_format": credential_format,
                        "client_id_prefix": "x509_san_dns",
                        "request_method": "request_uri_signed",
                        "response_mode": "direct_post.jwt",
                    },
                    False,
                )
                payload = request.call_args.args[3]
                credential = payload["dcql_query"]["credentials"][0]
                self.assertEqual(credential["format"], expected_format)
                self.assertEqual(credential["meta"], expected_meta)
                self.assertEqual(payload["request_method"], "request_uri_signed_get")

    def test_verifier_driver_uses_post_only_for_the_post_request_uri_module(self):
        module = load("run_openid4vc_conformance.py")
        driver = module.Openid4vcDriver(
            {
                "conformance_server": "https://localhost:8443",
                "target_origin": "https://auth.nazo.run",
                "verifier": {
                    "management_token": "management-token",
                    "credential_type_values": {
                        "sd_jwt_vc": "urn:eudi:pid:1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    },
                },
            },
            module.threading.Event(),
        )
        with patch.object(
            module,
            "request_json",
            return_value={"authorization_url": "https://localhost:8443/authorize"},
        ) as request, patch.object(module, "get_url"):
            driver.drive_verifier(
                "module-id",
                {
                    "alias": "vp-alias",
                    "testName": "oid4vp-1final-verifier-request-uri-method-post",
                },
                {
                    "credential_format": "sd_jwt_vc",
                    "request_method": "request_uri_signed",
                },
                False,
            )

        self.assertEqual(request.call_args.args[3]["request_method"], "request_uri_signed_post")

    def test_materializer_creates_unique_aliases_and_exact_plan_count(self):
        module = load("materialize_openid4vc_oidf_config.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            driver = root / "driver.json"
            output = root / "output"
            base.write_text(json.dumps({
                name: {
                    "alias": f"nazo-{name}",
                    **(
                        {
                            "vci": {},
                            "client": {
                                "client_id": "upstream-placeholder",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "EC",
                                            "crv": "P-256",
                                            "kid": "client-key",
                                            "x": "x",
                                            "y": "y",
                                            "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
                                        }
                                    ]
                                },
                            },
                            "client2": {
                                "client_id": "upstream-second-client",
                                "scope": "openid pid-scope",
                                "jwks": {
                                    "keys": [
                                        {
                                            "kty": "RSA",
                                            "alg": "PS256",
                                            "n": "modulus",
                                            "e": "AQAB",
                                            "d": "private",
                                        }
                                    ]
                                },
                            },
                        }
                        if name.startswith("vci")
                        else {"client": {"client_id": "{HOSTNAME}"}}
                    ),
                }
                for name in ("vci", "vci_haip", "vp", "vp_haip")
            }), encoding="utf-8")
            driver.write_text(json.dumps({
                "issuer": {
                    "credential_configuration_ids": {
                        "sd_jwt_vc": "pid-sd-jwt",
                        "mdoc": "org.iso.18013.5.1.mDL",
                    },
                    "tx_code": "123456",
                },
                "verifier": {
                    "request_object_trust_anchor_pem": (
                        "-----BEGIN CERTIFICATE-----\n"
                        "test-root\n"
                        "-----END CERTIFICATE-----\n"
                    ),
                    "credential_type_values": {
                        "sd_jwt_vc": "eu.europa.ec.eudi.pid.1",
                        "iso_mdl": "org.iso.18013.5.1.mDL",
                    }
                },
            }), encoding="utf-8")
            with patch("sys.argv", [
                "materialize_openid4vc_oidf_config.py",
                "--base-config-json-file", str(base),
                "--driver-config-json-file", str(driver),
                "--conformance-server", "https://suite.example",
                "--target-origin", "https://auth.nazo.run",
                "--output-dir", str(output),
            ]):
                self.assertEqual(module.main(), 0)
            plans = json.loads((output / "openid4vc-plan-set.json").read_text(encoding="utf-8"))
            materialized_driver = json.loads((output / "openid4vc-driver.json").read_text(encoding="utf-8"))
            configs = json.loads((output / "openid4vc-plan-configs.json").read_text(encoding="utf-8"))["configs"]
            expected_skips = json.loads((output / "openid4vc-expected-skips.json").read_text(encoding="utf-8"))
            expected_warnings = json.loads((output / "openid4vc-expected-warnings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(plans), 17)
            self.assertEqual(len(configs), 17)
            self.assertEqual(len(set(materialized_driver["aliases"])), 17)
            self.assertEqual(
                expected_skips,
                [
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-wallet-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-mdoc-issuer-plain.json",
                    },
                    {
                        "test-name": module.VCI_UNSUPPORTED_ENCRYPTION_MODULE,
                        "variant": "*",
                        "configuration-filename": "openid4vc-vci-sd-preauth.json",
                    },
                ],
            )
            self.assertEqual(
                expected_warnings,
                [
                    {
                        "test-name": module.VCI_DPOP_NEGATIVE_MODULE,
                        "variant": {
                            "sender_constrain": "dpop",
                            "client_auth_type": "client_attestation",
                            "vci_authorization_code_flow_variant": "wallet_initiated",
                            "credential_format": "mdoc",
                            "authorization_request_type": "simple",
                            "openid": "plain_oauth",
                            "fapi_request_method": "unsigned",
                            "vci_grant_type": "authorization_code",
                            "vci_credential_encryption": "plain",
                            "fapi_profile": "vci_haip",
                            "fapi_response_mode": "plain_response",
                        },
                        "configuration-filename": "openid4vc-vci-haip-mdoc-wallet.json",
                        "expected-result": "warning",
                        "current-block": module.VCI_DPOP_REUSE_BLOCK,
                        "condition": module.VCI_DPOP_STATUS_CONDITION,
                        "justification": (
                            "OIDF v5.2.0 reports this block as same-jti replay, but the logged "
                            "DPoP proofs carry distinct jti values after the resource nonce retry."
                        ),
                    },
                ],
            )
            self.assertEqual(materialized_driver["target_origin"], "https://auth.nazo.run")
            self.assertEqual(
                materialized_driver["verifier"]["credential_type_values"]["sd_jwt_vc"],
                "urn:eudi:pid:1",
            )
            for filename, config in configs.items():
                if "vp-" in filename:
                    self.assertEqual(config["client"]["client_id"], "auth.nazo.run")
                    if "redirect-query" in filename:
                        self.assertNotIn("request_object_trust_anchor_pem", config["client"])
                    else:
                        self.assertEqual(
                            config["client"]["request_object_trust_anchor_pem"],
                            "-----BEGIN CERTIFICATE-----\n"
                            "test-root\n"
                            "-----END CERTIFICATE-----\n",
                        )
            for filename, config in configs.items():
                if "vci-" not in filename:
                    continue
                self.assertEqual(config["vci"]["credential_issuer_url"], "https://auth.nazo.run")
                expected = "org.iso.18013.5.1.mDL" if "mdoc" in filename else "pid-sd-jwt"
                self.assertEqual(config["vci"]["credential_configuration_id"], expected)
                if "preauth" in filename:
                    self.assertEqual(config["vci"]["static_tx_code"], "123456")
                client2_keys = config["client2"]["jwks"]["keys"]
                self.assertEqual(
                    {(key["kty"], key["crv"], key["alg"]) for key in client2_keys},
                    {("EC", "P-256", "ES256")},
                )
                self.assertEqual(client2_keys[0]["kid"], "client-key-client2")
                self.assertNotEqual(
                    client2_keys[0]["d"],
                    config["client"]["jwks"]["keys"][0]["d"],
                )
                self.assertNotEqual(client2_keys[0]["x"], "x")
                self.assertNotEqual(client2_keys[0]["y"], "y")
            private_key_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_clients = {
                config["client"]["client_id"]
                for config in configs.values()
                if config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            self.assertEqual(private_key_clients, {module.VCI_PRIVATE_KEY_CLIENT_ID})
            self.assertEqual(attested_clients, {module.VCI_ATTESTED_CLIENT_ID})
            self.assertTrue(private_key_clients.isdisjoint(attested_clients))
            private_key_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "private_key_jwt"
            }
            attested_client2 = {
                config["client2"]["client_id"]
                for config in configs.values()
                if "vci-" in config["alias"]
                and config.get("nazo", {}).get("client_auth_type") == "client_attestation"
            }
            self.assertEqual(private_key_client2, {module.VCI_PRIVATE_KEY_CLIENT2_ID})
            self.assertEqual(attested_client2, {module.VCI_ATTESTED_CLIENT2_ID})
            self.assertTrue(private_key_client2.isdisjoint(attested_client2))


if __name__ == "__main__":
    unittest.main()
