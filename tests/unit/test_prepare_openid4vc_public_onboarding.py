import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "scripts" / "prepare_openid4vc_public_onboarding.py"
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def private_jwks(kid: str) -> dict[str, object]:
    return {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "kid": kid,
                "x": "public-x",
                "y": "public-y",
                "d": "private-d",
            }
        ]
    }


def vci_config(
    *,
    alias: str,
    configuration_id: str,
    authentication: str,
    client_id: str,
) -> dict[str, object]:
    return {
        "alias": alias,
        "description": alias,
        "vci": {"credential_configuration_id": configuration_id},
        "nazo": {
            "openid4vc_role": "issuer",
            "client_auth_type": authentication,
        },
        "client": {
            "client_id": client_id,
            "scope": "accounts offline_access" if authentication == "client_attestation" else "accounts",
            "jwks": private_jwks(f"{client_id}-one"),
        },
        "client2": {
            "client_id": f"{client_id}-2",
            "scope": "accounts offline_access" if authentication == "client_attestation" else "accounts",
            "jwks": private_jwks(f"{client_id}-two"),
        },
    }


class PrepareOpenid4vcPublicOnboardingTests(unittest.TestCase):
    def test_manifest_uses_public_approval_policy_and_never_exports_private_keys(self):
        module = load_module()
        configs = {
            "openid4vc-vci-standard-sd.json": vci_config(
                alias="standard-sd",
                configuration_id="pid-sd",
                authentication="private_key_jwt",
                client_id="private-wallet",
            ),
            "openid4vc-vci-standard-mdoc.json": vci_config(
                alias="standard-mdoc",
                configuration_id="mdl",
                authentication="private_key_jwt",
                client_id="private-wallet",
            ),
            "openid4vc-vci-haip-sd.json": vci_config(
                alias="haip-sd",
                configuration_id="pid-sd",
                authentication="client_attestation",
                client_id="attested-wallet",
            ),
            "openid4vc-vci-haip-mdoc.json": vci_config(
                alias="haip-mdoc",
                configuration_id="mdl",
                authentication="client_attestation",
                client_id="attested-wallet",
            ),
        }

        clients = module.prepare_clients(
            configs,
            target_origin="https://issuer.example",
            suite_origin="https://suite.example",
        )

        self.assertEqual(len(clients), 4)
        by_id = {item["logical_client_id"]: item["request"] for item in clients}
        for logical_id, request in by_id.items():
            self.assertTrue(request["require_dpop_bound_tokens"])
            self.assertFalse(request["require_mtls_bound_tokens"])
            self.assertEqual(request["grant_types"], ["authorization_code", "refresh_token"])
            self.assertEqual(set(request["scopes"]) & {"accounts"}, set())
            encoded = json.dumps(request)
            self.assertNotIn('"d"', encoded)
            self.assertNotIn("private-d", encoded)
            self.assertTrue(
                all(uri.startswith("https://suite.example/test/a/") for uri in request["redirect_uris"]),
                logical_id,
            )

        private = by_id["private-wallet"]
        self.assertEqual(private["token_endpoint_auth_method"], "private_key_jwt")
        self.assertFalse(private["require_par_request_object"])
        self.assertTrue(private["allow_client_assertion_endpoint_audience"])
        self.assertEqual(set(private["scopes"]), {"pid-sd", "mdl"})

        attested = by_id["attested-wallet"]
        self.assertEqual(attested["token_endpoint_auth_method"], "attest_jwt_client_auth")
        self.assertTrue(attested["require_par_request_object"])
        self.assertFalse(attested["allow_client_assertion_endpoint_audience"])
        self.assertEqual(set(attested["scopes"]), {"pid-sd", "mdl", "offline_access"})

    def test_cli_writes_apply_compatible_manifest_and_plan_manifest(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs_path = root / "configs.json"
            plans_path = root / "plans.json"
            output = root / "output"
            configs = {
                "openid4vc-vci-standard.json": vci_config(
                    alias="standard",
                    configuration_id="pid-sd",
                    authentication="private_key_jwt",
                    client_id="private-wallet",
                ),
                "openid4vc-vci-haip.json": vci_config(
                    alias="haip",
                    configuration_id="pid-sd",
                    authentication="client_attestation",
                    client_id="attested-wallet",
                ),
                "openid4vc-vp.json": {"alias": "vp", "description": "VP"},
            }
            configs_path.write_text(json.dumps({"configs": configs}), encoding="utf-8")
            plans_path.write_text(
                json.dumps(
                    [
                        "issuer-plan openid4vc-vci-standard.json",
                        "verifier-plan openid4vc-vp.json",
                    ]
                ),
                encoding="utf-8",
            )
            with patch(
                "sys.argv",
                [
                    "prepare_openid4vc_public_onboarding.py",
                    "--plan-configs",
                    str(configs_path),
                    "--plan-set",
                    str(plans_path),
                    "--target-issuer",
                    "https://issuer.example",
                    "--suite-base-url",
                    "https://suite.example",
                    "--applicant-email",
                    "applicant@example.test",
                    "--output-dir",
                    str(output),
                ],
            ):
                self.assertEqual(module.main(), 0)

            manifest = json.loads(
                (output / "oidf-onboarding-manifest.json").read_text(encoding="utf-8")
            )
            plan_manifest = json.loads(
                (output / "openid4vc-plan-set-manifest.json").read_text(encoding="utf-8")
            )

        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["applicant_email"], "applicant@example.test")
        self.assertEqual(manifest["target_issuer"], "https://issuer.example")
        self.assertEqual(manifest["suite_base_url"], "https://suite.example")
        self.assertEqual(len(manifest["clients"]), 4)
        self.assertEqual(len(plan_manifest["plans"]), 2)

    def test_public_origins_reject_product_local_and_raw_ip_targets(self):
        module = load_module()
        for value in (
            "https://localhost",
            "https://nginx:8443",
            "https://127.0.0.1",
            "http://suite.example",
        ):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                module.public_https_origin(value, label="origin")


if __name__ == "__main__":
    unittest.main()
