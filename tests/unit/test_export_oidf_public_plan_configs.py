import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


script = Path(__file__).resolve().parents[2] / "scripts" / "export_oidf_public_plan_configs.py"
spec = importlib.util.spec_from_file_location("export_oidf_public_plan_configs", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExportOidfPublicPlanConfigsTests(unittest.TestCase):
    def test_strip_private_jwks_removes_private_key_fields(self):
        rendered = {
            "configs": {
                "oidf-test-plan-config.json": {
                    "alias": "seed-alias",
                    "client": {
                        "client_id": "client-1",
                        "client_secret": "secret",
                        "scope": "openid accounts",
                        "jwks": {
                            "keys": [
                                {
                                    "kty": "RSA",
                                    "kid": "client-key",
                                    "alg": "PS256",
                                    "n": "modulus",
                                    "e": "AQAB",
                                    "d": "private",
                                    "p": "private",
                                    "q": "private",
                                    "dp": "private",
                                    "dq": "private",
                                    "qi": "private",
                                }
                            ]
                        },
                    },
                    "mtls": {
                        "cert": "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
                        "key": "private",
                    },
                    "nazo": {
                        "fapi_profile": "plain_fapi",
                        "fapi_sender_constrain": "mtls",
                        "oidf_user_password": "secret",
                    },
                    "automated_ciba_approval_url": "https://example.test/ciba?token=secret",
                    "browser": [{"type": "text", "value": "secret"}],
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_path = tmp_path / "configs.json"
            output_dir = tmp_path / "public"
            input_path.write_text(json.dumps(rendered), encoding="utf-8")

            self.assertEqual(
                module.main_with_args_for_test(
                    ["--config-json-file", str(input_path), "--output-dir", str(output_dir)]
                ),
                0,
            )

            exported = json.loads((output_dir / "oidf-test-plan-config.json").read_text())

        self.assertEqual(exported["alias"], "seed-alias")
        self.assertEqual(exported["client"]["client_id"], "client-1")
        self.assertEqual(exported["client"]["scope"], "openid accounts")
        self.assertEqual(
            exported["mtls"]["cert"],
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----",
        )
        self.assertEqual(exported["nazo"]["fapi_profile"], "plain_fapi")
        self.assertEqual(exported["nazo"]["fapi_sender_constrain"], "mtls")

        jwk = exported["client"]["jwks"]["keys"][0]
        self.assertEqual(jwk["kid"], "client-key")
        self.assertEqual(jwk["n"], "modulus")
        self.assertNotIn("d", jwk)
        self.assertNotIn("p", jwk)
        self.assertNotIn("q", jwk)
        self.assertNotIn("dp", jwk)
        self.assertNotIn("dq", jwk)
        self.assertNotIn("qi", jwk)
        self.assertNotIn("client_secret", exported["client"])
        self.assertNotIn("key", exported["mtls"])
        self.assertNotIn("oidf_user_password", exported["nazo"])
        self.assertNotIn("automated_ciba_approval_url", exported)
        self.assertNotIn("browser", exported)


if __name__ == "__main__":
    unittest.main()
