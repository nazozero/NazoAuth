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
                    "client": {
                        "client_id": "client-1",
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
                    }
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

        jwk = exported["client"]["jwks"]["keys"][0]
        self.assertEqual(jwk["kid"], "client-key")
        self.assertEqual(jwk["n"], "modulus")
        self.assertNotIn("d", jwk)
        self.assertNotIn("p", jwk)
        self.assertNotIn("q", jwk)
        self.assertNotIn("dp", jwk)
        self.assertNotIn("dq", jwk)
        self.assertNotIn("qi", jwk)


if __name__ == "__main__":
    unittest.main()
