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
    def test_matrix_is_bounded_and_covers_each_final_role_format(self):
        module = load("materialize_openid4vc_oidf_config.py")
        cases = module.matrix_cases()
        self.assertEqual(len(cases), 18)
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

    def test_materializer_creates_unique_aliases_and_exact_plan_count(self):
        module = load("materialize_openid4vc_oidf_config.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            driver = root / "driver.json"
            output = root / "output"
            base.write_text(json.dumps({
                name: {"alias": f"nazo-{name}", **({"vci": {}} if name.startswith("vci") else {})}
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
                "verifier": {},
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
            self.assertEqual(len(plans), 18)
            self.assertEqual(len(configs), 18)
            self.assertEqual(len(set(materialized_driver["aliases"])), 18)
            self.assertEqual(materialized_driver["target_origin"], "https://auth.nazo.run")
            for filename, config in configs.items():
                if "vci-" not in filename:
                    continue
                self.assertEqual(config["vci"]["credential_issuer_url"], "https://auth.nazo.run")
                expected = "org.iso.18013.5.1.mDL" if "mdoc" in filename else "pid-sd-jwt"
                self.assertEqual(config["vci"]["credential_configuration_id"], expected)
                if "preauth" in filename:
                    self.assertEqual(config["vci"]["static_tx_code"], "123456")


if __name__ == "__main__":
    unittest.main()
