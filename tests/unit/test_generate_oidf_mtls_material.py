import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "generate_oidf_mtls_material.py"
    spec = importlib.util.spec_from_file_location("generate_oidf_mtls_material", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


module = load_module()


@unittest.skipUnless(shutil.which("openssl"), "openssl is required")
class GenerateOidfMtlsMaterialTests(unittest.TestCase):
    def test_generation_deduplicates_clients_and_builds_strict_ca(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / "public"
            public.mkdir()
            config = {
                "client": {"client_id": "shared-client"},
                "client2": {"client_id": "second-client"},
                "mtls": {"ca": "public-ca", "cert": "public-cert"},
                "mtls2": {"ca": "public-ca", "cert": "public-cert-2"},
            }
            (public / "oidf-one.json").write_text(json.dumps(config), encoding="utf-8")
            (public / "oidf-two.json").write_text(
                json.dumps({"client": config["client"], "mtls": config["mtls"]}),
                encoding="utf-8",
            )
            output = root / "material.json"

            with mock.patch(
                "sys.argv",
                [
                    "generate_oidf_mtls_material.py",
                    "--public-config-directory",
                    str(public),
                    "--output",
                    str(output),
                ],
            ):
                self.assertEqual(module.main(), 0)

            material = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(set(material["clients"]), {"shared-client", "second-client"})
            ca = root / "ca.pem"
            ca.write_text(material["ca"], encoding="ascii")
            constraints = subprocess.run(
                ["openssl", "x509", "-in", str(ca), "-noout", "-ext", "basicConstraints"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            key_usage = subprocess.run(
                ["openssl", "x509", "-in", str(ca), "-noout", "-ext", "keyUsage"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("CA:TRUE", constraints)
            self.assertIn("critical", constraints)
            self.assertIn("Certificate Sign", key_usage)
            self.assertIn("critical", key_usage)


if __name__ == "__main__":
    unittest.main()
