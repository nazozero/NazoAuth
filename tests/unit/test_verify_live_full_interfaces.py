import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_live_full_interfaces.py"


class VerifyLiveCliTests(unittest.TestCase):
    def test_help_is_offline_and_documents_explicit_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            missing_secrets = workdir / "does-not-exist.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--help",
                    "--secrets-path",
                    str(missing_secrets),
                ],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--base-url", completed.stdout)
        self.assertIn("--secrets-path", completed.stdout)
        self.assertIn("--expected-backend-sha", completed.stdout)

    def test_source_keeps_production_defaults(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")

        self.assertIn('default="https://auth.nazo.run"', source)
        self.assertIn('default="/opt/nazo-oauth/secrets.json"', source)


if __name__ == "__main__":
    unittest.main()
