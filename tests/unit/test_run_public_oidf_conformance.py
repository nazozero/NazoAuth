import importlib.util
import os
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


def load_module():
    script = Path(__file__).resolve().parents[2] / "scripts" / "run_public_oidf_conformance.py"
    spec = importlib.util.spec_from_file_location("run_public_oidf_conformance", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicOidfRunnerTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_origins_are_normalized_and_non_origin_urls_are_rejected(self):
        self.assertEqual(
            self.module.origin("https://suite.example/", "--suite"),
            "https://suite.example",
        )
        for invalid in ("http://suite.example", "https://suite.example/path", "localhost"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.module.PublicRunError):
                    self.module.origin(invalid, "--suite")

    def test_required_environment_reports_all_missing_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                self.module.PublicRunError,
                "OIDF_APPLICANT_EMAIL.*OIDF_CONFORMANCE_TOKEN",
            ):
                self.module.required_environment("OIDF_CONFORMANCE_TOKEN")

    def test_plan_groups_use_explicit_inputs_and_isolate_browser_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = Namespace(
                suite_dir=root / "suite",
                suite_revision="suite-commit",
                conformance_server="https://suite.example",
                target_issuer="https://issuer.example",
                token_env="OIDF_CONFORMANCE_TOKEN",
                export_dir=root / "results",
                timeout_seconds=100,
                monitor_interval_seconds=5,
            )
            with mock.patch.object(self.module, "command") as command:
                self.module.run_plan_groups(args, root / "work", {})

            self.assertEqual(command.call_count, 4)
            invocations = [call.args[0] for call in command.call_args_list]
            self.assertNotIn("--no-parallel", invocations[0])
            self.assertNotIn("--no-parallel", invocations[1])
            self.assertIn("--no-parallel", invocations[2])
            self.assertIn("--no-parallel", invocations[3])
            self.assertTrue(all("--no-api-token" not in invocation for invocation in invocations))
            self.assertTrue(
                all(
                    invocation[invocation.index("--suite-revision") + 1] == "suite-commit"
                    for invocation in invocations
                )
            )

    def test_proxy_trust_install_and_restore_are_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "proxy" / "trust.pem"
            target.parent.mkdir()
            target.write_text("old\n", encoding="utf-8")
            executable = root / "proxy-bin"
            executable.write_text("", encoding="utf-8")
            approved = root / "approved.pem"
            approved.write_text("new\n", encoding="utf-8")
            work = root / "work"
            work.mkdir()
            trust = self.module.ProxyTrust(target, executable, work)

            with (
                mock.patch.object(self.module, "command") as command,
                mock.patch.object(self.module.ssl, "SSLContext"),
            ):
                trust.install(approved)
                self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
                trust.restore()

            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertFalse((work / "proxy-trust-bundle.before.pem").exists())
            self.assertEqual(command.call_count, 4)

    def test_proxy_validation_failure_restores_previous_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "trust.pem"
            target.write_text("old\n", encoding="utf-8")
            executable = root / "proxy-bin"
            executable.write_text("", encoding="utf-8")
            approved = root / "approved.pem"
            approved.write_text("new\n", encoding="utf-8")
            work = root / "work"
            work.mkdir()
            trust = self.module.ProxyTrust(target, executable, work)
            failure = subprocess.CalledProcessError(1, [str(executable), "-t"])

            with (
                mock.patch.object(
                    self.module,
                    "command",
                    side_effect=(failure, None, None),
                ),
                mock.patch.object(self.module.ssl, "SSLContext"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    trust.install(approved)

            self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
            self.assertFalse(trust.installed)


if __name__ == "__main__":
    unittest.main()
