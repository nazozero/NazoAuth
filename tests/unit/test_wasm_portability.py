"""The portable boundary must not acquire native execution through a library."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("wasm_portability", ROOT / "scripts/check_wasm_portability.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class WasmPortability(unittest.TestCase):
    def test_all_inner_roles_are_checked_and_native_composition_is_excluded(self):
        roles = GATE.contracts.PACKAGE_ROLES
        self.assertEqual(
            set(GATE.contracts.PORTABLE_PACKAGES),
            {package for package, role in roles.items() if role in {"domain", "application"}},
        )
        self.assertIn("nazo-oauth-server", GATE.contracts.PORTABLE_PACKAGES)
        self.assertNotIn("nazoauth", GATE.contracts.PORTABLE_PACKAGES)

    def test_transitive_runtime_network_storage_and_native_crypto_are_rejected(self):
        for package in ("tokio", "reqwest", "actix-web", "axum", "diesel", "fred", "aws-lc-sys", "nazo-valkey"):
            with self.subTest(package=package):
                tree = f"nazo-identity v1.0.0\nordinary-wrapper v1.0.0\n{package} v1.0.0 (*)\n"
                self.assertEqual(GATE.runtime_violations(tree), {package})

    def test_neutral_data_algorithms_and_web_primitives_are_allowed(self):
        tree = "\n".join(f"{package} v1.0.0" for package in (
            "nazo-identity", "futures-util", "http", "rustls-pki-types", "rustls-webpki",
            "chrono", "web-time", "wasm-bindgen", "getrandom", "p256", "sha2",
        ))
        self.assertEqual(GATE.runtime_violations(tree), set())

    def test_timezone_lookup_must_use_bundled_data_without_native_files(self):
        self.assertEqual(GATE.runtime_violations("jiff v1.0.0|std,tzdb-bundle-always\n"), set())
        self.assertEqual(
            GATE.runtime_violations("jiff v1.0.0|std,tz-system,tzdb-zoneinfo,tzdb-concatenated (*)\n"),
            {"jiff/tz-system", "jiff/tzdb-zoneinfo", "jiff/tzdb-concatenated"},
        )

    def test_compilation_checks_actual_production_closure_without_native_features(self):
        with patch.object(GATE.subprocess, "check_output", return_value="nazo-auth v1.0.0\n") as tree, patch.object(GATE.subprocess, "run") as compile:
            GATE.check(("nazo-auth", "nazo-identity"))
        tree_command = tree.call_args.args[0]
        command = compile.call_args.args[0]
        self.assertEqual(tree_command[tree_command.index("--edges") + 1], "normal,no-proc-macro")
        for args in (tree_command, command):
            self.assertIn("--locked", args)
            self.assertNotIn("--all-features", args)
            self.assertIn(GATE.TARGET, args)
            self.assertNotIn("--workspace", args)
            self.assertIn("nazo-auth", args)
            self.assertIn("nazo-identity", args)
        self.assertIn("--lib", command)
        self.assertTrue(compile.call_args.kwargs["check"])

    def test_all_portable_crypto_capabilities_are_checked_without_host_provisioning(self):
        with patch.object(GATE.subprocess, "check_output", return_value="nazo-crypto v1.0.0\n"), patch.object(GATE.subprocess, "run") as compile:
            GATE.check(("nazo-crypto",))
        command = compile.call_args.args[0]
        features = command[command.index("--features") + 1].split(",")
        self.assertEqual(
            set(features),
            {f"nazo-crypto/{feature}" for feature in ("jose", "ecdh", "aead", "password", "ed25519", "x509")},
        )
        self.assertEqual(
            GATE.runtime_violations("nazo-crypto v1.0.0|jose,x509,certificate-issuance\n"),
            {"nazo-crypto/certificate-issuance"},
        )

    def test_graph_violation_prevents_success_even_if_rust_would_compile(self):
        with patch.object(GATE.subprocess, "check_output", return_value="native-tls v1.0.0\n"), patch.object(GATE.subprocess, "run") as compile:
            with self.assertRaisesRegex(SystemExit, "native-tls"):
                GATE.check(("nazo-auth",))
            compile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
