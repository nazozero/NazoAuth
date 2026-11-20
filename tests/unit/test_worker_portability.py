import unittest

from scripts.check_worker_portability import native_violations, packages, violations


class WorkerPortabilityTests(unittest.TestCase):
    def test_cargo_repeat_marker_is_not_a_feature(self):
        self.assertEqual(list(packages(
            "tokio v1.54.1  (*)\n"
            "nazoauth v0.3.9 (/workspace/crates/nazoauth) deployment-control (*)\n"
        )), [("tokio", set()), ("nazoauth", {"deployment-control"})])

    def test_rejects_native_drivers_and_runtime_features(self):
        self.assertEqual(len(violations(
            "tokio v1.54.1 default,rt,net,sync\n"
            "diesel v2.4.0 postgres\n"
            "rusqlite v0.38.0 bundled\n"
        )), 4)

    def test_accepts_sdk_library_only_tokio(self):
        self.assertEqual(violations("tokio v1.54.1 sync\nworker v0.9.0 d1,http"), [])

    def test_rejects_native_workspace_adapter(self):
        self.assertEqual(len(violations("nazo-http-actix v0.3.9 (/workspace/crates/http-actix)")), 1)

    def test_rejects_native_control_and_certificate_features(self):
        self.assertEqual(len(violations(
            "nazoauth v0.3.9 (/workspace/crates/nazoauth) deployment-control\n"
            "nazo-crypto v0.3.9 (/workspace/crates/crypto) jose,certificate-issuance\n"
        )), 2)

    def test_rejects_worker_packages_in_native_artifact_graph(self):
        self.assertEqual(len(native_violations(
            "nazo-server-worker v0.3.9 (/workspace/crates/server-worker)\n"
            "nazo-oauth-server-d1 v0.3.9 (/workspace/crates/authorization-server-d1)\n"
            "worker v0.9.0 d1,http\n"
            "wasm-bindgen v0.2.130 std\n"
        )), 4)

    def test_accepts_native_shared_protocols_and_crypto(self):
        self.assertEqual(native_violations(
            "nazoauth v0.3.9 (/workspace/crates/nazoauth) deployment-control\n"
            "nazo-crypto v0.3.9 (/workspace/crates/crypto) jose,certificate-issuance\n"
            "aws-lc-rs v1.19.0 default\n"
        ), [])
