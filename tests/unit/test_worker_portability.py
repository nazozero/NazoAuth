import unittest

from scripts.check_worker_portability import violations


class WorkerPortabilityTests(unittest.TestCase):
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
