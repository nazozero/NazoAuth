import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "apply_public_conformance_onboarding.py"
    )
    spec = importlib.util.spec_from_file_location("apply_public_conformance_onboarding", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ApplyPublicConformanceOnboardingTests(unittest.TestCase):
    def test_target_must_be_an_exact_https_origin(self):
        module = load_module()

        self.assertEqual(
            module.canonical_https_origin("https://issuer.example/", label="issuer"),
            "https://issuer.example",
        )
        for value in (
            "http://issuer.example",
            "https://user:secret@issuer.example",
            "https://issuer.example/path",
            "https://issuer.example?query=1",
            "https://issuer.example/#fragment",
        ):
            with self.subTest(value=value):
                with self.assertRaises(module.OnboardingError):
                    module.canonical_https_origin(value, label="issuer")

    def test_client_rewrite_changes_only_exact_client_id_fields(self):
        module = load_module()
        document = {
            "client": {
                "client_id": "logical-client",
                "client_secret": "old-secret",
                "description": "logical-client",
            },
            "nested": [{"client_id": "another-client"}],
        }

        replacements = module.replace_client_material(
            document, "logical-client", "approved-client", "delivered-secret"
        )

        self.assertEqual(replacements, 1)
        self.assertEqual(document["client"]["client_id"], "approved-client")
        self.assertEqual(document["client"]["client_secret"], "delivered-secret")
        self.assertEqual(document["client"]["description"], "logical-client")
        self.assertEqual(document["nested"][0]["client_id"], "another-client")

    def test_manifest_rejects_duplicate_logical_clients_and_nonconfidential_requests(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                '{"schema":1,"clients":['
                '{"logical_client_id":"same","request":{"client_type":"confidential"}},'
                '{"logical_client_id":"same","request":{"client_type":"public"}}]}'
            )

            with self.assertRaises(module.OnboardingError):
                module.require_manifest(path)

    def test_control_plane_tool_has_no_database_or_server_crate_dependency(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "apply_public_conformance_onboarding.py"
        ).read_text(encoding="utf-8")

        for forbidden in (
            "DATABASE_URL",
            "psycopg",
            "sqlx",
            "nazo_postgres",
            "nazo-oauth-server",
            "INSERT INTO",
            "UPDATE oauth_clients",
        ):
            self.assertNotIn(forbidden, source)
        for required in (
            "/auth/me/access-requests",
            "/admin/access-requests/",
            "/auth/me/mtls-trust-requests",
            "/admin/mtls-trust-requests/",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
