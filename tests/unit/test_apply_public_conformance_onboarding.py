import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


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
    def test_access_request_site_name_is_stable_unique_and_within_product_limit(self):
        module = load_module()

        first = module.access_request_site_name("logical-client-" + "a" * 500)
        second = module.access_request_site_name("logical-client-" + "b" * 500)

        self.assertEqual(first, module.access_request_site_name("logical-client-" + "a" * 500))
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first.encode("utf-8")), 120)

    def test_apply_journals_partial_state_before_remote_approval_failure(self):
        module = load_module()

        class Applicant:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me"):
                    return {"id": "applicant", "admin_level": 0}
                if (method, path) == ("POST", "/auth/me/access-requests"):
                    return {"id": "request-1"}
                raise AssertionError((method, path, payload, kwargs))

        class Admin:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me"):
                    return {"id": "admin", "admin_level": 1}
                if method == "POST" and path.endswith("/approve"):
                    raise module.OnboardingError("approval rejected")
                raise AssertionError((method, path, payload, kwargs))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            configs = root / "configs.json"
            plan_set = root / "plans.json"
            plan_manifest = root / "plan-manifest.json"
            state = root / "state.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "suite_base_url": "https://suite.example",
                        "applicant_email": "applicant@example.com",
                        "clients": [
                            {
                                "logical_client_id": "logical-client",
                                "request": {"client_type": "confidential"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            configs.write_text(
                '{"configs":{"plan":{"client_id":"logical-client"}}}', encoding="utf-8"
            )
            plan_set.write_text("[]", encoding="utf-8")
            plan_manifest.write_text("{}", encoding="utf-8")
            args = SimpleNamespace(
                manifest=manifest,
                target_issuer="https://issuer.example",
                state_file=state,
                plan_configs=configs,
                plan_set=plan_set,
                plan_manifest=plan_manifest,
                runner_env=root / "runner.env",
                trust_bundle=root / "trust.pem",
            )

            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "OIDF_APPLICANT_PASSWORD": "applicant-password",
                        "OIDF_ADMIN_EMAIL": "admin@example.com",
                        "OIDF_ADMIN_PASSWORD": "admin-password",
                    },
                    clear=True,
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Applicant(), Admin()],
                ),
            ):
                with self.assertRaisesRegex(module.OnboardingError, "approval rejected"):
                    module.apply_onboarding(args)

            journal = json.loads(state.read_text(encoding="utf-8"))
            self.assertNotIn("complete", journal)
            self.assertEqual(
                journal["clients"],
                [
                    {
                        "logical_client_id": "logical-client",
                        "access_request_id": "request-1",
                    }
                ],
            )

    def test_cleanup_rejects_a_journaled_pending_request_without_a_client(self):
        module = load_module()

        class Applicant:
            def request_json(self, method, path, payload=None, **kwargs):
                if (method, path) == ("GET", "/auth/me/access-requests"):
                    return {"items": [{"id": "request-1", "status": 0}]}
                raise AssertionError((method, path, payload, kwargs))

        class Admin:
            def __init__(self):
                self.calls = []

            def request_json(self, method, path, payload=None, **kwargs):
                self.calls.append((method, path, payload, kwargs))
                return {"id": "request-1", "status": 2}

        admin = Admin()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "clients": [
                            {
                                "logical_client_id": "logical-client",
                                "access_request_id": "request-1",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                state_file=state,
                target_issuer="https://issuer.example",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "OIDF_APPLICANT_EMAIL": "applicant@example.com",
                        "OIDF_APPLICANT_PASSWORD": "applicant-password",
                        "OIDF_ADMIN_EMAIL": "admin@example.com",
                        "OIDF_ADMIN_PASSWORD": "admin-password",
                    },
                    clear=True,
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Applicant(), admin],
                ),
            ):
                self.assertEqual(module.cleanup_onboarding(args), 0)

            self.assertFalse(state.exists())
            self.assertEqual(admin.calls[0][0:2], ("POST", "/admin/access-requests/request-1/reject"))

    def test_cleanup_ignores_a_journal_entry_created_before_the_remote_request(self):
        module = load_module()

        class Session:
            def request_json(self, method, path, payload=None, **kwargs):
                raise AssertionError((method, path, payload, kwargs))

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target_issuer": "https://issuer.example",
                        "clients": [{"logical_client_id": "not-yet-submitted"}],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                state_file=state,
                target_issuer="https://issuer.example",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "OIDF_APPLICANT_EMAIL": "applicant@example.com",
                        "OIDF_APPLICANT_PASSWORD": "applicant-password",
                        "OIDF_ADMIN_EMAIL": "admin@example.com",
                        "OIDF_ADMIN_PASSWORD": "admin-password",
                    },
                    clear=True,
                ),
                mock.patch.object(
                    module.ControlPlaneSession,
                    "login",
                    side_effect=[Session(), Session()],
                ),
            ):
                self.assertEqual(module.cleanup_onboarding(args), 0)

            self.assertFalse(state.exists())

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
