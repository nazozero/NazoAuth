import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    script = ROOT / "scripts" / "check_spec_freshness.py"
    spec = importlib.util.spec_from_file_location("check_spec_freshness", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, payload, url="https://example.invalid/final"):
        self.payload = payload
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload

    def geturl(self):
        return self.url


class SpecFreshnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def test_repository_manifest_is_valid_and_complete(self):
        manifest = json.loads(
            (ROOT / "requirements" / "spec-freshness.json").read_text(encoding="utf-8")
        )

        self.module.validate_manifest(manifest, ROOT)
        identifiers = {entry["id"] for entry in manifest["sources"]}
        self.assertIn("oauth-browser-based-apps", identifiers)
        self.assertIn("oauth-grant-management", identifiers)
        self.assertIn("oidf-conformance-suite", identifiers)
        self.assertGreaterEqual(len(identifiers), 35)

    def test_manifest_rejects_duplicate_ids_and_unofficial_hosts(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": [],
            "sources": [
                {
                    "id": "same",
                    "title": "One",
                    "kind": "rfc",
                    "url": "https://example.com/rfc1",
                    "number": 1,
                    "markers": ["RFC 1"],
                },
                {
                    "id": "same",
                    "title": "Two",
                    "kind": "rfc",
                    "url": "https://www.rfc-editor.org/info/rfc2",
                    "number": 2,
                    "markers": ["RFC 2"],
                },
            ],
        }

        with self.assertRaisesRegex(ValueError, "official host|duplicate id"):
            self.module.validate_manifest(manifest, ROOT)

    def test_ietf_revision_mismatch_fails(self):
        entry = {
            "id": "browser",
            "title": "Browser",
            "kind": "ietf_draft",
            "url": "https://datatracker.ietf.org/doc/draft-example/",
            "document": "draft-example",
            "revision": "27",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps({"name": "draft-example", "rev": "26"}).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "expected revision 27, official source reports 26"):
            self.module.check_entry(entry, opener)

    def test_openid_marker_and_final_url_are_required(self):
        entry = {
            "id": "grant",
            "title": "Grant",
            "kind": "openid_document",
            "url": "https://openid.net/specs/oauth-v2-grant-management.html",
            "markers": ["oauth-v2-grant-management-03", "Second Implementer's Draft"],
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            b"oauth-v2-grant-management-03",
            "https://openid.net/specs/oauth-v2-grant-management-03.html",
        )

        with self.assertRaisesRegex(RuntimeError, "missing marker"):
            self.module.check_entry(entry, opener)

    def test_oidf_latest_release_tag_and_commit_are_required(self):
        entry = {
            "id": "suite",
            "title": "suite",
            "kind": "oidf_suite",
            "url": "https://gitlab.com/openid/conformance-suite/-/releases/release-v5.2.0",
            "api_url": "https://gitlab.com/api/v4/projects/openid%2Fconformance-suite/releases/permalink/latest",
            "tag": "release-v5.2.0",
            "commit": "dee9a25160e789f0f80517674693ef7989ab9fa1",
        }
        opener = lambda *_args, **_kwargs: FakeResponse(
            json.dumps(
                {
                    "tag_name": "release-v5.1.44",
                    "commit": {"id": "f326"},
                }
            ).encode()
        )

        with self.assertRaisesRegex(RuntimeError, "expected latest tag release-v5.2.0"):
            self.module.check_entry(entry, opener)

    def test_active_documents_reject_stale_draft_pins(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": ["active.md"],
            "sources": [
                {
                    "id": "browser",
                    "title": "Browser",
                    "kind": "ietf_draft",
                    "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/",
                    "document": "draft-ietf-oauth-browser-based-apps",
                    "revision": "27",
                }
            ],
        }
        temporary = ROOT / "active.md"
        temporary.write_text("draft-ietf-oauth-browser-based-apps-26", encoding="utf-8")
        self.addCleanup(temporary.unlink)

        with self.assertRaisesRegex(ValueError, "stale draft pin"):
            self.module.validate_manifest(manifest, ROOT)

    def test_manifest_rejects_active_path_escape(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": ["../outside.md"],
            "sources": [
                {
                    "id": "rfc7009",
                    "title": "Revocation",
                    "kind": "rfc",
                    "url": "https://www.rfc-editor.org/info/rfc7009",
                    "number": 7009,
                    "markers": ["RFC 7009"],
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "must stay within the repository"):
            self.module.validate_manifest(manifest, ROOT)

    def test_manifest_rejects_unofficial_suite_api(self):
        manifest = {
            "schema_version": 1,
            "active_document_paths": [],
            "sources": [
                {
                    "id": "suite",
                    "title": "suite",
                    "kind": "oidf_suite",
                    "url": "https://gitlab.com/openid/conformance-suite/-/releases/release-v5.2.0",
                    "api_url": "https://example.com/latest",
                    "tag": "release-v5.2.0",
                    "commit": "dee9a25160e789f0f80517674693ef7989ab9fa1",
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "official GitLab API"):
            self.module.validate_manifest(manifest, ROOT)


if __name__ == "__main__":
    unittest.main()
