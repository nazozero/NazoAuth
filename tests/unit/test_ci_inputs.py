"""Exercise evidence reuse boundaries, not just workflow string matching."""

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from scripts import ci_inputs as gate


NOW = datetime(2026, 11, 15, 10, tzinfo=timezone.utc)


def tree(*entries):
    return b"\0".join(f"100644 blob {oid}\t{path}".encode() for path, oid in entries)


class CiInputTests(unittest.TestCase):
    def test_docs_and_inventory_do_not_change_rust_inputs(self):
        base = tree(("crates/app/src/lib.rs", "a"))
        extra = tree(("docs/protocol/spec-freshness.md", "b"),
                     ("requirements/spec-freshness.json", "c"), ("README.md", "d"))
        for scope in gate.WORKFLOWS:
            self.assertEqual(gate.fingerprint(scope, base), gate.fingerprint(scope, base + b"\0" + extra))

    def test_source_fixtures_configuration_and_workflow_changes_invalidate(self):
        for path in ("crates/app/src/lib.rs", "crates/app/Cargo.toml", "Cargo.lock",
                     ".cargo/config.toml", "clippy.toml", ".dockerignore", "proptest-regressions/support/uri_policy.txt",
                     "tests/fixtures/data.json", "migrations/a/up.sql",
                     "scripts/generate_codecov_lcov.sh", ".github/workflows/code-quality.yml",
                     ".github/workflows/codecov.yml", "scripts/ci_inputs.py"):
            with self.subTest(path=path):
                original = gate.fingerprint("rust", tree((path, "a")))
                self.assertNotEqual(original, gate.fingerprint("rust", tree((path, "b"))))
                self.assertNotEqual(original, gate.fingerprint("rust", b""))
                self.assertNotEqual(original, gate.fingerprint("rust", tree((path, "a")).replace(b"100644", b"100755")))

    def test_scope_ownership(self):
        changes = {
            "crates/authorization-server/src/token.rs": {"rust", "codeql", "security"},
            "crates/crypto/src/signature.rs": {"rust", "codeql", "security", "fuzz"},
            "perf/tests/test_capacity_producer.py": {"perf"},
            "perf/env.yaml": {"security", "perf"},
            "scripts/full_real_request_load.py": {"security"},
            ".github/workflows/ci-inputs.yml": set(gate.WORKFLOWS),
        }
        for path, expected in changes.items():
            actual = {scope for scope in gate.WORKFLOWS if gate.fingerprint(scope, tree((path, "a"))) != gate.fingerprint(scope, b"")}
            self.assertEqual(actual, expected, path)

    def record(self, **changes):
        result = dict(id=1, workflow_id=12, status="completed", conclusion="success",
                      head_repository={"full_name": "owner/repo"}, event="pull_request",
                      head_branch="feature", pull_requests=[{"number": 272}],
                      created_at="2026-11-15T09:00:00Z", html_url="https://example/run/1")
        result.update(changes)
        return result

    def test_only_completed_success_in_same_context_can_be_reused(self):
        current = self.record(id=2, status="in_progress", conclusion=None)
        self.assertTrue(gate.reusable(self.record(), current, NOW))
        for changes in (dict(id=2), dict(workflow_id=13), dict(status="in_progress"),
                        dict(conclusion="failure"), dict(conclusion="cancelled"),
                        dict(head_repository={"full_name": "fork/repo"}),
                        dict(event="push"), dict(head_branch="another"),
                        dict(pull_requests=[]), dict(pull_requests=[{"number": 273}]),
                        dict(created_at="2026-11-08T09:59:59Z")):
            with self.subTest(changes=changes):
                self.assertFalse(gate.reusable(self.record(**changes), current, NOW))

    def test_security_freshness_does_not_force_daily_functional_retests(self):
        current = self.record(id=2)
        prior = self.record(created_at="2026-11-14T09:59:59Z")
        self.assertTrue(gate.reusable(prior, current, NOW, scope="rust"))
        self.assertFalse(gate.reusable(prior, current, NOW, scope="security"))

    def test_new_pr_can_reuse_same_repository_main_but_not_another_feature_branch(self):
        current = self.record(id=2)
        prior = self.record(event="push", head_branch="main", pull_requests=[])
        self.assertTrue(gate.reusable(prior, current, NOW))
        prior["event"] = "workflow_dispatch"
        self.assertTrue(gate.reusable(prior, current, NOW))
        prior["head_branch"] = "another-feature"
        self.assertFalse(gate.reusable(prior, current, NOW))
        prior["head_branch"] = "main"
        current["head_repository"] = {"full_name": "fork/repo"}
        self.assertFalse(gate.reusable(prior, current, NOW))

    @patch.dict(gate.os.environ, GITHUB_EVENT_NAME="pull_request", GITHUB_REPOSITORY="owner/repo", GITHUB_RUN_ID="2")
    @patch.object(gate.subprocess, "check_output", return_value=tree(("crates/a/src/lib.rs", "a")))
    def test_matches_actual_checkout_and_never_reuses_failed_run(self, _tree):
        current = self.record(id=2)
        identity = "ci-inputs-rust-" + gate.fingerprint("rust", _tree.return_value)
        artifact = dict(name=identity, expired=False, workflow_run={"id": 1})
        for conclusion, expected in (("success", False), ("failure", True), ("cancelled", True)):
            with patch.object(gate, "api", side_effect=[current, {"artifacts": [artifact]}, self.record(conclusion=conclusion)]), patch.object(gate, "datetime") as clock:
                clock.now.return_value = NOW
                clock.fromisoformat.side_effect = datetime.fromisoformat
                self.assertEqual(gate.decide("rust")[1], expected)

    @patch.object(gate.subprocess, "check_output", return_value=b"")
    @patch.object(gate, "api", side_effect=AssertionError("manual checks must not consult prior runs"))
    def test_manual_and_scheduled_checks_always_execute(self, _api, _tree):
        for event in ("workflow_dispatch", "schedule"):
            with patch.dict(gate.os.environ, GITHUB_EVENT_NAME=event):
                self.assertTrue(gate.decide("rust")[1])

    @patch.object(gate.subprocess, "run")
    @patch.object(gate.subprocess, "check_output")
    def test_main_reuses_pr_only_when_its_tested_base_and_inputs_match(self, output, run):
        prior = self.record(head_sha="tested", pull_requests=[{
            "number": 272, "base": {"ref": "main", "sha": "base"},
            "head": {"sha": "tested"},
        }])
        current = self.record(id=2, event="push", head_branch="main")
        output.return_value = tree(("crates/app/src/lib.rs", "tested-blob"))
        expected = gate.fingerprint("rust", output.return_value)
        run.return_value.returncode = 0
        self.assertTrue(gate.merged_pr_inputs_match(prior, current, "rust", expected))
        run.return_value.returncode = 1
        self.assertFalse(gate.merged_pr_inputs_match(prior, current, "rust", expected))
        run.return_value.returncode = 0
        self.assertFalse(gate.merged_pr_inputs_match(prior, current, "rust", "changed-inputs"))
        self.assertFalse(gate.merged_pr_inputs_match(prior, current, "security", expected))
        prior["head_repository"]["full_name"] = "untrusted/fork"
        self.assertFalse(gate.merged_pr_inputs_match(prior, current, "rust", expected))


if __name__ == "__main__":
    unittest.main()
