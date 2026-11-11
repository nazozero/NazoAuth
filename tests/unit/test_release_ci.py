from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import check_release_ci as gate


class ReleaseCiTests(unittest.TestCase):
    def run_record(self, **changes):
        return dict(head_branch="main", event="push", status="completed",
                    conclusion="success", head_sha="tested", **changes)

    def test_exact_commit_accepts_push_and_manual_checks(self):
        for event in ("push", "workflow_dispatch"):
            run = self.run_record()
            run["event"] = event
            self.assertTrue(gate.acceptable(run, "tested"))

    def test_untrusted_or_unsuccessful_checks_are_rejected(self):
        for key, value in (("head_branch", "feature"), ("event", "pull_request"),
                           ("status", "in_progress"), ("conclusion", "failure"),
                           ("conclusion", "cancelled")):
            run = self.run_record()
            run[key] = value
            self.assertFalse(gate.acceptable(run, "tested"))

    @patch.dict(gate.os.environ, RELEASE_SHA="tested", GITHUB_REPOSITORY="example/repo")
    @patch.object(gate, "is_ancestor", return_value=True)
    def test_missing_conformance_evidence_blocks_release(self, _ancestor):
        def workflow_runs(args, **_kwargs):
            runs = [] if "conformance-security.yml/runs" in args[4] else [self.run_record(id=1)]
            return gate.json.dumps({"workflow_runs": runs})

        with patch.object(gate.subprocess, "check_output", side_effect=workflow_runs):
            with self.assertRaisesRegex(SystemExit, "conformance-security"):
                gate.main()

    @patch.object(gate, "git")
    @patch.object(gate, "is_ancestor", return_value=True)
    def test_only_documentation_changes_can_reuse_ancestor(self, ancestor, git):
        for paths, expected in (
            ("README.md\0docs/project/testing.md\0", True),
            ("NazoAuth-Web-Runtime-Refactor-Task-Package/MANIFEST.json\0", True),
            ("crates/server/src/lib.rs\0", False),
            ("Cargo.lock\0", False),
            (".github/workflows/code-quality.yml\0", False),
            ("scripts/build.sh\0", False),
            ("Containerfile\0", False),
            ("docs/old.md\0crates/new.rs\0", False),
        ):
            with self.subTest(paths=paths):
                git.return_value = paths
                self.assertEqual(gate.acceptable(self.run_record(), "release"), expected)

    @patch.object(gate, "is_ancestor", return_value=False)
    def test_unrelated_or_newer_commit_is_rejected(self, ancestor):
        self.assertFalse(gate.acceptable(self.run_record(), "release"))

    @patch.object(gate, "is_ancestor", side_effect=RuntimeError("git failed"))
    def test_git_errors_do_not_allow_release(self, ancestor):
        with self.assertRaises(RuntimeError):
            gate.acceptable(self.run_record(), "release")


if __name__ == "__main__":
    unittest.main()
