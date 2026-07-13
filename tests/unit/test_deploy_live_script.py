import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "deploy_live.ps1"


class DeployLiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_exact_commits_are_mandatory_and_used_in_release_paths(self) -> None:
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\]\$BackendCommit",
        )
        self.assertRegex(
            self.source,
            r"\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\]\$FrontendCommit",
        )
        self.assertIn("ui-releases", self.source)
        self.assertIn("FrontendCommit", self.source)

    def test_remote_transaction_records_and_restores_both_targets(self) -> None:
        for marker in (
            "previous_image",
            "previous_container_id",
            "previous_ui_target",
            "candidate_image",
            "backend_commit",
            "frontend_commit",
            "rollback",
        ):
            self.assertIn(marker, self.source)
        self.assertRegex(self.source, r"trap\s+['\"]?rollback")

    def test_ui_switch_is_atomic_and_active_tree_is_never_deleted(self) -> None:
        self.assertNotRegex(
            self.source,
            re.compile(r"find\s+['\"]?`?\$UI_PATH.*-exec\s+rm\s+-rf", re.IGNORECASE),
        )
        self.assertIn("mv -T", self.source)
        self.assertIn("ln -s", self.source)

    def test_candidate_is_verified_before_success_is_recorded(self) -> None:
        health = self.source.index("/health")
        issuer = self.source.index("ExpectedIssuer")
        record = self.source.index("deployment-success")
        self.assertLess(health, record)
        self.assertLess(issuer, record)

    def test_rendered_remote_transaction_is_valid_bash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ui = root / "ui"
            ui.mkdir()
            (ui / "index.html").write_text("ok", encoding="utf-8")
            rendered = root / "deploy.sh"
            completed = subprocess.run(
                [
                    "pwsh",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(SCRIPT),
                    "-RemoteHost",
                    "render-only",
                    "-BackendCommit",
                    "1" * 40,
                    "-FrontendCommit",
                    "2" * 40,
                    "-LocalUiDist",
                    str(ui),
                    "-RenderRemoteScriptPath",
                    str(rendered),
                    "-SkipBuild",
                    "-SkipMigrate",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            bash = str(git_bash) if git_bash.exists() else "bash"
            syntax = subprocess.run(
                [bash, "-n", str(rendered)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
                check=False,
            )

        self.assertEqual(syntax.returncode, 0, syntax.stderr)


if __name__ == "__main__":
    unittest.main()
