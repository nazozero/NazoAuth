import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "deploy_live.ps1"


def init_repo(path: Path, files: dict[str, str]) -> str:
    path.mkdir()
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "deploy-test@example.invalid"],
        ["git", "config", "user.name", "Deploy Test"],
        ["git", "add", "."],
        ["git", "commit", "-qm", "fixture"],
    ):
        subprocess.run(command, cwd=path, check=True, capture_output=True)
    if path.name == "frontend":
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/nazozero/NazoAuthWeb"],
            cwd=path, check=True, capture_output=True,
        )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def write_frontend_manifest(dist: Path, commit: str) -> None:
    entries = []
    for path in sorted(item for item in dist.rglob("*") if item.is_file()):
        if path.name == ".nazo-build.json":
            continue
        relative = path.relative_to(dist).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(f"{relative}\t{digest}\n")
    artifact_digest = hashlib.sha256("".join(entries).encode()).hexdigest()
    (dist / ".nazo-build.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "source_commit": commit,
                "artifact_sha256": artifact_digest,
            }
        ),
        encoding="utf-8",
    )


def git_bash() -> str:
    candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
    return str(candidate) if candidate.exists() else "bash"


def bash_path(path: Path) -> str:
    completed = subprocess.run(
        [git_bash(), "-lc", 'cygpath -u "$1"', "_", str(path)],
        capture_output=True, text=True, check=True,
    )
    return completed.stdout.strip()


def render_fixture(root: Path, extra_arguments: list[str] | None = None) -> Path:
    backend = root / "backend"
    frontend = root / "frontend"
    backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
    frontend_commit = init_repo(frontend, {".gitignore": "dist/\n"})
    ui = frontend / "dist"
    ui.mkdir()
    (ui / "index.html").write_text("ok", encoding="utf-8")
    write_frontend_manifest(ui, frontend_commit)
    rendered = root / "deploy.sh"
    command = [
        "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
        "-RemoteHost", "render-only",
        "-BackendCommit", backend_commit,
        "-FrontendCommit", frontend_commit,
        "-LocalBackendWorktree", str(backend),
        "-LocalFrontendWorktree", str(frontend),
        "-LocalUiDist", str(ui),
        "-RenderRemoteScriptPath", str(rendered),
        "-SkipBuild", "-SkipFrontendBuild", "-SkipMigrate",
    ]
    command.extend(extra_arguments or [])
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, errors="replace",
        timeout=20, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return rendered


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

    def test_source_commits_are_bound_to_clean_worktrees_and_frontend_manifest(self) -> None:
        self.assertIn("Unable to discover sibling NazoAuthWeb repository", self.source)
        self.assertIn("remote\", \"get-url\", \"origin", self.source)
        self.assertIn("branch\", \"--show-current", self.source)
        self.assertIn("status --porcelain=v1", self.source)
        self.assertIn("Get-FileHash", self.source)
        self.assertIn(".nazo-build.json", self.source)
        self.assertIn("source_commit", self.source)
        self.assertIn("artifact_sha256", self.source)
        self.assertIn('"run", "build"', self.source)
        self.assertIn('"archive", "--format=tar"', self.source)
        self.assertIn('Join-Path $backendBuildContext "Containerfile"', self.source)
        self.assertIn('$backendBuildContext', self.source)

    def test_prebuilt_artifacts_are_not_accepted_for_a_real_deployment(self) -> None:
        self.assertIn("SkipBuild is only allowed when rendering", self.source)
        self.assertIn("SkipFrontendBuild is only allowed when rendering", self.source)
        self.assertIn("EXPECTED_IMAGE_ID", self.source)
        self.assertIn('test "`$actual_image_id" = "`$EXPECTED_IMAGE_ID"', self.source)

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

    def test_rollback_uses_the_previous_immutable_image_id(self) -> None:
        self.assertIn("previous_image_id", self.source)
        self.assertIn("--format '{{.Image}}'", self.source)
        self.assertIn('run_server "`$previous_image_id"', self.source)
        self.assertIn('podman image exists "`$previous_image_id"', self.source)
        self.assertNotIn('run_server "`$previous_image"', self.source)

    def test_verification_lease_is_atomically_claimed_by_commit_or_rollback(self) -> None:
        self.assertIn("VerificationLeaseSeconds", self.source)
        self.assertIn("LEASE_PENDING", self.source)
        self.assertIn("LEASE_COMMITTED", self.source)
        self.assertIn("LEASE_ROLLBACK", self.source)
        self.assertRegex(self.source, r'mv\s+"`\$LEASE_PENDING"\s+"`\$LEASE_COMMITTED"')
        self.assertIn("expire)", self.source)
        self.assertIn("nohup", self.source)
        self.assertIn("rollbackIfPresent", self.source)
        deploy_body = self.source[self.source.index("deploy() {") :]
        self.assertLess(
            deploy_body.index("start_verification_lease"),
            deploy_body.index('podman rm -f "`$CONTAINER_NAME"'),
        )

    def test_deployment_records_are_unique_and_current_switch_is_atomic(self) -> None:
        self.assertIn("DEPLOYMENT_ID", self.source)
        self.assertRegex(
            self.source,
            r'RECORD="`\$DEPLOYMENTS/`\$BACKEND_COMMIT-`\$FRONTEND_COMMIT-`\$DEPLOYMENT_ID\.json"',
        )
        self.assertIn("CURRENT_LINK_TEMP", self.source)
        self.assertRegex(self.source, r'mv\s+-T\s+"`\$CURRENT_LINK_TEMP"\s+"`\$DEPLOYMENTS/current\.json"')

    def test_existing_network_subnet_and_gateway_are_exactly_validated(self) -> None:
        self.assertIn("podman network inspect", self.source)
        self.assertIn("NETWORK_SUBNET", self.source)
        self.assertIn("NETWORK_GATEWAY", self.source)
        self.assertIn("unexpected subnet or gateway", self.source)
        self.assertIn("pairs == {expected}", self.source)

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
            rendered = render_fixture(root)
            syntax = subprocess.run(
                [git_bash(), "-n", str(rendered)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
                check=False,
            )

        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_frontend_sibling_is_discovered_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backend = root / "NazoAuth"
            frontend = root / "NazoAuthWeb"
            backend_commit = init_repo(backend, {"Containerfile": "FROM scratch\n"})
            frontend_commit = init_repo(frontend, {".gitignore": "dist/\n"})
            subprocess.run(
                ["git", "remote", "add", "origin", "https://github.com/nazozero/NazoAuthWeb"],
                cwd=frontend, check=True, capture_output=True,
            )
            ui = frontend / "dist"
            ui.mkdir()
            (ui / "index.html").write_text("ok", encoding="utf-8")
            rendered = root / "deploy.sh"
            completed = subprocess.run(
                [
                    "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
                    "-RemoteHost", "render-only",
                    "-BackendCommit", backend_commit,
                    "-FrontendCommit", frontend_commit,
                    "-LocalBackendWorktree", str(backend),
                    "-LocalUiDist", str(ui),
                    "-RenderRemoteScriptPath", str(rendered),
                    "-SkipBuild", "-SkipFrontendBuild", "-SkipMigrate",
                ],
                cwd=ROOT, capture_output=True, text=True, errors="replace",
                timeout=20, check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rendered_network_validation_rejects_additional_fake_subnets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment = root / "remote-deployment"
            keys = deployment / "runtime" / "keys"
            avatars = deployment / "runtime" / "avatars"
            keys.mkdir(parents=True)
            avatars.mkdir(parents=True)
            config = deployment / ".env.yaml"
            config.write_text("server: {}\n", encoding="utf-8")
            remote_temp = root / "remote-temp"
            remote_temp.mkdir()
            rendered = render_fixture(
                root,
                [
                    "-RenderRemoteTempDir", bash_path(remote_temp),
                    "-RemoteDeploymentRoot", bash_path(deployment),
                    "-RemoteConfigPath", bash_path(config),
                    "-RemoteKeysPath", bash_path(keys),
                    "-RemoteAvatarsPath", bash_path(avatars),
                    "-RemoteUiPath", bash_path(deployment / "ui"),
                ],
            )
            shell = r'''
podman() {
  if [ "$1 $2" = "network exists" ]; then return 0; fi
  if [ "$1 $2" = "network inspect" ]; then printf '%s\n' "$FAKE_NETWORK_JSON"; return 0; fi
  if [ "$1" = "run" ]; then return 0; fi
  if [ "$1" = "exec" ]; then printf 'PONG\n'; return 0; fi
  return 0
}
flock() { return 0; }
export -f podman flock
bash "$1" deploy
'''
            def execute(layout: dict) -> subprocess.CompletedProcess[str]:
                environment = os.environ.copy()
                environment["FAKE_NETWORK_JSON"] = json.dumps([layout])
                return subprocess.run(
                    [git_bash(), "-c", shell, "_", bash_path(rendered)],
                    capture_output=True, text=True, errors="replace", timeout=10,
                    check=False, env=environment,
                )

            exact = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24", "gateway": "10.101.0.1"},
                ]}
            )
            completed = execute(
                {"subnets": [
                    {"subnet": "10.101.0.0/24", "gateway": "10.101.0.1"},
                    {"subnet": "fd00::/64", "gateway": "fd00::1"},
                ]}
            )

        self.assertNotEqual(exact.returncode, 0)
        self.assertNotIn("unexpected subnet or gateway", exact.stdout + exact.stderr)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unexpected subnet or gateway", completed.stdout + completed.stderr)
        self.assertFalse((deployment / "deployments" / "active-deployment").exists())


if __name__ == "__main__":
    unittest.main()
