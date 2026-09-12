"""Accept governed CI for the release commit or a documentation-only ancestor."""

from __future__ import annotations

import json
import os
import subprocess


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def is_ancestor(base: str, head: str) -> bool:
    result = subprocess.run(["git", "merge-base", "--is-ancestor", base, head])
    if result.returncode not in (0, 1):
        result.check_returncode()
    return result.returncode == 0


def documentation_only(paths: list[str]) -> bool:
    return all(
        path.startswith(("docs/", "NazoAuth-Web-Runtime-Refactor-Task-Package/"))
        or ("/" not in path and path.endswith(".md"))
        for path in paths
    )


def acceptable(run: dict, release_sha: str) -> bool:
    if (
        run.get("head_branch") != "main"
        or run.get("event") not in ("push", "workflow_dispatch")
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        return False
    sha = run["head_sha"]
    if sha == release_sha:
        return True
    if not is_ancestor(sha, release_sha):
        return False
    paths = git("diff", "--name-only", "--no-renames", "-z", sha, release_sha).split("\0")
    return documentation_only([path for path in paths if path])


def main() -> None:
    release_sha = os.environ["RELEASE_SHA"]
    if not is_ancestor(release_sha, "refs/remotes/origin/main"):
        raise SystemExit("release commit is not reachable from main")
    for workflow in ("code-quality.yml", "release-policy.yml"):
        # Search the latest 100 runs; older evidence is not needed for normal releases.
        response = subprocess.check_output([
            "gh", "api", "--method", "GET",
            f"/repos/{os.environ['GITHUB_REPOSITORY']}/actions/workflows/{workflow}/runs",
            "-f", "branch=main", "-F", "per_page=100",
        ], text=True)
        for run in json.loads(response)["workflow_runs"]:
            if acceptable(run, release_sha):
                print(f"{workflow}: accepted {run['event']} run {run['id']} at {run['head_sha']}")
                break
        else:
            raise SystemExit(f"{workflow}: no successful governed CI for release inputs")


if __name__ == "__main__":
    main()
