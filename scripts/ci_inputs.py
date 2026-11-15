"""Reuse successful checks only for identical inputs in the same trust context."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


RUST = ("Cargo.*", "rust-toolchain*", "build.rs", ".cargo/*", "crates/*",
        "src/*", "tests/*", "fuzz/*", "benches/*", "examples/*", "migrations/*",
        "proptest-regressions/*")
WORKFLOWS = {
    "rust": "code-quality.yml",
    "codeql": "codeql.yml",
    "security": "conformance-security.yml",
    "fuzz": "operator-fuzz.yml",
    "perf": "perf-images.yml",
}
INPUTS = {
    "rust": RUST + ("scripts/*.sh", ".github/workflows/codecov.yml", "codecov.yml",
                    "requirements/codecov.txt", "Containerfile", ".env.yaml.example"),
    "codeql": RUST + ("Containerfile", ".dockerignore"),
    # Image construction, HTTP fixtures and source-policy checks are one contract.
    "security": RUST + ("scripts/*", "deploy/*", "Containerfile", "Dockerfile",
                        ".dockerignore", "compose*.yml", ".env.yaml.example", "deny.toml",
                        ".github/e2e-*"),
    "fuzz": ("Cargo.*", "rust-toolchain*", ".cargo/*", "crates/crypto/*",
             "crates/operator-protocol/*", "fuzz/*"),
    "perf": ("perf/*", ".dockerignore"),
}


def fingerprint(scope: str, tree: bytes) -> str:
    patterns = INPUTS[scope] + (
        f".github/workflows/{WORKFLOWS[scope]}", ".github/workflows/ci-inputs.yml",
        "scripts/ci_inputs.py", "tests/unit/test_ci_inputs.py",
    )
    records = []
    for entry in tree.split(b"\0"):
        if entry:
            path = entry.split(b"\t", 1)[1].decode("utf-8")
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
                records.append(entry)
    # ls-tree records include path, mode and object ID, covering deletions,
    # renames, executable-bit changes and the actual PR merge tree.
    return hashlib.sha256(b"\0".join(records)).hexdigest()


def api(path: str) -> dict:
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def reusable(run: dict, current: dict, now: datetime) -> bool:
    if (run["id"] == current["id"] or run["workflow_id"] != current["workflow_id"]
            or run["status"] != "completed" or run["conclusion"] != "success"
            or run["head_repository"]["full_name"] != current["head_repository"]["full_name"]):
        return False
    # Do not transfer untrusted PR evidence into main/release, or between PRs.
    if run["event"] != current["event"] or run["head_branch"] != current["head_branch"]:
        return False
    if current["event"] == "pull_request":
        old_prs = {pr["number"] for pr in run["pull_requests"]}
        new_prs = {pr["number"] for pr in current["pull_requests"]}
        if not old_prs or old_prs != new_prs:
            return False
    created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    # External advisory databases and runner images can change with identical
    # source inputs. Manual/scheduled checks always run; automatic reuse is daily.
    return timedelta(0) <= now - created < timedelta(days=1)


def decide(scope: str) -> tuple[str, bool, str]:
    tree = subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"])
    name = f"ci-inputs-{scope}-{fingerprint(scope, tree)}"
    if os.environ["GITHUB_EVENT_NAME"] not in ("push", "pull_request"):
        return name, True, "Manual/scheduled check: execute all selected checks."
    repo = os.environ["GITHUB_REPOSITORY"]
    current = api(f"repos/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    artifacts = api(f"repos/{repo}/actions/artifacts?name={name}&per_page=100")
    now = datetime.now(timezone.utc)
    for artifact in artifacts["artifacts"]:
        if artifact["expired"] or artifact["name"] != name:
            continue
        run = api(f"repos/{repo}/actions/runs/{artifact['workflow_run']['id']}")
        if reusable(run, current, now):
            return name, False, f"Identical {scope} inputs passed: {run['html_url']}"
    return name, True, f"No successful run with identical {scope} inputs: execute checks."


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", choices=WORKFLOWS)
    args = parser.parse_args()
    try:
        name, execute, reason = decide(args.scope)
    except (subprocess.CalledProcessError, KeyError, TypeError, ValueError) as error:
        # A missing/unreadable prior result is never permission to omit a check.
        name, execute, reason = "", True, f"Cannot establish reusable evidence ({type(error).__name__}); execute checks."
    print(reason)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"run={str(execute).lower()}\nartifact={name}\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(reason + "\n")
    evidence = Path("target/ci-inputs/evidence.txt")
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(reason + "\n")


if __name__ == "__main__":
    main()
