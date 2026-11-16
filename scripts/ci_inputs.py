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
        "proptest-regressions/*", "clippy.toml", "rustfmt.toml", ".rustfmt.toml")
WORKFLOWS = {
    "rust": "code-quality.yml",
    "codeql": "codeql.yml",
    "security": "conformance-security.yml",
    "fuzz": "operator-fuzz.yml",
    "perf": "perf-images.yml",
}
INPUTS = {
    "rust": RUST + ("scripts/*.sh", "scripts/ci_build_jobs.py", ".github/workflows/codecov.yml", "codecov.yml",
                    "requirements/codecov.txt", "Containerfile", ".dockerignore", ".env.yaml.example"),
    "codeql": RUST + ("Containerfile", ".dockerignore"),
    # Image construction, HTTP fixtures and source-policy checks are one contract.
    "security": RUST + ("scripts/*", "deploy/*", "Containerfile", "Dockerfile",
                        ".dockerignore", "compose*.yml", ".env.yaml.example", "deny.toml",
                        ".github/e2e-*", "perf/env.yaml", "LICENSE*"),
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


def api(path: str) -> dict | list[dict]:
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def reusable(run: dict, current: dict, now: datetime, *, scope: str = "rust", merged_pr: bool = False) -> bool:
    if (run["id"] == current["id"] or run["workflow_id"] != current["workflow_id"]
            or run["status"] != "completed" or run["conclusion"] != "success"
            or run["head_repository"]["full_name"] != current["head_repository"]["full_name"]):
        return False
    # A same-repository PR may start from already tested main inputs. This also
    # avoids a full service rebuild for the first commit of a documentation PR.
    from_main = (current["event"] == "pull_request" and run["head_branch"] == "main"
                 and run["event"] in ("push", "workflow_dispatch"))
    if not merged_pr and not from_main and (run["event"] != current["event"] or run["head_branch"] != current["head_branch"]):
        return False
    if current["event"] == "pull_request" and not from_main:
        old_prs = {pr["number"] for pr in run["pull_requests"]}
        new_prs = {pr["number"] for pr in current["pull_requests"]}
        if not old_prs or old_prs != new_prs:
            return False
    created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    # Security scans depend on external advisory databases; ordinary deterministic
    # checks can use the full artifact retention window. Scheduled/manual runs
    # refresh tools/environments even when source inputs remain unchanged.
    lifetime = timedelta(days=1 if scope == "security" else 7)
    return timedelta(0) <= now - created < lifetime


def merged_pr_inputs_match(run: dict, current: dict, scope: str, expected: str) -> bool:
    """Transfer ordinary PR tests to main only when Git proves identical inputs.

    If the tested base was not already in the PR head, its synthetic merge could
    differ from that head. Run main tests in that case instead of guessing a merge.
    """
    if scope != "rust" or current["event"] != "push" or current["head_branch"] != "main" or run["event"] != "pull_request":
        return False
    if run["head_repository"]["full_name"] != current["head_repository"]["full_name"]:
        return False
    # Actions drops run.pull_requests after merge. The commit association keeps
    # the merged PR's original head/base, including after a squash merge.
    repo = current["head_repository"]["full_name"]
    for pr in api(f"repos/{repo}/commits/{run['head_sha']}/pulls?per_page=100"):
        if (not pr["merged_at"] or pr["base"]["ref"] != "main"
                or pr["base"]["repo"]["full_name"] != repo
                or pr["head"]["repo"]["full_name"] != repo
                or pr["head"]["sha"] != run["head_sha"]):
            continue
        head, base = run["head_sha"], pr["base"]["sha"]
        subprocess.run(["git", "fetch", "--no-tags", "origin", head, base], check=True,
                       stdout=subprocess.DEVNULL)
        ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", base, head])
        if ancestor.returncode == 1:
            continue
        ancestor.check_returncode()
        prior = subprocess.check_output(["git", "ls-tree", "-r", "-z", head])
        if fingerprint(scope, prior) == expected:
            return True
    return False


def decide(scope: str) -> tuple[str, bool, str]:
    tree = subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"])
    digest = fingerprint(scope, tree)
    name = f"ci-inputs-{scope}-{digest}"
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
        if reusable(run, current, now, scope=scope) or (
            reusable(run, current, now, scope=scope, merged_pr=True)
            and merged_pr_inputs_match(run, current, scope, digest)
        ):
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
