#!/usr/bin/env python3
"""Fail when concrete database, KV or object-storage adapters leak into business graphs.

Cargo is the only dependency-graph authority: this guard evaluates ``cargo tree``
output directly and does not re-parse manifests or re-run the package-role
validator owned by ``verify_static_contracts.py --check``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import verify_static_contracts as contracts

PACKAGE_ROLES = contracts.PACKAGE_ROLES
ALLOWED_DEPENDENCY_ROLES = contracts.ALLOWED_DEPENDENCY_ROLES


# Storage-technology isolation beyond what package roles express: inner roots
# must not transitively reach any concrete backend, and each storage adapter
# must not reach the other technology's adapter or driver.
GRAPHS = {
    "nazo-oauth-server": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "nazo-oauth-server-object-store",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-key-management": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-identity": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
        "fred",
        "nazo-valkey",
        "rust-s3",
        "aws-sdk-s3",
    ),
    "nazo-oauth-server-valkey": (
        "nazo-postgres",
        "diesel",
        "diesel-async",
        "pq-sys",
        "tokio-postgres",
    ),
    "nazo-oauth-server-postgres": (
        "fred",
        "nazo-valkey",
        "nazo-oauth-server-valkey",
    ),
}


def package_names(package: str, root: Path | None = None) -> set[str]:
    command = [
        "cargo",
        "tree",
        "--locked",
        "--all-features",
        "--package",
        package,
        "--edges",
        "normal,build",
        "--prefix",
        "none",
    ]
    result = subprocess.run(
        command, cwd=root or contracts.ROOT, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no cargo diagnostic"
        raise RuntimeError(f"cargo tree failed for {package}: {detail}")
    names: set[str] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)\s+v\d", line.strip())
        if match:
            names.add(match.group(1))
    return names


def graph_roots() -> set[str]:
    # Cover every inner (domain/application) root plus the storage adapters that
    # carry cross-technology gates.
    return set(GRAPHS) | {
        name for name, role in PACKAGE_ROLES.items() if role in {"domain", "application"}
    }


def forbidden_graph_dependencies(package: str) -> set[str]:
    role = PACKAGE_ROLES[package]
    return set(GRAPHS.get(package, ())) | {
        name
        for name, dependency_role in PACKAGE_ROLES.items()
        if dependency_role not in ALLOWED_DEPENDENCY_ROLES[role]
    }


def main() -> int:
    violations: list[str] = []
    for package in sorted(graph_roots()):
        try:
            names = package_names(package)
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 2
        leaked = sorted(forbidden_graph_dependencies(package) & names)
        if leaked:
            violations.append(f"{package}: {', '.join(leaked)}")
    if violations:
        print("persistence dependency isolation failed:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("database, transient-state and object-storage dependency isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
