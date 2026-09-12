#!/usr/bin/env python3
"""Fail when concrete database, KV or object-storage adapters leak into business graphs."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

import verify_static_contracts as contracts

PACKAGE_ROLES = contracts.PACKAGE_ROLES
ALLOWED_DEPENDENCY_ROLES = contracts.ALLOWED_DEPENDENCY_ROLES


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


def metadata_dependency_violations(metadata: dict, root: Path) -> list[str]:
    """Cross-check Cargo's canonical normal/build edges against the shared manifest resolver."""
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    members = set(metadata["workspace_members"])
    violations: list[str] = []
    manifest_paths = set(root.joinpath("crates").glob("*/Cargo.toml"))
    metadata_paths: set[Path] = set()
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        name = package["name"]
        manifest_path = Path(package["manifest_path"]).resolve()
        metadata_paths.add(manifest_path)
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["package"]["name"] != name:
            violations.append(f"{manifest_path}: metadata package name differs from manifest")
        role = PACKAGE_ROLES.get(name)
        if role is None:
            violations.append(f"{name}: workspace package has no architectural role")
            continue
        expected = Counter(
            (
                dependency,
                spec["_alias"],
                spec["_kind"],
                spec["_target"],
                bool(spec.get("optional", False)),
                Path(spec["_path"]).resolve() if spec["_path"] is not None else None,
            )
            for dependency, spec in contracts.resolved_production_dependencies(
                manifest_path, workspace
            )
        )
        actual: Counter = Counter()
        for dependency in package["dependencies"]:
            kind = dependency["kind"] or "normal"
            if kind == "dev":
                continue
            dependency_name = dependency["name"]
            local_path = dependency.get("path")
            if local_path is not None:
                local_path = str(Path(local_path).resolve())
                local_manifest = tomllib.loads(
                    (Path(local_path) / "Cargo.toml").read_text(encoding="utf-8")
                )
                canonical_name = local_manifest["package"]["name"]
                if canonical_name != dependency_name:
                    violations.append(
                        f"{name}: metadata dependency {dependency_name} differs from local package {canonical_name}"
                    )
                dependency_name = canonical_name
            actual[(
                dependency_name,
                dependency.get("rename") or dependency["name"],
                kind,
                dependency.get("target"),
                bool(dependency.get("optional", False)),
                Path(local_path) if local_path is not None else None,
            )] += 1
            dependency_role = PACKAGE_ROLES.get(dependency_name)
            if local_path is not None and dependency_role is None:
                violations.append(f"{name}: local dependency {dependency_name} has no architectural role")
            elif dependency_role and dependency_role not in ALLOWED_DEPENDENCY_ROLES[role]:
                violations.append(f"{name} ({role}) -> {dependency_name} ({dependency_role})")
        if expected != actual:
            violations.append(
                f"{name}: Cargo metadata production edges differ from manifest "
                f"(missing={list((expected - actual).elements())}, "
                f"unexpected={list((actual - expected).elements())})"
            )
    expected_paths = {path.resolve() for path in manifest_paths}
    if expected_paths != metadata_paths:
        violations.append("Cargo metadata workspace package manifests differ from the canonical crate set")
    return violations


def graph_roots() -> set[str]:
    # Preserve storage-adapter cross-technology gates and cover every inner root.
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
    contracts.check_package_roles()
    metadata = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        cwd=contracts.ROOT, check=False, capture_output=True, text=True,
    )
    if metadata.returncode:
        print(metadata.stderr.strip() or metadata.stdout.strip() or "cargo metadata failed", file=sys.stderr)
        return 2
    try:
        violations.extend(metadata_dependency_violations(json.loads(metadata.stdout), contracts.ROOT))
    except (KeyError, OSError, ValueError) as error:
        print(f"Cargo metadata/manifest validation failed: {error}", file=sys.stderr)
        return 2
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
