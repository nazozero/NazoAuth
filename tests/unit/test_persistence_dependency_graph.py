from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "persistence_graph_guard", ROOT / "scripts" / "check_persistence_dependency_graph.py"
)
GRAPH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GRAPH)


class PersistenceGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        root_patch = mock.patch.object(GRAPH.contracts, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        (self.root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")

    def package(self, folder: str, name: str, dependency_text: str = "", dependencies=()) -> dict:
        path = self.root / "crates" / folder / "Cargo.toml"
        path.parent.mkdir(parents=True)
        path.write_text(
            f'[package]\nname = "{name}"\nversion = "0.0.0"\n' + dependency_text,
            encoding="utf-8",
        )
        return {"id": name, "name": name, "manifest_path": str(path), "dependencies": list(dependencies)}

    def dependency(self, name: str, *, folder=None, rename=None, kind=None, target=None, optional=False) -> dict:
        return {
            "name": name, "rename": rename, "kind": kind, "target": target,
            "optional": optional,
            "path": str(self.root / "crates" / folder) if folder else None,
        }

    @staticmethod
    def metadata(*packages) -> dict:
        return {"workspace_members": [p["id"] for p in packages], "packages": list(packages)}

    def test_uses_the_single_role_registry_and_covers_every_inner_graph(self) -> None:
        self.assertIs(GRAPH.PACKAGE_ROLES, GRAPH.contracts.PACKAGE_ROLES)
        self.assertIs(GRAPH.ALLOWED_DEPENDENCY_ROLES, GRAPH.contracts.ALLOWED_DEPENDENCY_ROLES)
        for package, role in GRAPH.PACKAGE_ROLES.items():
            if role in {"domain", "application"}:
                self.assertIn(package, GRAPH.graph_roots())
        self.assertIn("nazo-oauth-server-postgres", GRAPH.graph_roots())
        self.assertIn("nazo-oauth-server-valkey", GRAPH.graph_roots())

    def test_original_storage_technology_isolation_is_not_relaxed(self) -> None:
        for package in ("nazo-oauth-server", "nazo-key-management", "nazo-identity"):
            forbidden = GRAPH.forbidden_graph_dependencies(package)
            for dependency in ("nazo-postgres", "diesel", "diesel-async", "pq-sys", "tokio-postgres", "fred", "nazo-valkey", "rust-s3", "aws-sdk-s3"):
                self.assertIn(dependency, forbidden)
        self.assertIn("nazo-oauth-server-object-store", GRAPH.forbidden_graph_dependencies("nazo-oauth-server"))
        self.assertIn("nazo-postgres", GRAPH.forbidden_graph_dependencies("nazo-oauth-server-valkey"))
        self.assertIn("fred", GRAPH.forbidden_graph_dependencies("nazo-oauth-server-postgres"))
        self.assertIn("nazo-oauth-server", GRAPH.forbidden_graph_dependencies("nazo-auth"))
        self.assertNotIn("tokio", GRAPH.forbidden_graph_dependencies("nazo-auth"))

    def test_metadata_accepts_workspace_alias_to_canonical_domain_package(self) -> None:
        (self.root / "Cargo.toml").write_text(
            '[workspace]\n[workspace.dependencies]\nsemantic = { package = "nazo-auth", path = "crates/core" }\n',
            encoding="utf-8",
        )
        core = self.package("core", "nazo-auth")
        app = self.package(
            "app", "nazo-oauth-server", '[dependencies]\nsemantic = { workspace = true }\n',
            [self.dependency("nazo-auth", folder="core", rename="semantic")],
        )
        self.assertEqual(GRAPH.metadata_dependency_violations(self.metadata(app, core), self.root), [])

    def test_metadata_rejects_optional_target_build_alias_to_host(self) -> None:
        host = self.package("native", "nazoauth")
        app = self.package(
            "app", "nazo-oauth-server",
            '[target.\'cfg(windows)\'.build-dependencies]\nexecutor = { package = "nazoauth", path = "../native", optional = true }\n',
            [self.dependency("nazoauth", folder="native", rename="executor", kind="build", target="cfg(windows)", optional=True)],
        )
        violations = GRAPH.metadata_dependency_violations(self.metadata(app, host), self.root)
        self.assertTrue(any("nazo-oauth-server (application) -> nazoauth (host)" in v for v in violations), violations)
        self.assertFalse(any("differ from manifest" in v for v in violations), violations)

    def test_metadata_cannot_hide_local_adapter_behind_another_package_name(self) -> None:
        adapter = self.package("adapter", "nazo-http-actix")
        app = self.package(
            "app", "nazo-oauth-server", '[dependencies]\nwire = { package = "nazo-http-actix", path = "../adapter" }\n',
            [self.dependency("nazo-auth", folder="adapter", rename="wire")],
        )
        violations = GRAPH.metadata_dependency_violations(self.metadata(app, adapter), self.root)
        self.assertTrue(any("differs from local package nazo-http-actix" in v for v in violations), violations)
        self.assertTrue(any("nazo-http-actix (adapter)" in v for v in violations), violations)

    def test_metadata_detects_omitted_or_changed_optional_target_edge(self) -> None:
        core = self.package("core", "nazo-auth")
        app = self.package(
            "app", "nazo-oauth-server",
            '[target.\'cfg(unix)\'.dependencies]\nsemantic = { package = "nazo-auth", path = "../core", optional = true }\n',
            [self.dependency("nazo-auth", folder="core", rename="semantic", target="cfg(unix)", optional=False)],
        )
        self.assertTrue(any("production edges differ" in v for v in GRAPH.metadata_dependency_violations(self.metadata(app, core), self.root)))
        app["dependencies"] = []
        self.assertTrue(any("production edges differ" in v for v in GRAPH.metadata_dependency_violations(self.metadata(app, core), self.root)))

    def test_metadata_ignores_dev_edges_but_requires_all_workspace_manifests(self) -> None:
        host = self.package("native", "nazoauth")
        app = self.package(
            "app", "nazo-oauth-server", '[dev-dependencies]\nnazoauth = { path = "../native" }\n',
            [self.dependency("nazoauth", folder="native", kind="dev")],
        )
        self.assertEqual(GRAPH.metadata_dependency_violations(self.metadata(app, host), self.root), [])
        self.assertTrue(any("canonical crate set" in v for v in GRAPH.metadata_dependency_violations(self.metadata(app), self.root)))

    def test_tree_uses_locked_normal_and_build_edges_and_keeps_names(self) -> None:
        output = "nazo-auth v1.0.0 (local)\nnazoauth v1.0.0 (local)\ndiesel v2.3.0 (*)\n"
        with mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            self.assertEqual(GRAPH.package_names("nazo-auth", self.root), {"nazo-auth", "nazoauth", "diesel"})
        self.assertEqual(run.call_args.args[0], ["cargo", "tree", "--locked", "--package", "nazo-auth", "--edges", "normal,build", "--prefix", "none"])
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)

    def test_tree_failure_is_not_treated_as_an_empty_valid_graph(self) -> None:
        with mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "lockfile changed")):
            with self.assertRaisesRegex(RuntimeError, "lockfile changed"):
                GRAPH.package_names("nazo-auth", self.root)

    def test_main_reports_transitive_host_leak_from_actual_tree(self) -> None:
        core = self.package("core", "nazo-auth")
        app = self.package("app", "nazo-oauth-server")
        metadata = json.dumps(self.metadata(app, core))
        diagnostic = io.StringIO()
        with (
            mock.patch.object(GRAPH.contracts, "ROOT", self.root),
            mock.patch.object(GRAPH.contracts, "check_package_roles"),
            mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, metadata, "")),
            mock.patch.object(GRAPH, "graph_roots", return_value={"nazo-oauth-server"}),
            mock.patch.object(GRAPH, "package_names", return_value={"nazo-oauth-server", "nazoauth"}),
            contextlib.redirect_stderr(diagnostic),
        ):
            self.assertEqual(GRAPH.main(), 1)
        self.assertIn("nazo-oauth-server: nazoauth", diagnostic.getvalue())

    def test_main_checks_metadata_before_trees_without_unlocked_fallback(self) -> None:
        with (
            mock.patch.object(GRAPH.contracts, "check_package_roles"),
            mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "metadata unavailable")) as run,
            mock.patch.object(GRAPH, "package_names") as tree,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(GRAPH.main(), 2)
        self.assertEqual(run.call_args.args[0], ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"])
        tree.assert_not_called()


if __name__ == "__main__":
    unittest.main()
