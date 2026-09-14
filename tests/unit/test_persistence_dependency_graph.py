from __future__ import annotations

import contextlib
import importlib.util
import io
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

    def test_uses_the_single_role_registry_and_covers_every_inner_graph(self) -> None:
        self.assertIs(GRAPH.PACKAGE_ROLES, GRAPH.contracts.PACKAGE_ROLES)
        self.assertIs(GRAPH.ALLOWED_DEPENDENCY_ROLES, GRAPH.contracts.ALLOWED_DEPENDENCY_ROLES)
        for package, role in GRAPH.PACKAGE_ROLES.items():
            if role in {"domain", "application"}:
                self.assertIn(package, GRAPH.graph_roots())
        self.assertIn("nazo-oauth-server-postgres", GRAPH.graph_roots())
        self.assertIn("nazo-oauth-server-valkey", GRAPH.graph_roots())

    def test_storage_technology_isolation_is_not_relaxed(self) -> None:
        for package in ("nazo-oauth-server", "nazo-key-management", "nazo-identity"):
            forbidden = GRAPH.forbidden_graph_dependencies(package)
            for dependency in ("nazo-postgres", "diesel", "diesel-async", "pq-sys", "tokio-postgres", "fred", "nazo-valkey", "rust-s3", "aws-sdk-s3"):
                self.assertIn(dependency, forbidden)
        self.assertIn("nazo-oauth-server-object-store", GRAPH.forbidden_graph_dependencies("nazo-oauth-server"))
        self.assertIn("nazo-postgres", GRAPH.forbidden_graph_dependencies("nazo-oauth-server-valkey"))
        self.assertIn("fred", GRAPH.forbidden_graph_dependencies("nazo-oauth-server-postgres"))
        self.assertIn("nazo-oauth-server", GRAPH.forbidden_graph_dependencies("nazo-auth"))
        self.assertNotIn("tokio", GRAPH.forbidden_graph_dependencies("nazo-auth"))

    def test_tree_uses_locked_normal_and_build_edges_and_keeps_names(self) -> None:
        output = "nazo-auth v1.0.0 (local)\nnazoauth v1.0.0 (local)\ndiesel v2.3.0 (*)\n"
        with mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
            self.assertEqual(GRAPH.package_names("nazo-auth", self.root), {"nazo-auth", "nazoauth", "diesel"})
        self.assertEqual(run.call_args.args[0], ["cargo", "tree", "--locked", "--all-features", "--package", "nazo-auth", "--edges", "normal,build", "--prefix", "none"])
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)

    def test_tree_failure_is_not_treated_as_an_empty_valid_graph(self) -> None:
        with mock.patch.object(GRAPH.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "lockfile changed")):
            with self.assertRaisesRegex(RuntimeError, "lockfile changed"):
                GRAPH.package_names("nazo-auth", self.root)

    def test_main_reports_transitive_host_leak_from_actual_tree(self) -> None:
        diagnostic = io.StringIO()
        with (
            mock.patch.object(GRAPH, "graph_roots", return_value={"nazo-oauth-server"}),
            mock.patch.object(GRAPH, "package_names", return_value={"nazo-oauth-server", "nazoauth"}),
            contextlib.redirect_stderr(diagnostic),
        ):
            self.assertEqual(GRAPH.main(), 1)
        self.assertIn("nazo-oauth-server: nazoauth", diagnostic.getvalue())

    def test_main_fails_closed_when_tree_fails(self) -> None:
        with (
            mock.patch.object(GRAPH, "graph_roots", return_value={"nazo-oauth-server"}),
            mock.patch.object(GRAPH, "package_names", side_effect=RuntimeError("metadata unavailable")),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(GRAPH.main(), 2)

    def test_clean_graph_passes(self) -> None:
        with (
            mock.patch.object(GRAPH, "graph_roots", return_value={"nazo-oauth-server"}),
            mock.patch.object(GRAPH, "package_names", return_value={"nazo-oauth-server", "nazo-auth", "serde"}),
        ):
            self.assertEqual(GRAPH.main(), 0)


if __name__ == "__main__":
    unittest.main()
