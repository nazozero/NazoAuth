from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("application_guards", ROOT / "scripts" / "verify_static_contracts.py")
GUARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARDS)


class ApplicationDependencyBoundaries(unittest.TestCase):
    def assert_manifest_boundary(self, package: str, dependencies: str, rejected: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\n[workspace.dependencies]\nhidden = { package = "nazoauth", path = "crates/host" }\n')
            crate = root / "crates" / "consumer"
            crate.mkdir(parents=True)
            (crate / "Cargo.toml").write_text(f'[package]\nname = "{package}"\n' + dependencies)
            with patch.object(GUARDS, "ROOT", root):
                if rejected:
                    with self.assertRaises(SystemExit):
                        GUARDS.check_package_roles()
                else:
                    GUARDS.check_package_roles()

    def test_application_rejects_host_and_http_adapter(self) -> None:
        for dependency in ("nazoauth", "nazo-http-actix"):
            with self.subTest(dependency=dependency):
                self.assert_manifest_boundary("nazo-oauth-server", f'[dependencies]\n{dependency} = "1"\n', True)

    def test_domain_rejects_application(self) -> None:
        self.assert_manifest_boundary("nazo-identity", '[dependencies]\nnazo-oauth-server = "1"\n', True)

    def test_workspace_alias_cannot_hide_host(self) -> None:
        self.assert_manifest_boundary("nazo-oauth-server", '[dependencies]\nhidden.workspace = true\n', True)

    def test_optional_target_build_dependency_cannot_hide_adapter(self) -> None:
        self.assert_manifest_boundary("nazo-oauth-server", '[target.\'cfg(unix)\'.build-dependencies]\nhidden = { package = "nazo-http-actix", version = "1", optional = true }\n', True)

    def test_native_composition_and_application_domain_dependencies_are_allowed(self) -> None:
        self.assert_manifest_boundary("nazoauth", '[dependencies]\nnazo-http-actix = "1"\n', False)
        self.assert_manifest_boundary("nazo-oauth-server", '[dependencies]\nnazo-identity = "1"\nhttp = "1"\n', False)

    def test_dev_executor_is_not_a_production_edge(self) -> None:
        self.assert_manifest_boundary("nazo-oauth-server", '[dev-dependencies]\nfutures-executor = "1"\n', False)

    def test_renamed_framework_and_optional_target_runtime_are_rejected(self) -> None:
        for table in ("dependencies", "build-dependencies", "target.'cfg(windows)'.dependencies", "target.'cfg(unix)'.build-dependencies"):
            for package in ("actix-web", "tokio"):
                with self.subTest(table=table, package=package):
                    self.assert_manifest_boundary(
                        "nazo-oauth-server",
                        f'[{table}]\nhidden = {{ package = "{package}", version = "1", optional = true }}\n',
                        True,
                    )

    def test_unclassified_external_dependency_is_allowed(self) -> None:
        """Third-party crates use a denylist, not an allowlist: ordinary
        algorithm/data crates need no review entry."""
        for consumer in ("nazo-oauth-server", "nazo-identity", "nazoauth"):
            with self.subTest(consumer=consumer):
                self.assert_manifest_boundary(consumer, '[dependencies]\nnew-data-library = "1"\n', False)

    def test_mixed_library_keeps_data_but_rejects_execution_features(self) -> None:
        self.assert_manifest_boundary("nazo-identity", '[dependencies]\nlettre = { version = "1", default-features = false }\n', False)
        self.assert_manifest_boundary("nazo-identity", '[dependencies]\nlettre = { version = "1", features = ["smtp-transport"] }\n', True)

    def test_path_identity_and_workspace_origin_cannot_be_hidden(self) -> None:
        for workspace_edge in (False, True):
            with self.subTest(workspace_edge=workspace_edge), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                host = root / "private-host"
                host.mkdir()
                (host / "Cargo.toml").write_text('[package]\nname = "nazoauth"\n')
                inherited = '[workspace.dependencies]\nhidden = { path = "private-host" }\n' if workspace_edge else ""
                (root / "Cargo.toml").write_text('[workspace]\n' + inherited)
                consumer = root / "crates" / "consumer"
                consumer.mkdir(parents=True)
                edge = 'hidden.workspace = true' if workspace_edge else 'hidden = { path = "../../private-host" }'
                (consumer / "Cargo.toml").write_text('[package]\nname = "nazo-oauth-server"\n[dependencies]\n' + edge)
                with patch.object(GUARDS, "ROOT", root), self.assertRaises(SystemExit):
                    GUARDS.check_package_roles()

    def test_resolved_edges_keep_metadata_for_graph_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = root / "crates" / "consumer"
            consumer.mkdir(parents=True)
            path = consumer / "Cargo.toml"
            path.write_text('[package]\nname="nazoauth"\n[target.\'cfg(unix)\'.build-dependencies]\nhidden={workspace=true,optional=true,features=["rt"]}\n')
            workspace = {"dependencies": {"hidden": {"package": "tokio", "version": "1", "features": ["sync"]}}}
            with patch.object(GUARDS, "ROOT", root):
                edges = list(GUARDS.resolved_production_dependencies(path, workspace))
            self.assertEqual(len(edges), 1)
            name, spec = edges[0]
            self.assertEqual(name, "tokio")
            self.assertEqual((spec["_alias"], spec["_kind"], spec["_target"], spec["_path"]), ("hidden", "build", "cfg(unix)", None))
            self.assertTrue(spec["optional"])
            self.assertEqual(spec["features"], ["sync", "rt"])


class InnerSourceBoundaries(unittest.TestCase):
    def assert_source_boundary(self, source: str, rejected: bool, package: str = "nazo-oauth-server", dependencies: str = "", filename: str = "src/lib.rs") -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\n')
            consumer = root / "crates" / "consumer"
            consumer.mkdir(parents=True)
            (consumer / "Cargo.toml").write_text(f'[package]\nname="{package}"\n' + dependencies)
            path = consumer / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            with patch.object(GUARDS, "ROOT", root):
                if rejected:
                    with self.assertRaises(SystemExit):
                        GUARDS.check_inner_source_boundaries()
                else:
                    GUARDS.check_inner_source_boundaries()

    def test_concrete_request_response_extractor_and_public_wrappers_are_rejected(self) -> None:
        for source in (
            "pub struct Input { pub request: actix_web::HttpRequest }",
            "struct Wrapper(actix_web::HttpRequest); pub struct Input { pub request: Wrapper }",
            "pub type Output = actix_web::HttpResponse;",
            "use actix_web::{web::Data, HttpRequest as Request}; pub struct Input(pub Data<Request>);",
            "pub fn endpoint(input: axum::extract::State<State>) -> axum::response::Response { todo!() }",
            "pub struct Pending(pub tokio::task::JoinHandle<()>);",
            "pub struct NativeFacade(pub nazoauth::http::HttpRequest);",
        ):
            with self.subTest(source=source):
                self.assert_source_boundary(source, True)

    def test_renamed_dependency_and_import_alias_cannot_hide_runtime(self) -> None:
        self.assert_source_boundary(
            "use hidden::{task as tasks}; fn schedule() { tasks::spawn(async {}); }",
            True, dependencies='[dependencies]\nhidden={package="tokio",version="1"}\n',
        )
        self.assert_source_boundary(
            "extern crate hidden as runtime; pub struct Job(runtime::task::JoinHandle<()>);",
            True, dependencies='[dependencies]\nhidden={package="tokio",version="1"}\n',
        )
        self.assert_source_boundary("use std::{thread::{self as workers, Builder as Thread}}; fn run() { workers::spawn(|| {}); }", True)

    def test_fully_qualified_host_execution_and_imported_fields_are_rejected(self) -> None:
        for source in (
            "fn run() { ::std::thread::spawn(|| {}); }",
            "fn run() { std::process::Command::new(\"worker\").spawn(); }",
            "fn run() { std::env::var(\"TOKEN\"); }",
            "fn run() { std::fs::read(\"key.pem\"); }",
            "use std::{fs as disk}; fn run() { disk::read(\"key.pem\"); }",
            "use std::net::TcpStream; pub struct Socket(pub TcpStream);",
            "use lettre::AsyncSmtpTransport; pub type Mail = AsyncSmtpTransport<Executor>;",
            "pub struct Connection(pub rustls::ClientConnection);",
            "fn run() { futures_executor::block_on(async {}); }",
        ):
            with self.subTest(source=source):
                self.assert_source_boundary(source, True)

    def test_feature_gated_execution_is_still_production(self) -> None:
        for attribute in ('#[cfg(feature="runtime")]', '#[cfg(any(test, feature="runtime"))]', '#[cfg(not(test))]'):
            with self.subTest(attribute=attribute):
                self.assert_source_boundary(attribute + '\nfn run() { tokio::spawn(async {}); }', True)

    def test_neutral_data_crypto_and_module_lifecycle_are_allowed(self) -> None:
        self.assert_source_boundary(
            "use http::{Method, StatusCode}; use std::{time::Duration, net::IpAddr}; "
            "use nazo_runtime_modules::ModuleLifecycle; use lettre::Address; "
            "use rustls::{pki_types::CertificateDer, crypto::aws_lc_rs}; "
            "struct Input { method: Method, address: IpAddr, ttl: Duration, lifecycle: ModuleLifecycle } "
            "fn digest() { let _ = blake3::hash(b\"value\"); }", False,
        )

    def test_native_and_adapter_execution_and_test_executor_are_allowed(self) -> None:
        execution = "fn run() { tokio::spawn(async {}); std::fs::read(\"fixture\"); }"
        self.assert_source_boundary(execution, False, package="nazoauth")
        self.assert_source_boundary(execution, False, package="nazo-http-actix")
        for attribute in ('#[cfg(test)]', '#[cfg(all(test, feature="fixtures"))]'):
            with self.subTest(attribute=attribute):
                self.assert_source_boundary(attribute + '\nfn test_only() { futures_executor::block_on(async {}); }', False)
        self.assert_source_boundary(execution, False, filename="tests/worker.rs")

    def test_comments_literals_and_self_imports_are_not_runtime_ownership(self) -> None:
        self.assert_source_boundary(
            'use std::fmt::{self, Debug}; use crate::model::{self, Input}; '
            '// tokio::spawn(async {});\n'
            'const TEXT: &str = r#"std::fs::read(\"key\"); HttpRequest"#; '
            'fn format() -> fmt::Result { Ok(()) }', False,
        )


class RustTestStructureBoundaries(unittest.TestCase):
    """Physical test/production separation: test code lives under tests/."""

    def assert_structure(self, files: dict[str, str], rejected: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, source in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            with patch.object(GUARDS, "ROOT", root):
                if rejected:
                    with self.assertRaises(SystemExit):
                        GUARDS.check_rust_test_structure()
                else:
                    GUARDS.check_rust_test_structure()

    def test_inline_test_module_and_test_attributes_fail(self) -> None:
        for source in (
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn example() {}\n}\n",
            "#[test]\nfn example() {}\n",
            "#[tokio::test]\nasync fn example() {}\n",
            "#[actix_web::test]\nasync fn example() {}\n",
        ):
            with self.subTest(source=source):
                self.assert_structure({"crates/app/src/lib.rs": source}, True)

    def test_test_files_inside_src_fail(self) -> None:
        for relative in (
            "crates/app/src/tests.rs",
            "crates/app/src/foo_tests.rs",
            "crates/app/src/unit/tests.rs",
            "crates/app/src/tests/mod.rs",
        ):
            with self.subTest(relative=relative):
                self.assert_structure({relative: "#[test]\nfn example() {}\n"}, True)

    def test_test_only_mount_of_production_source_fails(self) -> None:
        self.assert_structure(
            {
                "crates/app/src/lib.rs": (
                    '#[cfg(test)]\n#[path = "inner.rs"]\nmod inner;\n'
                ),
                "crates/app/src/inner.rs": "#[test]\nfn example() {}\n",
            },
            True,
        )

    def test_test_file_recompiling_production_source_fails(self) -> None:
        for mount in (
            '#[path = "../src/inner.rs"]\nmod inner;\n',
            'include!("../src/inner.rs");\n',
        ):
            with self.subTest(mount=mount):
                self.assert_structure(
                    {
                        "crates/app/src/inner.rs": "pub fn run() {}\n",
                        "crates/app/tests/example.rs": mount,
                    },
                    True,
                )

    def test_external_test_mount_and_tests_directory_pass(self) -> None:
        self.assert_structure(
            {
                "crates/app/src/lib.rs": (
                    "pub fn production() {}\n"
                    '#[cfg(test)]\n#[path = "../tests/unit/inner.rs"]\nmod inner;\n'
                ),
                "crates/app/tests/unit/inner.rs": "#[test]\nfn example() {}\n",
                "crates/app/tests/example.rs": "#[test]\nfn example() {}\n",
            },
            False,
        )

    def test_renamed_test_file_and_feature_modules_pass(self) -> None:
        self.assert_structure(
            {
                "crates/app/src/lib.rs": (
                    "pub fn production() {}\n"
                    "pub(crate) fn for_review_seam() {}\n"
                    '#[cfg(feature = "x")]\nmod optional;\n'
                ),
                "crates/app/src/optional.rs": "pub fn feature() {}\n",
                "crates/app/tests/renamed_contract.rs": "#[test]\nfn behavior() {}\n",
            },
            False,
        )

    def test_test_only_items_beyond_module_mounts_fail(self) -> None:
        """Test-only helpers must live under tests/, not inside production source."""
        for source in (
            "#[cfg(test)]\nfn make_fake_runtime() {}\n",
            "#[cfg(test)]\nimpl Service {\n    fn for_test() {}\n}\n",
            "#[cfg(test)]\nconst TEST_VALUE: usize = 123;\n",
            "#[cfg(test)]\nuse helper::Fixture;\n",
            "#[cfg(test)]\npub use inner::TestClient;\n",
            "#[cfg(test)]\nstatic TEST_FLAG: bool = true;\n",
            "#[cfg(all(test, feature = \"fixtures\"))]\nfn seeded_rng() {}\n",
            "#[cfg(test)]\ntrait FakePort {}\n",
            "#[cfg(test)]\nmod tests;\n",
        ):
            with self.subTest(source=source):
                self.assert_structure({"crates/app/src/lib.rs": source}, True)

    def test_production_possible_and_production_only_cfg_items_pass(self) -> None:
        self.assert_structure(
            {
                "crates/app/src/lib.rs": (
                    '#[cfg(any(test, feature = "test-support"))]\n'
                    "pub(crate) fn for_review_seam() {}\n"
                    "#[cfg(not(test))]\n"
                    "pub fn production_only() {}\n"
                ),
            },
            False,
        )


class CibaPingConnectionPinning(unittest.TestCase):
    """Validated CIBA addresses must be the addresses the client dials."""

    SENDER = "crates/nazoauth/src/adapters/ciba_ping_sender.rs"

    def assert_pinning(self, source: str, rejected: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / self.SENDER
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            with patch.object(GUARDS, "ROOT", root):
                if rejected:
                    with self.assertRaises(SystemExit):
                        GUARDS.check_ciba_ping_connection_pinning()
                else:
                    GUARDS.check_ciba_ping_connection_pinning()

    def test_validated_resolution_then_pinned_connection_passes(self) -> None:
        self.assert_pinning(
            "async fn post(&self) {\n"
            "    let addresses = tokio::net::lookup_host((host, port)).await?.collect();\n"
            "    if addresses.iter().any(|a| is_blocked_ip(a.ip())) { bail!(); }\n"
            "    client.resolve_to_addrs(host, &addresses).build()\n"
            "}\n",
            False,
        )

    def test_dropping_any_step_of_the_chain_fails(self) -> None:
        for missing in (
            "fn post() { client.build() }",
            "fn post() { lookup_host((h, p)); client.build() }",
            "fn post() { lookup_host((h, p)); is_blocked_ip(ip); client.build() }",
        ):
            with self.subTest(source=missing):
                self.assert_pinning(missing, True)
