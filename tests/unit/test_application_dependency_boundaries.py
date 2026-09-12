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

    def test_unreviewed_dependency_requires_classification(self) -> None:
        for consumer in ("nazo-oauth-server", "nazo-identity", "nazoauth"):
            with self.subTest(consumer=consumer):
                self.assert_manifest_boundary(consumer, '[dependencies]\nnew-execution-library = "1"\n', True)

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

    def test_original_core_dependency_policy_remains_stricter_than_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\n')
            identity = root / "crates" / "identity"
            identity.mkdir(parents=True)
            (identity / "Cargo.toml").write_text('[package]\nname="nazo-identity"\n[dependencies]\nnazo-auth="1"\n')
            self.assertIn("nazo-auth", GUARDS.FORBIDDEN_CRATE_DEPENDENCIES["identity"])
            with patch.object(GUARDS, "ROOT", root), patch.object(
                GUARDS, "FORBIDDEN_CRATE_DEPENDENCIES", {"identity": GUARDS.FORBIDDEN_CRATE_DEPENDENCIES["identity"]}
            ):
                GUARDS.check_package_roles()
                with self.assertRaises(SystemExit):
                    GUARDS.check_crate_dependency_boundaries()


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


class ContractDefinitionBoundaries(unittest.TestCase):
    OWNER = "crates/authorization-server/src/contracts/metadata.rs"

    def assert_contract_boundary(self, files: dict[str, str], rejected: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, source in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            with (
                patch.object(GUARDS, "ROOT", root),
                patch.object(GUARDS, "T02_CONTRACT_OWNERS", {self.OWNER: ("MetadataSnapshot",)}),
            ):
                if rejected:
                    with self.assertRaises(SystemExit):
                        GUARDS.check_contract_definition_owners()
                else:
                    GUARDS.check_contract_definition_owners()

    def test_missing_wrong_and_duplicate_definitions_are_rejected(self) -> None:
        definition = "pub struct MetadataSnapshot;"
        for files in (
            {},
            {"crates/http-actix/src/metadata.rs": definition},
            {self.OWNER: definition, "crates/nazoauth/src/domain/metadata.rs": definition},
            {self.OWNER: definition + "\n" + definition},
        ):
            with self.subTest(files=files):
                self.assert_contract_boundary(files, True)

    def test_http_and_vc_adapter_contract_reexports_are_rejected(self) -> None:
        for adapter in ("http-actix", "openid4vc-http-actix"):
            for export in (
                "pub use nazo_oauth_server::contracts::metadata::MetadataSnapshot;",
                "pub(crate) use nazo_oauth_server::contracts::metadata::{MetadataSnapshot as Snapshot};",
                "use nazo_oauth_server::contracts::metadata::MetadataSnapshot as Snapshot;\npub use Snapshot;",
                "pub use nazo_oauth_server::contracts::metadata::*;",
                "use nazo_oauth_server::contracts::metadata as meta;\npub use meta::*;",
                "pub use nazo_oauth_server::contracts::metadata as old_metadata;",
                "pub use nazo_openid4vci::application;",
                "extern crate nazo_oauth_server as app; pub use app::contracts;",
            ):
                with self.subTest(adapter=adapter, export=export):
                    self.assert_contract_boundary(
                        {self.OWNER: "pub struct MetadataSnapshot;", f"crates/{adapter}/src/lib.rs": export},
                        True,
                    )

    def test_private_imports_and_transport_exports_are_allowed(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/src/lib.rs": (
                    "use nazo_oauth_server::contracts::metadata::MetadataSnapshot;\n"
                    "pub use metadata::MetadataHandles;"
                ),
            },
            False,
        )

    def test_test_directory_mock_and_test_only_items_are_not_production(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/tests/fake.rs": "struct MetadataSnapshot;",
                "crates/http-actix/src/lib.rs": (
                    "#[cfg(test)]\nmod fixtures { struct MetadataSnapshot; }\n"
                    "#[cfg(test)]\n#[allow(dead_code)]\nstruct MetadataSnapshot;\n"
                    "#[cfg(test)]\nuse fixture::MetadataSnapshot;"
                ),
            },
            False,
        )

    def test_comments_and_quoted_source_do_not_define_contracts(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/src/lib.rs": (
                    "// pub struct MetadataSnapshot;\n"
                    "/* pub use contracts::MetadataSnapshot; */\n"
                    'const SOURCE: &str = r#"\npub struct MetadataSnapshot;\n"#;'
                ),
            },
            False,
        )

    def test_optional_feature_definition_is_still_production(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/src/lib.rs": '#[cfg(feature = "compat")]\npub struct MetadataSnapshot;',
            },
            True,
        )

    def test_removed_request_context_file_cannot_return(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/src/request_context.rs": "pub struct RequestContext;",
            },
            True,
        )

    def test_removed_boundary_symbols_cannot_return_in_other_files(self) -> None:
        for symbol in ("SendCibaResponse", "OAuthJsonErrorFields", "RequestContext"):
            with self.subTest(symbol=symbol):
                self.assert_contract_boundary(
                    {self.OWNER: "pub struct MetadataSnapshot;", "crates/http-actix/src/compat.rs": f"pub type {symbol} = ();"}, True,
                )

    def test_same_line_duplicate_definition_is_rejected(self) -> None:
        self.assert_contract_boundary({self.OWNER: "pub struct MetadataSnapshot; pub struct MetadataSnapshot;"}, True)

    def test_http_handlers_named_like_contract_modules_remain_transport_exports(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/src/lib.rs": (
                    "pub use userinfo::{UserinfoEndpoint, userinfo};\n"
                    "pub use fapi_resource::{FapiResourceEndpoint, fapi_resource};\n"
                    "pub use dynamic_client_registration::{DynamicRegistrationEndpoint, dynamic_client_registration};"
                ),
            }, False,
        )

    def test_all_f1_contracts_are_registered(self) -> None:
        symbols = [symbol for group in GUARDS.T02_CONTRACT_OWNERS.values() for symbol in group]
        self.assertEqual(len(symbols), 115)
        self.assertEqual(len(set(symbols)), 115)
        self.assertTrue({"ScimRequestAuthorizer", "ScimBootstrapPasswordProvider", "UserinfoOperations", "UserinfoDpopError"}.issubset(symbols))

    def test_dependency_alias_cannot_reexport_contract_module(self) -> None:
        self.assert_contract_boundary(
            {
                self.OWNER: "pub struct MetadataSnapshot;",
                "crates/http-actix/Cargo.toml": '[package]\nname="nazo-http-actix"\n[dependencies]\nhidden={package="nazo-oauth-server",version="1"}\n',
                "crates/http-actix/src/lib.rs": "pub use hidden::contracts as legacy;",
            }, True,
        )
