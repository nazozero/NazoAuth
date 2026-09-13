#!/usr/bin/env python3
"""Mutation tests for check_crypto_boundary.py.

Every case builds a minimal temporary workspace fixture and runs the real
guard implementation; no guard rules are duplicated here.
"""

import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_crypto_boundary as guard

ROOT_MANIFEST = """\
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.dependencies]
nazo-crypto = { path = "crates/crypto", default-features = false }
"""

CRYPTO_MANIFEST = """\
[package]
name = "nazo-crypto"
version = "0.1.0"
edition = "2021"

[features]
default = []
jose = ["dep:jsonwebtoken", "jsonwebtoken/aws_lc_rs", "dep:aws-lc-rs",
        "dep:p256", "p256/pkcs8", "dep:ed25519-dalek",
        "dep:pkcs8", "dep:der", "dep:x509-cert", "dep:base64", "dep:rand",
        "dep:serde", "dep:serde_json"]
ecdh = ["dep:p256", "p256/ecdh", "dep:zeroize"]
aead = ["dep:aes-gcm"]
password = ["dep:argon2"]
ed25519 = ["dep:ed25519-dalek"]
x509 = ["dep:rcgen", "dep:rustls", "dep:x509-parser", "x509-parser/verify-aws"]

[dependencies]
thiserror = "1"
aes-gcm = { version = "0.10", optional = true }
argon2 = { version = "0.5", optional = true }
aws-lc-rs = { version = "1", optional = true }
base64 = { version = "0.22", optional = true }
der = { version = "0.8", optional = true }
ed25519-dalek = { version = "3", optional = true }
jsonwebtoken = { version = "11", optional = true }
p256 = { version = "0.14", optional = true }
pkcs8 = { version = "0.11", optional = true }
rand = { version = "0.9", optional = true }
rcgen = { version = "0.14", optional = true }
rustls = { version = "0.23", optional = true }
serde = { version = "1", optional = true }
serde_json = { version = "1", optional = true }
x509-cert = { version = "0.3", optional = true }
x509-parser = { version = "0.18", optional = true }
zeroize = { version = "1", optional = true }
"""

CRYPTO_LIB = """\
#[derive(Debug)]
pub enum CryptoError {
    InvalidInput,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub mod certificate;
pub mod jwt;
"""

CRYPTO_JWT = """\
pub use jsonwebtoken::{Algorithm, Header, TokenData, Validation};

pub struct VerificationKey {
    pub(crate) inner: jsonwebtoken::DecodingKey,
}

pub fn decode_header(token: &str) -> crate::Result<String> {
    let _ = token;
    Ok(String::new())
}
"""

CRYPTO_CERTIFICATE = """\
pub use rcgen::{BasicConstraints, CertificateParams, DistinguishedName};
pub use rcgen::string::PrintableString;

pub fn verify_signature(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    issuer_public_key: &x509_parser::x509::SubjectPublicKeyInfo<'_>,
) -> crate::Result<()> {
    let _ = (certificate, issuer_public_key);
    Ok(())
}

pub fn sign() -> crate::Result<()> {
    Ok(())
}

pub fn self_signed() -> crate::Result<()> {
    Ok(())
}
"""

APP_MANIFEST = """\
[package]
name = "nazo-oauth-server"
version = "0.1.0"
edition = "2021"

[dependencies]
nazo-crypto = { path = "../crypto", features = ["aead", "ecdh", "jose", "x509"] }
"""

APP_LIB = """\
use nazo_crypto::jwt::Algorithm;

pub fn algorithm() -> Algorithm {
    Algorithm::ES256
}
"""


def _write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def _append(path: Path, content: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(content))


class CryptoBoundaryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="crypto-boundary-test-"))
        self.addCleanup(shutil.rmtree, self._tmp, True)
        _write(self._tmp, "Cargo.toml", ROOT_MANIFEST)
        _write(self._tmp, "crates/crypto/Cargo.toml", CRYPTO_MANIFEST)
        _write(self._tmp, "crates/crypto/src/lib.rs", CRYPTO_LIB)
        _write(self._tmp, "crates/crypto/src/jwt.rs", CRYPTO_JWT)
        _write(self._tmp, "crates/crypto/src/certificate.rs", CRYPTO_CERTIFICATE)
        _write(self._tmp, "crates/app/Cargo.toml", APP_MANIFEST)
        _write(self._tmp, "crates/app/src/lib.rs", APP_LIB)

    @property
    def app_manifest(self) -> Path:
        return self._tmp / "crates/app/Cargo.toml"

    @property
    def app_lib(self) -> Path:
        return self._tmp / "crates/app/src/lib.rs"

    @property
    def crypto_manifest(self) -> Path:
        return self._tmp / "crates/crypto/Cargo.toml"

    @property
    def crypto_jwt(self) -> Path:
        return self._tmp / "crates/crypto/src/jwt.rs"

    def violations(self) -> list:
        return guard.collect_violations(self._tmp)

    def assertClean(self):
        self.assertEqual(self.violations(), [])

    def assertViolation(self, needle: str):
        violations = self.violations()
        self.assertTrue(
            any(needle in violation for violation in violations),
            f"expected violation containing {needle!r}; got {violations}",
        )

    # -- baseline ---------------------------------------------------------

    def test_clean_fixture_passes(self):
        self.assertClean()

    # -- manifest mutations ------------------------------------------------

    def test_alias_normal_backend_dependency_fails(self):
        _append(self.app_manifest, 'jwt = { package = "jsonwebtoken", version = "11" }\n')
        self.assertViolation("backend dependency: jwt (jsonwebtoken)")

    def test_target_specific_backend_dependency_fails(self):
        _append(
            self.app_manifest,
            "[target.'cfg(unix)'.dependencies]\nring = \"0.17\"\n",
        )
        self.assertViolation("backend dependency: ring")

    def test_optional_backend_dependency_fails(self):
        _append(self.app_manifest, 'argon2 = { version = "0.5", optional = true }\n')
        self.assertViolation("backend dependency: argon2")

    def test_build_dependency_fails(self):
        _append(self.app_manifest, '[build-dependencies]\np256 = "0.14"\n')
        self.assertViolation("backend dependency: p256")

    def test_workspace_inherited_alias_fails(self):
        _append(
            self._tmp / "Cargo.toml",
            'jwt = { package = "jsonwebtoken", version = "11" }\n',
        )
        _append(self.app_manifest, "jwt = { workspace = true }\n")
        self.assertViolation("backend dependency: jwt (jsonwebtoken)")

    def test_unknown_third_party_dependency_fails(self):
        _append(self.app_manifest, 'unreviewed-lib = "1"\n')
        self.assertViolation("unreviewed dependency: unreviewed-lib")

    def test_unknown_local_package_fails(self):
        _write(
            self._tmp,
            "crates/mystery/Cargo.toml",
            '[package]\nname = "mystery-pkg"\nversion = "0.1.0"\n',
        )
        _write(self._tmp, "crates/mystery/src/lib.rs", "")
        _append(self.app_manifest, 'mystery-pkg = { path = "../mystery" }\n')
        self.assertViolation("unregistered local package mystery-pkg")

    def test_backend_feature_forwarding_fails(self):
        _append(
            self.app_manifest,
            '[dev-dependencies]\njwt = { package = "jsonwebtoken", version = "11" }\n'
            '[features]\n'
            'forward = ["jwt/aws_lc_rs"]\n'
            'weak = ["jwt?/aws_lc_rs"]\n',
        )
        self.assertViolation("backend feature forwarding")

    def test_x509_verify_feature_fails(self):
        _append(
            self.app_manifest,
            'x509-parser = { version = "0.18", features = ["verify-aws"] }\n',
        )
        self.assertViolation("x509 verification feature")

    def test_crypto_consumer_feature_mismatch_fails(self):
        self.app_manifest.write_text(
            APP_MANIFEST.replace(
                '["aead", "ecdh", "jose", "x509"]', '["jose"]'
            ),
            encoding="utf-8",
        )
        self.assertViolation("crypto features: nazo-oauth-server")

    def test_unregistered_consumer_fails(self):
        _write(
            self._tmp,
            "crates/web/Cargo.toml",
            '[package]\nname = "nazo-http-actix"\nversion = "0.1.0"\n\n'
            '[dependencies]\nnazo-crypto = { path = "../crypto", features = ["jose"] }\n',
        )
        _write(self._tmp, "crates/web/src/lib.rs", "")
        self.assertViolation("crypto consumer: nazo-http-actix is not a registered consumer")

    def test_crypto_local_dependency_fails(self):
        _write(
            self._tmp,
            "crates/auth/Cargo.toml",
            '[package]\nname = "nazo-auth"\nversion = "0.1.0"\n',
        )
        _write(self._tmp, "crates/auth/src/lib.rs", "")
        _append(self.crypto_manifest, 'nazo-auth = { path = "../auth" }\n')
        self.assertViolation("crypto isolation: local dependency nazo-auth")

    def test_crypto_unlisted_external_dependency_fails(self):
        _append(self.crypto_manifest, 'unlisted-lib = "1"\n')
        self.assertViolation("crypto dependency: unlisted dependency unlisted-lib")

    def test_crypto_missing_required_dependency_fails(self):
        content = self.crypto_manifest.read_text(encoding="utf-8")
        self.crypto_manifest.write_text(
            content.replace('zeroize = { version = "1", optional = true }\n', ""),
            encoding="utf-8",
        )
        self.assertViolation("crypto dependency: missing required dependency zeroize")

    def test_crypto_feature_table_mismatch_fails(self):
        content = self.crypto_manifest.read_text(encoding="utf-8")
        self.crypto_manifest.write_text(
            content.replace("default = []", 'default = []\nextra = []'),
            encoding="utf-8",
        )
        self.assertViolation("crypto features:")

    def test_wrong_path_nazo_crypto_identity_fails(self):
        _write(
            self._tmp,
            "crates/evil/Cargo.toml",
            '[package]\nname = "nazo-crypto"\nversion = "0.1.0"\n',
        )
        _write(self._tmp, "crates/evil/src/lib.rs", "")
        self.app_manifest.write_text(
            APP_MANIFEST.replace('path = "../crypto"', 'path = "../evil"'),
            encoding="utf-8",
        )
        self.assertViolation("crypto identity")
        self.assertViolation("nazo-crypto must resolve to crates/crypto")

    # -- source mutations --------------------------------------------------

    def test_renamed_native_use_fails(self):
        _append(
            self.app_lib,
            "use p256 as ec;\n"
            "pub fn renamed() {\n"
            "    let _ = core::any::type_name::<ec::SecretKey>();\n"
            "}\n",
        )
        self.assertViolation("backend use: backend path p256")

    def test_nested_native_use_fails(self):
        _append(self.app_lib, "use aes_gcm::aead::Aead;\n")
        self.assertViolation("backend use: backend path aes_gcm")

    def test_native_reexport_fails(self):
        _append(self.app_lib, "pub use jsonwebtoken::DecodingKey;\n")
        self.assertViolation("backend use: backend path jsonwebtoken")

    def test_test_support_feature_use_fails(self):
        _append(
            self.app_lib,
            '#[cfg(feature = "test-support")]\nuse aes_gcm::Aes256Gcm;\n',
        )
        self.assertViolation("backend use: backend path aes_gcm")

    def test_string_and_comment_mentions_pass(self):
        _append(
            self.app_lib,
            "// aws_lc_rs is mentioned in a comment\n"
            'const DOC: &str = r#"aws_lc_rs raw string"#;\n'
            'const PLAIN: &str = "aws_lc_rs ordinary string";\n',
        )
        self.assertClean()

    def test_cfg_test_oracle_passes(self):
        _append(
            self.app_lib,
            "#[cfg(test)]\nmod tests {\n"
            "    use aes_gcm::Aes256Gcm;\n"
            "    fn oracle() { let _ = Aes256Gcm::generate_key; }\n"
            "}\n",
        )
        self.assertClean()

    def test_escaped_multiline_string_then_native_code_fails(self):
        _append(
            self.app_lib,
            'const ESCAPED: &str = "first\\\nsecond";\n'
            "use p256::SecretKey;\n",
        )
        self.assertViolation("backend use: backend path p256")

    def test_x509_parse_only_passes(self):
        _append(self.app_manifest, 'x509-parser = "0.18"\n')
        _append(self.app_lib, "use x509_parser::prelude::X509Certificate;\n")
        self.assertClean()

    def test_direct_verify_signature_fails(self):
        _append(self.app_lib, "pub fn check(c: &u8) { let _ = c.verify_signature(); }\n")
        self.assertViolation("native verify_signature call")

    def test_ufcs_verify_signature_fails(self):
        _append(
            self.app_lib,
            "pub fn check(c: &u8) { let _ = X509Certificate::verify_signature(c); }\n",
        )
        self.assertViolation("native verify_signature call")

    def test_rcgen_method_calls_fail(self):
        _append(
            self.app_lib,
            "pub fn issue(p: &u8, k: &u8) {\n"
            "    let _ = p.self_signed(k);\n"
            "    let _ = p.signed_by(k);\n"
            "}\n",
        )
        self.assertViolation("rcgen signing call")

    def test_crypto_certificate_api_calls_pass(self):
        _append(
            self.app_lib,
            "pub fn check(c: &u8, k: &u8) {\n"
            "    let _ = nazo_crypto::certificate::verify_signature(c, k);\n"
            "    let _ = nazo_crypto::certificate::sign();\n"
            "    let _ = nazo_crypto::certificate::self_signed();\n"
            "}\n",
        )
        self.assertClean()

    def test_tls_provider_exception_file_passes(self):
        _write(
            self._tmp,
            "crates/nazoauth/Cargo.toml",
            '[package]\nname = "nazoauth"\nversion = "0.1.0"\n\n'
            "[dependencies]\n"
            'nazo-crypto = { path = "../crypto", features = ["ed25519", "jose", "password", "x509"] }\n'
            'rustls = "0.23"\n',
        )
        _write(
            self._tmp,
            "crates/nazoauth/src/bootstrap/transport.rs",
            "pub fn provider() {\n"
            "    let _ = rustls::crypto::aws_lc_rs::default_provider();\n"
            "    let _ = rustls::crypto::CryptoProvider::get_default();\n"
            "}\n",
        )
        self.assertClean()

    def test_tls_provider_outside_exception_fails(self):
        _append(
            self.app_lib,
            "pub fn provider() { let _ = rustls::crypto::aws_lc_rs::default_provider(); }\n",
        )
        self.assertViolation("TLS provider path")

    def test_test_only_path_attribute_passes(self):
        _write(self._tmp, "crates/app/tests/oracle.rs", "use aes_gcm::Aes256Gcm;\n")
        _append(
            self.app_lib,
            "#[cfg(test)]\n"
            '#[path = "../tests/oracle.rs"]\nmod oracle;\n',
        )
        self.assertClean()

    def test_production_path_attribute_escaping_src_fails(self):
        _write(self._tmp, "crates/app/tests/oracle.rs", "")
        _append(
            self.app_lib,
            '#[path = "../tests/oracle.rs"]\nmod oracle;\n',
        )
        self.assertViolation("production path attribute")

    def test_include_macro_fails(self):
        _write(self._tmp, "crates/app/src/included.rs", "")
        _append(self.app_lib, 'include!("included.rs");\n')
        self.assertViolation("include macro")

    # -- crypto public surface --------------------------------------------

    def test_crypto_public_backend_field_fails(self):
        _append(
            self.crypto_jwt,
            "pub struct Leaked {\n    pub inner: p256::SecretKey,\n}\n",
        )
        self.assertViolation("crypto public surface: public field inner")

    def test_crypto_backend_reexport_fails(self):
        _append(self.crypto_jwt, "pub use p256::SecretKey;\n")
        self.assertViolation("crypto public surface: backend re-export")

    def test_crypto_deref_impl_fails(self):
        _append(
            self.crypto_jwt,
            "impl std::ops::Deref for VerificationKey {\n"
            "    type Target = jsonwebtoken::DecodingKey;\n"
            "    fn deref(&self) -> &Self::Target { &self.inner }\n"
            "}\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_into_inner_fails(self):
        _append(
            self.crypto_jwt,
            "impl VerificationKey {\n"
            "    pub fn into_inner(self) -> jsonwebtoken::DecodingKey { self.inner }\n"
            "}\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_public_trait_fails(self):
        _append(self.crypto_jwt, "pub trait Signer {}\n")
        self.assertViolation("crypto public surface: public trait")

    def test_crypto_public_signature_backend_path_fails(self):
        _append(
            self.crypto_jwt,
            "pub fn leak(key: &VerificationKey) -> p256::SecretKey {\n"
            "    let _ = key;\n"
            "    todo!()\n"
            "}\n",
        )
        self.assertViolation("crypto public surface: backend path p256::SecretKey")

    def test_crypto_aliased_type_export_fails(self):
        _append(
            self.crypto_jwt,
            "use p256::SecretKey;\n"
            "pub type ExposedKey = SecretKey;\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_module_alias_reexport_fails(self):
        _append(
            self.crypto_jwt,
            "use p256 as backend;\n"
            "pub use backend::SecretKey;\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_tuple_field_backend_fails(self):
        _append(
            self.crypto_jwt,
            "pub struct Exposed(pub p256::SecretKey);\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_public_field_on_opaque_type_fails(self):
        _append(
            self.crypto_jwt,
            "pub struct VerificationKey(pub u8);\n",
        )
        self.assertViolation("public tuple field on opaque type VerificationKey")
        _append(
            self.crypto_jwt,
            "pub struct VerificationKey { pub count: u8 }\n",
        )
        self.assertViolation("public field count on opaque type VerificationKey")

    def test_crypto_provider_reexport_fails(self):
        _append(
            self.crypto_jwt,
            "pub use rustls::crypto::CryptoProvider;\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_unlisted_public_fn_fails(self):
        _append(self.crypto_jwt, "pub fn issue_oauth_token() -> u64 { 1 }\n")
        self.assertViolation("crypto public surface")

    def test_crypto_unlisted_public_type_fails(self):
        _append(self.crypto_jwt, "pub struct KeyMaterial { raw: [u8; 32] }\n")
        self.assertViolation("crypto public surface")

    def test_crypto_unlisted_method_fails(self):
        _append(
            self.crypto_jwt,
            "impl VerificationKey {\n"
            "    pub fn raw_key(&self) -> &[u8] { &[] }\n"
            "}\n",
        )
        self.assertViolation("crypto public surface")

    def test_crypto_unlisted_public_mod_fails(self):
        _append(self.crypto_jwt, "pub mod extra {}\n")
        self.assertViolation("crypto public surface")

    def test_crypto_aliased_signature_backend_fails(self):
        _append(
            self.crypto_jwt,
            "use p256::SecretKey;\n"
            "pub fn leak() -> SecretKey { todo!() }\n",
        )
        self.assertViolation("crypto public surface")

    def test_aliased_ufcs_verify_signature_fails(self):
        _append(self.app_manifest, 'x509-parser = "0.18"\n')
        _append(
            self.app_lib,
            "use x509_parser::certificate::X509Certificate as Cert;\n"
            "pub fn check(c: &u8) { let _ = Cert::verify_signature(c); }\n",
        )
        self.assertViolation("native verify_signature call")

    def test_nested_alias_ufcs_verify_signature_fails(self):
        _append(self.app_manifest, 'x509-parser = "0.18"\n')
        _append(
            self.app_lib,
            "use x509_parser::certificate;\n"
            "pub fn check(c: &u8) {\n"
            "    let _ = certificate::X509Certificate::verify_signature(c);\n"
            "}\n",
        )
        self.assertViolation("native verify_signature call")

    def test_crypto_feature_member_forwarding_fails(self):
        content = self.crypto_manifest.read_text(encoding="utf-8")
        self.crypto_manifest.write_text(
            content.replace(
                'password = ["dep:argon2"]',
                'password = ["dep:argon2", "dep:aws-lc-rs"]',
            ),
            encoding="utf-8",
        )
        self.assertViolation("crypto features: password")

    def test_crypto_feature_member_missing_fails(self):
        content = self.crypto_manifest.read_text(encoding="utf-8")
        self.crypto_manifest.write_text(
            content.replace(
                '"dep:x509-parser", "x509-parser/verify-aws"',
                '"dep:x509-parser"',
            ),
            encoding="utf-8",
        )
        self.assertViolation("crypto features: x509")


if __name__ == "__main__":
    unittest.main()
