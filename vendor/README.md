# Local dependency patches

These are third-party libraries, not NazoAuth workspace crates. They keep their
upstream licenses, public APIs and tests. Production builds resolve them through
the root manifest and root `Cargo.lock`.

## passkey-auth 0.1.3

Source: the published [passkey-auth 0.1.3 crate](https://crates.io/crates/passkey-auth/0.1.3),
archive SHA-256 `68b76d109aa51f99c94d2f361c10dc0c93980dd87aa1ad5212df83e7e1b80a29`.
Its recorded upstream revision is
[`63a54b2df1cdc10d6f42b3383a761b68f8d68bf4`](https://github.com/marirs/passkey-auth-rs/commit/63a54b2df1cdc10d6f42b3383a761b68f8d68bf4).

The patch upgrades P-256 to 0.14 and adapts SEC1 public-key decoding and the
signature verification trait. It preserves the WebAuthn ceremony, attestation
and signature validation rules.
The test certificate generator uses x509-cert 0.3 and SHA-2 0.11 to exercise the
same curves without retaining a vulnerable test-only dependency. Production
certificate parsing remains on the original x509-cert API.

## mdoc-rs 0.2.0

Source: the previously pinned NazoAuth fork revision
[`c5d460cfd667324e51e590e8ecbbdb21f63bbdbe`](https://github.com/nazozero/mdoc-rs/commit/c5d460cfd667324e51e590e8ecbbdb21f63bbdbe).
The existing `UPSTREAM_PROVENANCE.md` records the original published crate.

The patch upgrades P-256/P-384/P-521 to 0.14, ECDSA to 0.17 and signature to 3.
It retains the reviewed COSE encoding and borrowed-transcript changes. NazoAuth
continues to enable only `issue`, with default features disabled; optional TSP
support is outside the production dependency graph.

## Retirement

Both patches remove the old curve dependency on `crypto-bigint 0.5.5`, which is
affected by [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The production lock must resolve a patched, non-yanked `crypto-bigint` release.
Do not ignore the advisory or restore the vulnerable dependency chain.

TODO: replace each local patch with a maintained release once it uses patched
RustCrypto dependencies and passes the retained authentication/credential tests.
The mdoc replacement must also preserve the COSE and transcript contracts above.
