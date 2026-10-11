# Managed mdoc privacy validation — 2026-10-11

The three batch time-linkability warnings in p029, p031 and p033 are resolved
for locally managed mdoc material. All three official batch modules are PASSED.
The complete three-plan rerun has **44 PASSED, 1 SKIPPED, zero WARNING, zero
FAILED and zero incomplete modules**. All 30 batch credentials were checked,
including actual time values, not just the absence of warnings.

## Revisions and deployment

- Baseline report/code head: `b1f4350dee6d0c2f565abf95a16ca6ee83a9c23d`;
  its deployed runtime was `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
- Fixed server source and deployed runtime: `0ddf22e03366a979dfe31de59ca410fd64e406e2`.
- Unchanged controller source: `e2525b4bd7b6a9fbaca4cade6798be264c924562`.
  The private candidate was rebuilt only to select the new server image;
  the installed signed controller was not replaced.
- Running binary SHA-256:
  `91a3941c33120bc5214f103319d9b6fc0b86f669396eea3afce34905c1dd6936`.
- Image manifest:
  `sha256:25289c16b3b4ae621d197cac332142ad199964aa6c87f45c37158c84e26dcdaf`.

Snapshot, isolated restore rehearsal, update, doctor and verify all exited 0.
The running image revision and binary hash match the candidate. Public discovery
returned HTTP 200 with the expected issuer before and after the official runs.
No production database was used for the Rust regression tests. The official
runs used their owned temporary tenants and cleaned each of them successfully.
No active conformance run journal remains; Suite evidence is retained.

## Root cause and change

The VCI service already rounds issuance and expiry claims to UTC days. The
mdoc signer correctly prevents `signed` from preceding the pinned DS
certificate's `notBefore`, but locally generated DS/IACA certificates previously
started at their precise generation second. On the first day, that certificate
lower bound replaced the rounded time.

The previous three batches each contained ten credentials with
`signed = validFrom = certificate.notBefore = 2026-10-11T02:46:13Z`.
Their `validUntil` was already rounded. The original Suite warning records use a
120-second near-now heuristic; waiting longer can hide the warning without
removing the precise timestamp. Historical fluctuations therefore do not prove
that the privacy issue was absent.

`build_openid4vc_certificate_bundle` now anchors locally generated mdoc DS and
IACA validity to the UTC creation day. Both ends use the same boundary: DS
lifetime remains exactly 457 days and IACA lifetime 3650 days. Expiry moves
no later than before (less than one day earlier), and credential expiry is not
extended. Key generation/publication, signing leases, revocation, signatures,
holder binding, imports and historical material retention are unchanged.
No request-path queue, storage write or background mechanism was added.

[RFC 9901 §10.1](https://www.rfc-editor.org/rfc/rfc9901.html#section-10.1)
describes rounded or randomized time claims for batch unlinkability.
[RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)
defines certificate validity boundaries. This repair aligns issuer-owned
certificate validity with the existing credential privacy interval; it does
not bypass either certificate boundary.

## Regression and quality evidence

The negative variant preserves the old now-based builder behavior and adds
only the regression plus explicit clock input. It compiled and ran, then failed
with exit **101**: actual `notBefore = 1791590401`, expected `1791590400`.
There was one assertion failure, zero passed and zero ignored; this is not a
compile failure. The exact variant patch hash is retained in the evidence.

After repair, the deterministic certificate test covers midnight, one second
later, midday, the last second and the following UTC day. It checks the actual
DER validity fields and retained mdoc profile. The full owning lifecycle group
also exercises generation reuse, concurrent initialization, rotation,
historical roots/CRLs and import preservation.

All commands below exited **0** on Hostinger with Rust 1.99.0, one checkout,
one target cache and `CARGO_BUILD_JOBS=2`. The test and quality group also set
`RUST_TEST_THREADS=1` and `LC_ALL=C`:

```sh
cargo +1.99.0 test --release --locked -p nazoauth --lib keyctl::openid4vc_material::tests -- --nocapture
# 16 passed, 0 failed, 0 ignored
cargo +1.99.0 test --release --locked -p nazo-oauth-server --lib domain::openid4vc::credential_crypto::tests -- --nocapture
# 34 passed, 0 failed, 0 ignored
cargo +1.99.0 test --release --locked -p nazo-openid4vci --test service_contract -- --nocapture
# 8 passed, 0 failed, 0 ignored
cargo +1.99.0 fmt --check
python3 scripts/verify_static_contracts.py --check
python3 scripts/check_persistence_dependency_graph.py
cargo +1.99.0 clippy --release --locked -p nazoauth --lib --tests -- -D warnings
cargo +1.99.0 build --release --locked -p nazoauth
```

## Official rerun

Each command used the private candidate, target instance `production`,
`NAZOAUTHCTL_TARGET_STATE_ROOT=/var/lib/nazoauthctl/target-state`, and exited 0:

```sh
$CTL --instance production oidf run openid4vc-vci-p029 --json --jobs 4 --poll-timeout 1800
$CTL --instance production oidf run openid4vc-vci-p031 --json --jobs 4 --poll-timeout 1800
$CTL --instance production oidf run openid4vc-vci-p033 --json --jobs 4 --poll-timeout 1800
```

| Plan | Modules | PASSED | SKIPPED | Seconds | Batch module |
| --- | ---: | ---: | ---: | ---: | --- |
| p029 | 15 | 15 | 0 | 86.89 | `dZVGw1iBjBaCdnx` |
| p031 | 15 | 14 | 1 | 91.90 | `TWIMnAPNbMCmO1H` |
| p033 | 15 | 15 | 0 | 72.37 | `D0VqapvCsVAWt2L` |

The one SKIPPED module is
`oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm` in p031's plain
response variant, unchanged from the baseline. It is not counted as passed.
All three plans have `acceptance_pass=true`; p031 retains `suite_pass=false`
because its official result set includes that SKIPPED module.

Every one of the 30 credentials has:

| Field | Observed value |
| --- | --- |
| DS notBefore, signed, validFrom | `2026-10-11T00:00:00Z` |
| validUntil | `2027-10-11T00:00:00Z` |
| DS notAfter | `2028-01-11T00:00:00Z` |

All three `VCIEnsureBatchTimeClaimsNotLinkable` checks return SUCCESS. Each
credential also passes its issuer signature, DS chain and both certificate-time
bounds; each batch passes distinct holder keys and matching sent proof keys.
All 45 raw module hashes, three manifests and their public report hashes verify.

## Scope and retained evidence

CODE, the affected SECURITY boundaries, and these three PRIVACY warnings:
**PASS**. The selected plans retain their actual official results above.
This is not a rerun of the earlier 516-module selection or a certification
approval; its other REVIEW items and four discovery-scope warnings are outside
this change and remain in the historical report.

Existing and imported certificates are not silently reissued or backdated.
An imported certificate with a precise first-day lower bound can still constrain
the MSO to that boundary. Such authorities must provision a validity interval
compatible with their privacy policy or assess the shared cohort; this patch
does not claim general unlinkability for arbitrary imported certificates,
issuer/verifier collusion or identifying disclosed claims.

The [sanitized command and module ledger](../../../evidence/deployment-upgrade-20261010/oidf-mdoc-privacy-20261011.json)
contains full source identity, actual commands/exit codes, the negative proof,
before/after batch intervals, module IDs/hashes and cleanup evidence.
Private raw evidence remains under
`/var/lib/nazoauthctl/evidence/main-oidf-20261010/mdoc-privacy-20261011`;
credentials, private keys, access tokens and raw module configurations are not
published. The [preceding report](oidf-no-webdriver-2026-10-11.md) is retained
unchanged. No merge was performed.
