# Release Security

## Scope

Dependency, image, signing, and provenance checks are release gates. A release
artifact is not trusted until these gates pass for the exact commit or tag.

## Continuous Gates

The `conformance-security` workflow runs supply-chain checks for code,
dependency, migration, script, deployment, container, runtime config, and
workflow changes:

- `cargo audit` over `Cargo.lock`
- `cargo deny` using `deny.toml`
- CycloneDX SBOM generation for Rust dependencies
- container image build from `Containerfile`
- Trivy vulnerability scan of the built image
- SBOM upload as a workflow artifact

The supply-chain job is independent from the Rust unit/integration gate.
Dependency and image regressions fail before a deployment-shaped release is
trusted.

`dependency-review` also runs `cargo audit` on a weekly schedule, so a newly
published advisory is evaluated even when the repository has no new commit.
Dependabot and the single root `renovate.json` configuration cover Cargo,
GitHub Actions, container/Compose inputs, locked Python inputs, the exact Rust
stable pin, and the pinned security CLI versions. Renovate vulnerability
alerts are not restricted to the normal weekly update window.

## Tagged Release Gates

The `release-security` workflow runs for `v*` tags and manual dispatch:

- a tag-triggered run accepts only an exact stable `vMAJOR.MINOR.PATCH` tag;
  the tag without its `v` prefix must equal `[workspace.package].version`, and
  `cargo metadata --locked` must resolve every workspace member to that same
  version. A mismatch stops the policy job before artifacts are built or
  published
- the tag commit must be reachable from `main` with successful exact-SHA `main`
  push quality gates. Arbitrary branches and unverified tags fail closed
- a `workflow_dispatch` for a commit reachable from `main` remains a
  non-publishing native-matrix rehearsal. It runs the policy, native tests,
  binary builds, and OCI assembly, and skips every tag-only attestation and
  publication job

- builds eight platform targets on native x86-64 and Arm64 Linux, Windows, and
  macOS runners with the pinned Rust toolchain
- executes the server binary on every native target and verifies its package
  release version and operator protocol version
- packages `nazo-operator-protocol` once from its unique source, verifies the
  package build, records its digest, and gives the exact `.crate` standard
  build-provenance attestation
- reruns `cargo audit` and `cargo deny` for the exact tag
- builds one `linux/amd64` plus `linux/arm64` OCI index
- scans the exact OCI archive with Trivy and publishes that archive without a
  second build
- generates the server CycloneDX SBOM
- binds each server binary to the closed schema-7 ReleaseManifest with the custom
  `https://nazo.run/attestations/release-manifest/v1` GitHub attestation
- derives the operator protocol version from its Rust source; controllers
  validate the manifest schema and protocol version without a release-version range
- signs the OCI index; a rerun accepts an existing tag only when it resolves to
  the exact scanned digest and rejects every mismatch
- retains SBOMs, OCI archives, predicates, and Sigstore bundles as internal CI
  evidence
- publishes exactly 8 platform-suffixed server executable files plus the exact
  versioned `nazo-operator-protocol` crate as persistent GitHub Release assets;
  JSON, tar, bundle, script, checksum, and SBOM files are not Release assets
- resumes partial publication only when every existing Release asset is
  byte-identical, and never overwrites a mismatching tag or asset
- emits standard provenance attestations in addition to the custom manifest
  predicates

Standalone production deployments consume the server binaries through the
independently released `nazoauthctl` from `nazozero/NazoAuthCtl`.
The lifecycle tool retrieves the subject's GitHub attestation, verifies the
tag-specific workflow identity and closed predicate before parsing artifact
names or changing runtime state, and verifies the OCI descriptors. Custom
deployment pipelines must enforce the same artifact identity, digest, target,
and database recovery boundaries.

NazoAuthWeb is the default, optional UI. On first use, NazoAuth discovers the
latest stable release from NazoAuthWeb's own GitHub repository, verifies the
download against that release asset's digest and size, and installs writable
files under `${DATA_DIR}/ui/current`. No frontend version or digest is stored in the
backend release manifest. Existing `index.html` prevents automatic installation;
backend upgrades do not overwrite deployed UI files or recheck their digest.

Frontend files can be replaced in place while the backend is running. Use
`UI_STATIC_DIR` for an existing custom directory, or `UI_ENABLED=false` to disable
backend UI hosting. An initial download failure is logged and does not prevent
API startup; the empty UI directory can subsequently be populated by an operator.
The frontend must remain compatible with the API it uses. This is an API contract,
not a requirement to release the frontend, backend, and controller together.

Release schema 7 omits frontend pins, controller SemVer ranges, and asserted
rollback policy. After executing a migration, the controller stops the writer
on activation failure and requires verified recovery. A successful migrated
update drops the previous artifact reference; a completed database recovery
also clears the previous reference. Neither operation claims that the previous
binary can run against the resulting database. Updates without migration retain
the existing previous-artifact rollback path.

The corresponding controller uses deployment-state schema 8 and backup-manifest
schema 5. These are closed formats: older state and backup formats are not
silently reinterpreted. Keep the prior controller and its recovery material
available when preparing this format transition; this source change does not
migrate deployed state or backups.

All controller GitHub requests are HTTPS-only across redirects and have
connection, redirect-count, total-time, and response-size bounds. Once an
attested artifact size is known, that exact size is the curl transfer ceiling;
the first server-binary fetch uses a fixed bootstrap ceiling because its digest
is the subject used to retrieve the attestation. When host Cosign is absent,
the private temporary staging directory is mounted into the pinned Cosign
container as `ro,Z`: read-only with a private SELinux relabel, compatible with
Podman and Docker without sharing the label or adding container privileges.

The precise native target and managed-lifecycle qualification boundary is
documented in [platform-support.md](platform-support.md).

## Required Evidence

For each production release, preserve:

- Git tag and commit SHA
- `conformance-security` workflow URL and conclusion
- `release-security` workflow URL and conclusion
- all 8 server binary asset names and digests
- the operator protocol package name, digest, and provenance attestation URL
- each target's custom ReleaseManifest attestation URL
- the internal server SBOM artifact name and digest
- Trivy scan result
- Sigstore certificate identity and issuer
- OCI index digest and both platform-manifest digests
- GitHub artifact attestation URLs and internal bundle references

Do not publish a release image if audit, deny, SBOM generation, image scanning,
signing, or provenance attestation fails.
