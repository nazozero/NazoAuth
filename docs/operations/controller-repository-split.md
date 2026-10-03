# NazoAuthCtl repository split

NazoAuth and NazoAuthCtl are separate release and failure domains.

NazoAuth owns the server, `operator-task`, migrations, production-key mutation,
consistency leases, and the local `admin-provision` command. NazoAuthCtl owns host and
container orchestration, Release/OCI verification, task issuance and receipt
verification, controller audit state, backup lifecycle, recovery, diagnostics,
the administrator-provisioning client, and controller self-update/rollback.

The signed `keys-list` and `keys-validate` operations diagnose one existing
authoritative key generation. They validate its sealed public/private material
without creating missing keys, advancing rotation, or resealing wrapping keys.
Missing or invalid generations fail; initialization and maintenance remain
explicit mutation/startup responsibilities.

The command entry retains first-admission registry, signature, deployment and
configuration checks. An existing accepted journal remains bound to the exact
operation id/request hash and owns its original authorization snapshot; receipt
recovery introduces no additional command surface or caller-authentication bypass.
Stored resource outcomes contain only revision, public identities/mappings and
manifest digest, never passwords, client secrets or private key material.

Accepted tenant-resource operations recover their exact, validated database
outcome before loading current tenant configuration or mutation capabilities.
A committed outcome remains recoverable after a later tenant disable or config
loss. A missing outcome retains the active-tenant admission gate; only Apply
loads change-set payloads and registration/key preparation. Enumerate and Revoke
use the same atomic state, audit and outcome owner without those capabilities.

`crates/operator-protocol` remains only in this repository. NazoAuthCtl pins a
released package version by server tag. Tagged server Releases additionally
publish that exact package with provenance so later controller dependency
updates have an immutable review subject; the compiled controller never
downloads it during recovery. The server Release manifest schema 7
binds `operator_protocol.version`. Interoperability uses the accepted protocol
version and manifest schema, not a separately maintained controller SemVer
range. Missing, malformed, or unsupported contracts fail closed; the controller
[compatibility contract](https://github.com/nazozero/NazoAuthCtl/blob/main/docs/compatibility.md)
is the authority for its accepted formats.

The same crate owns the signed online discovery and offline deployment
statement contracts; see [control discovery](control-discovery.md). These
identity statements never substitute for independent Release and artifact
verification.

The server release workflow builds each server platform binary once. The same
uploaded binary is used by OCI assembly, smoke checks, custom attestation,
standard provenance, signing evidence, and publication. It never builds or
publishes NazoAuthCtl. Cross-repository integration downloads signed server
Release/OCI artifacts and does not rebuild the server. Before publication,
candidate validation may build both current working trees directly, including
their uncommitted changes; the exact artifact digests, not Git state, identify
what is deployed for that validation.

The server repository contains no controller implementation, controller release
job, controller state, or alternate command surface. NazoAuthCtl is built and
published from its own repository. Cross-repository verification selects one
exact controller commit and one exact supported server Release; coupled
publication must not be reintroduced.

Recovery commands are not application operations. Backup recovery,
interrupted-update recovery, and identity recovery must work with the HTTP
service stopped and without trusting execution of the failed server runtime.
Whole-machine loss remains an off-host recovery-package boundary; a controller
and backup stored only on the lost machine cannot satisfy it.
