# Release and black-box validation boundary

NazoAuth production artifacts contain the protocol implementation, migrations,
and the independently signed `nazoauth` executable. `nazoauthctl` is built,
signed, and released by `nazozero/NazoAuthCtl`.

The server repository and artifacts contain no third-party test runner, plan
registry, browser automation, test credentials, test-only onboarding model, or
expected-result catalog. An external validator is an ordinary client: it uses
public HTTPS protocols and the same tenant/client administration available to
all other integrations. Product code never branches on validator identity,
plan names, callback paths, test headers, or build flags.

The long-running runtime container contains only `nazoauth`. Its `server` entry
point cannot mutate schema; privileged host work uses the signed controller
protocol. External validation tooling is versioned and operated outside this
repository. Maintained regression contracts and official certification links
live under [docs/conformance](../conformance/README.md). Run-specific artifact
identities, original outcomes, manual review, cleanup, and evidence digests
belong in CI artifacts or the associated issue/PR; private logs and test secrets
are not packaged into the executable or committed as project documentation.

`crates/operator-protocol` remains the single source of controller protocol and
cryptographic rules. Release compatibility is declared by protocol version and
release-manifest schema; unsupported combinations fail closed. Controller
SemVer ranges are not part of schema 7.
