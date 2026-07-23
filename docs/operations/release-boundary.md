# Release and conformance boundary

Production artifacts contain the protocol implementation, migrations, and
operator tools. They do not contain OIDF plan definitions, runner source,
browser automation, expected-result registries, onboarding fixtures, test
credentials, or conformance scripts.

The runtime container contains only the `nazoauth` executable. Its `server`,
`migrate`, and `keyctl` subcommands expose the product and operator entry
points. OIDF tools stay in the source repository and interact with a deployed
issuer only through its public HTTPS protocol and normal public administration
flows. Product code must not branch on suite aliases, plan names, callback
paths, test headers, or a conformance build flag.

The official OpenID Foundation Conformance Suite is checked out at an exact
commit and its tracked source must remain unchanged. Repository code may prepare
external runner configuration and monitor public suite APIs, but must never
patch the official runner or its protocol assertions.

These boundaries are enforced by `tests/unit/test_release_governance.py` and the
container build. A change that needs an OIDF-specific product branch is invalid;
implement the governing specification and verify the resulting public behavior
instead.
