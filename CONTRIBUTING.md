# Contributing to NazoAuth

## Contributions and licensing

Pull requests for code, tests, and documentation are welcome. You can submit a
pull request directly; no contributor license agreement (CLA), copyright
assignment, or Developer Certificate of Origin (DCO) sign-off is required.

By submitting a contribution for inclusion in this repository, you license it
under the [Apache License 2.0](LICENSE) and confirm that you have the right to
do so. You retain copyright in your work. Preserve applicable third-party
licenses and attribution notices. Contributions accepted under earlier terms
retain those terms unless their copyright holders separately authorize
relicensing.

Dependency updates remain subject to the dependencies' licenses and the
repository's supply-chain policy.

Code contributions must follow the workspace boundaries in
[docs/project/architecture.md](docs/project/architecture.md) and the mandatory
test layout in [docs/project/testing.md](docs/project/testing.md). The latter is
enforced by `python scripts/verify_static_contracts.py --check`.

Do not submit confidential information or material you are not authorized to
share.

## Documentation

Update affected documentation, examples, translations, and indexes when a
change affects documented behavior, contracts, ownership, configuration,
source paths, or other documented facts. Purely internal or mechanical
changes with no documentation impact do not require documentation-only
churn. Follow
[documentation maintenance rules](docs/README.md#maintenance-rules): keep durable
contracts and runbooks, put one-time task/review evidence in the issue, PR, or
CI artifacts, and repair indexes and references when removing a document.
