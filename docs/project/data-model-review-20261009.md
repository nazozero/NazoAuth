# Data-model review and refactoring

## Final integrated review

The model review and repairs are consolidated into PR #230. Final source: `b5b0f4246d8a443466a1c256429a76f88bf2c6e0`. PRs #236 and #237 are integrated; main is not merged.

See the [complete review and evidence](../../evidence/model-consolidation-20261009/publish/README.md) and [model ownership analysis](../../evidence/model-consolidation-20261009/publish/model-review.md). The original four capacity points pass unchanged gates, and the target decision cohort naturally reaches zero after its final retention deadline and completed maintenance cycle. Historical cost increases and unmeasured long-term bounds remain explicit in the report. Final report-head CI is a separate PR gate.

<details>
<summary>Original branch tracking record (historical, not the current acceptance status)</summary>

# Data-model review and refactoring

## Baseline and scope

- Parent: PR #230, branch `refactor/authorization-decision-facts-20261001`.
- Pinned source: `3da0734de491a380b315fc2fb2827f4043c04823`.
- Refactoring branch: `refactor/model-authority-20261009`.
- Status: **IN PROGRESS**. This document does not certify an exhaustive review or passing tests.

The review includes every first-party data-model definition, not only database rows: protocol inputs/outputs, validated domain values, application commands and results, persisted records and JSON payloads, Valkey payloads and Lua state, cryptographic material, audit and delivery state, configuration, runtime and operator contracts. Test-only fixtures and historical migrations are evidence, not additional current runtime authorities.

For each field, record the fact it represents, the component that owns it, actual producers and consumers, lifecycle and invalidation, relevant protocol requirements, overlapping representations, and the decision: retain, derive, remove, or move to its owning boundary. A field-count threshold is a review aid, never a reason to split a model. A source inventory is not a semantic audit; unresolved items stay unresolved.

## Safety boundaries

- Keep tenant isolation, original authorization bounds, sender binding, single-use fences, replay revocation, original deadlines and acknowledged-commit requirements.
- Distinguish original grant authority from requested access-token scope/resource and current refresh generation.
- Distinguish authenticated facts from untrusted protocol input and from transport evidence.
- Do not replace historical decisions with current configuration or equate an unacknowledged write with a known rollback.
- A stored duplicate may be removed only after its reader, writer, transition, compatibility and concurrency obligations have been accounted for.
- Database row layout, JSON encoding, indexes, statement-cache shape and storage encryption configuration belong to adapters; protocol and atomicity semantics do not.
- No merge, deployment, force push, new paid environment or changes to PR #230 are authorized by this refactoring branch.

## Coverage ledger

The following groups are the required review surface. Listing a group here does **not** mark its fields reviewed.

| Group | Status |
| --- | --- |
| Identity, accounts, profiles, sessions and authentication | In progress |
| MFA, passkeys, federation, registration and avatars | In progress |
| Client registration, metadata, client credentials and policy | In progress |
| Authorization, PAR/JAR, consent, code and logout | In progress |
| Token issuance, refresh, exchange, introspection and revocation | In progress |
| Device and CIBA state and delivery | In progress |
| OpenID4VCI, OpenID4VP, DCQL and trust | In progress |
| Resource-server and HTTP-signature contracts | In progress |
| SCIM resources, events and polling receipts | In progress |
| Runtime modules, tenancy, operator and recovery contracts | In progress |
| Key management and cryptographic representations | In progress |
| All PostgreSQL tables, query projections and persisted JSON | In progress |
| All Valkey keys, payloads, indexes and Lua transitions | In progress |
| Host configuration, transport DTOs, examples and documentation | In progress |

## Validation

No execution result is claimed by this initial tracking commit. Refactoring commits must add focused regressions and report their exact-source results separately from baseline CI. Existing performance failures in PR #230 remain outside any correctness claim made by this review.

</details>
