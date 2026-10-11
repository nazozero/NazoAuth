# Security Cloud review — 2026-10-11

This review starts at NazoAuth `8674dc8dece7a4ba636bca12ae30cfe218f8fd2c`.
Final verified source: b4f35d27aa32db5907f81d261ceca65fe747ef8e.
It covers the 15 server findings in the 42-item Security Cloud inventory.
The controller's 27 findings are tracked in its separate report:
[NazoAuthCtl security review](https://github.com/nazozero/NazoAuthCtl/blob/7daec1eeae62e25518de332619eaa63d4cf5b778/docs/security-cloud-20261011.md).
Neither PR was merged and no production deployment was changed by this review.

## Confirmed repairs

| Finding | Root cause and repair | Verification |
|---|---|---|
| `a782199a15a88191adde44b6786e10eb` | Token admission and introspection could use a weaker explicit client policy. Server FAPI requirements are now a floor; client requirements can strengthen it. Existing authorization/PAR/JARM floors remain. | Baseline DCR metadata rejected under each FAPI token profile; global and client introspection signature requirements preserved. |
| `f9f61666352081919aa471cfdb989124` | Every unauthenticated SCIM denial caused a Required append without admission. A source-IP-hash rate limit now precedes denial auditing; admitted denials still await persistence. Limiter failure closes admission; valid credentials are not charged to this bucket. | First denial audited, excess denial returns 429 without an append, valid bearer request accepted, audit failure remains fail-closed. |
| `7f00e863ab288191a14ad40a57929d87` | Exporter SQL ACK privilege bypassed receipt verification. Only the independent receiver now has ACK/genesis privilege. It fsyncs evidence and commits before sending success; the worker verifies the signature and reads committed confirmation. | Real PG old-grant deletion proof, denied direct ACK/genesis, retained pending evidence, reachable-role negative, receiver ACK and read-only confirmation; real HTTPS faults listed below. |
| `8827b11d8f248191920d7ada1d9327fd` | Mutable release metadata authenticated no UI producer. Initial UI install now verifies the native Sigstore bundle against the embedded production root, GitHub issuer, exact release workflow/tag and downloaded digest before extraction. | Real official bundle positive; wrong tag/digest, absent bundle and altered signature negative; existing/custom UI preserved. |
| `e5737ab8feb88191bf832391a8a23160` | Tenant scoping discarded existing global module decisions for peer tenants. The affected upgrade SQL copies the global decisions before filling missing defaults. | Real PG comparison: old migration changes peer DCR to enabled; corrected migration retains disabled. The Rust SQL regression also retains explicit inherit. |
| `45a635c68dc881918a4573039b908a9d` | Schema identity omitted function behavior and security context. Canonical output includes pg_get_functiondef, definer status and function settings. | Four real PG states (original, changed body, definer, search_path): old fingerprint identical; new fingerprints all distinct. |
| `258d866cb4108191bb8642a01dbfb319` | Refresh invalid_grant alone was treated as expected. Both producer and legacy evaluator now count uncorroborated rejection as failure. | Actual JS producer run under Node returns unexpected; capacity accounting regressions pass. No capacity benchmark was re-run or reclassified as passing. |
| `63963f182c208191ac0c6c9f00965971` | Rotation ignored registered external candidates. Eligible external successors of the active algorithm participate in rotation and take priority over automatic local candidates; external-active keysets never silently fall back to local signing. | Key-management suite, local-to-external and subsequent external rotation; existing prepublication/grace rules retained. |
| `523ec04ed1f4819181284948aa458dc1` | Higher-revision Valkey JSON could directly change tenant routing. Cache entries now trigger authoritative PG reconciliation only; higher forged revisions are quarantined and repaired from PG. | Forged higher revision host swap/empty directory scenarios plus real Valkey authoritative repair. |
| `fcd43a6febc88191903efd95f36e5e95` | Compose passed the Valkey password as argv. A private tmpfs configuration file now supplies it; the process environment is unset before exec. | Real pinned Valkey: no-auth rejected, authenticated PONG, no password in argv, file mode 0600. |

Previously fixed in the starting source: `4ee7ab7d1e148191864f81227b3817d1`
(silent OIDC login session binding) and `3c5edcfccc808191bf6fbd10171a2e22`
(measured operation failures in the capacity gate). Their closure is not attributed
to a new patch in this review.

## Required operational boundaries

The audit role change is a coordinated cutover. Migration
`20261011000100_receiver_owned_audit_ack` revokes all non-owner ACK/genesis
function grants, including old exporter grants. Provision the independently
protected receiver login after migration, configure its database connection,
and upgrade receiver and worker together before admitting Required traffic.
The reference receiver is in `perf/audit-anchor-receiver`; this review does not
claim that a separately deployed receiver has been upgraded. Application and
exporter credentials must not be able to assume receiver authority. No permanent
local archive, additional queue, or weaker commit confirmation was introduced.

The tenant correction intentionally updates the historical scope migration and
its recorded checksum. Databases that already recorded that migration do not
replay it. This patch is not a claim that their current per-tenant policies were
reconciled: compare the pre-upgrade policy and subsequent administrative events.
Where that provenance is absent, preserve the current data and obtain an explicit
policy decision; do not infer intent from a default-looking row or overwrite it.

## Findings retained open

- `c39bb8659c448191a3879b164c3ffd95`: a real bounded detection window remains.
  Expired/missing codes always fail, but after the compact receipt expires a
  code replay cannot identify the original longer-lived refresh family for
  directed revocation. Current retention follows code/access-token acceptance,
  not refresh-family lifetime. This is not represented as fixed or as full
  replay-triggered family revocation. RFC 6749 requires denying code reuse and
  recommends revocation when possible; changing this storage/security policy
  needs separate work, not an unsupported assertion that the risk disappeared.
- `23c5f4f2ee3c8191be70c617b69dfdd2`: old/new FAPI HTTP-signature namespaces are
  not safe for mixed-version rolling admission. The supported cutover stops all
  old consumers and drains the old acceptance window (configured max age + 5s,
  at most 305s, with time past the boundary) before starting new consumers.
  The specific runbook has been restored; no permanent dual-key authority was
  added, and the unsupported mixed-version behavior is not claimed repaired.
- `0f53090993b081918eb1655299e47194`: the current privileged controller measures
  the live artifact against protected DeploymentState before executing a signed
  operation. The server authenticates deployment/configuration/request bindings.
  The proposed attack requires influence over privileged host/engine execution;
  no independent lower-privilege route was established in the current path.
  Stale documentation claiming server-side artifact measurement was corrected.
  This is a current-boundary classification, not a new artifact-envelope fix.

The connector only supports closing an item as fixed. Unresolved policy risks
and findings not reproduced under the current authority model remain open;
absence of a reproduced exploit is not used as a fake repair justification.

## Executed verification

All checks below ran in the authorized isolated fixtures on Hostinger, using
one existing checkout and one target cache. Rust 1.99.0, two build jobs and one
test thread were used. Database URLs, receiver credentials and test signing keys
were supplied privately and are not included in this report. The Python command
used the evidence virtual environment containing the required dependencies.

| Actual command | Exit | Scope |
|---|---|---|
| `cargo +1.99.0 test --release --locked -p nazo-oauth-server -p nazo-key-management --lib` | 0 | 375 OAuth + 88 key-management tests |
| `cargo +1.99.0 test --release --locked -p nazo-postgres --test audit_receiver_authority` | 0 | Real PostgreSQL old-grant exploit and receiver-only authority |
| `cargo +1.99.0 test --release --locked -p nazo-postgres --test tenant_module_scope` | 0 | Real PostgreSQL tenant policy preservation |
| `cargo +1.99.0 test --release --locked -p nazo-postgres --test audit_preflight_roles --test audit_pending_upgrade` | 0 | 6 real PostgreSQL role and pending upgrade cases |
| `cargo +1.99.0 test --release --locked -p nazoauth --lib ui_release -- --nocapture` | 0 | 8 passed; opt-in live case separately executed below |
| `cargo +1.99.0 test --release --locked -p nazoauth --lib ui_release -- --ignored --nocapture` | 0 | 1 live official UI download, verify, install and custom replacement |
| `cargo +1.99.0 test --release --locked -p nazoauth --lib adapters::audit_anchor -- --nocapture` | 0 | 46 passed, including real PostgreSQL idle heartbeat |
| `cargo +1.99.0 test --release --locked -p nazo-valkey --test tenant_directory_cache_contract` | 0 | Real Valkey authoritative cache repair |
| `cargo +1.99.0 clippy --release --workspace --all-targets --all-features --locked --keep-going -- -D warnings` | 0 | Workspace compile/lint, not a full executed workspace test suite |
| `cargo +1.99.0 clippy --release --locked --manifest-path perf/audit-anchor-receiver/Cargo.toml --all-targets -- -D warnings` | 0 | Standalone receiver compile/lint |
| `cargo +1.99.0 fmt --all -- --check` | 0 | Server format |
| `cargo +1.99.0 fmt --manifest-path perf/audit-anchor-receiver/Cargo.toml -- --check` | 0 | Receiver format |
| `python3 scripts/verify_static_contracts.py --check` | 0 | Static contracts and migration checksums |
| `cargo +1.99.0 build --release --locked -p nazoauth --bin nazoauth` | 0 | Final server release binary |
| `cargo +1.99.0 build --release --locked --manifest-path perf/audit-anchor-receiver/Cargo.toml` | 0 | Final receiver release binary |
| `bash perf/tools/audit_anchor_fault_regression.sh` | 0 | Real PostgreSQL + HTTPS: 12 scenarios, 34 assertions, zero failures |
| `python -m unittest -v perf.tests.test_capacity_window perf.tests.test_stream_cohort perf.tests.test_capacity_producer` | 0 | 87 tests: 85 passed, 2 k6-dependent skips; Node invalid_grant regression executed |

Cargo deny (advisories, bans, licenses and sources), the persistence dependency
graph check, shell/Python syntax checks and git diff --check also exited 0.
Controller workspace execution is documented in the linked controller report.
The server workspace was compiled and linted, but only the affected server suites
were executed locally; this is not a claim of a full local workspace test run.

The [machine-readable ledger](security-cloud-20261011.json) records the commands,
exit codes, before/after fingerprint and tenant-policy observations, binary
digests and final receiver/database checkpoint.

### Real receiver failure and recovery

The actual final binaries exercised receiver outage, HTTP 500, dropped response
after persistence, invalid signature, permanent reject/unblock, concurrent
exporters, tampering, drain and dropped response after database ACK. The final two
cases injected a deferred commit exception and terminated the receiver backend
during COMMIT. An independent connection observed the terminated backend gone.
Both cases returned HTTP 5xx; the worker did not report confirmed anchoring before
recovery. Retry preserved the receiver's durable event identities.

After recovery the receiver journal held **62 accepted, unique events**. PostgreSQL
and the receiver both ended at sequence **62**, hash
`628ca13fc13d91ea7f5ebbd1c38a882480045f36a48c650a31e0bdcf2e50e86f`.
Pending events and retained chain entries were both **0**. All **12 scenarios /
34 assertions passed**. These are real PostgreSQL and HTTPS results. Database TLS
was explicitly disabled only inside this isolated fixture; HTTP delivery used the
test CA. This does not establish production deployment or production DB TLS
configuration.

The separate authority regression reproduces deletion under the old exporter ACK
grant and then denies that same login ACK/genesis after migration. It also rejects
reachable receiver authority through SET ROLE. Receiver confirmation still works.

### Acceptance boundaries

The ten repairs above pass their targeted checks. Two server findings were
already fixed before this revision. Three server findings remain open with the
reasons above; the controller report retains one further classification item.
No benchmark was used to assert improved capacity, no production migration was
performed, and no CI result is inferred from a local build. Earlier failed setup,
compile and fixture attempts remain in private execution evidence; they are not
counted as negative vulnerability demonstrations.

