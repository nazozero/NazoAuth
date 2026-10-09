# Publication of the validated storage/model candidate

Source commit: `7203ab33a79dc2db2cad801e15d75e313fdc689b`.
Base: `4b4fdc33b6a570aa270b17f5785e1f3188f3fc84` (GitHub main at publication preparation).
Validated patch SHA-256: `8057cd5e01e3f6a45ee7fdb239a77090ac73bcb98722d0d6ddf776bb7a59c744`.

The clean replacement CNB checkout used the same base and exact saved patch.
Patch SHA-256, reverse-application check, staged whitespace check and static
contracts check passed. No source repair or rebase was made during publication.
The replacement image has no Cargo: repeating the persistence dependency
graph check there exited 1 with FileNotFoundError for cargo. This is not a new
passing run. The original candidate's successful boundary check, Clippy,
real-service regressions and workspace results remain the validation evidence.

REPORT.md and all original evidence are historical and unchanged, including
their then-uncommitted candidate status and unsuccessful intermediate commands.
The source is now committed at the SHA above. No merge or deployment occurred.

Code, affected security boundaries and affected recovery regressions passed.
The original workspace run has 3707 passed, 0 failed, 4 ignored; the FAPI PAR
ignored case was subsequently run explicitly and passed. The other ignored
cases are not counted as passing standalone executions.

The owner paused further performance investigation and requested publication
after code review. This does not change PERFORMANCE=FAIL or STORAGE=INVALID
in the original report. Shared-resource interference is a plausible cause,
not an established explanation or exemption. The independent 72000-decision
cohort reached zero after its final retention deadline and a full natural
cleanup cycle; the two sustained runs retain their incomplete terminal proof.

Migration 00600 changes the maintenance function signature; the migration and
application must be deployed together. Internal public Rust model shapes also
change; HTTP protocol fields and existing safety retention remain unchanged.
