# Fresh Deployment and Production Activation

This runbook intentionally replaces the current NazoAuth data plane and gates
activation on host-local OIDF conformance. It is not the quick-start path. For
a normal first deployment or upgrade, use [Deployment Guide](deployment.md).

The procedure uses Docker Compose as its platform-neutral control interface.
An operator may use another orchestrator if it preserves the same ordering,
isolation, persistence, and verification boundaries.

## Completion boundary

Production is active only when all of these are true:

1. backend and frontend artifacts come from clean, exact, reviewed commits;
2. the application image contains the single `nazoauth` binary;
3. PostgreSQL and Valkey use newly created storage;
4. migrations, health, discovery, and public UI checks pass;
5. fresh applicant and administrator journeys pass through public APIs;
6. host-local OIDC/FAPI and OpenID4VC matrices finish successfully;
7. the activation record contains artifact, data, backup, and test evidence.

Do not turn a failure into an expected failure or skip merely to pass this
gate.

## Parallel and serial work

| Stage | Work | Scheduling |
| --- | --- | --- |
| A1 | verify commits, test, build immutable artifacts | parallel with A2/A3 |
| A2 | database backup, config/key manifest, source archive | parallel with A1/A3 |
| A3 | capacity, network, proxy, and OIDF preflight | parallel with A1/A2 |
| Gate A | A1, A2, and A3 succeed | serial join before downtime |
| B1 | stop writes and remove only inventoried containers | serial |
| B2 | remove the verified old source directory | after B1 |
| B3 | create new storage and an empty database | after B2 |
| B4 | migrate, start, and switch traffic | after B3 |
| B5 | create two isolated fresh-user journeys | parallel per user, ordered within each user |
| Gate B | users, profile, administrator, and smoke checks pass | serial join |
| C1 | OIDC/FAPI matrix | after Gate B |
| C2 | OpenID4VC matrix | after C1 |
| Gate C | evidence and cleanup pass | production activation |

OIDF plans use `--plan-group-size 1` because they share browser sessions,
dynamic clients, and proxy state. Read-only health monitoring, log hashing, and
result summarization may run concurrently.

## A. Prepare without downtime

### A1. Build the exact artifact

Require clean, pushed source commits and run the repository quality gates.
Build once and record the image ID and source revision:

```sh
docker compose build
docker compose images
```

If a registry or isolated builder supplies the image, pin its digest and verify
the embedded source revision. Do not rebuild the same commit independently in
each later stage.

### A2. Create a recovery point

Use a new, access-restricted backup directory. In parallel, capture:

- exact container and volume inventory;
- PostgreSQL custom-format dump;
- runtime configuration and a key-file checksum manifest;
- exact source commit archive;
- current image ID and public UI revision.

Validate the database dump with a matching PostgreSQL image, validate the
source archive listing, and verify every checksum. Do not enter downtime until
all recovery evidence passes.

### A3. Preflight

Confirm:

- enough disk space for the new image, database, results, and rollback copy;
- the intended reverse-proxy upstream and public HTTPS issuer;
- the pinned OIDF suite revision and clean runner workspace;
- unique names for the new database, storage, and result directories;
- a tested rollback path that does not overwrite the backup.

## B. Replace the data plane

1. Stop external writes.
2. Remove only the application, PostgreSQL, Valkey, and OIDF containers listed
   in the reviewed inventory. Preserve old volumes as rollback evidence.
3. Verify the source archive again, resolve the exact old source path, then
   remove only that directory.
4. Create new PostgreSQL, Valkey, key, and avatar storage. Start an empty
   database; do not restore the old dump.
5. Select the new private configuration through `NAZOAUTH_CONFIG`.
6. Run migration and start the server:

```sh
docker compose up -d
docker compose ps
```

Keep the reverse proxy on the old target until health and discovery pass, then
switch it atomically to the candidate. A Compose-only single-node deployment
already exposes the candidate on loopback and does not need a proxy-specific
release script.

## Fresh-user gate

Do not reuse users, sessions, or subject IDs from the old database.

Create an applicant and administrator through `/auth/register` using separate
verification codes and cookie jars. For each user, keep registration, login,
profile update, and avatar upload ordered. The two user journeys may run in
parallel when their identity and session material is isolated.

If no public first-administrator bootstrap exists, promote only the freshly
registered administrator through one controlled database update. Never insert
users directly or copy old records. Complete every applicant claim required by
the OIDC `profile`, `address`, and `phone` scopes.

## C. Production and OIDF gates

Verify the public HTTPS origin:

- `/health`;
- `/.well-known/openid-configuration`;
- `/ui/auth` and at least one referenced asset.

Run conformance from an exact, clean source export:

1. OIDC/FAPI full matrix with `--plan-group-size 1`;
2. clean dynamic clients, browser sessions, and temporary proxy state;
3. OpenID4VC full matrix with `--plan-group-size 1`;
4. clean onboarding state, generated plan configs, and temporary private keys.

The OpenID4VC operator material must bind the current fresh applicant through
`--subject-id`. Require a non-empty mTLS trust bundle only when the current run
requested at least one trust anchor.

Both the product source and OIDF suite must finish with
`git status --porcelain` empty, including untracked files.

## Activation record

Record:

```text
activation status and UTC time
backend/frontend commits
image name, digest, and source revision
new database and storage identifiers
backup identifier and verification status
deployment/orchestrator revision
OIDF suite revision
OIDC/FAPI result directory, counts, and exit code
OpenID4VC result directory, counts, and exit code
source, suite, onboarding, and private-material cleanup status
```

Until both matrices and cleanup gates pass, the state is “candidate deployed,”
not “production activated.”
