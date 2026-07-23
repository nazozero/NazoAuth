# Fresh Deployment and Production Activation

This runbook replaces the NazoAuth runtime containers and the old remote source
tree, starts PostgreSQL on a new database and new volume, deploys immutable
backend/frontend commits, and promotes the candidate only after host-local OIDF
conformance passes. For normal data-preserving releases, use
[deployment.md](deployment.md).

## Completion boundary

Production activation requires all of the following:

1. clean, pushed, exact backend and frontend commits;
2. an application image containing only the `nazoauth` application binary;
3. a newly created PostgreSQL database on a newly created volume;
4. successful migration, health, discovery, UI, and public asset checks;
5. passing host-local OIDC/FAPI and OpenID4VC OIDF matrices;
6. a record of commits, image ID, database and volume names, backup path, suite
   revision, result directories, counts, and activation time.

Treat every conformance failure first as evidence of an incomplete deployment,
configuration, or runtime transition. Do not convert failures into skips or
expected failures to satisfy the activation gate.

## Parallel/serial execution graph

The workflow is a gated DAG:

| Stage | Work | Scheduling |
| --- | --- | --- |
| A1 | source verification, tests, exact-commit frontend build, image build | parallel with A2/A3 |
| A2 | database dump, config/key manifest, old-source archive | parallel with A1/A3 |
| A3 | capacity, network, proxy, and OIDF runner preflight | parallel with A1/A2 |
| Gate A | A1, A2, and A3 all succeed | serial join before downtime |
| B1 | stop writes and remove only inventoried NazoAuth/OIDF containers | serial |
| B2 | verify the archive, then remove `/home/nazoAuth` | after B1 |
| B3 | create new PostgreSQL/Valkey volumes and the new database | after B2 |
| B4 | migrate, start the candidate, verify it, switch the UI | after B3 |
| C1 | production smoke tests | serial activation gate |
| C2 | host-local OIDC/FAPI matrix | after C1 |
| C3 | host-local OpenID4VC matrix | after C2 |
| Gate C | C1, C2, and C3 all succeed | production activation |

Independent A-stage jobs may run concurrently because they do not mutate the
same state. OIDC/FAPI and OpenID4VC remain serial with
`--plan-group-size 1`: they share browser sessions, dynamic clients, and proxy
state. Result summarization, log hashing, and read-only production monitoring
may run in parallel after each matrix ends.

## Destructive-action boundary

Create a root-only backup directory and record exact container and volume
inventories before removal. Back up the current database with `pg_dump -Fc`,
copy the root-only runtime configuration, hash the runtime key files, require a
clean `/home/nazoAuth` worktree, and archive its exact commit with
`git archive`. Validate the dump list through
`podman run --rm -i postgres:18 pg_restore --list <oauth.dump` rather than
assuming the host has `pg_restore`; also validate the tar listing and hashes
before entering downtime. Record the size of `target` but do not archive that
reproducible build cache.

Remove only names reviewed in the inventory, such as:

```text
nazo-oauth-server
nazo-oauth-server-rollback-*
nazo-oauth-postgres
nazo-oauth-valkey
the explicitly inventoried OIDF compose containers
```

Never use a broad image/label match to delete containers. Preserve the old
PostgreSQL and Valkey volumes as recovery points. Verify
`realpath /home/nazoAuth` and the source archive before deleting that exact
directory. Do not recreate it.

## Fresh data plane

Use a unique UTC run ID. Create new volumes named with that run ID and a new
database such as `oauth_fresh_<run-id>`. Preserve the database credential from
the root-only config, update only the database path in `DATABASE_URL`, and never
print the credential. Start:

- PostgreSQL 18 as `nazo-oauth-postgres` on `nazo_oauth_net`,
  `10.101.0.10`, with the new database and new volume;
- Valkey 8 as `nazo-oauth-valkey` on `10.101.0.11`, with a new volume and the
  existing persistence command.

Require `pg_isready`, `valkey-cli ping`, and a database inventory showing only
the new application database plus PostgreSQL system databases. Do not restore
the old dump into the fresh database.

## Immutable deployment

Run [scripts/deploy_live.ps1](../../scripts/deploy_live.ps1) with exact pushed
backend/frontend commits, explicit worktrees, issuer, and expected branches.
Pre-merge deployments must name their review branches and must not claim
`main`. The script rechecks sources and provenance, loads the immutable image,
runs `nazoauth migrate`, starts `nazoauth server`, verifies the internal
candidate and Angie upstream, atomically switches the UI, and verifies public
assets.

Export the exact backend commit with `git archive` to
`/opt/nazo-oauth/conformance/sources/<backend-sha>` for conformance. The
production image must not contain the OIDF runner or suite.

## Production and OIDF gates

Require public health, discovery, login UI, and referenced asset checks before
starting conformance. Recreate the pinned-revision host-local OIDF compose
project on its own network. Run the OIDC/FAPI full matrix, clean its dynamic
state, then run the OpenID4VC full matrix and clean its onboarding/private
material. Use unique result directories under
`/opt/nazo-oauth/conformance/results`.

Record:

```text
run_id, backend_sha, frontend_sha, image_id
database_name, postgres_volume, valkey_volume, backup_root
deployment_record, oidf_suite_revision
OIDC result directory and passed/total
OpenID4VC result directory and passed/total
activation timestamp (UTC)
```

Until both matrices are fully passing, the state is “candidate deployed,” not
“production activated.”
