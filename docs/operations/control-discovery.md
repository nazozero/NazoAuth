# NazoAuth control discovery protocol

NazoAuth exposes a product-specific, read-only discovery endpoint at
`POST /.well-known/nazoauth-control`. The request contains schema version `1`
and a fresh 32-byte base64url nonce. The response contains an Ed25519 compact
JWS with type `nazoauth-control-discovery+jwt` plus the instance public key.

The signed statement binds the nonce, issuer, immutable deployment ID,
runtime-instance ID, release version, and supported control and
operator protocol versions. It contains no database or Valkey URL, credential,
administrator data, Controller key material, Recovery Secret material, or privileged
operation.

The instance identity is separate from OAuth signing and the registered
Controller key. A single-instance deployment stores it at:

```text
DATA_DIR/instance/identity.key
DATA_DIR/instance/identity.pub
DATA_DIR/instance/deployment-statement.jws
```

For a replicated deployment, `DATA_DIR/instance/deployment-id` is the shared
logical deployment identity. Each replica must set `INSTANCE_IDENTITY_DIR` to
its own persistent mount; its `identity.key`, `identity.pub`, runtime ID and
signed statement live there and must never be shared with another replica.

`deployment-statement.jws` uses the distinct
`nazoauth-deployment-statement+jwt` type and has no freshness claim. It permits
offline identification when the server cannot start; it is not proof that the
current binary or OCI image is trusted. A recovery controller must separately
verify the mounted binary hash or local OCI digest against cached Release,
attestation, and signature evidence.

Replicas sharing a logical deployment must share the persisted deployment ID
but use separate instance identity directories and runtime-instance IDs. Set
`INSTANCE_IDENTITY_DIR` and `RUNTIME_INSTANCE_ID` per replica, and set the same
`DEPLOYMENT_ID` for the deployment. A persisted identity mismatch fails startup
closed.

The one-shot `operator-task` executor validates a signed canonical
`ControlOperation` before it claims a request: the Controller Registry key,
deployment ID and target digest must match local
facts. When `DATA_DIR/instance/deployment-id` already exists, it must agree with
`DEPLOYMENT_ID` in the mounted server configuration.
The operator-state mount also persists the same identity for one-shot
containers that intentionally do not mount the full server data directory;
once present, that anchor is required for every subsequent task. During the
first migration, before either local anchor exists, the canonical mounted
`DEPLOYMENT_ID` is the explicit bootstrap source for `migrate-apply` only.
`NAZOAUTH_OPERATOR_DEPLOYMENT_ID_FILE` may be set to require a separate
read-only identity mount; a configured but unavailable file fails closed. This
check is local and does not make the recovery controller a runtime dependency.

The wire DTOs, JWS types, signing/verification policy, strict parsing,
and fixed vectors live only in `crates/operator-protocol`. Controllers consume
the protocol version shipped by the supported NazoAuth release; they do not
copy protocol code.

First admission validates the active Controller key and its validity window.
After acceptance, the exact operation ID and request hash select the durable
journal record; a retry recovers that request's state or result even if the key
has since retired. A new request signed by a retired key is rejected. Unknown
executing outcomes require recovery by the owning operation, not blind replay.

The database and local identity files do not provide an independent monotonic
rollback anchor. Recovery must reconcile deployment, accepted release, journal,
and backup state. These identity statements do not replace the
[external audit receiver](../security/audit-anchor.md).
