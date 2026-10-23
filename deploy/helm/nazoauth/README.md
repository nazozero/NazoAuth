# NazoAuth Helm chart

This chart supplies Kubernetes Deployment, Service, configuration, and volume
templates. It is not the signed `nazoauthctl` install/update/recovery lifecycle.
Review the rendered manifests against the current
[deployment contract](../../../docs/operations/deployment.md) before use.

## Current prerequisites and template limits

- Provision PostgreSQL and Valkey separately. `connections.existingSecret`
  supplies `database-url` and `valkey-url`; the server uses the runtime role.
  The chart does not run lifecycle migrations or tenant bootstrap.
- Set `valkeyStateEpoch` to the deployment's current UUIDv7. A restore requires
  a fresh epoch and the token-invalidation/ingress-deadline recovery procedure;
  an ordinary restart reuses its existing epoch.
- Set `signing.existingSecret`, `signing.wrappingKeySecretKey`, and
  `signing.wrappingKeyId` to the wrapping root already used by the database.
  The chart mounts the root and supplies its file path; it does not generate
  the root or initialize the encrypted database keyset.
- `appSecrets.existingSecret` optionally imports the client-secret pepper,
  pairwise subject secret, and dynamic-registration token. Without it these
  values, the MFA root, and instance identity persist on the data PVC.
- This Deployment supports one replica with persistence enabled. Each HA
  instance needs its own persistent identity and correctly shared encryption
  roots; those resources are not supplied by this chart.
- Startup, readiness and liveness probes use the public issuer's Host.
- The image template renders `repository:tag`. Verify the artifact first and
  pin its platform digest in the rendered Deployment through the deployment
  pipeline; a mutable tag alone does not verify Release identity.

## Render for review

Create the connection Secret from private files, then render a single-instance
candidate with a deployment-owned values file:

```sh
kubectl create secret generic nazoauth-connections \
  --from-file=database-url=/secure/database-url \
  --from-file=valkey-url=/secure/valkey-url
helm template nazoauth ./deploy/helm/nazoauth \
  --values /secure/nazoauth-values.yaml
```

The values file must set the verified image reference, public issuer,
`valkeyStateEpoch`, exact trusted proxy CIDRs, and the secret/volume inputs
above. Review and apply the resulting manifest only after completing the
lifecycle and probe requirements.

## TLS and external signing

The chart requires `transportMode=trusted-proxy`; its Service and probes use HTTP
inside the cluster. Set `mtls.trustedProxyCidrs` to the exact ingress peers and
configure an ingress/gateway separately. The current chart does not mount the
server/client-CA identities or TLS probes required for Direct TLS and rejects
that mode when rendering. Follow the
[proxy contract](../../proxy/README.md) when forwarding certificate identity.

`signing.externalCommand` configures an external signer. Its executable and
credentials require `extraVolumes` and `extraVolumeMounts`; selecting a command
does not itself establish KMS/HSM custody or recovery guarantees.
