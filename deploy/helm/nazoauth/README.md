# NazoAuth Helm chart

This chart supplies Kubernetes Deployment, Service, configuration, and volume
templates for a single persistent instance. The deployment operator prepares
infrastructure, initializes application state and applies the rendered manifests.
Follow the [deployment contract](../../../docs/operations/deployment.md) for
bootstrap, migration and recovery requirements. NazoAuthCtl provides the separate
signed host install, update and recovery workflow.

## Prerequisites

- Provision PostgreSQL and Valkey separately. `connections.existingSecret`
  supplies `database-url` and `valkey-url`; the server uses the runtime role.
  Complete lifecycle migrations and tenant bootstrap before starting the Pod.
- Set `valkeyStateEpoch` to the deployment's current UUIDv7. A restore requires
  a fresh epoch and the token-invalidation/ingress-deadline recovery procedure;
  an ordinary restart reuses its existing epoch.
- For a fresh deployment, create the signing wrapping root and initialize the
  encrypted database keyset. Set `signing.existingSecret`, `signing.wrappingKeySecretKey`, and
  `signing.wrappingKeyId` to the wrapping root already used by the database.
  The chart mounts that root and supplies its file path.
- `appSecrets.existingSecret` optionally imports the client-secret pepper,
  pairwise subject secret, and dynamic-registration token. Without it these
  values, the MFA root, and instance identity persist on the data PVC.
- This chart deploys one replica with persistence enabled. HA deployments need
  separate manifests that give each instance its own persistent identity and
  correctly shared encryption roots.
- Startup, readiness and liveness probes use the public issuer's Host.
- The image template renders `repository:tag`. Verify the artifact first and
  pin its platform digest in the rendered Deployment through the deployment
  pipeline.

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

The chart supports `transportMode=trusted-proxy`; its Service and probes use HTTP
inside the cluster. Configure TLS termination in a separate ingress/gateway and
set `mtls.trustedProxyCidrs` to its exact ingress peers. Rendering rejects Direct
TLS mode, which requires server/client-CA identities and TLS probes. Follow the
[proxy contract](../../proxy/README.md) when forwarding certificate identity.

`signing.externalCommand` configures an external signer. Its executable and
credentials require `extraVolumes` and `extraVolumeMounts`. The external signer
owns KMS/HSM key custody and recovery.
