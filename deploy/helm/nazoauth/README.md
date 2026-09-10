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
- Provision the shared signing-key wrapping root and ID through `extraEnv`
  plus Secret mounts. Signing keys live in encrypted database generations;
  the chart does not generate their wrapping root or initialize that keyset.
- `appSecrets.existingSecret` mounts only the client-secret pepper, pairwise
  subject secret, and dynamic-registration token. It does not provide all
  shared encryption roots. MFA, token-response and enabled OpenID4VC secrets
  must also remain consistent across replicas through explicit inputs.
- The default data PVC is ReadWriteOnce. The template rejects multiple replicas
  with that PVC, or without `appSecrets.existingSecret`. Passing those guards
  does not establish HA: supply each replica's persistent instance identity,
  all shared secrets, and suitable avatar storage explicitly.
- The current probes have no Host override. For a hostname-bound tenant, add
  the issuer's Host to `/startup`, `/health`, and `/live` probes in the rendered
  deployment. An IP-only probe is rejected by tenant routing.
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

The chart defaults to `transportMode=trusted-proxy`; its Service exposes HTTP
inside the cluster. Set `mtls.trustedProxyCidrs` to the exact ingress peers and
configure an ingress/gateway separately. The current chart does not mount the
server/client-CA identities required for Direct TLS. Follow the
[proxy contract](../../proxy/README.md) when forwarding certificate identity.

`signing.externalCommand` configures an external signer. Its executable and
credentials require `extraVolumes` and `extraVolumeMounts`; selecting a command
does not itself establish KMS/HSM custody or recovery guarantees.
