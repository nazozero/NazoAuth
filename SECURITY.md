# Security Policy

Nazo Auth Server is security-sensitive infrastructure. Report suspected
vulnerabilities privately before public disclosure.

## Supported Versions

The project is pre-0.5 and releases versioned artifacts. Security fixes land on
`main` and are published in new releases; older versions do not have a separate
maintenance promise. Use the release notes and the controller's
current format policy when planning an update or recovery.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting when available:
<https://github.com/nazozero/NazoAuth/security/advisories/new>.

Send a private report to the repository maintainer through a non-public channel.
Include:

- affected commit or version
- vulnerable endpoint or component
- reproduction steps
- expected and actual behavior
- impact assessment
- logs or traces with secrets removed

Do not include live access tokens, refresh tokens, private keys, passwords,
session cookies, or production database contents in a report.

## Handling Targets

High-priority vulnerability classes include:

- authorization code replay or confused-client behavior
- redirect URI validation bypass
- PKCE bypass
- refresh token rotation or reuse-detection bypass
- token revocation or introspection failures that expose active metadata incorrectly
- DPoP or mTLS sender-constraint bypass
- client assertion, request object, or DPoP replay bypass
- JWKS/key rotation behavior that publishes or accepts an incorrect key
- trusted proxy header spoofing
- CSRF or session fixation defects
- leakage of private key material, token material, or password hashes

## Production Boundaries

Production deployments treat these as hard security boundaries:

- `ISSUER` must be exact and HTTPS.
- `COOKIE_SECURE` must be `true`.
- `TRUSTED_PROXY_CIDRS` must include only controlled reverse proxies.
- Reverse proxies must strip inbound forwarded, mTLS, and certificate headers before adding trusted values.
- Tenant signing and mdoc authority keysets are encrypted in shared durable
  storage. Protect and back up their independent wrapping roots separately;
  missing roots cannot be repaired by generating new keys.
- PostgreSQL and Valkey must not be exposed to untrusted networks.
- Tenant routing, operator admission, audit durability, and external receiver
  trust are defined in the [Threat Model](docs/security/threat-model.md).

## Disclosure

Public disclosure waits until a fix is available or a coordinated timeline is
agreed. Security fixes include focused regression tests whenever practical.
