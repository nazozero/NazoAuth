# 2026-06-14 Security-Coverage OIDF Full Matrix

## Outcome

Local OpenID Foundation Conformance Suite full matrix runs after the Rust
security-invariant coverage work. The suite ran in local containers and
targeted the public issuer at `https://auth.nazo.run`.

| Field | Value |
| --- | --- |
| Result | Passed |
| Exported plan archives | `16` |
| Test log modules audited | `562` |
| Final module results | `559 PASSED`, `3 REVIEW` |
| Bad final results | `0 FAILED`, `0 WARNING`, `0 SKIPPED`, `0 INTERRUPTED` |
| Bad log results | `0 FAILURE`, `0 WARNING` |
| Implementation tree under test | Working tree after token-management auth-boundary, authorization redirect, and authorization-code replay-marker invariant tests |
| Public issuer under test | `https://auth.nazo.run` |
| Conformance server | `https://localhost.emobix.co.uk:8443` |
| Suite location | `/root/oauth2_server/oidf-conformance-suite` |
| Export directory | `runtime/oidf/results-local-full-20260614T140947Z` |
| Runner mode | Local suite runner, public `auth.nazo.run` target |
| Latest official GitHub Actions run before this local batch | `27500481513` |
| Latest official run URL before this local batch | `https://github.com/bymoye/NazoAuth/actions/runs/27500481513` |
| Latest official run head SHA before this local batch | `8370f8123af310a7dae009609021c7320a19a725` |
| Official run result | Passed |

The local runner process exited after exporting all 16 configured plan archives.
The exported `test-log-*.json` files were unpacked and scanned for failed,
warning, skipped, or interrupted results. A follow-up read-only Conformance
Suite API audit checked the final state of every exported module id and found:

```text
module_count=562
result_counts={"PASSED": 559, "REVIEW": 3}
```

The three `REVIEW` modules are allowed review states for the configured OIDF
plans. No exported module had a failed, warning, skipped, or interrupted final
result, and no exported module log contained a `FAILURE` or `WARNING` result.

An earlier local rerun at `runtime/oidf/results-local-full-20260614T140736Z`
was intentionally discarded after the suite reported an unexpected stale
`implicit/...` request during discovery verification before the full matrix
completed. That was treated as local suite state contamination, not as passing
evidence.

The previous official full-matrix workflow also passed for the last pushed
commit before this local batch:

```text
run_id=27500481513
head_sha=8370f8123af310a7dae009609021c7320a19a725
conclusion=success
url=https://github.com/bymoye/NazoAuth/actions/runs/27500481513
```

## Coverage

Profiles and protocol features covered by this run:

- OIDC Basic OP certification plan
- OIDC Config OP certification plan
- FAPI2 Security Profile Final
- FAPI2 Message Signing Final
- FAPI2 client credentials grant variants
- `private_key_jwt`
- mTLS client authentication
- DPoP sender constraint
- mTLS sender constraint
- PAR
- signed request objects / JAR
- JARM and plain authorization responses
- OpenID Connect and plain OAuth modes

## Exported Artifact Filenames

Artifact contents in `runtime/oidf/results-local-full-20260614T140947Z`:

- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-jarm-1L67pWzFw6emz-14-Jun-2026.zip`
- `fapi2-message-signing-final-test-plan-private_key_jwt-dpop-simple-openid_connect-signed_non_repudiation-plain_fapi-plain_response-8aj4v17mvwoll-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-openid_connect-plain_fapi-MaROg53aIKRGc-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-fapi_client_credentials_grant-Dn9UCcjBjxtvQ-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-dpop-simple-plain_oauth-plain_fapi-vvVbQxdYAMwcT-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-openid_connect-plain_fapi-A1NaVrfdOpsyJ-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-fapi_client_credentials_grant-sHFjQpYCgkcrp-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-mtls-mtls-simple-plain_oauth-plain_fapi-tOIoU2wGpLMoi-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-openid_connect-plain_fapi-OK5Sc2mUxb6I5-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-fapi_client_credentials_grant-DETFvgQUBaMv9-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-dpop-simple-plain_oauth-plain_fapi-mMBMWSG6pPVPs-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-openid_connect-plain_fapi-8udwVZFJTS02r-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-fapi_client_credentials_grant-CxklYbgPj0JpV-14-Jun-2026.zip`
- `fapi2-security-profile-final-test-plan-private_key_jwt-mtls-simple-plain_oauth-plain_fapi-G0jppcpAEKSHa-14-Jun-2026.zip`
- `oidcc-basic-certification-test-plan-discovery-static_client-VPUkWGmeua92l-14-Jun-2026.zip`
- `oidcc-config-certification-test-plan--itGZbG7dxG7ez-14-Jun-2026.zip`

## Verification Commands

```bash
python3 scripts/run_oidf_conformance.py \
  --suite-dir ../oidf-conformance-suite \
  --conformance-server https://localhost.emobix.co.uk:8443 \
  --no-api-token \
  --disable-ssl-verify \
  --config-json-file runtime/oidf/oidf-plan-configs.json \
  --config-file-name oidf-plan-configs.json \
  --plan-set-json-file runtime/oidf/oidf-plan-set.json \
  --export-dir runtime/oidf/results-local-full-20260614T140947Z \
  --timeout-seconds 10800 \
  --monitor-interval-seconds 30

grep -R '"result"[[:space:]]*:[[:space:]]*"\(FAILED\|WARNING\|INTERRUPTED\|SKIPPED\)"' \
  runtime/oidf/results-local-full-20260614T140947Z
```

Read-only final state audit:

```bash
python3 - <<'PY'
import json, ssl, sys, urllib.request, zipfile
from pathlib import Path

base = "https://localhost.emobix.co.uk:8443"
export = Path("runtime/oidf/results-local-full-20260614T140947Z")
ctx = ssl._create_unverified_context()
ids = []

for zpath in sorted(export.glob("*.zip")):
    with zipfile.ZipFile(zpath) as archive:
        for name in archive.namelist():
            if name.startswith("test-log-") and name.endswith(".json"):
                ids.append(Path(name).stem.rsplit("-", 1)[-1])

bad = []
counts = {}
for module_id in sorted(set(ids)):
    with urllib.request.urlopen(
        f"{base}/api/info/{module_id}",
        context=ctx,
        timeout=20,
    ) as response:
        info = json.load(response)
    status = str(info.get("status") or "").upper()
    result = str(info.get("result") or "").upper()
    counts[result or status or "<empty>"] = counts.get(result or status or "<empty>", 0) + 1
    if (
        info.get("error")
        or status in {"FAILED", "SKIPPED", "INTERRUPTED"}
        or result in {"FAILED", "SKIPPED", "INTERRUPTED", "WARNING"}
    ):
        bad.append((module_id, status, result, info.get("error")))

print(f"module_count={len(set(ids))}")
print("result_counts=" + json.dumps(counts, sort_keys=True))
if bad:
    print(json.dumps(bad[:20], indent=2))
    sys.exit(1)
PY
```

## Notes

- This is a local regression record, not an OpenID Foundation certification
  statement.
- The official `oidf-conformance-full` workflow also passed on
  `2026-06-14T13:49:27Z` for head SHA
  `8370f8123af310a7dae009609021c7320a19a725`:
  `https://github.com/bymoye/NazoAuth/actions/runs/27500481513`.
- The record intentionally excludes plan configuration bodies and suite logs
  that may contain private client keys, certificates, or local credentials.
