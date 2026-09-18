#!/usr/bin/env python3
"""Smoke every registered route on the perf deployment. Records method,path,status.
Unauthenticated requests expect 4xx for protected routes (proves route exists);
404 means unregistered (module-gated routes expect 404)."""
import json, urllib.request, urllib.error, uuid

BASE = "http://nazoauth:8000"
TENANT = "127.0.0.1:8000"
UID = str(uuid.uuid4())

def req(method, path, data=None, headers=None, tenant=True):
    h = {"accept": "application/json"}
    if tenant: h["Host"] = TENANT
    if headers: h.update(headers)
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = "&".join(f"{k}={v}" for k, v in data.items()).encode()
            h["content-type"] = "application/x-www-form-urlencoded"
        else:
            body = data
    r = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()[:200].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200].decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)[:120]

E = []  # (group, method, path, note)
def add(g, m, p, note=""): E.append((g, m, p, note))

# discovery / infra
for p in ["/health", "/live", "/startup", "/jwks.json",
          "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
          "/.well-known/oauth-protected-resource", f"/.well-known/mdoc/{UID}.crl",
          "/.well-known/openid-credential-issuer"]:
    add("discovery", "GET", p)
add("discovery", "POST", "/.well-known/nazoauth-control", "control-tenant only")
add("discovery", "GET", "/__perf/metrics", "control-tenant only")
# oauth core
add("oauth", "GET", "/authorize"); add("oauth", "POST", "/authorize")
add("oauth", "GET", "/authorize/client-presentation"); add("oauth", "GET", "/authorize/consent")
add("oauth", "POST", "/authorize/decision")
add("oauth", "POST", "/par"); add("oauth", "POST", "/bc-authorize")
add("oauth", "GET", f"/ciba/{UID}")
add("oauth", "POST", "/device_authorization"); add("oauth", "GET", "/device")
add("oauth", "GET", "/device/verification"); add("oauth", "POST", "/device/decision")
add("oauth", "POST", "/token")
add("oauth", "GET", "/logout"); add("oauth", "POST", "/logout")
add("oauth", "GET", "/check_session"); add("oauth", "GET", "/check_session/status")
add("oauth", "POST", "/revoke"); add("oauth", "POST", "/introspect")
add("oauth", "GET", "/fapi/resource"); add("oauth", "POST", "/fapi/resource")
add("oauth", "GET", "/userinfo"); add("oauth", "POST", "/userinfo")
add("oauth", "POST", "/register", "DCR")
add("oauth", "GET", f"/register/{UID}"); add("oauth", "PUT", f"/register/{UID}"); add("oauth", "DELETE", f"/register/{UID}")
# scim
for p in ["/scim/v2/ServiceProviderConfig", "/scim/v2/Schemas", "/scim/v2/ResourceTypes"]:
    add("scim", "GET", p)
add("scim", "POST", "/scim/v2/SecurityEvents")
add("scim", "GET", "/scim/v2/Users"); add("scim", "POST", "/scim/v2/Users")
add("scim", "GET", f"/scim/v2/Users/{UID}"); add("scim", "PUT", f"/scim/v2/Users/{UID}")
add("scim", "PATCH", f"/scim/v2/Users/{UID}"); add("scim", "DELETE", f"/scim/v2/Users/{UID}")
# auth UI/api
add("auth", "GET", "/auth/captcha-config"); add("auth", "POST", "/auth/send-code")
add("auth", "POST", "/auth/register"); add("auth", "POST", "/auth/login")
add("auth", "GET", "/auth/federation/providers"); add("auth", "POST", "/auth/federation/saml/acs")
add("auth", "GET", f"/auth/federation/{UID}/start"); add("auth", "GET", f"/auth/federation/{UID}/callback")
add("auth", "POST", "/auth/passkey/begin"); add("auth", "POST", "/auth/passkey/finish")
add("auth", "POST", "/auth/mfa/verify"); add("auth", "GET", "/auth/csrf")
add("auth", "GET", "/auth/me"); add("auth", "PATCH", "/auth/me")
add("auth", "GET", "/auth/me/passkeys"); add("auth", "POST", "/auth/me/passkeys/begin")
add("auth", "POST", "/auth/me/passkeys/finish"); add("auth", "DELETE", f"/auth/me/passkeys/{UID}")
add("auth", "POST", "/auth/me/mfa/totp/begin"); add("auth", "POST", "/auth/me/mfa/totp/confirm")
add("auth", "POST", "/auth/me/mfa/step-up"); add("auth", "POST", "/auth/me/mfa/backup-codes/regenerate")
add("auth", "POST", "/auth/me/mfa/disable")
add("auth", "POST", "/auth/me/avatar"); add("auth", "GET", "/auth/me/avatar"); add("auth", "DELETE", "/auth/me/avatar")
add("auth", "GET", "/auth/me/avatar/uploads"); add("auth", "POST", "/auth/me/avatar/uploads")
add("auth", "POST", f"/auth/me/avatar/uploads/{UID}/complete")
add("auth", "GET", "/auth/me/applications"); add("auth", "GET", "/auth/me/federation/links")
add("auth", "DELETE", f"/auth/me/federation/links/{UID}")
add("auth", "GET", "/auth/me/access-requests"); add("auth", "POST", "/auth/me/access-requests")
add("auth", "GET", "/auth/me/mtls-trust-requests"); add("auth", "POST", "/auth/me/mtls-trust-requests")
add("auth", "POST", "/auth/me/access-delivery")
add("auth", "GET", f"/auth/ciba/{UID}"); add("auth", "POST", f"/auth/ciba/{UID}")
add("auth", "POST", "/auth/logout")
# admin (session+admin required -> 401/403 proves route)
for m, p in [("GET","/admin/users"),("POST","/admin/users"),("PATCH",f"/admin/users/{UID}"),
    ("PATCH",f"/admin/tenants/{UID}/users/{UID}/admin"),
    ("GET","/admin/clients"),("POST","/admin/clients"),("GET","/admin/clients/templates"),
    ("GET","/admin/clients/x"),("PATCH","/admin/clients/x"),
    ("GET","/admin/federation/providers"),("GET","/admin/grants"),("POST","/admin/grants/revoke"),
    ("GET","/admin/access-requests"),("POST",f"/admin/access-requests/{UID}/approve"),
    ("POST",f"/admin/access-requests/{UID}/reject"),
    ("GET","/admin/mtls-trust-requests"),("GET","/admin/mtls-trust-anchors.pem"),
    ("POST",f"/admin/mtls-trust-requests/{UID}/approve"),("POST",f"/admin/mtls-trust-requests/{UID}/reject"),
    ("POST",f"/admin/mtls-trust-requests/{UID}/revoke"),
    ("GET","/admin/runtime-modules"),("GET","/admin/runtime-modules/events"),("PATCH","/admin/runtime-modules/x"),
    ("POST","/admin/controller-registry/slots"),("POST","/admin/controller-registry/slots/rotate"),
    ("POST","/admin/controller-registry/slots/revoke"),("POST","/admin/controller-registry/approvals"),
    ("GET","/admin/controller-registry/recovery-root"),("POST","/admin/controller-registry/recovery-root/approvals"),
    ("POST","/admin/controller-registry/recovery-root/rotate"),
    ("GET",f"/admin/openid4vci/credential-datasets/{UID}/cfg"),("PUT",f"/admin/openid4vci/credential-datasets/{UID}/cfg"),
    ("DELETE",f"/admin/openid4vci/credential-datasets/{UID}/cfg")]:
    add("admin", m, p)
add("recovery", "POST", "/controller-recovery/challenges"); add("recovery", "POST", "/controller-recovery/recover")
# openid4vc (module gated -> 404 expected)
for m, p in [("POST","/openid4vci/offers"),("GET",f"/openid4vci/offers/{UID}"),("POST","/openid4vci/nonce"),
    ("POST","/openid4vci/credential"),("POST","/openid4vci/deferred_credential"),("POST","/openid4vci/notification"),
    ("GET",f"/openid4vp/complete/{UID}"),("POST","/openid4vp/presentations"),
    ("GET",f"/openid4vp/request/{UID}"),("POST",f"/openid4vp/request/{UID}"),
    ("POST",f"/openid4vp/response/{UID}"),("GET",f"/openid4vp/result/{UID}")]:
    add("openid4vc", m, p)

rows = []
for g, m, p, note in E:
    st, body = req(m, p)
    rows.append({"group": g, "method": m, "path": p, "status": st, "note": note})
    print(f"{g:12s} {m:6s} {p:60s} -> {st} {note}")

with open("/out/endpoint_smoke.json", "w") as f:
    json.dump(rows, f, indent=1)
print("WROTE /out/endpoint_smoke.json total", len(rows))
