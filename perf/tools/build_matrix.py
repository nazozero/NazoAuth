import json
rows=json.load(open("/workspace/perf-results/endpoint_smoke.json"))
# classification: (load_tested, scenario|reason)
LT={
 "/token":"load: cc/refresh/authcode/exchange/native-sso/mTLS/fapi2 via cap_*+ladder",
 "/par":"load: cap_authorization_code/fapi2/cold-login steps",
 "/authorize":"load: cap_authorization_code + cold-login steps",
 "/authorize/decision":"load: cap_authorization_code steps",
 "/userinfo":"load: cap_userinfo_pairwise",
 "/introspect":"load: introspect_opaque_refresh_token",
 "/revoke":"load: revoke_refresh_token",
 "/.well-known/openid-configuration":"load: metadata_jwks",
 "/jwks.json":"load: metadata_jwks",
 "/.well-known/oauth-authorization-server":"load: metadata_jwks (same surface)",
 "/auth/login":"load: oidc_cold_login_refresh (Argon2 lane)",
 "/logout":"smoke only: session-terminating, low-frequency",
 "/check_session":"smoke only: iframe HTML",
 "/check_session/status":"smoke only: session poll",
 "/fapi/resource":"smoke only: needs DPoP-bound AT per call; covered via fapi2 token path",
}
out=[]
for r in rows:
    p,m,s,g=r["path"],r["method"],r["status"],r["group"]
    cls=LT.get(p)
    if not cls:
        if s==404: cls="NOT LOAD TESTED: 404 in this deployment (module/feature gated or resource-missing)"
        elif str(s) in ("401","403"): cls="smoke only: auth/admin-gated"
        elif str(s)=="400": cls="smoke only: registered, rejected empty/invalid payload"
        elif str(s)=="415": cls="smoke only: registered, requires specific content-type"
        elif s==200: cls="smoke only: public endpoint"
        elif str(s)=="redirect": cls="smoke only: browser UI redirect"
        else: cls="smoke only"
    out.append({**r,"classification":cls})
json.dump(out,open("/workspace/perf-results/endpoint_matrix.json","w"),indent=1)
print(len(out),"rows classified")
