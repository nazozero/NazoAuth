import json
# Static scenario coverage plan, not evidence of an executed load.
LT={
 "/token":"planned: cc/refresh/authcode/exchange/native-sso/mTLS/fapi2 via cap_*+ladder",
 "/par":"planned: cap_authorization_code/fapi2/cold-login steps",
 "/authorize":"planned: cap_authorization_code + cold-login steps",
 "/authorize/decision":"planned: cap_authorization_code steps",
 "/userinfo":"planned: cap_userinfo_pairwise",
 "/introspect":"planned: introspect_opaque_refresh_token",
 "/revoke":"planned: revoke_refresh_token",
 "/.well-known/openid-configuration":"planned: metadata_jwks",
 "/jwks.json":"planned: metadata_jwks",
 "/.well-known/oauth-authorization-server":"planned: metadata_jwks (same surface)",
 "/auth/login":"planned: oidc_cold_login_refresh (Argon2 lane)",
 "/logout":"smoke only: session-terminating, low-frequency",
 "/check_session":"smoke only: iframe HTML",
 "/check_session/status":"smoke only: session poll",
 "/fapi/resource":"smoke only: resource handler needs its own DPoP-bound request load",
}
def build_matrix(rows):
    return [{**row, "classification": "smoke observation only",
             "load_status": "UNVERIFIED", "scenario_plan": LT.get(row["path"])}
            for row in rows]


def main():
    from pathlib import Path
    directory = Path("/workspace/perf-results")
    rows = json.loads((directory / "endpoint_smoke.json").read_text())
    out = build_matrix(rows)
    (directory / "endpoint_matrix.json").write_text(json.dumps(out, indent=1))
    print(len(out), "smoke observations; load coverage is unverified")


if __name__ == "__main__":
    main()
