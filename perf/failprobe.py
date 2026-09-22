#!/usr/bin/env python3
"""Stale-connection failure probe for the RecyclingMethod A/B.

Modes:
  cc      - low-rate client_credentials probes
  refresh - mint one family via SQL insert, then rotate it per probe

Every ~250ms performs one probe and prints one JSONL line:
  {t, ms, status, ok, err}
Run inside the perf container network: nazoauth:8000, postgres reachable via
DATABASE_URL env.
"""
import json, os, sys, time, urllib.request, urllib.error, urllib.parse

BASE = "http://nazoauth:8000"
HOST = "127.0.0.1:8000"
INTERVAL = 0.25
DURATION = float(os.environ.get("PROBE_SECONDS", "45"))


def post_token(form):
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(
        f"{BASE}/token", data=body,
        headers={"Host": HOST, "Content-Type": "application/x-www-form-urlencoded"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode()), (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, {"err_body": e.read().decode()[:300]}, (time.time() - t0) * 1000
    except Exception as e:
        return -1, {"err_body": str(e)[:300]}, (time.time() - t0) * 1000


def emit(t0, status, ms, ok, extra=None):
    line = {"t": round(time.time() - t0, 3), "ms": round(ms, 1),
            "status": status, "ok": ok}
    if extra:
        line.update(extra)
    print(json.dumps(line), flush=True)


def cc_probe(t0):
    status, body, ms = post_token({
        "grant_type": "client_credentials",
        "client_id": "perf-client-credentials",
        "client_secret": "PerfClientSecret-2026!",
        "scope": "profile",
    })
    ok = status == 200 and bool(body.get("access_token"))
    emit(t0, status, ms, ok, None if ok else {"err": body.get("err_body")})


def mint_family():
    """Insert one refresh family (contract + family row); return raw token."""
    import secrets as pysec, psycopg
    from blake3 import blake3
    from datetime import datetime, timedelta, timezone
    raw = "rt-abtest-" + pysec.token_urlsafe(32)
    dsn = os.environ["DATABASE_URL"]
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT c.id, u.id FROM oauth_clients c, users u "
            "WHERE c.tenant_id='00000000-0000-0000-0000-000000000001'::uuid "
            "AND c.client_id='perf-oidc-client' "
            "AND u.tenant_id=c.tenant_id AND lower(u.email)='perf-user@example.test' LIMIT 1"
        ).fetchone()
        cid, uid = row
        now = datetime.now(timezone.utc)
        # Byte-identical to the Rust RefreshContract canonical serialization:
        # struct field order, compact separators, nonce/id_token_sid stripped.
        contract = {
            "subject": str(uid),
            "scopes": ["openid", "profile", "offline_access"],
            "audiences": ["resource://default"],
            "authorization_details": [],
            "authentication_context": {
                "version": 1, "issuer": "http://127.0.0.1:8000",
                "audience": "perf-oidc-client", "auth_time": int(now.timestamp()),
                "amr": ["pwd"], "oidc_sid": None, "id_token_sid": None,
                "acr": None, "nonce": None, "userinfo_claims": [],
                "userinfo_claim_requests": [], "id_token_claims": [],
                "id_token_claim_requests": []},
        }
        digest = blake3(
            json.dumps(contract, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")).digest()
        conn.execute(
            "INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract)"
            " VALUES ('00000000-0000-0000-0000-000000000001'::uuid, %s, %s::jsonb)"
            " ON CONFLICT (tenant_id, contract_blake3) DO NOTHING",
            (digest, json.dumps(contract, separators=(",", ":"),
                                ensure_ascii=False)))
        conn.execute(
            "INSERT INTO oauth_refresh_families (tenant_id, token_family_id,"
            " client_id, user_id, contract_blake3, current_member_id,"
            " current_token_blake3, current_audience, current_issued_at,"
            " current_expires_at, created_at) VALUES"
            " ('00000000-0000-0000-0000-000000000001'::uuid, gen_random_uuid(),"
            " %s, %s, %s, gen_random_uuid(), %s, %s::jsonb, %s, %s, %s)",
            (cid, uid, digest, blake3(raw.encode()).digest(),
             json.dumps(["resource://default"]), now,
             now + timedelta(days=30), now))
        conn.commit()
    return raw


def refresh_probe(t0, rt):
    status, body, ms = post_token({
        "grant_type": "refresh_token",
        "client_id": "perf-oidc-client",
        "client_secret": "PerfClientSecret-2026!",
        "refresh_token": rt,
    })
    ok = status == 200 and bool(body.get("refresh_token"))
    nxt = body.get("refresh_token") if ok else None
    emit(t0, status, ms, ok, None if ok else {"err": body.get("err_body")})
    return nxt


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "cc"
    t0 = time.time()
    rt = mint_family() if mode == "refresh" else None
    if mode == "refresh":
        print(json.dumps({"t": -1, "minted": True, "rt_prefix": rt[:18]}), flush=True)
    deadline = t0 + DURATION
    while time.time() < deadline:
        if mode == "refresh":
            nxt = refresh_probe(t0, rt)
            if nxt:
                rt = nxt
        else:
            cc_probe(t0)
        time.sleep(INTERVAL)


main()
