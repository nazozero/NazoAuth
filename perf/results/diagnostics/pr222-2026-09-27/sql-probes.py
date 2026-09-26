"""Narrow, rollback-only PR222 plans against its migrated isolated test DB."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

import psycopg
from argon2 import PasswordHasher

root = Path('/workspace')
out = Path('/tmp/pr222-validation/sql-plans.json')
dsn = os.environ['DATABASE_URL']
assert dsn == os.environ['NAZO_TEST_DATABASE_URL']
assert psycopg.conninfo.conninfo_to_dict(dsn)['dbname'] == 'pr222_test'


def production_literals(path):
    source = (root / path).read_text()
    return [json.loads(re.sub(r'\\\n\s*', '', match.group(1)), strict=False)
            for match in re.finditer(r'sql_query\(\s*("(?:[^"\\]|\\.)*")\s*,?\s*\)', source, re.S)]


owner_queries = production_literals('crates/persistence-postgres/src/repositories/token_issuance.rs')
owner_cursor = next(q for q in owner_queries if q.startswith('DECLARE nazo_owner_token_revocations'))
owner_read = owner_cursor.split(' FOR ', 1)[1]
owner_write = next(q for q in owner_queries if q.startswith('UPDATE openid4vci_access_grants AS grant_row'))
event_read = next(q for q in production_literals('crates/persistence-postgres/src/repositories/scim_events.rs')
                  if q.startswith('SELECT event.id'))
skew = int(re.search(r'MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS: i64 = (\d+)',
                    (root / 'crates/resource-server/src/lib.rs').read_text()).group(1))
row_source = (root / 'crates/persistence-postgres/src/rows/identity.rs').read_text()
fields = re.findall(r'pub\(crate\) (\w+):', row_source.split('pub(crate) struct PublicAccountRow {')[1].split('}')[0])
scim_page = ('SELECT ' + ', '.join('users.' + field for field in fields) +
             ' FROM users WHERE tenant_id = $1 AND (users.created_at, users.id) > ($2, $3)'
             ' ORDER BY users.created_at ASC, users.id ASC LIMIT $4 OFFSET $5')
scim_count = 'SELECT COUNT(*) FROM users WHERE tenant_id = $1'
assert '(users.created_at, users.id)' in (root / 'crates/persistence-postgres/src/repositories/scim.rs').read_text()

results = {'source_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
           'method': 'Real bound parameters; production owner/poll SQL extracted from Rust; SCIM SQL reconstructed from its Diesel projection. No index changes. Every fixture and analyzed UPDATE is rolled back.',
           'queries': [], 'rounds': []}


def bound(sql):
    return re.sub(r'\$(\d+)', lambda m: '%(p' + m.group(1) + ')s', sql)


def explain(conn, label, query, params, analyze=True):
    start = time.monotonic()
    options = 'ANALYZE, BUFFERS, WAL, FORMAT JSON' if analyze else 'FORMAT JSON'
    plan = conn.execute('EXPLAIN (' + options + ') ' + bound(query),
                        {'p' + str(i + 1): p for i, p in enumerate(params)}).fetchone()[0][0]
    result = {'label': label, 'sql': query, 'params': [str(p) if p is not None else None for p in params],
              'wall_seconds': time.monotonic() - start, 'plan': plan}
    results['queries'].append(result)
    print(label, 'execution_ms=', plan.get('Execution Time'), 'shared_hit=', plan['Plan'].get('Shared Hit Blocks'), flush=True)


password_hash = PasswordHasher().hash(uuid.uuid4().hex)
with psycopg.connect(dsn, autocommit=True) as conn:
    results['server'] = conn.execute('SELECT version()').fetchone()[0]
    for n in (1000, 10000):
        conn.execute('BEGIN')
        try:
            conn.execute("SET LOCAL statement_timeout = '15s'")
            tenant, realm, org, target_user, other_user, target_client, other_client, receiver = [uuid.uuid4() for _ in range(8)]
            base = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
            conn.execute('INSERT INTO tenants(id,slug,display_name) VALUES (%s,%s,%s)', (tenant, str(tenant), 'PR222 probe'))
            conn.execute("INSERT INTO realms(id,tenant_id,slug,display_name) VALUES (%s,%s,'default','PR222')", (realm, tenant))
            conn.execute("INSERT INTO organizations(id,tenant_id,slug,display_name) VALUES (%s,%s,'default','PR222')", (org, tenant))
            for user in (target_user, other_user):
                conn.execute('INSERT INTO users(id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES (%s,%s,%s,%s,%s,%s,%s)',
                             (user, tenant, realm, org, str(user), str(user) + '@example.test', password_hash))
            policy = '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'
            for client in (target_client, other_client):
                conn.execute("INSERT INTO oauth_clients(id,tenant_id,realm_id,organization_id,client_id,client_name,client_type,redirect_uris,scopes,grant_types,token_endpoint_auth_method,security_policy) VALUES (%s,%s,%s,%s,%s,'PR222','public','[\"https://client.example/cb\"]','[\"openid\"]','[\"authorization_code\"]','none',%s::jsonb)",
                             (client, tenant, realm, org, str(client), policy))
            conn.execute("INSERT INTO oauth_token_issuances(issuance_id,tenant_id,client_id,user_id,access_token_jti,access_token_expires_at,retain_until) SELECT uuidv7(),%s,CASE WHEN g <= 5 THEN %s ELSE %s END,CASE WHEN g <= 5 THEN %s ELSE %s END,'probe-' || g, CURRENT_TIMESTAMP + interval '1 hour', CURRENT_TIMESTAMP + interval '2 hours' FROM generate_series(1,%s) g",
                         (tenant, target_client, other_client, target_user, other_user, n))
            conn.execute("INSERT INTO openid4vci_access_grants(token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) SELECT uuidv7(),md5('probe-' || g) || md5('vc-' || g),%s,CASE WHEN g <= 5 THEN %s ELSE %s END,CASE WHEN g <= 5 THEN %s ELSE %s END,'[\"pid\"]','[]',CURRENT_TIMESTAMP - interval '1 hour',CURRENT_TIMESTAMP + interval '1 hour' FROM generate_series(1,%s) g",
                         (tenant, target_user, other_user, str(target_client), str(other_client), n))
            # Count/page distribution is one whole directory, plus the two owner users.
            conn.execute("INSERT INTO users(id,tenant_id,realm_id,organization_id,username,email,password_hash,created_at) SELECT uuidv7(),%s,%s,%s,'page-' || g,'page-' || g || '@example.test',%s,%s::timestamptz + g * interval '1 millisecond' FROM generate_series(1,%s) g",
                         (tenant, realm, org, password_hash, base, n))
            conn.execute("INSERT INTO scim_tokens(id,tenant_id,token_hash,label,created_at,event_audience) VALUES (%s,%s,%s,'PR222',%s,'https://receiver.example')",
                         (receiver, tenant, hashlib.sha256(receiver.bytes).hexdigest(), base - dt.timedelta(minutes=1)))
            conn.execute("INSERT INTO scim_security_events(id,tenant_id,transaction_id,subject_uri,events,occurred_at,expires_at) SELECT uuidv7(),%s,uuidv7(),%s,'{\"urn:ietf:params:scim:event:provisioning:create\":{}}',%s::timestamptz + g * interval '1 millisecond',CURRENT_TIMESTAMP + interval '6 days' FROM generate_series(1,%s) g",
                         (tenant, '/Users/' + str(target_user), base, n))
            conn.execute("INSERT INTO scim_security_event_receipts(event_id,scim_token_id,disposition) SELECT id,%s,'acknowledged' FROM scim_security_events WHERE tenant_id=%s", (receiver, tenant))
            for table in ('users', 'oauth_clients', 'oauth_token_issuances', 'openid4vci_access_grants', 'scim_tokens', 'scim_security_events', 'scim_security_event_receipts'):
                conn.execute('ANALYZE ' + table)
            counts = {table: conn.execute('SELECT count(*) FROM ' + table + ' WHERE tenant_id=%s', (tenant,)).fetchone()[0]
                      for table in ('users', 'oauth_token_issuances', 'openid4vci_access_grants', 'scim_security_events')}
            results['rounds'].append({'distribution': n, 'counts': counts, 'target_per_token_source': 5, 'acked_events': n})
            now = dt.datetime.now(dt.timezone.utc)
            for owner, client, user in (('client', target_client, None), ('user', None, target_user)):
                args = (tenant, client, user, now, skew)
                # Retain the cursor planning context separately from the analyzed read.
                explain(conn, f'owner-{owner}-{n}-cursor-plan', owner_cursor, args, analyze=False)
                explain(conn, f'owner-{owner}-{n}-read', owner_read, args)
                conn.execute('SAVEPOINT owner_write')
                explain(conn, f'owner-{owner}-{n}-update', owner_write, args[:4])
                conn.execute('ROLLBACK TO SAVEPOINT owner_write')
            cursor = conn.execute('SELECT created_at,id FROM users WHERE tenant_id=%s ORDER BY created_at,id OFFSET %s LIMIT 1', (tenant, n // 2)).fetchone()
            explain(conn, f'scim-count-{n}', scim_count, (tenant,))
            explain(conn, f'scim-page-{n}', scim_page, (tenant, cursor[0], cursor[1], 100, 0))
            explain(conn, f'event-all-acked-{n}', event_read, (receiver, tenant, 11))
            assert conn.execute(bound(event_read), {'p1': receiver, 'p2': tenant, 'p3': 11}).fetchall() == []
        finally:
            conn.execute('ROLLBACK')
        assert conn.execute('SELECT count(*) FROM tenants WHERE id=%s', (tenant,)).fetchone()[0] == 0
    results['cleanup'] = 'Both fixture transactions rolled back; tenant absence verified.'
out.write_text(json.dumps(results, indent=2, default=str) + '\n')
print('Saved', out, flush=True)
