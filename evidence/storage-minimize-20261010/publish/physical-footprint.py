from pathlib import Path
import subprocess,json,re
E=Path('/workspace/evidence/storage-minimize-20261010');result={}
def run(db,q):
 r=subprocess.run(['docker','exec','-i','nazo-storage-pg-20261010','psql','-X','-qAt','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1'],input=q,text=True,capture_output=True,check=True)
 return r.stdout.strip()
for table in ['user_mfa_remembered_devices','user_mfa_backup_codes','user_totp_credentials']:
 result[table]={}
 for phase,db in [('before','oauth'),('after','oauth_final')]:
  attrs=json.loads(run(db,f"SELECT json_agg(json_build_object('num',a.attnum,'name',a.attname,'dropped',a.attisdropped,'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='{table}'::regclass AND a.attnum>0;"))
  indexes=json.loads(run(db,f"SELECT json_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname='public' AND tablename='{table}';"))
  cols=[];drops=[]
  for a in attrs:
   if a['dropped']:name=f'dropped_slot_{a["num"]}';cols.append(f'"{name}" integer');drops.append(f'ALTER TABLE measured DROP COLUMN "{name}";')
   else:cols.append('"'+a['name']+'" '+a['type']+(' DEFAULT '+a['default'] if a['default'] else '')+(' NOT NULL' if a['notnull'] else ''))
  ddl='BEGIN; CREATE TEMP TABLE measured ('+','.join(cols)+');'+''.join(drops)
  for i,idx in enumerate(indexes):
   match=re.search(r'CREATE (UNIQUE )?INDEX .*? ON .*? USING (.*)',idx);assert match,idx
   ddl+='CREATE '+('UNIQUE ' if match[1] else '')+f'INDEX measured_index_{i} ON measured USING '+match[2]+';'
  if table=='user_mfa_backup_codes':fields='tenant_id,user_id,code_hash';values="'00000000-0000-0000-0000-000000000001',md5('user-'||i)::uuid,repeat('x',97)"
  elif table=='user_totp_credentials':
   fields='tenant_id,user_id,secret_ciphertext,secret_key_id,confirmed_at,last_used_step';values="'00000000-0000-0000-0000-000000000001',md5('user-'||i)::uuid,decode(repeat('01',64),'hex'),'fixture-key','2026-10-01T00:00:00Z',123"
   if phase=='before':fields+=',label';values+=",'fixture@example.org (issuer)'"
  else:
   fields='tenant_id,user_id,token_hash,user_agent_hash,expires_at';values="'00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',md5(i::text)||md5('token-'||i::text),repeat('a',64),'2026-11-10T00:00:00Z'"
  q=ddl+f"INSERT INTO measured({fields}) SELECT {values} FROM generate_series(1,10000) n(i); SELECT json_build_object('rows',count(*),'avg_tuple_bytes',avg(pg_column_size(d)),'heap_bytes',pg_table_size('measured'),'index_bytes',pg_indexes_size('measured'),'total_bytes',pg_total_relation_size('measured'),'dropped_slots',(SELECT count(*) FROM pg_attribute WHERE attrelid='measured'::regclass AND attnum>0 AND attisdropped)) FROM measured d; ROLLBACK;"
  out=json.loads(run(db,q));out['exit']=0;out['source_attribute_count']=len(attrs);result[table][phase]=out
  (E/f'{table}-{phase}-physical-footprint.sql').write_text(q)
result['method']='10000 new rows in transaction-local tables preserving actual pg_attribute order including dropped slots, defaults, nullability, types and index definitions from old and final migrated schema; no manual vacuum. Layout-only fixture, not immediate shrink of pre-existing tuples.'
(E/'physical-row-footprint.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))