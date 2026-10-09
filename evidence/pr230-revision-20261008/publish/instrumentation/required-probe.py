import json,time,uuid,os,urllib.request,urllib.error,statistics
import psycopg,redis
from psycopg.types.json import Jsonb
TENANT='00000000-0000-0000-0000-000000000001';REALM='00000000-0000-0000-0000-000000000002';ORG='00000000-0000-0000-0000-000000000003'
u=str(uuid.uuid4());sid=uuid.uuid4().hex;dep=os.environ['PROBE_DEPLOYMENT'];epoch='019c8ca2-30a6-7000-8000-00000000e103'
c=psycopg.connect('postgresql://postgres:postgres@postgres:5432/oauth',autocommit=True);v=redis.Redis(host='valkey',decode_responses=True)
c.execute("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level,mfa_enabled) VALUES (%s,%s,%s,%s,%s,%s,'fixture','admin',1,TRUE)",(u,TENANT,REALM,ORG,'required-probe-'+u,'required-probe-'+u+'@example.test'))
key=f'nazo:state:v1:{dep}:{epoch}:tenant:{TENANT}:oauth:session:{sid}'
v.setex(key,600,json.dumps({'user_id':u,'auth_time':int(time.time()),'amr':['pwd','otp','mfa'],'pending_mfa':False,'oidc_sid':'oidc-'+sid}))
rows=[]
try:
 for i in range(30):
  req=urllib.request.Request('http://nazoauth:8000/admin/mtls-trust-anchors.pem',headers={'Cookie':'nazo_oauth_session='+sid,'Host':'127.0.0.1:8000'})
  start=time.perf_counter();status=0;attachment=False
  try:
   with urllib.request.urlopen(req,timeout=10) as response:status=response.status;attachment='attachment' in response.headers.get('Content-Disposition','');response.read()
  except urllib.error.HTTPError as error:status=error.code;error.read()
  rows.append({'i':i,'utc_epoch':time.time(),'status':status,'attachment':attachment,'ms':(time.perf_counter()-start)*1000})
  time.sleep(.1)
 print(json.dumps({'kind':'low_traffic_required_bundle_export','rows':rows,'successes':sum(r['status']==200 and r['attachment'] for r in rows)}))
finally:
 v.delete(key);c.execute('DELETE FROM users WHERE id=%s',(u,));c.close()
