import os,json,time,uuid,threading,queue,http.client,ssl,urllib.request,urllib.error,statistics
import psycopg,redis,hmac,hashlib,base64
TENANT='00000000-0000-0000-0000-000000000001';REALM='00000000-0000-0000-0000-000000000002';ORG='00000000-0000-0000-0000-000000000003'
c=psycopg.connect('postgresql://postgres:postgres@postgres:5432/oauth',autocommit=True);v=redis.Redis(host='valkey',decode_responses=True)
u=str(uuid.uuid4());sid=uuid.uuid4().hex;dep=os.environ['PROBE_DEPLOYMENT'];epoch='019c8ca2-30a6-7000-8000-00000000e103'
c.execute("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level,mfa_enabled) VALUES (%s,%s,%s,%s,%s,%s,'fixture','admin',1,TRUE)",(u,TENANT,REALM,ORG,'fault-probe-'+u,'fault-probe-'+u+'@example.test'))
key=f'nazo:state:v1:{dep}:{epoch}:tenant:{TENANT}:oauth:session:{sid}'
v.setex(key,600,json.dumps({'user_id':u,'auth_time':int(time.time()),'amr':['pwd','otp','mfa'],'pending_mfa':False,'oidc_sid':'oidc-'+sid}))
root=os.environ['PROBE_DCR_TOKEN'].encode();prk=hmac.new(uuid.UUID(TENANT).bytes,root,hashlib.sha256).digest();initial_token=base64.urlsafe_b64encode(hmac.new(prk,b'nazoauth/dynamic-client-registration/initial-access/v1'+bytes([1]),hashlib.sha256).digest()).decode().rstrip('=')
conn=http.client.HTTPConnection('nazoauth',8000,timeout=10)
conn.request('POST','/register',body=json.dumps({'client_name':'revision-fault-telemetry','redirect_uris':['https://client.example/callback'],'grant_types':['authorization_code'],'response_types':['code'],'token_endpoint_auth_method':'none','scope':'openid'}),headers={'Content-Type':'application/json','Authorization':'Bearer '+initial_token,'Host':'127.0.0.1:8000'})
r=conn.getresponse();body=r.read()
if r.status!=201:raise RuntimeError('dynamic registration fixture failed '+str(r.status)+' '+body.decode()[:300])
registration=json.loads(body);client_id=registration['client_id'];token=registration['registration_access_token'];conn.close()
rows=queue.SimpleQueue();stop=threading.Event();start=time.monotonic()
sslctx=ssl.create_default_context(cafile=os.environ['PROBE_CA'])
def fault(mode):
 req=urllib.request.Request(os.environ['PROBE_RECEIVER']+'/__fault',data=json.dumps({'mode':mode}).encode(),headers={'Authorization':'Bearer '+os.environ['PROBE_RECEIVER_TOKEN'],'Content-Type':'application/json'})
 with urllib.request.urlopen(req,context=sslctx,timeout=10) as r:r.read();status=r.status
 print(json.dumps({'kind':'fault_transition','seconds':time.monotonic()-start,'mode':mode,'status':status}),flush=True)
def worker(kind,index,rate):
 h=http.client.HTTPConnection('nazoauth',8000,timeout=5);next_at=start+index/(8*rate) if kind=='telemetry' else start
 while not stop.is_set():
  now=time.monotonic()
  if now<next_at:
   if stop.wait(next_at-now):break
  began=time.perf_counter();status=0;attachment=False
  try:
   if kind=='telemetry':h.request('GET','/register/'+client_id,headers={'Authorization':'Bearer '+token,'Host':'127.0.0.1:8000'})
   else:h.request('GET','/admin/mtls-trust-anchors.pem',headers={'Cookie':'nazo_oauth_session='+sid,'Host':'127.0.0.1:8000'})
   r=h.getresponse();status=r.status;attachment='attachment' in (r.getheader('Content-Disposition') or '');r.read()
  except Exception:h.close();h=http.client.HTTPConnection('nazoauth',8000,timeout=5)
  rows.put({'kind':kind,'status':status,'attachment':attachment,'ms':(time.perf_counter()-began)*1000,'seconds':time.monotonic()-start})
  next_at+=1/rate
  if next_at<time.monotonic()-1/rate:
   rows.put({'kind':kind,'drop':max(1,int((time.monotonic()-next_at)*rate))});next_at=time.monotonic()
 h.close()
threads=[threading.Thread(target=worker,args=('telemetry',i,25),daemon=True) for i in range(8)]+[threading.Thread(target=worker,args=('required',0,1),daemon=True)]
for t in threads:t.start()
phases={40:'http_500',90:'none',135:'reject_permanent',185:'none'}
try:
 for second in range(401):
  target=start+second
  if time.monotonic()<target:time.sleep(target-time.monotonic())
  if second in phases:
   fault(phases[second])
   if second==185:
    recovered=c.execute('SELECT public.nazo_unblock_security_audit_batch()').fetchone()[0]
    print(json.dumps({'kind':'operator_unblock','seconds':time.monotonic()-start,'result':recovered}),flush=True)
  if second==240:
   stop.set()
   for t in threads:t.join(timeout=6)
   print(json.dumps({'kind':'load_stopped','seconds':time.monotonic()-start}),flush=True)
  batch=[]
  while not rows.empty():batch.append(rows.get())
  report={'kind':'sample','second':second,'ts':time.time(),'http':batch,'vk_used_memory':v.info('memory')['used_memory']}
  if second%5==0:
   try:report['storage']=c.execute(os.environ['PROBE_STORAGE_SQL']).fetchone()[0]
   except Exception as error:report['storage_error']=str(error)
  print(json.dumps(report),flush=True)
finally:
 stop.set()
 for t in threads:t.join(timeout=6)
 v.delete(key);c.execute('DELETE FROM users WHERE id=%s',(u,));c.close()
