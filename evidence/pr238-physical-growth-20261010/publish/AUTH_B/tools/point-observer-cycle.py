import pathlib,sys,os,json,subprocess,threading,time,importlib.util,re,datetime
ROOT=pathlib.Path('/src/evidence/pr238-physical-growth-20261010/AUTH_B')
# User-requested UI observation before each remaining test; no load threshold change.
if sys.argv[1]!='setup':
 (ROOT/'ui-waiting.json').write_text(json.dumps({'ts':time.time(),'key':sys.argv[1]}))
 while True:
  gate=ROOT/'ui-release.json'
  if gate.exists():
   observation=json.loads(gate.read_text())
   if 0<=time.time()-observation['observed_at']<=120:break
  if time.time()>1791613671.163251:raise SystemExit('UI gate deadline')
  time.sleep(2)
 (ROOT/'ui-gate-passed.json').write_text(json.dumps({'ts':time.time(),'observation':observation}))
spec=importlib.util.spec_from_file_location('diagnostic_controller',ROOT/'diagnostic_controller.py');ctl=importlib.util.module_from_spec(spec);spec.loader.exec_module(ctl)
BEGIN=time.monotonic();STOP=threading.Event();OBSERVER=None;LOGGER=None;LOGTHREAD=None;APP_ID=None;DRAINED=False;COHORT_CUTOFF=None
SQL=(ROOT/'observer.sql').read_text()
ROLES="SELECT json_build_object('ts',extract(epoch from clock_timestamp()),'activity',(SELECT json_agg(s) FROM (SELECT usename,application_name,state,wait_event_type,wait_event,count(*) AS n,max(extract(epoch from clock_timestamp()-xact_start)) AS oldest_xact_s FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() GROUP BY 1,2,3,4,5) s));"
def snapshot():
 row=json.loads(ctl.sis.psql(SQL))
 if COHORT_CUTOFF is not None:
  query="SELECT json_build_object('count',count(*),'eligible',count(*) FILTER(WHERE exported_at IS NOT NULL AND business_retain_until<=clock_timestamp()),'retained',count(*) FILTER(WHERE business_retain_until>clock_timestamp()),'unexported',count(*) FILTER(WHERE exported_at IS NULL),'last_business_retain_until',max(business_retain_until),'last_remaining_s',extract(epoch FROM max(business_retain_until)-clock_timestamp())) FROM security_audit_events WHERE event_type='authorization_decision_committed' AND occurred_at<=to_timestamp("+str(float(COHORT_CUTOFF))+");"
  row['target_decisions']=json.loads(ctl.sis.psql(query))
 return row

original_pin=ctl.sis.pin_container
def pin(container,cpus):
 for attempt in range(3):
  r=original_pin(container,cpus)
  if r['verified']:return r
  time.sleep(.25)
 return r
ctl.sis.pin_container=pin
original_audit=ctl.sis.audit_pair_up
def audit(runid,depid):
 global LOGGER,LOGTHREAD,APP_ID
 result=original_audit(runid,depid);APP_ID=ctl.RAW('inspect',ctl.sis.APP,'--format','{{.Id}}').stdout.strip()
 ctl.save(ctl.E/'followed-instance.json',{'id':APP_ID,'name':ctl.sis.APP,'ts':time.time()})
 LOGGER=subprocess.Popen(['docker','logs','--follow',APP_ID],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 def follow():
  with (ctl.E/'maintenance.log').open('w',buffering=1) as f:
   for line in LOGGER.stdout:
    if 'security-state maintenance ' in line:f.write(line)
 LOGTHREAD=threading.Thread(target=follow,daemon=True);LOGTHREAD.start();return result
ctl.sis.audit_pair_up=audit

def census():
 q=ctl.RAW('run','--rm','--network',ctl.sis.NETWORK,'--label',ctl.sis.SIS_LABEL+'='+ctl.P,'-e','RUN_ID='+ctl.P,'-v',ctl.SCRIPT_VOL+':/scripts:ro','--entrypoint','python3',ctl.M['runner_image'],'/scripts/vkledger.py','redis://valkey:6379/0','80',check=False,timeout=15)
 if q.returncode:raise RuntimeError('Valkey census failed')
 return json.loads(q.stdout)

def observe():
 tick=0
 with (ctl.E/'storage.jsonl').open('w',buffering=1) as db,(ctl.E/'pg-roles.jsonl').open('w',buffering=1) as roles,(ctl.E/'valkey-series.jsonl').open('w',buffering=1) as vk:
  while not STOP.is_set():
   began=time.monotonic()
   try:
    row=snapshot()
    if COHORT_CUTOFF is not None:
     target=ctl.E/'target-cohort.json';old=json.loads(target.read_text()) if target.exists() else None
     last=row['target_decisions']['last_business_retain_until']
     previous=old['target_decisions']['last_business_retain_until'] if old else None
     if old is None or (last and (previous is None or last>previous)):ctl.save(target,row)
    row['observer_elapsed_s']=time.monotonic()-began;db.write(json.dumps(row)+'\n')
    roles.write(json.dumps(json.loads(ctl.sis.psql(ROLES)))+'\n')
    if tick%12==0:
     db.write(json.dumps({'physical_detail':physical_detail(),'ts':time.time()})+'\n')
    if tick%6==0:
     row=census();row['ts']=time.time();vk.write(json.dumps(row)+'\n')
   except Exception as e:
    db.write(json.dumps({'ts':time.time(),'error':ctl.scrub(str(e))[:200]})+'\n')
   tick+=1;STOP.wait(max(1,10-(time.monotonic()-began)))
original_load=ctl.sis.run_load
def load(point,runid,outdir):
 global OBSERVER,COHORT_CUTOFF
 started=time.time();COHORT_CUTOFF=started+120
 ctl.save(ctl.E/'cohort-definition.json',{'defined_at':started,'occurred_at_lte':COHORT_CUTOFF,'rule':'all decisions created before load launch + 120s; original retention, full load continues'})
 ctl.save(ctl.E/'load-boundary.json',{'load_start':started,'point':point['name']})
 OBSERVER=threading.Thread(target=observe,daemon=True);OBSERVER.start()
 try:return original_load(point,runid,outdir)
 finally:
  ctl.save(ctl.E/'load-ended.json',{'load_return':time.time()});ctl.save(ctl.E/'cohort-at-stop.json',snapshot())
ctl.sis.run_load=load
original_drain=ctl.sis.audit_drain
def drain(*a,**kw):
 global DRAINED
 r=original_drain(*a,**kw)
 if DRAINED:return r
 DRAINED=True;start=time.monotonic();deadline=min(start+ctl.M['post_observe_s'],BEGIN+ctl.M['point_timeout_s']-35)
 ctl.save(ctl.E/'post-start.json',{'ts':time.time(),'budget_s':max(0,deadline-start),'audit':r})
 while time.monotonic()<deadline:
  if ctl.RAW('inspect',ctl.sis.APP,'--format','{{.Id}}').stdout.strip()!=APP_ID:raise RuntimeError('application changed')
  time.sleep(min(5,max(.01,deadline-time.monotonic())))
 ctl.save(ctl.E/'storage-terminal.json',snapshot())
 ctl.save(ctl.E/'valkey-terminal.json',census())
 ctl.save(ctl.E/'indexes-terminal.json',json.loads(ctl.sis.psql("SELECT coalesce(json_agg(s),'[]') FROM (SELECT relname,indexrelname,pg_relation_size(indexrelid) AS bytes,idx_scan,idx_tup_read,idx_tup_fetch FROM pg_stat_user_indexes ORDER BY pg_relation_size(indexrelid) DESC LIMIT 30) s;")))
 ctl.save(ctl.E/'post-ended.json',{'ts':time.time(),'elapsed_s':time.monotonic()-start})
 return r
ctl.sis.audit_drain=drain

def cycle_after_deadline():
 target=json.loads((ctl.E/'target-cohort.json').read_text())['target_decisions'];last=target['last_business_retain_until']
 if not last:return False
 deadline=datetime.datetime.fromisoformat(last.replace('Z','+00:00')).timestamp()
 for line in (ctl.E/'maintenance.log').read_text().splitlines():
  line=re.sub(r'\x1b\[[0-9;]*m','',line)
  if 'cycle completed' not in line:continue
  end=datetime.datetime.fromisoformat(line.split()[0].replace('Z','+00:00')).timestamp();elapsed=int(re.search(r'elapsed_ms=(\d+)',line)[1])/1000
  if end-elapsed>=deadline:return True
 return False

original_worker=ctl.sb.worker

def worker(*a,**kw):
 r=original_worker(*a,**kw)
 row=snapshot();ctl.save(ctl.E/'storage-after-validation.json',row)
 if not row['target_decisions']['count'] and not json.loads((ctl.E/'target-cohort.json').read_text())['target_decisions']['last_business_retain_until']:
  row['cohort_not_applicable']=True;row['full_cycle_after_target_deadline']=None
  ctl.save(ctl.E/'natural-final.json',row);return r
 while (row['target_decisions']['count'] or not cycle_after_deadline()) and time.monotonic()<BEGIN+ctl.M['point_timeout_s']-15:
  time.sleep(min(2,max(.01,BEGIN+ctl.M['point_timeout_s']-15-time.monotonic())))
  row=snapshot()
  with (ctl.E/'natural-tail.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
 row['full_cycle_after_target_deadline']=cycle_after_deadline()
 ctl.save(ctl.E/'natural-final.json',row)
 return r
ctl.sb.worker=worker


def physical_detail():
 tables=['oauth_token_issuances','security_audit_events','oauth_refresh_families','security_audit_chain_entries']
 data={'relations':{},'indexes':{}}
 for name in tables:
  data['relations'][name]=json.loads(ctl.sis.psql("SELECT row_to_json(t) FROM pgstattuple('"+name+"') t"))
 indexes=json.loads(ctl.sis.psql("SELECT json_agg(indexrelid::regclass::text) FROM pg_index WHERE indrelid IN ('oauth_token_issuances'::regclass,'security_audit_events'::regclass,'oauth_refresh_families'::regclass)"))
 for name in indexes:
  data['indexes'][name]=json.loads(ctl.sis.psql("SELECT row_to_json(t) FROM pgstatindex('"+name+"') t"))
 data['options']=json.loads(ctl.sis.psql("SELECT json_agg(t) FROM (SELECT relname,reloptions FROM pg_class WHERE relname IN ('oauth_token_issuances','security_audit_events','oauth_refresh_families')) t"))
 data['vacuum_progress']=json.loads(ctl.sis.psql("SELECT coalesce(json_agg(t),'[]') FROM (SELECT relid::regclass::text,phase,heap_blks_total,heap_blks_scanned,heap_blks_vacuumed,index_vacuum_count FROM pg_stat_progress_vacuum) t"))
 return data
original_pre_diagnostic_load=ctl.sis.run_load
def diagnostic_load(*a,**kw):
 ctl.sis.psql('CREATE EXTENSION IF NOT EXISTS pgstattuple;')
 return original_pre_diagnostic_load(*a,**kw)
ctl.sis.run_load=diagnostic_load

try:
 if sys.argv[1]=='setup':ctl.setup()
 else:ctl.run(sys.argv[1])
finally:
 STOP.set()
 if OBSERVER:OBSERVER.join(timeout=20)
 if LOGGER:
  if LOGGER.poll() is None:LOGGER.terminate()
  LOGGER.wait(timeout=10);LOGTHREAD.join(timeout=5)
