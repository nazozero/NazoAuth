import pathlib,sys,os,json,subprocess,threading,time,gzip,hashlib
sys.path.insert(0,'/src/perf/tools')
import cnb_controller as ctl
BEGIN=time.monotonic();LOGGER=None;THREAD=None;APP_ID=None;COHORT=None
SQL=pathlib.Path('/src/evidence/pr230-bottleneck-20261009/storage-observer.sql').read_text()
WAIT_SQL="SELECT json_build_object('ts',extract(epoch from clock_timestamp()),'activity',(SELECT json_agg(s) FROM (SELECT usename,application_name,state,wait_event_type,wait_event,count(*) AS n,max(extract(epoch from clock_timestamp()-xact_start)) AS oldest_xact_s FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() GROUP BY 1,2,3,4,5) s));"

original_pin=ctl.sis.pin_container
def pin_with_evidence(container,cpus):
 for attempt in range(3):
  result=original_pin(container,cpus)
  with (ctl.E/'pin-attempts.jsonl').open('a') as f:f.write(json.dumps({'ts':time.time(),'attempt':attempt+1,'result':result})+'\n')
  if result['verified']:return result
  time.sleep(.25)
 return result
ctl.sis.pin_container=pin_with_evidence

original_audit=ctl.sis.audit_pair_up

def audit(runid,depid):
 global LOGGER,THREAD,APP_ID
 result=original_audit(runid,depid)
 APP_ID=ctl.RAW('inspect',ctl.sis.APP,'--format','{{.Id}}').stdout.strip()
 ctl.save(ctl.E/'followed-instance.json',{'id':APP_ID,'name':ctl.sis.APP,'started_after_audit_pair':True,'ts':time.time()})
 LOGGER=subprocess.Popen(['docker','logs','--follow',APP_ID],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 def follow():
  with (ctl.E/'application-ledger-maintenance.log').open('w',buffering=1) as f:
   for line in LOGGER.stdout:
    if 'POOLLEDGER ' in line or 'POOLSTATUS ' in line or 'security-state maintenance ' in line:f.write(line)
 THREAD=threading.Thread(target=follow,daemon=True);THREAD.start()
 return result
ctl.sis.audit_pair_up=audit
original_load=ctl.sis.run_load

def load(point,runid,outdir):
 global COHORT
 stop=threading.Event()
 def observe():
  tick=0
  with (ctl.E/'pg-roles.jsonl').open('w',buffering=1) as waits,(ctl.E/'storage.jsonl').open('w',buffering=1) as storage:
   while not stop.is_set():
    try:
     waits.write(json.dumps(json.loads(ctl.sis.psql(WAIT_SQL)))+'\n')
     if tick%5==0:storage.write(json.dumps(json.loads(ctl.sis.psql(SQL)))+'\n')
    except Exception as ex:waits.write(json.dumps({'ts':time.time(),'error':type(ex).__name__})+'\n')
    tick+=1;stop.wait(1)
 t=threading.Thread(target=observe,daemon=True);t.start()
 try:return original_load(point,runid,outdir)
 finally:
  stop.set();t.join(timeout=20)
  if ctl.M.get('decision_follow'):
   sql="SELECT coalesce(json_agg(json_build_object('event_id',event_id,'business_retain_until',extract(epoch from business_retain_until),'exported_at',extract(epoch from exported_at),'occurred_at',extract(epoch from occurred_at))),'[]') FROM security_audit_events WHERE event_type='authorization_decision_committed';"
   COHORT=json.loads(ctl.sis.psql(sql));ctl.save(ctl.E/'decision-cohort.json',COHORT)
ctl.sis.run_load=load
original_drain=ctl.sis.audit_drain

def drain(*a,**kw):
 result=original_drain(*a,**kw)
 if ctl.M.get('decision_follow') and COHORT:
  # Snapshot identities are evidence, never metric labels. No payload/subject is recorded.
  # Traffic has stopped; counting every decision is a conservative superset of the frozen cohort.
  q="SELECT json_build_object('ts',extract(epoch from clock_timestamp()),'remaining',count(*),'eligible',count(*) FILTER(WHERE exported_at IS NOT NULL AND business_retain_until<=clock_timestamp()),'retained',count(*) FILTER(WHERE business_retain_until>clock_timestamp()),'unexported',count(*) FILTER(WHERE exported_at IS NULL),'last_retain',max(extract(epoch from business_retain_until)),'last_exported',max(extract(epoch from exported_at))) FROM security_audit_events WHERE event_type='authorization_decision_committed';"
  deadline=BEGIN+ctl.M.get('decision_observe_budget_s',450)
  with (ctl.E/'decision-cohort-series.jsonl').open('w',buffering=1) as f,(ctl.E/'storage.jsonl').open('a',buffering=1) as storage:
   while time.monotonic()<deadline:
    row=json.loads(ctl.sis.psql(q));f.write(json.dumps(row)+'\n');storage.write(json.dumps(json.loads(ctl.sis.psql(SQL)))+'\n')
    same=ctl.RAW('inspect',ctl.sis.APP,'--format','{{.Id}}').stdout.strip()==APP_ID
    if not same:raise RuntimeError('application instance changed during cohort observation')
    if row['remaining']==0 and row['ts']>=max(x['business_retain_until'] for x in COHORT):
     ctl.save(ctl.E/'decision-cohort-terminal.json',{'cohort_size':len(COHORT),'terminal':row,'same_instance':same,'last_retain':max(x['business_retain_until'] for x in COHORT),'maintenance_log':'application-ledger-maintenance.log','status':'ZERO_REQUIRES_COMPLETED_CYCLE_CORRELATION'})
     break
    time.sleep(5)
   else:ctl.save(ctl.E/'decision-cohort-terminal.json',{'status':'INSUFFICIENT','last':row,'cohort_size':len(COHORT),'last_retain':max(x['business_retain_until'] for x in COHORT)})
 # Collect the exact final instance, after drain/observation, in addition to live following.
 if APP_ID:
  q=ctl.RAW('logs',APP_ID,timeout=20)
  lines=[l for l in (q.stdout+q.stderr).splitlines() if 'POOLLEDGER ' in l or 'POOLSTATUS ' in l or 'security-state maintenance ' in l]
  (ctl.E/'application-ledger-maintenance-final.log').write_text('\n'.join(lines)+'\n')
 return result
ctl.sis.audit_drain=drain
original_alarm=ctl.signal.alarm
ctl.signal.alarm=lambda s:original_alarm((570 if ctl.M.get('decision_follow') else 480) if s==390 else s)
try:
 if sys.argv[1]=='setup':ctl.setup()
 else:ctl.run(sys.argv[1])
finally:
 if LOGGER:
  if LOGGER.poll() is None:LOGGER.terminate()
  LOGGER.wait(timeout=10)
  THREAD.join(timeout=5)
  ctl.save(ctl.E/'follower-terminal.json',{'instance':APP_ID,'exit':LOGGER.returncode,'thread_finished':not THREAD.is_alive()})

