import pathlib,sys,os,json,subprocess,threading,time
sys.path.insert(0,'/src/perf/tools')
import cnb_controller as ctl
import hashlib
for leaf,digest in ctl.M.get('instrumentation_sha256',{}).items():
 assert hashlib.sha256((pathlib.Path('/src/evidence/pr230-revision-20261008')/leaf).read_bytes()).hexdigest()==digest,leaf

original_pin=ctl.sis.pin_container
def measured_pin(container,cpus):
 for attempt in range(3):
  result=original_pin(container,cpus)
  with (ctl.E/'pin-attempts.jsonl').open('a') as f:f.write(json.dumps({'ts':time.time(),'attempt':attempt,'result':result})+'\n')
  if result['verified'] or not container.startswith(('sis-load-','sis-side-')):return result
  time.sleep(.2)
 return result
ctl.sis.pin_container=measured_pin

original=ctl.sis.audit_pair_up
def audit(runid,depid):
 result=original(runid,depid)
 if ctl.M.get('low_required_probe'):
  before=ctl.points.audit_state_snapshot(runid)
  code=pathlib.Path('/src/evidence/pr230-revision-20261008/required-probe.py').read_text()
  q=ctl.dc('run','--rm','--network',ctl.sis.NETWORK,'--label',ctl.sis.SIS_LABEL+'='+ctl.P,'-e','PROBE_DEPLOYMENT='+depid,'--entrypoint','python',ctl.M['runner_image'],'-c',code,check=False,timeout=25)
  out=ctl.E/'low-required.json';out.write_text(q.stdout)
  ctl.event('low-required-probe',exit=q.returncode,successes=json.loads(q.stdout).get('successes') if q.returncode==0 else None)
  if q.returncode or json.loads(q.stdout).get('successes')!=30:raise RuntimeError('low traffic Required HTTP probe failed')
  drained=original_drain()
  after=ctl.points.audit_state_snapshot(runid)
  ctl.save(ctl.E/'low-required-audit.json',{'before':before,'after':after,'drain':drained})
 return result
ctl.sis.audit_pair_up=audit
load=ctl.sis.run_load
sql=pathlib.Path('/src/evidence/pr230-revision-20261008/storage-observer.sql').read_text()
def observe_load(point,runid,outdir):
 stop=threading.Event()
 def observe():
  with (outdir/'revision-storage.jsonl').open('w',buffering=1) as f:
   while not stop.is_set():
    try:row=json.loads(ctl.sis.psql(sql));f.write(json.dumps(row)+'\n')
    except Exception as e:f.write(json.dumps({'ts':time.time(),'error':type(e).__name__+': '+ctl.scrub(str(e))})+'\n')
    stop.wait(5)
 t=threading.Thread(target=observe,daemon=True);t.start()
 try:return load(point,runid,outdir)
 finally:stop.set();t.join(timeout=20)
ctl.sis.run_load=observe_load
original_drain=ctl.sis.audit_drain
def drain(*args,**kwargs):
 result=original_drain(*args,**kwargs)
 point=ctl.sis.CURRENT_POINT;out=ctl.E/'results'/point['phase']/point['name']
 try:
  row=json.loads(ctl.sis.psql(sql));row['phase']='post_drain'
  with (out/'revision-storage.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
 except Exception as error:ctl.event('storage-drain-observation-error',error=str(error))
 return result
ctl.sis.audit_drain=drain
if ctl.M.get('sustained'):
 original_alarm=ctl.signal.alarm
 ctl.signal.alarm=lambda seconds:original_alarm(510 if seconds==390 else seconds)
if sys.argv[1]=='setup':ctl.setup()
else:ctl.run(sys.argv[1])
