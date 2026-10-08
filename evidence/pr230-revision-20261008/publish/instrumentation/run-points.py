from pathlib import Path
import subprocess,json,time,datetime
E=Path('/src/evidence/pr230-revision-20261008');meta=json.loads((E/'perf-identities.json').read_text());commands=[]
for key in meta['order']:
 base=E/'perf'/key
 if list(base.glob('results/*/*/task-cleanup.json')):continue
 env=dict(__import__('os').environ,SIS_WORKSPACE='/src',SIS_CNB_EVIDENCE=str(base))
 for action in ['setup',key]:
  cmd=['python',str(E/('controller-wrapper-pin.py' if key in ['p03-B1','p04-B1','p04-A1'] else 'controller-wrapper.py')),action];start=time.monotonic();log=base/(action+'.log')
  with log.open('w') as f:r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
  record={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'key':key,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'log':str(log)}
  with (E/'perf-commands.jsonl').open('a') as f:f.write(json.dumps(record)+'\n')
  print(json.dumps(record),flush=True);print(log.read_text()[-2200:],flush=True)
  if action=='setup' and r.returncode:raise SystemExit(r.returncode)
  if r.returncode==3:raise SystemExit(3)
 # Continue strict FAIL capacity points; stop invalid orchestration before spending another point.
 paths=list((base/'results').glob('*/*/short-result.json'))
 if not paths or json.loads(paths[0].read_text()).get('verdict')=='INVALID':raise SystemExit(2)
