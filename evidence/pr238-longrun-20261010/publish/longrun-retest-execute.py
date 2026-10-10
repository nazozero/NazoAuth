from pathlib import Path
import subprocess,json,time
E=Path('/workspace/evidence/pr238-longrun-20261010');deadline=1791607688
assert any(json.loads(s)['key']=='CC10' and json.loads(s)['action']=='CC10' for s in (E/'commands.jsonl').read_text().splitlines())
assert not (E/'REFRESH10/load-boundary.json').exists()
for key in ['AUTH1R2','MIX1R2']:
 D=E/key;m=json.loads((D/'requests/manifest.json').read_text())
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_LOAD_BUDGET_S='+str(m['point_budget_s']),'-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-longrun-20261010/'+key,'-w','/src','nazoauth-long-controller-20261010','python','/src/evidence/pr238-longrun-20261010/'+key+'/point-observer-cycle.py',action]
  began=time.time()
  with (D/(action+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=max(1,deadline-120-time.time()))
  row={'key':key,'action':action,'command':cmd,'exit':r.returncode,'start':began,'end':time.time(),'persistent_orchestrator':True}
  with (E/'commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  print(json.dumps(row),flush=True)
  if action=='setup' and r.returncode:raise SystemExit(r.returncode)
  if r.returncode not in [0,2]:raise SystemExit(r.returncode)
