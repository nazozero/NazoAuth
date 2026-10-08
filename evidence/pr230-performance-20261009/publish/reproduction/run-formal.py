import subprocess,pathlib,time,json
root=pathlib.Path('/workspace/evidence/pr230-performance-20261009')
for key in ['A06','B06','B10','A10','A03','B03','B04','A04']:
 e='/src/evidence/pr230-performance-20261009/'+key
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE='+e,'-w','/src','nazoauth-perf-controller-20261009','python','/src/evidence/pr230-performance-20261009/point-wrapper.py',action]
  log=root/(key+'-'+action+'.log');t=time.monotonic()
  with log.open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
  row={'key':key,'action':action,'command':cmd,'exit':r.returncode,'elapsed_s':time.monotonic()-t};print(row,flush=True)
  with (root/'formal-commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  if action=='setup':assert r.returncode==0
  else:assert r.returncode in [0,2,3]
