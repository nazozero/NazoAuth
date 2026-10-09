import subprocess,pathlib,time,json
root=pathlib.Path('/workspace/evidence/pr230-performance-20261009')
deadline=time.monotonic()+360
while not any(x.get('action')=='A04' for x in [json.loads(l) for l in (root/'formal-commands.jsonl').read_text().splitlines()]):
 if time.monotonic()>deadline:raise RuntimeError('prior serial run did not finish')
 time.sleep(5)
for key in ['A06R','A03R','B03R','B04R','A04R']:
 e='/src/evidence/pr230-performance-20261009/'+key
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE='+e,'-w','/src','nazoauth-perf-controller-20261009','python','/src/evidence/pr230-performance-20261009/point-wrapper-retry.py',action]
  t=time.monotonic()
  with (root/(key+'-'+action+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
  row={'key':key,'action':action,'command':cmd,'exit':r.returncode,'elapsed_s':time.monotonic()-t};print(row,flush=True)
  with (root/'formal-commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  assert r.returncode in ([0] if action=='setup' else [0,2,3])
