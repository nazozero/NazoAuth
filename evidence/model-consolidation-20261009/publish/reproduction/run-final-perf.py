from pathlib import Path
import subprocess,time,json
E=Path('/workspace/evidence/model-consolidation-20261009')
script='''from pathlib import Path
import subprocess,time,json
E=Path('/workspace/evidence/model-consolidation-20261009')
for key in ['MODEL02','MODEL10','MODEL03','MODEL04']:
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/model-consolidation-20261009/'+key,'-w','/src','nazoauth-perf-controller-20261009','python','/src/evidence/model-consolidation-20261009/point-wrapper-model.py',action]
  t=time.monotonic()
  with (E/(key+'-'+action+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
  row={'key':key,'action':action,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t}
  with (E/'formal-commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\\n')
  print(row,flush=True)
  if action=='setup' and r.returncode:raise SystemExit(r.returncode)
  if action!='setup' and r.returncode not in [0,2,3]:raise SystemExit(r.returncode)
'''
(E/'run-formal.py').write_text(script)
with (E/'launch-formal.log').open('w') as f:p=subprocess.Popen(['python3',str(E/'run-formal.py')],stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
print(p.pid)

