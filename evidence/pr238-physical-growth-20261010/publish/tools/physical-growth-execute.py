from pathlib import Path
import subprocess,time,json,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010');key=sys.argv[1];D=E/key
cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_LOAD_BUDGET_S=2700','-e','SIS_CNB_EVIDENCE='+str(D).replace('/workspace/','/src/'),'-w','/src','nazoauth-long-controller-20261010','python',str(D/'point-observer-cycle.py').replace('/workspace/','/src/'),key]
start=time.time()
with (D/'execute.log').open('w') as f:
 r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
record={'command':cmd,'exit':r.returncode,'start':start,'end':time.time()}
(D/'execution.json').write_text(json.dumps(record,indent=2));print(json.dumps(record));sys.exit(r.returncode)
