from pathlib import Path
import subprocess,json,time,sys
R=Path('/workspace');E=R/'evidence/pr238-physical-growth-20261010';key=sys.argv[1];D=E/key
p=json.loads((D/'requests'/f'{key}.json').read_text());candidate='4ccd02de2767a7dd586f19ccb7cf502197e02aeb'
assert key in ['AUTH_A_CAP','AUTH_A_CAP2','AUTH_CAP']
assert not (D/'execution.json').exists()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()==candidate
assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=R,text=True).strip()
cc=list((E/'CC_B15').glob('results/*/*/task-cleanup.json'));assert cc and not json.loads(cc[0].read_text())['containers_remaining']
branch=subprocess.check_output(['git','branch','--show-current'],cwd=R,text=True).strip();assert branch
records=[]
def run(cmd,label):
 start=time.time()
 with (D/(label+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=R,stdout=f,stderr=subprocess.STDOUT)
 records.append({'command':cmd,'exit':r.returncode,'start':start,'end':time.time()})
 (D/'checkout-execution.json').write_text(json.dumps({'original_branch':branch,'original_head':candidate,'records':records},indent=2))
 return r.returncode
code=1
try:
 if p['source_sha']!=candidate:assert run(['git','switch','--detach',p['source_sha']],'checkout-baseline')==0
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()==p['source_sha']
 setup=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_LOAD_BUDGET_S=2700','-e','SIS_CNB_EVIDENCE='+str(D).replace('/workspace/','/src/'),'-w','/src','nazoauth-long-controller-20261010','python',str(D/'point-observer-cycle.py').replace('/workspace/','/src/'),'setup']
 assert run(setup,'setup')==0
 code=run(['python3','/tmp/physical-growth-execute.py',key],'execute-wrapper')
finally:
 if p['source_sha']!=candidate:assert run(['git','switch',branch],'restore-candidate')==0
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()==candidate
print(json.dumps({'key':key,'exit':code,'restored_head':candidate}));sys.exit(code)
