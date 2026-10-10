from pathlib import Path
import subprocess,json,hashlib,shutil,re,time,ast
R=Path('/workspace');E=R/'evidence/pr238-physical-growth-20261010';D=E/'AUTH_A_CAP';assert not (D/'execution.json').exists();D.mkdir(exist_ok=True);(D/'requests').mkdir(exist_ok=True)
old=E/'AUTH_DIAG';normal=R/'evidence/pr238-longrun-20261010/AUTH10'
p=json.loads((old/'requests/AUTH_DIAG.json').read_text());p.update(name='pr238-physical-auth-a-cap-20261010',request_key='AUTH_A_CAP',arm='A',duration='195s',effective_seconds=180,phase_budget_seconds=600,diagnostic_only=False,status='CAPACITY_CONFIRMATION')
assert p['source_sha']=='432d87e523106b476dc5249390c29f82cb2615b4'
p['source_tree']=subprocess.check_output(['git','rev-parse',p['source_sha']+'^{tree}'],cwd=R,text=True).strip()
target=D/'requests/AUTH_A_CAP.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((normal/'requests/manifest.json').read_text());m.update(project=p['name'],source_sha=p['source_sha'],app_image=p['image'],point_timeout_s=570,point_budget_s=600,post_observe_s=0,requests={'AUTH_A_CAP':{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}})
(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
for f in ['diagnostic_controller.py','observer.sql']:shutil.copyfile(normal/f,D/f)
s=(normal/'point-observer-cycle.py').read_text().replace(str(normal).replace('/workspace/','/src/'),str(D).replace('/workspace/','/src/'))
s=re.sub(r'if time.time\(\)>[^:]+:raise SystemExit\(\x27Task deadline reached before UI observation\x27\)',"if time.time()>"+str(time.time()+7200)+":raise SystemExit('UI gate deadline')",s);ast.parse(s);(D/'point-observer-cycle.py').write_text(s)
print('Prepared',D,'without changing checkout or emitting load')
