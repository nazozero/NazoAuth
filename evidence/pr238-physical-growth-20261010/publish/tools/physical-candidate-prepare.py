from pathlib import Path
import json, subprocess, hashlib, shutil, ast, sys, time
R=Path('/workspace');E=R/'evidence/pr238-physical-growth-20261010';OLD=R/'evidence/pr238-longrun-20261010'/(sys.argv[4] if len(sys.argv)>4 else 'AUTH10')
key=sys.argv[1];seconds=int(sys.argv[2]);diagnostic=sys.argv[3]=='diagnostic';D=E/key
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=R,text=True).strip()
build=json.loads((E/'build.json').read_text());assert sha==build['source_sha']
D.mkdir(exist_ok=False);(D/'requests').mkdir()
p=json.loads((OLD/'requests'/(OLD.name+'.json')).read_text())
p.update(name='pr238-physical-'+key.lower().replace('_','-')+'-20261010',request_key=key,source_sha=sha,source_tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=R,text=True).strip(),image=build['image'],expected_binary_sha256=build['binary_sha256'],duration=str(seconds+15)+'s',effective_seconds=seconds,phase_budget_seconds=seconds+420,diagnostic_only=False,status='PHYSICAL_GROWTH_DIAGNOSTIC' if diagnostic else 'CAPACITY_CONFIRMATION')
target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((OLD/'requests/manifest.json').read_text());m.update(project=p['name'],source_sha=sha,app_image=build['image'],point_timeout_s=seconds+390,point_budget_s=seconds+420,requests={key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}})
if diagnostic:
 tail=180 if OLD.name=='CC10' else 420
 margin=tail+360
 p['phase_budget_seconds']=seconds+margin
 target.write_text(json.dumps(p,indent=2))
 m.update(point_timeout_s=seconds+margin-30,point_budget_s=seconds+margin,post_observe_s=tail)
 m['requests'][key]['sha256']=hashlib.sha256(target.read_bytes()).hexdigest()
(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
shutil.copyfile(OLD/'diagnostic_controller.py',D/'diagnostic_controller.py');shutil.copyfile(OLD/'observer.sql',D/'observer.sql')
template=E/'AUTH_DIAG' if diagnostic else OLD
s=(template/'point-observer-cycle.py').read_text().replace(str(template).replace('/workspace/','/src/'),str(D).replace('/workspace/','/src/'))
# A fresh observation is required, with a per-point wait bound rather than the old task deadline.
import re
s=re.sub(r'if time.time\(\)>[^:]+:raise SystemExit\(\x27Task deadline reached before UI observation\x27\)',"if time.time()>"+str(time.time()+3600)+":raise SystemExit('UI gate deadline')",s)
ast.parse(s);(D/'point-observer-cycle.py').write_text(s)
print(D)
