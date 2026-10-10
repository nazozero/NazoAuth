from pathlib import Path
import subprocess,json,hashlib,shutil,time,ast
R=Path('/workspace');E=R/'evidence/pr238-physical-growth-20261010';D=E/'AUTH_A_CAP2';D.mkdir(exist_ok=False);(D/'requests').mkdir()
source='6714d3187c528ac2b9aac5c67729b1653b67a427';baseline='432d87e523106b476dc5249390c29f82cb2615b4'
cmd=['git','diff','--exit-code',source,baseline,'--','crates','migrations','Cargo.toml','Cargo.lock','rust-toolchain.toml','Containerfile','.env.yaml.example','perf'];start=time.time();r=subprocess.run(cmd,cwd=R,capture_output=True,text=True);assert r.returncode==0,r.stdout
(D/'source-equivalence.json').write_text(json.dumps({'command':cmd,'exit':r.returncode,'start':start,'end':time.time(),'image_build_source':source,'pre_revision_report_head':baseline,'meaning':'Application inputs and performance harness byte-identical; use the actual image source SHA rather than bypassing provenance checks.'},indent=2))
p=json.loads((E/'AUTH_A_CAP/requests/AUTH_A_CAP.json').read_text());p.update(name='pr238-physical-auth-a-cap2-20261010',request_key='AUTH_A_CAP2',source_sha=source,source_tree=subprocess.check_output(['git','rev-parse',source+'^{tree}'],cwd=R,text=True).strip())
target=D/'requests/AUTH_A_CAP2.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((E/'AUTH_A_CAP/requests/manifest.json').read_text());m.update(project=p['name'],source_sha=source,requests={'AUTH_A_CAP2':{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}});(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
for name in ['diagnostic_controller.py','observer.sql','observation-delta.json']:shutil.copyfile(E/'AUTH_A_CAP'/name,D/name)
s=(E/'AUTH_A_CAP/point-observer-cycle.py').read_text().replace('/src/evidence/pr238-physical-growth-20261010/AUTH_A_CAP','/src/evidence/pr238-physical-growth-20261010/AUTH_A_CAP2')
s='\n'.join((line[:len(line)-len(line.lstrip())]+f"if time.time()>{time.time()+3600}:raise SystemExit('UI gate deadline')") if "raise SystemExit('UI gate deadline')" in line else line for line in s.splitlines())+'\n';ast.parse(s);(D/'point-observer-cycle.py').write_text(s)
print('Prepared label-matched baseline; application inputs/harness equal pre-revision report head')
