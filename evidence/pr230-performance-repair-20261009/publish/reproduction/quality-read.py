from pathlib import Path
import subprocess,json,os,time
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009';env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()))
commands=[('read-clippy',['cargo','clippy','--locked','--workspace','--all-targets','--all-features','--','-D','warnings']),('read-affected-tests',['cargo','test','--locked','--all-features','-p','nazo-postgres','--lib','--','--nocapture'])]
for name,cmd in commands:
 t=time.monotonic()
 with (e/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
 row={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/(name+'-exit.json')).write_text(json.dumps(row));print(row,flush=True);print((e/(name+'.log')).read_text()[-4500:],flush=True)
 if r.returncode:raise SystemExit(r.returncode)
