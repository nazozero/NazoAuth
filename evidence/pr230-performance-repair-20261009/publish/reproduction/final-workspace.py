from pathlib import Path
import subprocess,os,json,time
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009';sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip();assert sha==(e/'read-source-sha.txt').read_text().strip();assert not subprocess.check_output(['git','diff','--name-only'],cwd=p,text=True).strip();env=os.environ.copy();env.update(json.loads((e/'workspace-env.json').read_text()))
commands=[('final-fmt',['cargo','fmt','--all','--','--check']),('final-schema',['cargo','test','--locked','--all-features','-p','nazo-postgres','--test','migrations','pending_migrations_create_all_runtime_module_state_tables','--','--exact','--nocapture']),('final-workspace',['cargo','test','--workspace','--all-features','--locked','--no-fail-fast','--','--nocapture'])]
for name,cmd in commands:
 t=time.monotonic()
 with (e/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
 row={'source_sha':sha,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/(name+'-exit.json')).write_text(json.dumps(row));print(row,flush=True);print((e/(name+'.log')).read_text()[-4000:],flush=True)
 if r.returncode:raise SystemExit(r.returncode)
