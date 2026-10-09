from pathlib import Path
import subprocess,json,os,time,datetime
p=Path('/src');e=p/'evidence/pr230-bottleneck-20261009';env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()));sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip();assert sha=='3da0734de491a380b315fc2fb2827f4043c04823';assert not subprocess.check_output(['git','diff','--name-only'],cwd=p,text=True).strip()
commands=[('final-static',['python3','scripts/verify_static_contracts.py','--check']),('final-dependency',['python3','scripts/check_persistence_dependency_graph.py']),('final-fmt',['cargo','fmt','--all','--','--check']),('final-schema-fixture',['cargo','test','--locked','--all-features','-p','nazo-postgres','--test','migrations','pending_migrations_create_all_runtime_module_state_tables','--','--exact','--nocapture']),('final-postgres-suite',['cargo','test','--locked','--all-features','-p','nazo-postgres','--no-fail-fast','--','--nocapture'])]
for name,cmd in commands:
 t=time.monotonic();start=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with (e/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
 row={'source_sha':sha,'command':cmd,'exit':r.returncode,'elapsed_s':time.monotonic()-t,'started':start};(e/(name+'-exit.json')).write_text(json.dumps(row,indent=2));print(row,flush=True);print((e/(name+'.log')).read_text()[-1500:],flush=True)
 if r.returncode:break

