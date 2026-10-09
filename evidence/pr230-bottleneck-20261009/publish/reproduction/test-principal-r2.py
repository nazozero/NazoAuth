from pathlib import Path
import subprocess,json,time,os
p=Path('/src');e=p/'evidence/pr230-bottleneck-20261009';cmd=['python3','scripts/verify_static_contracts.py','--check'];r=subprocess.run(cmd,cwd=p,capture_output=True,text=True);print(r.returncode,r.stdout,r.stderr);assert not r.returncode
(e/'static-append-exit.json').write_text(json.dumps({'command':cmd,'exit':r.returncode}))
env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()));cmd=['cargo','test','--locked','--no-fail-fast','-p','nazo-postgres','--test','query_counts','--test','refresh_family_capacity','--test','refresh_authority','--test','token_issuance_atomicity','--test','token_issuance_fresh','--test','auth_repositories','--','--nocapture'];t=time.monotonic()
with (e/'principal-regressions-r2.log').open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
row={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/'principal-regressions-r2-exit.json').write_text(json.dumps(row));print(row);print((e/'principal-regressions-r2.log').read_text()[-8500:])




