from pathlib import Path
import os,json,subprocess,time
p=Path('/src');E=p/'evidence/pr230-performance-repair-20261009';env=os.environ.copy();env.update(json.loads((E/'workspace-env.json').read_text()));cmd=['cargo','test','--locked','--all-features','-p','nazoauth','--lib','http::authorization::par::tests::par_fapi2_rejects_shared_secret_client_auth_after_authentication','--','--exact','--ignored','--nocapture'];t=time.monotonic()
with (E/'final-explicit-fapi.log').open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
row={'source_sha':subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip(),'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(E/'final-explicit-fapi-exit.json').write_text(json.dumps(row));print(row);print((E/'final-explicit-fapi.log').read_text()[-4000:]);raise SystemExit(r.returncode)
