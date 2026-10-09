from pathlib import Path
import subprocess,json,os,time
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009';env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()))
cmd=['cargo','test','--locked','--all-features','-p','nazo-postgres']
for name in ['read_connection_ownership','identity_repositories','oauth_client_dcr','auth_repositories','query_counts','audit_commit_boundary','security_state_commit_boundary']:cmd+=['--test',name]
cmd+=['--','--nocapture'];t=time.monotonic()
with (e/'read-integration.log').open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
row={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/'read-integration-exit.json').write_text(json.dumps(row));print(row);print((e/'read-integration.log').read_text()[-5000:]);raise SystemExit(r.returncode)
