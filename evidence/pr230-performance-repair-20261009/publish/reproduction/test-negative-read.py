from pathlib import Path
import subprocess,os,json,time
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009';env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()));cmd=['cargo','test','--locked','-p','nazo-postgres','--test','read_connection_ownership','--','--nocapture'];t=time.monotonic()
with (e/'negative-read-ownership.log').open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
row={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/'negative-read-ownership-exit.json').write_text(json.dumps(row));print(row);print((e/'negative-read-ownership.log').read_text()[-5500:])
