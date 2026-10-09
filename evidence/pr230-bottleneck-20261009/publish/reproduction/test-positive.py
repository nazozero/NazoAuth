from pathlib import Path
import subprocess,os,json,time
p=Path('/src');e=p/'evidence/pr230-bottleneck-20261009';env=os.environ.copy();env.update(json.loads((e/'unit-env.json').read_text()));subprocess.run(['cargo','fmt'],cwd=p,check=True)
cmd=['cargo','test','--locked','-p','nazo-postgres','--test','query_counts','new_family_capacity_transition_has_bounded_round_trips_and_complete_evidence','--','--exact','--nocapture'];t=time.monotonic()
with (e/'positive-round-trips.log').open('w') as f:r=subprocess.run(cmd,cwd=p,env=env,stdout=f,stderr=subprocess.STDOUT)
row={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(e/'positive-round-trips-exit.json').write_text(json.dumps(row));print(row);print((e/'positive-round-trips.log').read_text()[-6000:])
