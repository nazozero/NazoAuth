from pathlib import Path
import subprocess,json
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009'
script='''from pathlib import Path
import os,subprocess,json,time
r=Path('/src');e=r/'evidence/model-consolidation-20261009';env=os.environ.copy();env.update(json.loads((r/'evidence/pr230-performance-repair-20261009/workspace-env.json').read_text()))
def run(name,cmd):
 t=time.monotonic()
 with (e/(name+'.log')).open('w') as f: p=subprocess.run(cmd,cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT)
 (e/(name+'-exit.json')).write_text(json.dumps(dict(command=cmd,exit=p.returncode,seconds=time.monotonic()-t)))
 return p.returncode
p=r/'crates/identity/src/session.rs';final=p.read_text();line='        && amr.iter().all(|method| !method.trim().is_empty())\\n';assert line in final
try:
 p.write_text(final.replace(line,''))
 code=run('session-negative',['cargo','test','--all-features','--locked','-p','nazo-identity','--test','authentication_method_authority','real_session_metadata_rejects_empty_evidence_and_invalid_time_or_sid','--','--exact'])
 assert code==101
 assert 'assertion failed: !valid_authentication_metadata' in (e/'session-negative.log').read_text()
finally:p.write_text(final)
assert run('authority-fmt',['cargo','fmt','--all'])==0
assert run('authority-identity',['cargo','test','--all-features','--locked','-p','nazo-identity'])==0
assert run('authority-postgres',['cargo','test','--all-features','--locked','-p','nazo-postgres','--lib'])==0
assert run('authority-session',['cargo','test','--all-features','--locked','-p','nazo-valkey','--test','session_contract'])==0
'''
(E/'test-authority.py').write_text(script)
with (E/'launch-authority.log').open('w') as f:
 p=subprocess.Popen(['docker','exec','-w','/src','nazoauth-perf-runner-20261009','python3','/src/evidence/model-consolidation-20261009/test-authority.py'],stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
print(p.pid)
