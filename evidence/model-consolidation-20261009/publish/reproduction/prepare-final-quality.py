from pathlib import Path
import subprocess
E=Path('/workspace/evidence/model-consolidation-20261009')
s='''from pathlib import Path
import subprocess,os,json,time,shutil,hashlib
R=Path('/src');E=R/'evidence/model-consolidation-20261009';sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert sha==(E/'final-source-sha.txt').read_text().strip()
assert not subprocess.check_output(['git','diff','--name-only'],cwd=R,text=True).strip()
env=os.environ.copy();env.update(json.loads((R/'evidence/pr230-performance-repair-20261009/workspace-env.json').read_text()))
commands=[('final-fmt',['cargo','fmt','--all','--','--check']),('final-clippy',['cargo','clippy','--workspace','--all-targets','--all-features','--locked','--','-D','warnings']),('final-workspace',['cargo','test','--workspace','--all-features','--locked','--no-fail-fast','--','--nocapture']),('final-release',['cargo','build','--release','--locked','-p','nazoauth'])]
for name,cmd in commands:
 t=time.monotonic()
 with (E/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=R,env=env,stdout=f,stderr=subprocess.STDOUT)
 row={'source_sha':sha,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-t};(E/(name+'-exit.json')).write_text(json.dumps(row));print(row,flush=True)
 if r.returncode:raise SystemExit(r.returncode)
shutil.copy2(R/'target/release/nazoauth',E/'final-nazoauth')
(E/'final-binary.json').write_text(json.dumps({'source_sha':sha,'sha256':hashlib.file_digest((E/'final-nazoauth').open('rb'),'sha256').hexdigest()}))
'''
(E/'final-quality.py').write_text(s)
with (E/'launch-final-quality.log').open('w') as f:p=subprocess.Popen(['docker','exec','-w','/src','nazoauth-perf-runner-20261009','python3','/src/evidence/model-consolidation-20261009/final-quality.py'],stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
print(p.pid)
