from pathlib import Path
import subprocess,json,shutil
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009'
assert (E/'final-release-exit.json').exists(), 'wait for current quality job'
for n in ['final-fmt','final-clippy','final-workspace','final-release']:
 assert json.loads((E/(n+'-exit.json')).read_text())['exit']==0,n
assert not subprocess.check_output(['git','diff','--name-only'],cwd=R,text=True).strip()
for d in ['20261009000300_compact_oidc_claim_selections','20261009000400_single_presentation_response_mode']:
 cmd=['docker','exec','-w','/src','nazoauth-perf-controller-20261009','python','scripts/verify_static_contracts.py','--append-migration',d]
 r=subprocess.run(cmd,capture_output=True,text=True);print(r.returncode,r.stdout,r.stderr);r.check_returncode()
changed=subprocess.check_output(['git','diff','--name-only'],cwd=R,text=True).splitlines();assert changed==['tests/contracts/migrations.sha256'],changed
subprocess.run(['git','diff','--check'],cwd=R,check=True)
subprocess.run(['git','add','tests/contracts/migrations.sha256'],cwd=R,check=True)
subprocess.run(['git','commit','-m','test(migrations): register model authority migrations'],cwd=R,check=True)
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip();(E/'final-source-sha.txt').write_text(sha+'\n');print(sha)
archive=E/'pre-manifest-quality';archive.mkdir(exist_ok=True)
for p in list(E.glob('final-*.log'))+list(E.glob('final-*-exit.json'))+[E/'final-binary.json']:
 if p.exists():shutil.move(p,archive/p.name)

